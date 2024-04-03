from lib.colors import bcolors
from lib.Offer import Offer
from lib.Log import Log
import http.client, urllib
import requests, time, os, sys, json
from requests.models import Response
from datetime import datetime, timedelta
from prettytable import PrettyTable
from urllib.parse import unquote, urlparse, parse_qs
import base64, hashlib, hmac, gzip, secrets
import pyaes
from pbkdf2 import PBKDF2

try:
  from twilio.rest import Client
except:
  pass

# APP_NAME = "com.amazon.rabbit"
APP_NAME = "Amazon Flex"
APP_VERSION = "0.0"
DEVICE_NAME = "Stephen's 4th iOS Device"
MANUFACTURER = "Apple"
OS_VERSION = "17.3.1"

class FlexUnlimited:
  allHeaders = {
    "AmazonApiRequest": {
      "x-amzn-identity-auth-domain": "api.amazon.com",
      "User-Agent": "AmazonWebView/Amazon Flex/0.0/iOS/17.3.1/iPhone"
    },
    "FlexCapacityRequest": {
      "Accept": "application/json",
      "x-amz-access-token": None,
      "Authorization": "RABBIT3-HMAC-SHA256 SignedHeaders=x-amz-access-token;x-amz-date, "
                       "Signature=eef7d3bd5d82581e288a567d18e7ca714c699bee181ffe04efee33314d45908d",
      "X-Amz-Date": None,
      "Accept-Encoding": "gzip, deflate, br",
      "x-flex-instance-id": "BBE946E4-FECD-4330-B430-DAEB92327769",
      "Accept-Language": "en-US",
      "Content-Type": "application/json",
      "User-Agent": "iOS/17.3.1 (iPhone Darwin) Model/iPhone Platform/iPhone14,4 RabbitiOS/2.128.3",
      "Connection": "keep-alive",
      "Cookie": 'session-id=136-5500057-6492553; session-id-time=2342200573l; '
                'session-token=Zs/uyvQDU4mnjO6W8TRfMhYWJ1H4zEtzfnULvTXuUUD6zhI3Dr2qwsvAtWXmWTve/S0vl6+'
                '73mKpC8C+cmbJrzF7V4DvogSijYsUXghdHo0gcB4WOZao5EdmsnhQCZ9XPwhV1Tej2wQ5wBqDYj79PrRB4suZ'
                'LNUX6cfESeUHLC0Clnr1HOsBkVuTPOMpI+a3mDdo2aqaKlvM6K3j58naPFBH/nqK212m+ldHvHdmwgKN69f4'
                '+4CKxVhqUYgJT6fta3L7RCR7ehAwDRUdO82rdI8z8wBL8+lvD+ydJXddi9mZt9AgcwCBKi+Krbxr8AZDdZrkd'
                'Rafg02ddWwufgh86OdT8NJe9itmZag1FJVH9196sb5GGJzLClR6yS38cuVj; '
                'at-main="Atza|IwEBIIt-0n2AAQo9LYLP9qBGbb--NyVl2o8n3q-XAK9AmHuR3YAkPZGK1IG0wmNWpzDQyFSwTRClDVkgybx14'
                '-kX47Y0D8d821E_7IBarOWis4-wxYAlyQm5kGAGSHCBnc9V-EY0jShpJAzVMTkqpWniVFn7eimPBKgq5aNLXHFehZxod7Q_'
                '_uzzU0l8AXp7wD6GVX4_Y8yr8Ol6GifAk9YOcfB7lkUCxIWPQsTccOrMA_PleF2EvvuIRnvynTATJdX9NuxZD5LRhDTeHtbgupkM'
                'spyDc5SzuNb7Hl4gPkyMW2kDAWdWMesC2XWzpeA3mow5ds0"; '
                'sess-at-main="z9x/GSzPfOttC1XiSG6NN84J+exP3avGuODIFqTkYUM="; '
                'ubid-main=130-7585751-7988802; '
                'x-main="rIGi3aFueuKjl2PKBO15W32on@HpaIs6"'
    }
  }
  routes = {
    "GetOffers": "https://flex-capacity-na.amazon.com/GetOffersForProviderPost",
    "AcceptOffer": "https://flex-capacity-na.amazon.com/AcceptOffer",
    "GetAuthToken": "https://api.amazon.com/auth/register",
    "RequestNewAccessToken": "https://api.amazon.com/auth/token",
    "ForfeitOffer": "https://flex-capacity-na.amazon.com/schedule/blocks/",
    "GetEligibleServiceAreas": "https://flex-capacity-na.amazon.com/eligibleServiceAreas",
    "GetOfferFiltersOptions": "https://flex-capacity-na.amazon.com/getOfferFiltersOptions",
    "RealTimeAvailability": "https://flex-capacity-na.amazon.com/realTimeAvailability" # { "isAvailable": true|false } /person returns GET with state change
  }

  def __init__(self) -> None:
    try:
      with open("config.json") as configFile:
        config = json.load(configFile)
        self.username = config["username"]
        self.password = config["password"]
        self.desiredWarehouses = config["desiredWarehouses"] if len(config["desiredWarehouses"]) >= 1 else []  # list of warehouse ids
        self.minBlockRate = config["minBlockRate"]
        self.minPayRatePerHour = config["minPayRatePerHour"]
        self.arrivalBuffer = config["arrivalBuffer"]  # arrival buffer in minutes
        self.timeToLeaveBuffer = config["timeToLeaveBuffer"] # how much time needed to get ready to leave in minutes
        self.desiredStartTime = config["desiredStartTime"]  # start time in military time
        self.desiredEndTime = config["desiredEndTime"]  # end time in military time
        self.desiredWeekdays = set()
        self.retryLimit = config["retryLimit"]  # number of jobs retrieval requests to perform
        self.refreshInterval = config["refreshInterval"]  # sets delay in between getOffers requests
        self.twilioFromNumber = config["twilioFromNumber"]
        self.twilioToNumber = config["twilioToNumber"]
        self.__retryCount = 0
        self.__rate_limit_number = 1
        self.__acceptedOffers = []
        self.__startTimestamp = time.time()
        self.__requestHeaders = FlexUnlimited.allHeaders.get("FlexCapacityRequest")
        self.refreshToken = config["refreshToken"]
        self.accessToken = config["accessToken"]
        self.session = requests.Session()
        
        desiredWeekdays = config["desiredWeekdays"]

        twilioAcctSid = config["twilioAcctSid"]
        twilioAuthToken = config["twilioAuthToken"]

    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()

    if twilioAcctSid != "" and twilioAuthToken != "" and self.twilioFromNumber != "" and self.twilioToNumber != "":
      self.twilioClient = Client(twilioAcctSid, twilioAuthToken)
    else:
      self.twilioClient = None
      
    self.__setDesiredWeekdays(desiredWeekdays)

    if self.refreshToken == "":
      self.__registerAccount()

    self.__requestHeaders["x-amz-access-token"] = self.accessToken
    self.__requestHeaders["X-Amz-Date"] = FlexUnlimited.__getAmzDate()
    self.serviceAreaIds = self.__getEligibleServiceAreas()
    self.__offersRequestBody = {
      "apiVersion": "V2",
      "filters": {
        "serviceAreaFilter": self.desiredWarehouses,
        "timeFilter": {"endTime": self.desiredEndTime, "startTime": self.desiredStartTime}
      },
      "serviceAreaIds": self.serviceAreaIds
    }
    
  def __setDesiredWeekdays(self, desiredWeekdays):
    weekdayMap = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
    if len(desiredWeekdays) == 0:
      self.desiredWeekdays = None
    else:
      for day in desiredWeekdays:
        dayAbbreviated = day[:3].lower()
        if dayAbbreviated not in weekdayMap:
          print("Weekday '" + day + "' is misspelled. Please correct config.json file and restart program.")
          exit()
        self.desiredWeekdays.add(weekdayMap[dayAbbreviated])
      if len(self.desiredWeekdays) == 7:
        self.desiredWeekdays = None

  def __registerAccount(self):
    link = "https://www.amazon.com/ap/signin?ie=UTF8&clientContext=134-9172090-0857541&openid.pape.max_auth_age=0&use_global_authentication=false&accountStatusPolicy=P1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&use_audio_captcha=false&language=en_US&pageId=amzn_device_na&arb=97b4a0fe-13b8-45fd-b405-ae94b0fec45b&openid.return_to=https%3A%2F%2Fwww.amazon.com%2Fap%2Fmaplanding&openid.assoc_handle=amzn_device_na&openid.oa2.response_type=token&openid.mode=checkid_setup&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.ns.oa2=http%3A%2F%2Fwww.amazon.com%2Fap%2Fext%2Foauth%2F2&openid.oa2.scope=device_auth_access&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&disableLoginPrepopulate=0&openid.oa2.client_id=device%3A32663430323338643639356262653236326265346136356131376439616135392341314d50534c4643374c3541464b&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0"
    print("Link: " + link)
    maplanding_url = input("Open the previous link (make sure to copy the entire link) in a browser, sign in, and enter the entire resulting URL here:\n")
    parsed_query = parse_qs(urlparse(maplanding_url).query)
    reg_access_token = unquote(parsed_query['openid.oa2.access_token'][0])
    # reg_access_token = self.accessToken
    device_id = secrets.token_hex(16)
    amazon_reg_data = {
      "auth_data": {
        "access_token": reg_access_token
      },
      "cookies": {
        "domain": ".amazon.com",
        "website_cookies": []
      },
      "device_metadata": {
        "device_model": "iPhone",
        "device_serial": device_id,
        "device_type": "A3NWHXTQ4EBCZS",
        "mac_address": secrets.token_hex(64).upper(),
        "manufacturer": MANUFACTURER,
        "model": DEVICE_NAME,
        "os_version": "17.3.1",
        "product": DEVICE_NAME
      },
      "registration_data": {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "device_model": DEVICE_NAME,
        "device_serial": device_id,
        "device_type": "A3NWHXTQ4EBCZS",
        "domain": "Device",
        "os_version": OS_VERSION,
        "software_version": "1"
      },
      "requested_extensions": [
        "device_info",
        "customer_info"
      ],
      "requested_token_type": [
        "bearer",
        "mac_dms",
        "store_authentication_cookie",
        "website_cookies"
      ],
      "user_context_map": {
        "frc": self.__generate_frc(device_id)
      }
    }

    reg_headers = {
      "Content-Type": "application/json",
      "Accept-Charset": "utf-8",
      "x-amzn-identity-auth-domain": "api.amazon.com",
      "Connection": "keep-alive",
      "Accept": "*/*",
      "Accept-Language": "en-US"
    }
    res = self.session.post(FlexUnlimited.routes.get("GetAuthToken"), json=amazon_reg_data, headers=reg_headers, verify=True)
    if res.status_code != 200:
        print("login failed")
        exit(1)
    res = res.json()
    tokens = res['response']['success']['tokens']['bearer']
    self.accessToken = tokens['access_token']
    self.refreshToken = tokens['refresh_token']
    print("Displaying refresh token in case config file fails to save tokens.")
    print("If it fails, copy the refresh token into the config file manually.")
    print("Refresh token: " + self.refreshToken)
    try:
      with open("config.json", "r+") as configFile:
        config = json.load(configFile)
        config["accessToken"] = self.accessToken
        config["refreshToken"] = self.refreshToken
        configFile.seek(0)
        json.dump(config, configFile, indent=2)
        configFile.truncate()
    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()
    print("registration successful")

  @staticmethod
  def __generate_frc(device_id):
    """
    Helper method for the register function. Generates user context map.
    """
    cookies = json.dumps({
      "ApplicationName": APP_NAME,
      "ApplicationVersion": APP_VERSION,
      "DeviceLanguage": "en",
      "DeviceName": DEVICE_NAME,
      "DeviceOSVersion": OS_VERSION,
      "IpAddress": requests.get('https://api.ipify.org').text,
      "ScreenHeightPixels": "1920",
      "ScreenWidthPixels": "1280",
      "TimeZone": "00:00",
    })
    compressed = gzip.compress(cookies.encode())
    key = PBKDF2(device_id, b"AES/CBC/PKCS7Padding").read(32)
    iv = secrets.token_bytes(16)
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=iv))
    ciphertext = encrypter.feed(compressed)
    ciphertext += encrypter.feed()
    hmac_ = hmac.new(PBKDF2(device_id, b"HmacSHA256").read(32), iv + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\0" + hmac_[:8] + iv + ciphertext).decode()

  def __getFlexAccessToken(self):
    data = {
      "app_name": APP_NAME,
      "app_version": APP_VERSION,
      "source_token_type": "refresh_token",
      "source_token": self.refreshToken,
      "requested_token_type": "access_token",
    }
    headers = { 
      "User-Agent": "iOS/17.3.1 (iPhone Darwin) Model/iPhone Platform/iPhone14,4 RabbitiOS/2.128.3",
      "x-amzn-identity-auth-domain": "api.amazon.com",
    }
    res = self.session.post(FlexUnlimited.routes.get("RequestNewAccessToken"), json=data, headers=headers).json()
    self.accessToken = res['access_token']
    try:
      with open("config.json", "r+") as configFile:
        config = json.load(configFile)
        config["accessToken"] = self.accessToken
        configFile.seek(0)
        json.dump(config, configFile, indent=2)
        configFile.truncate()
    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()
    self.__requestHeaders["x-amz-access-token"] = self.accessToken

  def __getFlexRequestAuthToken(self) -> str:
    """
        Get authorization token for Flex Capacity requests
        Returns:
        An access token as a string
        """
    payload = {
      "requested_extensions": ["device_info", "customer_info"],
      "cookies": {
        "website_cookies": [],
        "domain": ".amazon.com"
      },
      "registration_data": {
        "domain": "Device",
        "app_version": "0.0",
        "device_type": "A3NWHXTQ4EBCZS",
        "os_version": "17.3.1",
        "device_serial": "0000000000000000",
        "device_model": "iPhone",
        "app_name": "Amazon Flex",
        "software_version": "1"
      },
      "auth_data": {
        "user_id_password": {
          "user_id": self.username,
          "password": self.password
        }
      },
      "user_context_map": {
        "frc": ""},
      "requested_token_type": ["bearer", "mac_dms", "website_cookies"]
    }
    try:
      response: Response = self.session.post(FlexUnlimited.routes.get("GetAuthToken"),
                               headers=FlexUnlimited.allHeaders.get("AmazonApiRequest"), json=payload).json()
      return response.get("response").get("success").get("tokens").get("bearer").get("access_token")
    except Exception as e:
      twoStepVerificationChallengeUrl = self.__getTwoStepVerificationChallengeUrl(response)
      print("Unable to authenticate to Amazon Flex.")
      print(f"\nPlease try completing the two step verification challenge at \033[1m{twoStepVerificationChallengeUrl}\033[0m . Then try again.")
      print("\nIf you already completed the two step verification, please check your Amazon Flex username and password in the config file and try again.")
      sys.exit()

  """
  Parse the verification challenge code unique to the user from the failed login attempt and return the url where they can complete the two step verification.
  """
  def __getTwoStepVerificationChallengeUrl(self, challengeRequest: Response) -> str:
    verificationChallengeCode: str = challengeRequest.get("response").get("challenge").get("uri").split("?")[1].split("=")[1]
    return "https://www.amazon.com/ap/challenge?openid.return_to=https://www.amazon.com/ap/maplanding&openid.oa2.code_challenge_method=S256&openid.assoc_handle=amzn_device_ios_us&pageId=amzn_device_ios_light&accountStatusPolicy=P1&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.mode=checkid_setup&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.ns.oa2=http://www.amazon.com/ap/ext/oauth/2&openid.oa2.client_id=device:30324244334531423246314134354635394236443142424234413744443936452341334e5748585451344542435a53&language=en_US&openid.ns.pape=http://specs.openid.net/extensions/pape/1.0&openid.oa2.code_challenge=n76GtDRiGSvq-Bhrez9x0CypsZFB_7eLfEDy_qZtqFk&openid.oa2.scope=device_auth_access&openid.ns=http://specs.openid.net/auth/2.0&openid.pape.max_auth_age=0&openid.oa2.response_type=code" + f"&arb={verificationChallengeCode}"

  @staticmethod
  def __getAmzDate() -> str:
    """
        Returns Amazon formatted timestamp as string
        """
    return datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

  def __getEligibleServiceAreas(self):
    self.__requestHeaders["X-Amz-Date"] = FlexUnlimited.__getAmzDate()
    response = self.session.get(
      FlexUnlimited.routes.get("GetEligibleServiceAreas"),
      headers=self.__requestHeaders)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      response = self.session.get(
        FlexUnlimited.routes.get("GetEligibleServiceAreas"),
        headers=self.__requestHeaders
      )
    return response.json().get("serviceAreaIds")

  def getAllServiceAreas(self):
    self.__requestHeaders["X-Amz-Date"] = FlexUnlimited.__getAmzDate()
    response = self.session.get(
      FlexUnlimited.routes.get("GetOfferFiltersOptions"),
      headers=self.__requestHeaders
      )
    if response.status_code == 403:
      self.__getFlexAccessToken()
      response = self.session.get(
        FlexUnlimited.routes.get("GetOfferFiltersOptions"),
        headers=self.__requestHeaders
      )

    serviceAreaPoolList = response.json().get("serviceAreaPoolList")
    serviceAreasTable = PrettyTable()
    serviceAreasTable.field_names = ["Service Area Name", "Service Area ID"]
    for serviceArea in serviceAreaPoolList:
      serviceAreasTable.add_row([serviceArea["serviceAreaName"], serviceArea["serviceAreaId"]])
    return serviceAreasTable

  def __getOffers(self) -> Response:
    """
    Get job offers.
    
    Returns:
    Offers response object
    """
    response = self.session.post(
      FlexUnlimited.routes.get("GetOffers"),
      headers=self.__requestHeaders,
      json=self.__offersRequestBody)
    if response.status_code == 403:
      self.__getFlexAccessToken()
      response = self.session.post(
        FlexUnlimited.routes.get("GetOffers"),
        headers=self.__requestHeaders,
        json=self.__offersRequestBody)
    return response

  def __acceptOffer(self, offer: Offer):
    self.__requestHeaders["X-Amz-Date"] = self.__getAmzDate()

    request = self.session.post(
      FlexUnlimited.routes.get("AcceptOffer"),
      headers=self.__requestHeaders,
      json={"offerId": offer.id})

    if request.status_code == 403:
      self.__getFlexAccessToken()
      request = self.session.post(
        FlexUnlimited.routes.get("AcceptOffer"),
        headers=self.__requestHeaders,
        json={"offerId": offer.id})

    if request.status_code == 200:
      self.__acceptedOffers.append(offer)
      # Mark last minute accepted offers as urgent notifications.
      is_urgent = False
      if self.arrivalBuffer and self.timeToLeaveBuffer:
        is_urgent = offer.startTime - datetime.now() < timedelta(minutes=self.arrivalBuffer + self.timeToLeaveBuffer)

      self.__sendPushNotif(msg=offer.toHTML(), title="Flex block scheduled!", is_urgent=is_urgent)
      Log.info(f"Successfully accepted an offer.")
    else:
      Log.error(f"Unable to accept an offer. Request returned status code {request.status_code}")

  def __sendPushNotif(self, msg: str, title="", is_urgent=False):
    PUSHER_APP_TOKEN = None
    PUSHER_USER_KEY = None
    PUSHER_DEVICE = None

    try:
      with open("config.json") as configFile:
        config = json.load(configFile)
        PUSHER_APP_TOKEN = config["PUSHER_APP_TOKEN"]
        PUSHER_USER_KEY = config["PUSHER_USER_KEY"]
        PUSHER_DEVICE = config["PUSHER_DEVICE"]
    except KeyError as nullKey:
      Log.error(f'{nullKey} was not set. Please setup FlexUnlimited as described in the README.')
      sys.exit()
    except FileNotFoundError:
      Log.error("Config file not found. Ensure a properly formatted 'config.json' file exists in the root directory.")
      sys.exit()

    if PUSHER_APP_TOKEN is not None and PUSHER_USER_KEY is not None:
      conn = http.client.HTTPSConnection("api.pushover.net:443")
      unix_timestamp = (datetime.now() - datetime(1970, 1, 1)).total_seconds()
      req = {
        "token": PUSHER_APP_TOKEN,
        "user": PUSHER_USER_KEY,
        "message": msg,
        "priority": 1,
        "html": 1,
        "timestamp": unix_timestamp,
        "ttl": 3600
      }
      if PUSHER_DEVICE is not None:
        req['device'] = PUSHER_DEVICE
      
      if title != "":
        req['title'] = title

      if is_urgent:
        # TODO: add different sound
        req['priority'] = 2
        # These are required with priority=2. See https://pushover.net/api#priority
        req['retry'] = 30
        req['expire'] = 1800

      conn.request("POST", "/1/messages.json", urllib.parse.urlencode(req), { "Content-type": "application/x-www-form-urlencoded" })
      conn.getresponse()
    else:
      Log.error(bcolors.FAIL + "Unable to send push notification. Configure Pusher.net settings ing config.json" + bcolors.END)


  def __processOffer(self, offer: Offer):
    if offer.hidden:
      return
      
    if self.desiredWeekdays:
      if offer.weekday not in self.desiredWeekdays:
        return

    if self.minBlockRate:
      if offer.blockRate < self.minBlockRate:
        return

    if self.minPayRatePerHour:
      if offer.ratePerHour < self.minPayRatePerHour:
        return

    if self.arrivalBuffer:
      deltaTime = (offer.startTime - datetime.now()).seconds / 60
      if deltaTime < self.arrivalBuffer:
        return

    Log.info(offer.toString(True) + "\n--------------------------------")
    if offer.id == "Ok9mZmVySWQuRW5jcnlwdGlvbktleS02aGlZbDQAAACDDtWCQwmuLr5tJZbLlTawLohz7rveFJ5Il3+r7p0D6BSmhpWkZJ1OkwIOWOrjhCVhmyiYg9HAH2q8e0F8ShWf676rH5ZIoHtsp6lWRDWNChkHLgk6C6oVkYW/AEaB4bVJR+oIaZyC+TrKxOy7l7pgYYP50DLOEwKivsI1pkvQXWb1vwBGuZTnBbSKixN4ZRzw6H9IaprJ20MDtW+jm8EIXgXRv2tcEOi7v8rprYUkoFI1enoCUD/Clz0Kndk0XTKfiKlEkDPXGgMwlmDOGL9zSE7SOZ98KcdsdfQs0XM/scOjR1Q9YtzO9LAAGfXR5D4qFu8zKDJSSdl4YZwwnilYJ4EtcloWEWrm/uK/BgNwczos3hUXPRaJJd9IvadrDwqlnx5fUh/SXEtvaVIvui0oqNTXXFKy6J39R9ANV4PYcdXZQf7PnkwEuzHWrbAtV1RH7N2UDQciy5EO0xEVXhvYGg==|x/uka/G6Qmq9q/Pse3t+Zc9yI65L2ijKwvRp0hXD+20=":
      Log.info("sending notif")
      is_urgent = offer.startTime - datetime.now() < timedelta(minutes=self.arrivalBuffer + self.timeToLeaveBuffer)
      self.__sendPushNotif(msg=offer.toHTML(), title="Flex block scheduled!", is_urgent=is_urgent)
    # self.__acceptOffer(offer)

  def run(self):
    Log.info("Starting job search...")
    while self.__retryCount < self.retryLimit:
      if not self.__retryCount % 50:
        print(self.__retryCount, 'requests attempted\n\n')

      offersResponse = self.__getOffers()
      if offersResponse.status_code == 200:
        currentOffers = offersResponse.json().get("offerList")
        currentOffers.sort(key=lambda pay: int(pay['rateInfo']['priceAmount']),
                           reverse=True)
        Log.info("Showing " + str(len(currentOffers)) + " offers")
        for offer in currentOffers:
          # Log.info("offer response" + print(offer))
          offerResponseObject = Offer(offerResponseObject=offer)
          self.__processOffer(offerResponseObject)
        # We got a respsonse, so don't need to keep trying.
        # TODO: Will this still be ok to do if the AcceptOffer fails?
        self.__retryCount = self.retryLimit
      elif offersResponse.status_code == 400:
        minutes_to_wait = 30 * self.__rate_limit_number
        Log.info("Rate limit reached. Waiting for " + str(minutes_to_wait) + " minutes.")
        time.sleep(minutes_to_wait * 60)
        if self.__rate_limit_number < 4:
          self.__rate_limit_number += 1
        else:
          self.__rate_limit_number = 1
        Log.info("Resuming search.")
      else:
        Log.error(offersResponse.json())
        break
      time.sleep(self.refreshInterval)
    Log.info("Job search cycle ending...")
    Log.info(f"Accepted {len(self.__acceptedOffers)} offers in {time.time() - self.__startTimestamp} seconds")
