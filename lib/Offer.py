from datetime import datetime

from lib.Log import Log
from lib.colors import bcolors
from lib.Locations import Locations

def toCurrency(num: float) -> str:
    return "${:.2f}".format(num)

class Offer:

    def __init__(self, offerResponseObject: object) -> None:
        self.id = offerResponseObject.get("offerId")
        self.expirationDate = datetime.fromtimestamp(offerResponseObject.get("expirationDate"))
        self.startTime = datetime.fromtimestamp(offerResponseObject.get("startTime"))
        self.endTime = datetime.fromtimestamp(offerResponseObject.get('endTime'))
        self.location = offerResponseObject.get('serviceAreaId')
        self.blockRate = float(offerResponseObject.get('rateInfo').get('priceAmount'))
        self.blockDuration = (self.endTime - self.startTime).seconds / 3600
        self.hidden = offerResponseObject.get("hidden")
        self.ratePerHour = self.blockRate / self.blockDuration
        self.weekday = self.expirationDate.weekday()
        self.isSurge = offerResponseObject.get('rateInfo').get('isSurge')
        self.surgeMultiplier = offerResponseObject.get('rateInfo').get('surgeMultiplier')
        self.projectedTips = float(offerResponseObject.get('rateInfo').get('projectedTips'))

    def toHTML(self) -> str:
        body = '<b>' + self.startTime.strftime("%A, %d. %B") + '</b>\n'
        body += '<b>' + self.startTime.strftime("%I:%M%p") + '-' + self.endTime.strftime("%I:%M%p") + '</b>\n'
        body += str(toCurrency(self.blockRate)) + '&nbsp;<font color="#ff0080">' + str(toCurrency(self.ratePerHour)) + '/hr</font>\n'
        body += str(self.blockDuration) + f'{" hour" if self.blockDuration == 1 else " hours"}\n'

        if self.projectedTips > 0:
            body += '<b><font color="#00ff00" size="1">TIPS: ' + str(toCurrency(self.projectedTips)) + '</font></b>\n'

        if self.isSurge and self.surgeMultiplier is not None:
            body += '<font color="#31ce31" size="1">SURGE: ' + str(self.surgeMultiplier) + '</font>\n'

        body += '<font size="2">Location: ' + Locations.get(self.location) + '</font>\n'

        return body


    def toString(self, debug = False) -> str:
        body = bcolors.HEADER + 'Location: ' + Locations.get(self.location) + bcolors.END + '\n'
        body += 'Date: ' + str(self.startTime.month) + '/' + str(self.startTime.day) + '\n'
        body += 'Pay: ' + bcolors.FAIL + str(self.blockRate) + bcolors.END + '\n'
        body += 'Pay rate per hour: ' + f'{bcolors.FAIL if self.ratePerHour > 20.0 else ""}' + str(self.ratePerHour) + bcolors.END + '\n'
        body += 'Block Duration: ' + str(self.blockDuration) + f'{"hour" if self.blockDuration == 1 else "hours"}\n'

        if not self.startTime.minute:
            body += 'Start time: ' + str(self.startTime.hour) + '00\n'
        elif self.startTime.minute < 10:
            body += 'Start time: ' + str(self.startTime.hour) + '0' + str(self.startTime.minute) + '\n'
        else:
            body += 'Start time: ' + str(self.startTime.hour) + str(self.startTime.minute) + '\n'

        if not self.endTime.minute:
            body += 'End time: ' + str(self.endTime.hour) + '00\n'
        elif self.endTime.minute < 10:
            body += 'End time: ' + str(self.endTime.hour) + '0' + str(self.endTime.minute) + '\n'
        else:
            body += 'End time: ' + str(self.endTime.hour) + str(self.endTime.minute) + '\n'

        # ⇧ 
        if self.isSurge and self.surgeMultiplier is not None:
            body += bcolors.OKGREEN + 'SURGE: ' + str(self.surgeMultiplier) + bcolors.END + '\n'
        # elif self.isSurge:
        #     body += bcolors.WARNING + 'SURGE: No multiplier' + bcolors.END +'\n'

        if self.projectedTips > 0:
            body += 'TIPS: ' + str(self.projectedTips) + '\n'

        if debug:
            body += 'offer ID: ' + self.id

        return body
