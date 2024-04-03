!#/bin/bash

# Run from python venv
# source .venv/bin/activate

random_in_range() {
  jot -r 1 ${1} ${2}
}

get_watch_command() {
  echo $1
}

watch_rand() {
  command_str=$1
  min=$2
  max=$3
  
  while :; 
    do 
    clear
    date
    $(get_watch_command ${command_str})
    sleep_time=$(random_in_range ${min} ${max})
    echo "Sleeping ${sleep_time}s"
    sleep ${sleep_time}
  done
}

watch_rand 'python3 /Users/user/code/vendor/AmazonFlexUnlimited/app.py' 15 180
