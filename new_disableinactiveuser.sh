#!/bin/bash
# This script takes everyone with id>1000 from /etc/passwd and removes every user account in case if it hasn't been used for the last 30 days.
# Make sure that script is being executed with root priviligies.

if [[ "${UID}" -ne 0 ]]
then
echo "You should run this script as a root!"
exit 1
fi

# First of all we need to know id limit (min & max)

USER_MIN=$(grep -Po "^UID_MIN *\K.*" /etc/login.defs)
USER_MAX=$(grep -Po "^UID_MAX *\K.*" /etc/login.defs)

# create an associative array, see: help declare
declare -A users
# read all users with its uid to this associative array
while IFS=":" read -r user x uid x; do users[$user]="$uid"; done </etc/passwd
# see output of: declare -p users

# remove all unwanted lines including headline. NR is line number
lastlog -b 30 | awk '! /Never logged in/ && NR>1 {print $1}' |
  while read -r user; do
    if [[ ${users[$user]} -ge $USER_MIN ]] && [[ ${users[$user]} -le $USER_MAX ]]; then
      echo "Disable user $user with uid ${users[$user]}"
      # add your code here to disable user $user
	  usermod --expiredate 1 "$user"
    fi
  done