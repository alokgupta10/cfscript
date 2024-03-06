#!/bin/bash

# Define the threshold for inactivity (in days)
threshold=30

# Get the current date
current_date=$(date +%s)

# Iterate over each user on the system
while IFS=: read -r username _ _ _ _ home_directory _; do
    # Check if the user has logged in recently
    last_login=$(last -FRn 1 "$username" | awk '{print $5,$6,$7}')
    if [ -n "$last_login" ]; then
        last_login_date=$(date -d "$last_login" +%s)
        inactive_days=$(( (current_date - last_login_date) / 86400 ))
        if [ "$inactive_days" -ge "$threshold" ]; then
            echo "User $username has not logged in for $inactive_days days. Disabling..."
            sudo usermod --expiredate 1 "$username"
            echo "User $username disabled."
        fi
    else
        echo "User $username has never logged in. Disabling..."
        sudo usermod --expiredate 1 "$username"
        echo "User $username disabled."
    fi
done < /etc/passwd
