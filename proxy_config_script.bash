#!/bin/bash

unset http_proxy
unset https_proxy

# Variable to be stored if required
proxy_domain=''
proxy_port=''

# Enter the Proxy Domain Name which was created in the Output of Cloudformation Stack 
echo "Enter the Proxy Domain Name: "
read proxy_domain
echo "Proxy Domain Name : ${proxy_domain}"

# Enter the Proxy Port Number which was created in the Output of Cloudformation Stack 
echo "Enter the Proxy Port Number: "
read proxy_port

# Validation of the Port Number, it should be Numeric with 4 Digit
reg='^[0-9]{4}$'
if [[ ! $proxy_port =~ $reg ]]; then
  echo 'Format of Proxy Pory is Wrong, It should be 4 digit Numeric'
  exit 0
else
   echo "Proxy Port Number : ${proxy_port}"
fi

# Printing the URL of Proxy Domain and Port
echo "Domain Proxy URL - http://${proxy_domain}:${proxy_port}"

# Setting the Environment Variable
export http_proxy=http://${proxy_domain}:${proxy_port}
export https_proxy=http://${proxy_domain}:${proxy_port}

# Appending the Proxy Configuration to bashrc file
echo "export http_proxy=http://${proxy_domain}:${proxy_port}" >> ~/.bashrc
echo "export https_proxy=http://${proxy_domain}:${proxy_port}" >> ~/.bashrc

# Appending the Proxy Configuration to bash_profile file
echo "export http_proxy=http://${proxy_domain}:${proxy_port}" >> ~/.bash_profile
echo "export https_proxy=http://${proxy_domain}:${proxy_port}" >> ~/..bash_profile

# Completion Message
echo "Proxy Configuration Completed Successfully"