#!/bin/sh

user_name=$1
group_name=$2

echo "sudo chown ${user_name}:${group_name} -R /home/${user_name} ; wait a while..."
sudo chown ${user_name}:${group_name} -R /home/${user_name}

/bin/bash
