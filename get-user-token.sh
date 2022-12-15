#!/usr/bin/env bash

curl -sS \
     -X POST \
     -F "client_id=$1" \
     -F "client_secret=$2" \
     -F "redirect_uri=$3" \
     -F 'grant_type=authorization_code' \
     -F "code=$4" \
     -F 'scope=read write' \
     "https://$5/oauth/token"
