#!/usr/bin/env bash

domain="$1"
redirect_url="$2"
website="$3"
out="$4"

curl -sS \
     -X POST \
     -F 'client_name=ShrubGrazer' \
     -F "redirect_uris=$2" \
     -F 'scopes=read write' \
     -F "website=$3" \
     "https://$domain/api/v1/apps" > "$out"
