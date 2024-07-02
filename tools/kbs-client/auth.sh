#!/usr/bin/bash

curl -k -X POST https://$1/kbs/v0/auth \
     -i \
     -H 'Content-Type: application/json' \
     -d @auth.json
