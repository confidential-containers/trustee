#!/usr/bin/bash

curl -X POST $1/kbs/v0/auth \
     -i \
     -H 'Content-Type: application/json' \
     -d @auth.json
