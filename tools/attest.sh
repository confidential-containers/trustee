#!/usr/bin/bash

curl -X POST $1/kbs/v0/attest \
     -i \
     -b 'kbs-session-id='$2'' \
     -H 'Content-Type: application/json' \
     -d @attest.json
