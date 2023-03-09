#!/usr/bin/bash

curl -k -X POST https://$1/kbs/v0/attest \
     -i \
     -b 'kbs-session-id='$2'' \
     -H 'Content-Type: application/json' \
     -d @attest.json
