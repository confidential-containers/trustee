#!/bin/bash

# TODO: If desired, this can be beefed up (take the kbs port as an arg, check
# the args themselves, etc.)

kbs_url=$1
lighthouse_vpn_ip=$2

kbs_port=8080
lighthouse_prefix_len=24

# get creds for the lighthouse from the kbs
/usr/local/bin/kbs-client \
  --url http://${kbs_url}:${kbs_port} \
  get-resource \
  --path "plugin/nebula-ca/credential?name=nebula-lighthouse&ip=${lighthouse_vpn_ip}/${lighthouse_prefix_len}" \
| base64 \
  -d \
  &> /tmp/raw-vpn-creds

# parse the creds from the response
cat /tmp/raw-vpn-creds | jq .node_crt[] | awk '{printf "%c", $1}' &> /opt/nebula/creds/lighthouse.crt
cat /tmp/raw-vpn-creds | jq .node_key[] | awk '{printf "%c", $1}' &> /opt/nebula/creds/lighthouse.key
cat /tmp/raw-vpn-creds | jq .ca_crt[] | awk '{printf "%c", $1}' &> /opt/nebula/creds/ca.crt


# start the lighthouse
/usr/local/bin/nebula -config /opt/nebula/config/lighthouse-config.yaml     
