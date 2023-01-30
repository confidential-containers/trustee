#!/usr/bin/bash

export AA_SAMPLE_ATTESTER_TEST=1

rm -rf /opt/confidential-containers/kbs/repository/test
mkdir -p /opt/confidential-containers/kbs/repository/test/key
echo "1234567" >> /opt/confidential-containers/kbs/repository/test/key/test_key

resource_result=`../target/debug/client --kbs-url $1 -r test/key/test_key`

if [ "$resource_result" != "1234567" ]; then
    echo "Test failed: resource result is $resource_result"
    exit 1
fi

echo "Test passed: Get resource succussfully"
exit 0