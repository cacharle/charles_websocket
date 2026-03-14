#!/bin/sh

docker run -it --rm \
  -v $(pwd):/config \
  -v "${PWD}/reports:/reports" \
  -v "cert.pem:/cert.pem" \
  --network=host \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingclient -s /config/autobahn.json -c /cert.pem
