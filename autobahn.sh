#!/bin/sh

# docker run -it --rm \
#   -v "${PWD}/config:/config" \
#   -v "${PWD}/reports:/reports" \
#   --network host \
#   crossbario/autobahn-testsuite \
#   wstest -m fuzzingclient -s /config/fuzzingclient.json

docker run -it --rm \
  -v $(pwd):/config \
  -v "${PWD}/reports:/reports" \
  --network=host \
  crossbario/autobahn-testsuite \
  wstest -m fuzzingclient -s /config/autobahn.json
