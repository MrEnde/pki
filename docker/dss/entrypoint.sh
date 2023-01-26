#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly cmd="$*"

ca_ready () {
  # Check that ca is up and running on port `9000`:
  dockerize -wait 'tcp://ca:9000' -timeout 5s
}

until ca_ready; do
  >&2 echo 'CA Server is unavailable - sleeping'
done

>&2 echo 'CA Server is up - continuing...'

exec $cmd
