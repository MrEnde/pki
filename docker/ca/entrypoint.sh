#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly cmd="$*"

openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/ca-root.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/school1788.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/school1.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/test1.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/test3.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/tsa.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/interm.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/interm-ocsp.key.pem'
openssl genpkey -algorithm gost2012_512 -pkeyopt paramset:A -out '/certomancer/tests/data/keys/template.key.pem'

exec $cmd
