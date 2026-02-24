#!/usr/bin/env bash

# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# This script runs the benchmarks.
# It requires `unshare` to create a new network namespace.

if ! command -v unshare >/dev/null 2>&1; then
    echo "unshare is required but not found." >&2
    exit 1
fi

echo "Running benchmarks in a new network namespace..."

# Compile the test binary
# We use -c to compile the test binary, and then execute it in its own network namespace.
TEST_BINARY="./benchmark.test"
go test -race -c -o "${TEST_BINARY}" .

cleanup() {
    rm -f "${TEST_BINARY}"
}
trap cleanup EXIT

# Run the test binary in a new network namespace
# We filter for Benchmark functions
unshare -rn "${TEST_BINARY}" -test.v -test.bench . -test.benchmem -test.run ^$
