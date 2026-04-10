#!/usr/bin/env bash
set -euxo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$repo_dir/test/run-tests.sh"
