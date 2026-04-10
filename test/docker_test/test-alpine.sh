#!/usr/bin/env bash
set -euxo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! pkg-config --exists krb5 || ! pkg-config --exists krb5-gssapi; then
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache krb5-dev
    else
        echo "error: krb5 pkg-config metadata is missing and apk is not available" >&2
        exit 1
    fi
fi

"$repo_dir/test/run-tests.sh"
