#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${BUILD_DIR:-$repo_dir/build}"

qore_bin="$(command -v qore)"
qore_prefix="$(dirname "$(dirname "$qore_bin")")"

cmake -S "$repo_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$qore_prefix"
cmake --build "$build_dir"

export QORE_MODULE_DIR="$repo_dir/qlib:$build_dir:${QORE_MODULE_DIR:-}"
cd "$repo_dir/test"
"$qore_bin" --enable-debug krb5.qtest -v

