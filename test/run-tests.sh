#!/usr/bin/env bash
set -euxo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${BUILD_DIR:-$repo_dir/build}"
env_file=/tmp/env.sh

if [[ -f "${env_file}" ]]; then
    # shellcheck disable=SC1090
    set +u
    . "${env_file}"
    set -u
fi

qore_bin="$(command -v qore || true)"
if [[ -z "${qore_bin}" ]]; then
    echo "error: qore executable not found in PATH" >&2
    exit 1
fi
qore_prefix="${INSTALL_PREFIX:-$(dirname "$(dirname "$qore_bin")")}"

uname -a
"$qore_bin" --version
cmake --version
pkg-config --modversion krb5
pkg-config --modversion krb5-gssapi

cmake -S "$repo_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$qore_prefix"
cmake --build "$build_dir"

export QORE_MODULE_DIR="$repo_dir/qlib:$build_dir:${QORE_MODULE_DIR:-}"
cd "$repo_dir/test"
"$qore_bin" --enable-debug krb5.qtest -v
