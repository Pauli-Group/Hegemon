#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    exit 0
fi

declare -a candidates=(
    "/Library/Developer/CommandLineTools/usr/lib/libclang.dylib"
    "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib"
)

source_path=""
for candidate in "${candidates[@]}"; do
    if [[ -f "${candidate}" ]]; then
        source_path="${candidate}"
        break
    fi
done

if [[ -z "${source_path}" ]]; then
    echo "error: libclang.dylib not found. Install Xcode Command Line Tools or Xcode before building Hegemon on macOS." >&2
    exit 1
fi

mkdir -p "${HOME}/lib"
target_path="${HOME}/lib/libclang.dylib"

if [[ -L "${target_path}" ]]; then
    current_target="$(readlink "${target_path}")"
    if [[ "${current_target}" == "${source_path}" ]]; then
        exit 0
    fi
    rm -f "${target_path}"
fi

if [[ -e "${target_path}" && ! -L "${target_path}" ]]; then
    echo "info: leaving existing ${target_path} in place; expected libclang fallback already exists." >&2
    exit 0
fi

ln -s "${source_path}" "${target_path}"
echo "Linked ${target_path} -> ${source_path}"
