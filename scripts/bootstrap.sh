#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.
set -euo pipefail

# microx git repo root directory
DIR="$( dirname "$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )" )"
PYTHON="${PYTHON:-python3}"
XED_MFILE_FLAGS="${XED_MFILE_FLAGS-"--static"}"
export CC="${CC:-$(command -v cc)}"
export CXX="${CXX:-$(command -v c++)}"

function download_and_install_xed()
{
    pushd "$DIR"/third_party/src

    if [[ ! -e xed ]] ; then
        git clone --depth 1 --single-branch --branch master https://github.com/intelxed/xed.git
    else
        pushd xed
        git pull origin master
        popd
    fi;

    if [[ ! -e mbuild ]] ; then
        git clone --depth 1 --single-branch --branch master https://github.com/intelxed/mbuild.git
    else
        pushd mbuild
        git pull origin master
        popd
    fi;

    pushd xed

    #rm -rf ./obj
    rm -rf ./microx-kit

    "${PYTHON}" ./mfile.py install \
        --install-dir ./microx-kit \
        --extra-flags="-fPIC" \
        --cc="$CC" \
        --cxx="$CXX" \
        $XED_MFILE_FLAGS

    rm -rf "$DIR"/third_party/include/xed
    cp -r ./microx-kit/include/xed "$DIR"/third_party/include/
    rm -f "$DIR"/third_party/lib/libxed*
    cp -r ./microx-kit/lib/* "$DIR"/third_party/lib/

    popd
    popd

    if [[ "$OSTYPE" == "darwin"* ]]; then
        find "$DIR"/third_party/lib -name 'libxed*.dylib' -exec install_name_tool -id {} {} \;
    fi
}

mkdir -p "$DIR"/third_party/src
mkdir -p "$DIR"/third_party/lib
mkdir -p "$DIR"/third_party/include

download_and_install_xed
