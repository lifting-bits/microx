#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`

XED_RELEASE=2016-02-02

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-lin-x86-64

elif [[ "$OSTYPE" == "darwin"* ]]; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-mac-x86-64
else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n"
    exit 1
fi

function fix_library()
{
    if [[ "$OSTYPE" == "darwin"* ]]; then
        install_name_tool -id $DIR/third_party/lib/lib$1.dylib $DIR/third_party/lib/lib$1.dylib
    fi
}

function download_and_extract_xed()
{
    sub_category "Downloading and installing XED."

    if [[ ! -e $DIR/blob/${XED_VERSION}.zip ]] ; then
        error "Please download XED from ${XED_URL} and place it into ${DIR}/blob."
    fi

    mkdir -p $DIR/third_party/src/xed
    unzip $DIR/blob/${XED_VERSION}.zip -d $DIR/third_party/src/xed

    # 'install' XED.
    mkdir -p $DIR/third_party/include/intel
    cp -r $DIR/third_party/src/xed/kits/${XED_VERSION}/lib/* $DIR/third_party/lib
    cp -r $DIR/third_party/src/xed/kits/${XED_VERSION}/include/* $DIR/third_party/include/intel
    fix_library xed
}

mkdir -p $DIR/third_party/lib
mkdir -p $DIR/third_party/include

if [[ -e $DIR/third_party/lib/libxed.$LIB_EXT ]] ; then
    notice "${BLUE}XED FOUND!"
else
    download_and_extract_xed
fi;