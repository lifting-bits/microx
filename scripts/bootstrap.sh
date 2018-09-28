#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`
XED_RELEASE=`date +%Y-%m-%d`
LIB_EXT=a

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
    if [[ "$OSTYPE" == "darwin"* && "$LIB_EXT" == "dylib" ]]; then
        install_name_tool -id $DIR/third_party/lib/lib$1.dylib $DIR/third_party/lib/lib$1.dylib
    fi
}

function download_and_extract_xed()
{
    pushd $DIR/third_party/src
    if [[ ! -e xed ]] ; then
        git clone --depth 1 --single-branch --branch master git@github.com:intelxed/xed.git
    else
        pushd xed
        git pull origin master
        popd
    fi;

    if [[ ! -e mbuild ]] ; then
        git clone --depth 1 --single-branch --branch master git@github.com:intelxed/mbuild.git
    else
        pushd mbuild
        git pull origin master
        popd
    fi;

    pushd xed
    python ./mfile.py install
    mkdir -p $DIR/third_party/include/intel
    
    if [[ -e ./kits/${XED_VERSION}/lib/libxed.a ]] ; then
        LIB_EXT=a
    elif [[ -e ./kits/${XED_VERSION}/lib/libxed.so ]] ; then
        LIB_EXT=so
    elif [[ -e ./kits/${XED_VERSION}/lib/libxed.dylib ]] ; then
        LIB_EXT=dylib
    fi

    cp -r ./kits/${XED_VERSION}/lib/libxed.$LIB_EXT $DIR/third_party/lib
    cp -r ./kits/${XED_VERSION}/include/* $DIR/third_party/include/intel

    fix_library xed

    popd
    popd 
}

mkdir -p $DIR/third_party/src
mkdir -p $DIR/third_party/lib
mkdir -p $DIR/third_party/include

download_and_extract_xed
