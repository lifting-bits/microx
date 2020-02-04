#!/usr/bin/env python3
# Copyright 2019 Trail of Bits, all rights reserved.

import setuptools
import os
import sys

if sys.version_info < (3, 5):
    print("Microx is only supported on Python 3.5 and above.")
    exit(1)

MICROX_DIR = os.path.dirname(os.path.realpath(__file__))
os.chdir(MICROX_DIR)

microx_core = setuptools.Extension(
    "microx_core",
    include_dirs=[
        MICROX_DIR,
        os.path.join(MICROX_DIR, "third_party", "include")],
    sources=[
        os.path.join(MICROX_DIR, "microx", "Executor.cpp"),
        os.path.join(MICROX_DIR, "microx", "Python.cpp")],
    extra_compile_args=["-std=gnu++11", "-g3", "-O0"],
    libraries=["xed"],
    library_dirs=[os.path.join(MICROX_DIR, "third_party", "lib")],
    runtime_library_dirs=[os.path.join(MICROX_DIR, "third_party", "lib")])

setuptools.setup(
    name="microx",
    version="1.0",
    description="x86 and x86_64 micro-executor.",
    author="Peter Goodman",
    author_email="peter@trailofbits.com",
    url="https://github.com/trailofbits/microx",
    license="Apache-2.0",
    py_modules=["microx.__init__"],
    ext_modules=[microx_core])
