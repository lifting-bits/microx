#!/usr/bin/env python3
# Copyright 2019 Trail of Bits, all rights reserved.

import os
import setuptools
import sys

if sys.version_info < (3, 5):
    print("Microx is only supported on Python 3.5 and above.")
    exit(1)

here = os.path.dirname(__file__)

with open(os.path.join(here, "README.md")) as f:
    README = f.read()

with open(os.path.join(here, "VERSION")) as f:
    VERSION = f.read().strip()

microx_core = setuptools.Extension(
    "microx_core",
    include_dirs=["microx/include", "third_party/include"],
    sources=["microx/Executor.cpp", "microx/Python.cpp"],
    extra_compile_args=["-DPYTHON_BINDINGS=1", "-std=gnu++11", "-g3", "-O0"],
    libraries=["xed"],
    library_dirs=["third_party/lib"],
    runtime_library_dirs=["third_party/lib"],
)

setuptools.setup(
    name="microx",
    version=VERSION,
    description="x86 and x86_64 micro-executor.",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Peter Goodman",
    author_email="peter@trailofbits.com",
    url="https://github.com/trailofbits/microx",
    license="Apache-2.0",
    py_modules=["microx.__init__"],
    ext_modules=[microx_core],
)
