#!/usr/bin/env python3
# Copyright 2019 Trail of Bits, all rights reserved.

import distutils.core
import os
import platform

if 2 >= int(platform.python_version().split(".")[0]):
  print("Microx is only supported on Python 3 and above.")
  exit(1)

MICROX_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

microx_core = distutils.core.Extension(
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

distutils.core.setup(
    name="microx",
    version="1.0",
    description="x86 and x86_64 micro-executor.",
    author="Peter Goodman",
    author_email="peter@trailofbits.com",
    url="https://github.com/trailofbits/microx",
    license="Apache-2.0",
    py_modules=["microx.__init__"],
    ext_modules=[microx_core])
