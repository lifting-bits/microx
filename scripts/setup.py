#!/usr/bin/env python
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import distutils.core
import os

MICROX_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

microx = distutils.core.Extension(
    "microx",
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
    version="0.2",
    description="x86 and x86_64 micro-executor.",
    author="Peter Goodman",
    author_email="peter@trailofbits.com",
    ext_modules=[microx])
