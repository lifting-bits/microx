/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MICROX_XED_H_
#define MICROX_XED_H_

#if defined(__clang__)
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wsign-conversion"
# pragma clang diagnostic ignored "-Wconversion"
# pragma clang diagnostic ignored "-Wold-style-cast"
# pragma clang diagnostic ignored "-Wswitch-enum"

#elif defined(__GNUG__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wsign-conversion"
# pragma GCC diagnostic ignored "-Wconversion"
# pragma GCC diagnostic ignored "-Wold-style-cast"
# pragma GCC diagnostic ignored "-Wswitch-enum"

#else
# error "Unknown compiler."
#endif

extern "C" {
#define XED_DLL
#include <intel/xed-interface.h>
}  // extern C

#if defined(__clang__)
# pragma clang diagnostic pop
#elif defined(__GNUG__)
# pragma GCC diagnostic pop
#endif

#endif  // MICROX_XED_H_
