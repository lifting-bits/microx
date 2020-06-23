/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MICROX_EXECUTOR_H_H_
#define MICROX_EXECUTOR_H_H_

#include <cstdint>

namespace microx {

struct alignas(16) Data {
  uint8_t bytes[512 / 8];  // Largest register is 512 bits.
};

enum class ExecutorStatus {
  kGood,
  kErrorNotInitialized,
  kErrorDecode,
  kErrorUnsupportedCFI,
  kErrorUnsupportedStack,
  kErrorExecute,
  kErrorFault,
  kErrorFloatingPointException,
  kErrorReadFlags,
  kErrorWriteFlags,
  kErrorReadReg,
  kErrorWriteReg,
  kErrorReadMem,
  kErrorReadInstMem,
  kErrorWriteMem,
  kErrorReadFPU,
  kErrorWriteFPU
};

enum class RegRequestHint {
  kNone,
  kGeneral,
  kProgramCounter,
  kConditionCode,
  kWriteBack,
  kMemoryBaseAddress,
  kMemoryIndexAddress,
  kMemorySegmentAddress
};

enum class MemRequestHint {
  kReadOnly,
  kReadExecutable,
  kWriteOnly,
  kReadWrite,
  kAddressGeneration
};

// TODO(pag): Assumes little endian.
struct float80_t final {
  uint8_t data[10];
} __attribute__((packed));

struct vec128_t final {
  uint8_t bytes[16];
} __attribute__((packed));

union FPUStatusWord final {
  uint16_t flat;
  struct {
    uint16_t ie : 1;   // Invalid operation.
    uint16_t de : 1;   // Denormal operand.
    uint16_t ze : 1;   // Zero divide.
    uint16_t oe : 1;   // Overflow.
    uint16_t ue : 1;   // Underflow.
    uint16_t pe : 1;   // Precision.
    uint16_t sf : 1;   // Stack fault.
    uint16_t es : 1;   // Error summary status.
    uint16_t c0 : 1;   // Part of condition code.
    uint16_t c1 : 1;   // Used for a whole lot of stuff.
    uint16_t c2 : 1;   // Part of condition code.
    uint16_t top : 3;  // Stack pointer.
    uint16_t c3 : 1;   // Part of condition code.
    uint16_t b : 1;    // Busy.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(2 == sizeof(FPUStatusWord),
              "Invalid structure packing of `FPUFlags`.");

#ifdef __clang__

enum FPUPrecisionControl : uint16_t {
  kPrecisionSingle,
  kPrecisionReserved,
  kPrecisionDouble,
  kPrecisionExtended
};

enum FPURoundingControl : uint16_t {
  kFPURoundToNearestEven,
  kFPURoundDownNegInf,
  kFPURoundUpInf,
  kFPURoundToZero
};

enum FPUInfinityControl : uint16_t { kInfinityProjective, kInfinityAffine };

#else
using FPUPrecisionControl = uint16_t;
using FPURoundingControl = uint16_t;
using FPUInfinityControl = uint16_t;
#endif

union FPUControlWord final {
  uint16_t flat;
  struct {
    uint16_t im : 1;  // Invalid Operation.
    uint16_t dm : 1;  // Denormalized Operand.
    uint16_t zm : 1;  // Zero Divide.
    uint16_t om : 1;  // Overflow.
    uint16_t um : 1;  // Underflow.
    uint16_t pm : 1;  // Precision.
    uint16_t _rsvd0 : 2;
    FPUPrecisionControl pc : 2;  // bit 8
    FPURoundingControl rc : 2;
    FPUInfinityControl x : 1;
    uint16_t _rsvd1 : 3;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(2 == sizeof(FPUControlWord),
              "Invalid structure packing of `FPUControl`.");

struct FPUStackElem final {
  union {
    float80_t st;
    struct {
      uint64_t mmx;
      uint16_t infinity;  // When an MMX register is used, this is all 1s.
    } __attribute__((packed));
  } __attribute__((packed));
  uint8_t _rsvd[6];
} __attribute__((packed));

static_assert(0 == __builtin_offsetof(FPUStackElem, st),
              "Invalid structure packing of `FPUStackElem::st`.");

static_assert(0 == __builtin_offsetof(FPUStackElem, mmx),
              "Invalid structure packing of `FPUStackElem::mmx`.");

static_assert(8 == __builtin_offsetof(FPUStackElem, infinity),
              "Invalid structure packing of `FPUStackElem::st`.");

static_assert(10 == __builtin_offsetof(FPUStackElem, _rsvd[0]),
              "Invalid structure packing of `FPUStackElem::st`.");

static_assert(16 == sizeof(FPUStackElem),
              "Invalid structure packing of `FPUStackElem`.");

union FPUControlStatus {
  uint32_t flat;
  struct {
    uint32_t ie : 1;   // Invalid operation.
    uint32_t de : 1;   // Denormal flag.
    uint32_t ze : 1;   // Divide by zero.
    uint32_t oe : 1;   // Overflow.
    uint32_t ue : 1;   // Underflow.
    uint32_t pe : 1;   // Precision.
    uint32_t daz : 1;  // Denormals are zero.
    uint32_t im : 1;   // Invalid operation.
    uint32_t dm : 1;   // Denormal mask.
    uint32_t zm : 1;   // Divide by zero mask.
    uint32_t om : 1;   // Overflow mask.
    uint32_t um : 1;   // Underflow mask.
    uint32_t pm : 1;   // Precision mask.
    uint32_t rn : 1;   // Round negative.
    uint32_t rp : 1;   // Round positive.
    uint32_t fz : 1;   // Flush to zero.
    uint32_t _rsvd : 16;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(4 == sizeof(FPUControlStatus),
              "Invalid structure packing of `SSEControlStatus`.");

#ifdef __clang__
enum FPUTag : uint16_t {
  kFPUTagNonZero,
  kFPUTagZero,
  kFPUTagSpecial,  // Invalid (NaN, unsupported), infinity, denormal.
  kFPUTagEmpty
};

enum FPUAbridgedTag : uint8_t { kFPUAbridgedTagEmpty, kFPUAbridgedTagValid };
#else
using FPUTag = uint16_t;
using FPUAbridgedTag = uint8_t;
#endif

// Note: Stored in top-of-stack order.
union FPUTagWord final {
  uint16_t flat;
  struct {
    FPUTag tag0 : 2;
    FPUTag tag1 : 2;
    FPUTag tag2 : 2;
    FPUTag tag3 : 2;
    FPUTag tag4 : 2;
    FPUTag tag5 : 2;
    FPUTag tag6 : 2;
    FPUTag tag7 : 2;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(FPUTagWord) == 2,
              "Invalid structure packing of `TagWord`.");

// Note: Stored in physical order.
union FPUAbridgedTagWord final {
  uint8_t flat;
  struct {
    FPUAbridgedTag r0 : 1;
    FPUAbridgedTag r1 : 1;
    FPUAbridgedTag r2 : 1;
    FPUAbridgedTag r3 : 1;
    FPUAbridgedTag r4 : 1;
    FPUAbridgedTag r5 : 1;
    FPUAbridgedTag r6 : 1;
    FPUAbridgedTag r7 : 1;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(FPUAbridgedTagWord) == 1,
              "Invalid structure packing of `FPUAbridgedTagWord`.");

#ifdef __clang__
enum RequestPrivilegeLevel : uint16_t {
  kRPLRingZero = 0,
  kRPLRingOne = 1,
  kRPLRingTwo = 2,
  kRPLRingThree = 3
};

enum TableIndicator : uint16_t {
  kGlobalDescriptorTable = 0,
  kLocalDescriptorTable = 1
};
#else
using RequestPrivilegeLevel = uint16_t;
using TableIndicator = uint16_t;
#endif

union SegmentSelector final {
  uint16_t flat;
  struct {
    RequestPrivilegeLevel rpi : 2;
    TableIndicator ti : 1;
    uint16_t index : 13;
  } __attribute__((packed));
} __attribute__((packed));

static_assert(sizeof(SegmentSelector) == 2,
              "Invalid packing of `union SegmentSelector`.");

// FPU register state that conforms with `FSAVE` and `FRSTOR`.
struct FpuFSAVE {
  FPUControlWord cwd;
  uint16_t _rsvd0;
  FPUStatusWord swd;
  uint16_t _rsvd1;
  FPUTagWord ftw;
  uint16_t fop;        // Last instruction opcode.
  uint32_t ip;         // Offset in segment of last non-control FPU instruction.
  SegmentSelector cs;  // Code segment associated with `ip`.
  uint16_t _rsvd2;
  uint32_t dp;         // Operand address.
  SegmentSelector ds;  // Data segment associated with `dp`.
  uint16_t _rsvd3;
  FPUStackElem st[8];
} __attribute__((packed));

// FPU register state that conforms with `FXSAVE` and `FXRSTOR`.
struct FpuFXSAVE {
  FPUControlWord cwd;
  FPUStatusWord swd;
  FPUAbridgedTagWord ftw;
  uint8_t _rsvd0;
  uint16_t fop;        // Last instruction opcode.
  uint32_t ip;         // Offset in segment of last non-control FPU instruction.
  SegmentSelector cs;  // Code segment associated with `ip`.
  uint16_t _rsvd1;
  uint32_t dp;         // Operand address.
  SegmentSelector ds;  // Data segment associated with `dp`.
  uint16_t _rsvd2;
  FPUControlStatus mxcsr;
  FPUControlStatus mxcsr_mask;
  FPUStackElem st[8];
  vec128_t xmm[16];
} __attribute__((packed));

// FPU register state that conforms with `FXSAVE64` and `FXRSTOR64`.
struct FpuFXSAVE64 {
  FPUControlWord cwd;
  FPUStatusWord swd;
  FPUAbridgedTagWord ftw;
  uint8_t _rsvd0;
  uint16_t fop;  // Last instruction opcode.
  uint64_t ip;   // Offset in segment of last non-control FPU instruction.
  uint64_t dp;   // Operand address.
  FPUControlStatus mxcsr;
  FPUControlStatus mxcsr_mask;
  FPUStackElem st[8];
  vec128_t xmm[16];
} __attribute__((packed));

// FP register state that conforms with `FXSAVE` and `FXSAVE64`.
union alignas(16) FPU final {
  uint8_t bytes[512];  // X87 FPU needs 512 bytes of state.

  struct : public FpuFSAVE {
    uint8_t _padding0[512 - sizeof(FpuFSAVE)];
  } __attribute__((packed)) fsave;

  struct : public FpuFXSAVE {
    uint8_t _padding0[512 - sizeof(FpuFXSAVE)];
  } __attribute__((packed)) fxsave32;

  struct : public FpuFXSAVE64 {
    uint8_t _padding0[512 - sizeof(FpuFXSAVE64)];
  } __attribute__((packed)) fxsave64;
} __attribute__((packed));

static_assert(512 == sizeof(FPU), "Invalid structure packing of `FPU`.");

class Executor {
 public:
  Executor(size_t addr_size_, bool has_avx_ = false, bool has_avx512_ = false);

  virtual ~Executor(void);

  static bool Init(void);

  ExecutorStatus Execute(size_t max_num_executions = 1);

  virtual uintptr_t ComputeAddress(const char *seg_name, uintptr_t base,
                                   uintptr_t index, uintptr_t scale,
                                   uintptr_t displacement, size_t size,
                                   MemRequestHint hint) const;

  virtual bool ReadReg(const char *name, size_t size, RegRequestHint hint,
                       Data &val) const = 0;

  virtual bool WriteReg(const char *name, size_t size,
                        const Data &val) const = 0;

  virtual bool ReadMem(uintptr_t addr, size_t size, MemRequestHint hint,
                       Data &val) const = 0;

  virtual bool WriteMem(uintptr_t addr, size_t size, const Data &val) const = 0;

  virtual bool ReadFPU(FPU &val) const = 0;

  virtual bool WriteFPU(const FPU &val) const = 0;

  const size_t addr_size;
  const bool has_avx;
  const bool has_avx512;

 private:
  Executor(void) = delete;
  Executor(const Executor &) = delete;
  Executor(const Executor &&) = delete;
  Executor &operator=(const Executor &) = delete;
  Executor &operator=(const Executor &&) = delete;
};

}  // namespace microx

#endif  // MICROX_EXECUTOR_H_H_
