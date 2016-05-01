/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MICROX_EXECUTOR_H_H_
#define MICROX_EXECUTOR_H_H_

#include <cstdint>

namespace microx {

struct alignas(16) Data {
  uint8_t bytes[512 / 8];  // Largest register is 512 bits.
};

struct alignas(16) FPU {
  uint8_t bytes[512];  // X87 FPU needs 512 bytes of state.
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
  kMemoryIndexAddress
};

enum class MemRequestHint {
  kReadOnly,
  kWriteOnly,
  kReadWrite
};

class Executor {
 public:
  Executor(size_t addr_size_, bool has_avx_=false, bool has_avx512_=false);

  virtual ~Executor(void);

  static bool Init(void);

  ExecutorStatus Execute(const uint8_t *bytes, size_t num_bytes);

  virtual bool ReadReg(const char *name, size_t size, RegRequestHint hint,
                       Data &val) const = 0;

  virtual bool WriteReg(const char *name, size_t size,
                        const Data &val) const = 0;

  virtual bool ReadMem(uintptr_t addr, size_t size, MemRequestHint hint,
                       Data &val) const = 0;

  virtual bool WriteMem(uintptr_t addr, size_t size,
                        const Data &val) const = 0;

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
