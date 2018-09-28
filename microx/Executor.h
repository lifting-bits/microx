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

struct alignas(64) FPU {
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

  virtual bool ReadMem(const char *seg, uintptr_t addr, size_t size,
                       MemRequestHint hint, Data &val) const = 0;

  virtual bool WriteMem(const char *seg, uintptr_t addr, size_t size,
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
