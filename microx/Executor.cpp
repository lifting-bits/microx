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

#define _XOPEN_SOURCE 1

#include <bitset>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#endif  //_WIN32

#include "XED.h"
#include "microx/Executor.h"

// TODO(ww): These headers really shouldn't be included here at all;
// the hack in Executor::Executor with PyErr_Occurred should be fixed
// at some point.
#ifdef PYTHON_BINDINGS
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-register"
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bytesobject.h>
#pragma clang diagnostic pop
#endif

namespace microx {
namespace {

enum : size_t { kPageSize = 4096 };

// A memory value that is read by the executor.
struct Memory final {
  bool present;
  bool write_back;
  xed_operand_enum_t op_name;
  xed_reg_enum_t segment_reg;
  xed_reg_enum_t base_reg;
  xed_reg_enum_t index_reg;

  uintptr_t base;
  uintptr_t index;
  uintptr_t scale;
  uintptr_t displacement;

  uintptr_t address;
  size_t size;  // In bits.
  xed_memop_t *mem_op;
  Data data;
};

union alignas(8) Flags final {
  uint64_t flat;
  struct {
    uint32_t cf : 1;  // bit 0.
    uint32_t must_be_1 : 1;
    uint32_t pf : 1;
    uint32_t must_be_0a : 1;

    uint32_t af : 1;  // bit 4.
    uint32_t must_be_0b : 1;
    uint32_t zf : 1;
    uint32_t sf : 1;

    uint32_t tf : 1;   // bit 8.
    uint32_t _if : 1;  // underscore to avoid token clash.
    uint32_t df : 1;
    uint32_t of : 1;

    uint32_t iopl : 2;  // A 2-bit field, bits 12-13.
    uint32_t nt : 1;
    uint32_t must_be_0c : 1;

    uint32_t rf : 1;  // bit 16.
    uint32_t vm : 1;
    uint32_t ac : 1;  // Alignment check.
    uint32_t vif : 1;

    uint32_t vip : 1;               // bit 20.
    uint32_t id : 1;                // bit 21.
    uint32_t reserved_eflags : 10;  // bits 22-31.
    uint32_t reserved_rflags;       // bits 32-63.
  } __attribute__((packed));
} __attribute__((packed));

static_assert(8 == sizeof(Flags), "Invalid structure packing of `Flags`.");

// Scoped access to a mutex.
#ifdef _WIN32
class LockGuard {
 public:
  LockGuard(CRITICAL_SECTION &lock_) : lock(&lock_) {
    EnterCriticalSection(lock);
  }
  ~LockGuard(void) { LeaveCriticalSection(lock); }
  LockGuard(const LockGuard &) = delete;
  LockGuard &operator=(const LockGuard &) = delete;

 private:
  CRITICAL_SECTION *lock;
};
#else
class LockGuard {
 public:
  LockGuard(pthread_mutex_t &lock_) : lock(&lock_) { pthread_mutex_lock(lock); }
  ~LockGuard(void) { pthread_mutex_unlock(lock); }
  LockGuard(const LockGuard &) = delete;
  LockGuard &operator=(const LockGuard &) = delete;

 private:
  pthread_mutex_t *lock;
};
#endif  //_WIN32

// 32-bit decoded state.
static const xed_state_t kXEDState32 = {XED_MACHINE_MODE_LONG_COMPAT_32,
                                        XED_ADDRESS_WIDTH_32b};

// 64-bit decoded state.
static const xed_state_t kXEDState64 = {XED_MACHINE_MODE_LONG_64,
                                        XED_ADDRESS_WIDTH_64b};

// Decoded instructions.
static xed_decoded_inst_t gXedd_;
static xed_decoded_inst_t *const gXedd = &gXedd_;

// High-level encoder info for the decoded instruction to be re-emitted.
static xed_encoder_instruction_t gEmu;
static unsigned gEmuSize = 0;

// Region of executable code.
static uint8_t gExecArea_[kPageSize * 2] = {0xCC};
static uint8_t *gExecArea = nullptr;

// Storage for register data.
static std::bitset<XED_REG_LAST> gUsedRegs;
static std::bitset<XED_REG_LAST> gModifiedRegs;
static std::bitset<XED_REG_LAST> gStoreRegs;
static Data gRegs[XED_REG_LAST] = {{0}};
static xed_reg_enum_t gStackPtrAlias = XED_REG_INVALID;

static bool gUsesFPU = false;
static bool gUsesMMX = false;
FPU gFPU, gNativeFPU;

#ifdef _WIN32
static DWORD gExceptionCode = 0;
#else
static int gSignal = 0;
static struct sigaction gSignalHandler;
static struct sigaction gSIGILL;
static struct sigaction gSIGSEGV;
static struct sigaction gSIGBUS;
static struct sigaction gSIGFPE;
static sigjmp_buf gRecoveryTarget;
#endif  //_WIN32

// Flags that must be written back.
static Flags gWriteBackFlags;

// Memory read from the executor.
static Memory gMemory[2];

// Guards accesses to globals. Using pthreads for portability, so that
// libc++ / libstdc++ doesn't need to be linked in (otherwise `std::mutex`
// would be nicer).
#ifdef _WIN32
static CRITICAL_SECTION gExecutorLock;
static bool gExecutorLockInitialized = [] {
  InitializeCriticalSection(&gExecutorLock);
  return true;
}();
#else
static pthread_mutex_t gExecutorLock = PTHREAD_MUTEX_INITIALIZER;
#endif  //_WIN32

// Returns true if the executor is initialized.
static bool gIsInitialized = false;

// Decode an instruction.
static bool DecodeInstruction(const uint8_t *bytes, size_t num_bytes,
                              size_t addr_size) {
  auto dstate = 32 == addr_size ? &kXEDState32 : &kXEDState64;
  xed_decoded_inst_zero_set_mode(gXedd, dstate);
  xed_decoded_inst_set_input_chip(gXedd, XED_CHIP_ALL);
  if (XED_ERROR_NONE == xed_decode(gXedd, bytes, num_bytes)) {
    memset(&gEmu, 0, sizeof(gEmu));

    // Good defaults, will fixup special cases later.
    gEmuSize = 0;
    gEmu.iclass = xed_decoded_inst_get_iclass(gXedd);
    gEmu.effective_address_width = 64;
    gEmu.effective_operand_width = xed_decoded_inst_get_operand_width(gXedd);
    gEmu.mode = kXEDState64;

    return true;
  } else {
    return false;
  }
}

// Return the widest version of the register that respects the address size
// and presence of AVX(512).
static xed_reg_enum_t WidestRegister(const Executor *executor,
                                     xed_reg_enum_t reg) {
  xed_reg_enum_t wreg;
  wreg = (64 == executor->addr_size)
             ? xed_get_largest_enclosing_register(reg)
             : xed_get_largest_enclosing_register32(reg);
  if (wreg == XED_REG_INVALID) {
    return reg;
  }

  // If not using AVX512, then downgrade a ZMM register to a YMM register.
  if (XED_REG_ZMM_FIRST <= wreg && wreg <= XED_REG_ZMM_LAST) {
    if (!executor->has_avx512) {
      wreg = static_cast<xed_reg_enum_t>((wreg - XED_REG_ZMM_FIRST) +
                                         XED_REG_YMM_FIRST);
    }
  }

  // If not using AVX, then downgrade a YMM register to an XMM register.
  if (XED_REG_YMM_FIRST <= wreg && wreg <= XED_REG_YMM_LAST) {
    if (!executor->has_avx) {
      wreg = static_cast<xed_reg_enum_t>((wreg - XED_REG_YMM_FIRST) +
                                         XED_REG_XMM_FIRST);
    }
  }

  return wreg;
}

// Read in a register from the executor. The data of the register is stored
// into the largest enclosing register of any arch, but we identify the
// register with the widest enclosing register that respects the features
// (avx, avx512) and the address size (32, 64).
static bool ReadRegister(const Executor *executor, xed_reg_enum_t reg,
                         RegRequestHint hint) {
  if (XED_REG_INVALID == reg) {
    return true;
  }

  const auto reg_class = xed_reg_class(reg);
  if (XED_REG_CLASS_X87 == reg_class || XED_REG_CLASS_PSEUDOX87 == reg_class) {
    gUsesFPU = true;
    return true;

    // Mark the FPU as being used; we'll merge/split the MMX state manually.
  } else if (XED_REG_CLASS_MMX == reg_class) {
    gUsesFPU = true;
    gUsesMMX = true;
  }

  // Stack operations.
  if (XED_REG_STACKPUSH == reg || XED_REG_STACKPOP == reg) {
    reg = XED_REG_ESP;
    hint = RegRequestHint::kWriteBack;
  }

  // If this register will be modified then mark it as write-back so that
  // later we can only overwrite the necessary registers.
  auto widest_reg = WidestRegister(executor, reg);
  if (RegRequestHint::kWriteBack == hint) {
    gModifiedRegs.set(widest_reg);
  }

  // Don't request this register if we already got it.
  if (gUsedRegs.test(widest_reg)) {
    return true;
  }

  auto name = xed_reg_enum_t2str(widest_reg);
  auto size = xed_get_register_width_bits64(widest_reg);
  auto store_reg = xed_get_largest_enclosing_register(reg);
  auto &data = gRegs[store_reg];
  memset(data.bytes, 0, size / 8);
  auto read = executor->ReadReg(name, size, hint, data);
  gUsedRegs.set(widest_reg);
  gStoreRegs.set(store_reg);

  return read;
}

// Read in register values associated with memory operands.
static bool ReadRegistersMemOp(const Executor *executor, unsigned op_num) {
  auto base_reg = xed_decoded_inst_get_base_reg(gXedd, op_num);
  auto index_reg = xed_decoded_inst_get_index_reg(gXedd, op_num);
  return ReadRegister(executor, base_reg, RegRequestHint::kMemoryBaseAddress) &&
         ReadRegister(executor, index_reg, RegRequestHint::kMemoryIndexAddress);
}

// Read in registers from the executor. This opportunistically read in written-
// only instructions for completeness/simplicity, even though that introduces
// a false dependency.
static bool ReadRegisters(const Executor *executor) {
  auto num_operands = xed_decoded_inst_noperands(gXedd);
  auto xedi = xed_decoded_inst_inst(gXedd);

  // Start by going and getting registers involved in memory access.
  for (auto i = 0U, mem_index = 0U; i < num_operands; ++i) {
    auto xedo = xed_inst_operand(xedi, i);
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
      case XED_OPERAND_MEM1:
        if (!ReadRegistersMemOp(executor, mem_index++)) {
          return false;
        }
        break;
      default:
        break;
    }
  }

  // Then get the registers associated with reads.
  for (auto i = 0U; i < num_operands; ++i) {
    auto xedo = xed_inst_operand(xedi, i);
    if (xed_operand_written(xedo)) {
      continue;
    }
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_REG:
      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
      case XED_OPERAND_REG4:
      case XED_OPERAND_REG5:
      case XED_OPERAND_REG6:
      case XED_OPERAND_REG7:
      case XED_OPERAND_REG8:
        if (auto reg = xed_decoded_inst_get_reg(gXedd, op_name)) {
          if (!ReadRegister(executor, reg, RegRequestHint::kGeneral)) {
            return false;
          }
        }
        break;
      default:
        break;
    }
  }

  // Finally get the written registers.
  for (auto i = 0U; i < num_operands; ++i) {
    auto xedo = xed_inst_operand(xedi, i);
    if (!xed_operand_written(xedo)) {
      continue;
    }
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_REG:
      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
      case XED_OPERAND_REG4:
      case XED_OPERAND_REG5:
      case XED_OPERAND_REG6:
      case XED_OPERAND_REG7:
      case XED_OPERAND_REG8:
        if (auto reg = xed_decoded_inst_get_reg(gXedd, op_name)) {
          if (!ReadRegister(executor, reg, RegRequestHint::kWriteBack)) {
            return false;
          }
        }
        break;
      default:
        break;
    }
  }

  return true;
}

// Cast the value of a specific register to a type.
template <typename T>
static T ReadValue(xed_reg_enum_t reg) {
  auto reg_store = xed_get_largest_enclosing_register(reg);
  return *reinterpret_cast<T *>(gRegs[reg_store].bytes);
}

// Read the value of a general-purpose register. This handles things like
// reading from AH, BH, CH, or DH.
uintptr_t ReadGPR(xed_reg_enum_t reg) {
  auto size = xed_get_register_width_bits64(reg);
  uintptr_t shift = 0;
  if (XED_REG_GPR8h_FIRST <= reg && reg <= XED_REG_GPR8h_LAST) {
    shift = 8;
    size = 16;
  }
  switch (size) {
    case 64:
      return ReadValue<uint64_t>(reg) >> shift;
    case 32:
      return ReadValue<uint32_t>(reg) >> shift;
    case 16:
      return ReadValue<uint16_t>(reg) >> shift;
    case 8:
      return ReadValue<uint8_t>(reg) >> shift;
    default:
      return 0;
  }
}

// Cast the value of a specific register to a type.
template <typename T>
static void WriteValue(xed_reg_enum_t reg, uintptr_t val) {
  auto reg_store = xed_get_largest_enclosing_register(reg);
  *reinterpret_cast<T *>(gRegs[reg_store].bytes) = static_cast<T>(val);
}

// Write a value to a general-purpose register. This handles things like
// reading from AH, BH, CH, or DH.
void WriteGPR(xed_reg_enum_t reg, uintptr_t val) {
  switch (xed_get_register_width_bits64(reg)) {
    case 64:
      WriteValue<uint64_t>(reg, val);
      break;
    case 32:
      WriteValue<uint64_t>(reg, static_cast<uint32_t>(val));  // Zero-extends.
      break;
    case 16:
      WriteValue<uint16_t>(reg, val);
      break;
    case 8:
      if (XED_REG_GPR8h_FIRST <= reg && reg <= XED_REG_GPR8h_LAST) {
        auto whole_val = ReadValue<uint64_t>(reg);
        whole_val &= ~0xFF00;
        whole_val |= ((val & 0xFFU) << 8);
        WriteValue<uint64_t>(reg, whole_val);
      } else {
        WriteValue<uint8_t>(reg, val);
      }
      break;
    default:
      return;
  }
}

// Write the registers back to the executor. We only write back ones that
// may have been modified (W, *RW, *CW).
static bool WriteRegisters(const Executor *executor) {
  if (XED_REG_INVALID != gStackPtrAlias) {
    WriteGPR(XED_REG_RSP, ReadGPR(gStackPtrAlias));
    gStackPtrAlias = XED_REG_INVALID;
  }

  xed_reg_enum_t pc_reg = XED_REG_INVALID;
  for (auto i = 0UL; i < gUsedRegs.size(); ++i) {
    const auto reg = static_cast<xed_reg_enum_t>(i);
    if (!gUsedRegs[i]) {
      continue;
    }
    if (i == XED_REG_EIP || i == XED_REG_RIP) {
      pc_reg = reg;
    } else if (gModifiedRegs.test(i)) {
      const auto name = xed_reg_enum_t2str(reg);
      const auto size = xed_get_register_width_bits64(reg);
      const auto store_reg = xed_get_largest_enclosing_register(reg);
      if (!executor->WriteReg(name, size, gRegs[store_reg])) {
        return false;
      }
    }
  }

  // Make sure the last written register is the program counter.
  if (XED_REG_INVALID != pc_reg) {
    const auto name = xed_reg_enum_t2str(pc_reg);
    const auto size = xed_get_register_width_bits64(pc_reg);
    const auto store_reg = xed_get_largest_enclosing_register(pc_reg);
    if (!executor->WriteReg(name, size, gRegs[store_reg])) {
      return false;
    }
  }

  return true;
}

// Get the bit offset for a `BT*` instruction.
//
// Note: This function is destructive insofar as it goes and modifies the
//       reg/immediate source operands to "relative" them to the bit to the
//       memory cell that should be read.
static uintptr_t GetBitOpByteOffset(void) {
  const auto iform = xed_decoded_inst_get_iform_enum(gXedd);
  const auto bit_width = gEmu.effective_operand_width;
  switch (iform) {
    case XED_IFORM_BT_MEMv_IMMb:
    case XED_IFORM_BTS_MEMv_IMMb:
    case XED_IFORM_BTS_LOCK_MEMv_IMMb:
    case XED_IFORM_BTC_LOCK_MEMv_IMMb:
    case XED_IFORM_BTR_LOCK_MEMv_IMMb: {
      auto bit_offset = xed_decoded_inst_get_unsigned_immediate(gXedd);
      xed_decoded_inst_set_immediate_unsigned(
          gXedd, bit_offset % bit_width,
          xed_decoded_inst_get_immediate_width(gXedd));
      return 8 * (bit_offset / bit_width);
    }

    case XED_IFORM_BT_MEMv_GPRv:
    case XED_IFORM_BTS_MEMv_GPRv:
    case XED_IFORM_BTS_LOCK_MEMv_GPRv:
    case XED_IFORM_BTC_MEMv_IMMb:
    case XED_IFORM_BTC_MEMv_GPRv:
    case XED_IFORM_BTC_LOCK_MEMv_GPRv:
    case XED_IFORM_BTR_MEMv_IMMb:
    case XED_IFORM_BTR_MEMv_GPRv:
    case XED_IFORM_BTR_LOCK_MEMv_GPRv: {
      auto reg0 = xed_decoded_inst_get_reg(gXedd, XED_OPERAND_REG0);
      auto bit_offset = ReadGPR(reg0);
      WriteGPR(reg0, bit_offset % bit_width);
      return 8 * (bit_offset / bit_width);
    }

    default:
      return 0;
  }
}

// Compute a memory address and then ask the executor to read the memory at
// that address.
static bool ReadMemory(const Executor *executor, unsigned op_num,
                       unsigned mem_index) {
  const auto iform = xed_decoded_inst_get_iform_enum(gXedd);
  const auto xedi = xed_decoded_inst_inst(gXedd);
  const auto xedo = xed_inst_operand(xedi, op_num);
  auto &mem = gMemory[mem_index];

  mem.present = true;
  mem.write_back = xed_operand_written(xedo);
  mem.op_name = xed_operand_name(xedo);
  mem.segment_reg = xed_decoded_inst_get_seg_reg(gXedd, mem_index);
  mem.base_reg = xed_decoded_inst_get_base_reg(gXedd, mem_index);
  mem.index_reg = xed_decoded_inst_get_index_reg(gXedd, mem_index);
  mem.base = ReadGPR(mem.base_reg);

  // Deduce the implicit segment register.
  if (XED_REG_INVALID == mem.segment_reg) {
    mem.segment_reg = XED_REG_DS;
    if (XED_REG_RSP == xed_get_largest_enclosing_register(mem.base_reg) ||
        XED_REG_RBP == xed_get_largest_enclosing_register(mem.base_reg)) {
      mem.segment_reg = XED_REG_SS;
    }
  }

  // PC-relative memory accesses are relative to the next PC.
  if (XED_REG_EIP == mem.base_reg || XED_REG_RIP == mem.base_reg) {
    mem.base += xed_decoded_inst_get_length(gXedd);
  }

  mem.index = ReadGPR(mem.index_reg);
  mem.scale = xed_decoded_inst_get_scale(gXedd, mem_index);
  mem.displacement = static_cast<uintptr_t>(
      xed_decoded_inst_get_memory_displacement(gXedd, mem_index));

  // Adjust the displacement for this memory operand so that we're always
  // dealing with the correct memory address.
  const auto op_size_bytes = gEmu.effective_operand_width / 8;
  if (0 == mem_index) {
    switch (iform) {
      // For these, the memop is `[RSP]`, not `[RSP-N]` (which is what is
      // actually modified), so adjust accordingly.
      case XED_IFORM_CALL_NEAR_RELBRz:
      case XED_IFORM_CALL_NEAR_RELBRd:
      case XED_IFORM_CALL_NEAR_GPRv:
      case XED_IFORM_PUSH_GPRv_FFr6:
      case XED_IFORM_PUSH_GPRv_50:
      case XED_IFORM_PUSH_IMMz:
      case XED_IFORM_PUSH_IMMb:
      case XED_IFORM_PUSHF:
      case XED_IFORM_PUSHFD:
      case XED_IFORM_PUSHFQ:
      case XED_IFORM_PUSH_ES:
      case XED_IFORM_PUSH_CS:
      case XED_IFORM_PUSH_SS:
      case XED_IFORM_PUSH_DS:
      case XED_IFORM_PUSH_FS:
      case XED_IFORM_PUSH_GS:
        mem.displacement -= op_size_bytes;
        break;

      // Special case where, if the memory address being read by the POP uses
      // the stack pointer as the base register, then the stack pointer used
      // will be that *after* the POP happens.
      case XED_IFORM_POP_MEMv:
        if (XED_REG_RSP == xed_get_largest_enclosing_register(mem.base_reg)) {
          mem.displacement += op_size_bytes;
        }
        break;

      // In the case of `BT*` instructions, the memory operand is really a base
      // and the memory access itself can be very far away from the base. Figure
      // out what memory address is actually accessed by taking into account
      // what is being set/tested.
      case XED_IFORM_BT_MEMv_IMMb:
      case XED_IFORM_BT_MEMv_GPRv:
      case XED_IFORM_BTS_MEMv_IMMb:
      case XED_IFORM_BTS_MEMv_GPRv:
      case XED_IFORM_BTS_LOCK_MEMv_IMMb:
      case XED_IFORM_BTS_LOCK_MEMv_GPRv:
      case XED_IFORM_BTC_MEMv_IMMb:
      case XED_IFORM_BTC_MEMv_GPRv:
      case XED_IFORM_BTC_LOCK_MEMv_IMMb:
      case XED_IFORM_BTC_LOCK_MEMv_GPRv:
      case XED_IFORM_BTR_MEMv_IMMb:
      case XED_IFORM_BTR_MEMv_GPRv:
      case XED_IFORM_BTR_LOCK_MEMv_IMMb:
      case XED_IFORM_BTR_LOCK_MEMv_GPRv:
        mem.displacement += GetBitOpByteOffset();
        break;

      default:
        break;
    }
  } else {
    switch (iform) {
      // Same stack adjustment as above, just on a different memop.
      case XED_IFORM_CALL_NEAR_MEMv:
      case XED_IFORM_PUSH_MEMv:
        mem.displacement -= (gEmu.effective_operand_width / 8);
        break;

      default:
        break;
    }
  }

  // Create a hint for the request, so that they can pre-emptively check things
  // like writability of the address before the instruction is emulated
  // or executed.
  auto hint = MemRequestHint::kReadOnly;
  if ((xed_operand_read(xedo) || xed_operand_conditional_write(xedo)) &&
      xed_operand_written(xedo)) {
    hint = MemRequestHint::kReadWrite;
  } else if (xed_operand_written(xedo)) {
    hint = MemRequestHint::kWriteOnly;
  }

  if (XED_OPERAND_AGEN == mem.op_name) {
    hint = MemRequestHint::kAddressGeneration;
  }

  mem.address = executor->ComputeAddress(xed_reg_enum_t2str(mem.segment_reg),
                                         mem.base, mem.index, mem.scale,
                                         mem.displacement, mem.size, hint);

  // Mask the address down to its proper width. The individual values might
  // all have the correct width; however, when added together, some 32-bit
  // values might overflow into a 64-bit value.
  if (32 == xed_decoded_inst_get_memop_address_width(gXedd, mem_index)) {
    mem.address = static_cast<uint32_t>(mem.address);
  } else if (16 == xed_decoded_inst_get_memop_address_width(gXedd, mem_index)) {
    mem.address = static_cast<uint16_t>(mem.address);
  }

  mem.size = 8 * xed_decoded_inst_get_memory_operand_length(gXedd, mem_index);

  // Read in the data.
  memset(mem.data.bytes, 0, sizeof(mem.data));
  return (XED_OPERAND_AGEN == mem.op_name) ||
         executor->ReadMem(mem.address, mem.size, hint, mem.data);
}

// Read in memory from the executor.
static bool ReadMemory(const Executor *executor) {
  gMemory[0].present = false;
  gMemory[1].present = false;

  auto num_operands = xed_decoded_inst_noperands(gXedd);
  auto xedi = xed_decoded_inst_inst(gXedd);
  for (auto i = 0U; i < num_operands; ++i) {
    auto xedo = xed_inst_operand(xedi, i);
    switch (xed_operand_name(xedo)) {
      case XED_OPERAND_AGEN:
      case XED_OPERAND_MEM0:
        if (!ReadMemory(executor, i, 0)) {
          return false;
        }
        break;
      case XED_OPERAND_MEM1:
        if (!ReadMemory(executor, i, 1)) {
          return false;
        }
        break;
      default:
        break;
    }
  }
  return true;
}

// Write the memory back to the executor, if the operand action specifies it,
// that is.
static bool WriteMemory(const Executor *executor) {
  for (auto &mem : gMemory) {
    if (!mem.present || !mem.write_back) {
      continue;
    }
    if (!executor->WriteMem(mem.address, mem.size, mem.data)) {
      return false;
    }
  }
  return true;
}

// Return the value of the program counter.
static bool ReadPC(const Executor *executor) {
  auto reg = WidestRegister(executor, XED_REG_EIP);
  gModifiedRegs.set(reg);
  if (ReadRegister(executor, reg, RegRequestHint::kProgramCounter)) {
    return true;
  } else {
    return false;
  }
}

// Returns the target of a branch instruction assuming the branch is taken.
static uintptr_t BranchTarget(uintptr_t next_pc) {
  auto disp = xed_decoded_inst_get_branch_displacement(gXedd);
  return next_pc + static_cast<uintptr_t>(static_cast<intptr_t>(disp));
}

// The current program counter.
static uintptr_t GetPC(const Executor *executor) {
  auto reg = WidestRegister(executor, XED_REG_EIP);
  auto pc = ReadGPR(reg);
  if (32 == executor->addr_size) {
    return static_cast<uint32_t>(pc);
  } else {
    return pc;
  }
}

// The next program counter.
static uintptr_t GetNextPC(const Executor *executor) {
  auto reg = WidestRegister(executor, XED_REG_EIP);
  auto pc = ReadGPR(reg);
  auto next_pc = pc + xed_decoded_inst_get_length(gXedd);
  if (32 == executor->addr_size) {
    return static_cast<uint32_t>(next_pc);
  } else {
    return next_pc;
  }
}

// Get the first immediate operand as if it's a signed value.
static uint64_t GetSignedImmediate(void) {
  int64_t simm0 = xed_decoded_inst_get_signed_immediate(gXedd);
  switch (gEmu.effective_operand_width) {
    case 64:
      return static_cast<uint64_t>(simm0);
    case 32:
      return static_cast<uint32_t>(simm0);
    case 16:
      return static_cast<uint16_t>(simm0);
    case 8:
      return static_cast<uint8_t>(simm0);
    default:
      return 0;
  }
}

// Read the flags structure.
static Flags &ReadFlags(void) {
  return *reinterpret_cast<Flags *>(&(gRegs[XED_REG_RFLAGS].bytes[0]));
}

// Compute the parity flag for a value. This is only computed on the low 8
// bits of some value.
static bool ParityFlag(uint8_t r0) {
  auto r1 = r0 >> 1;
  auto r2 = r1 >> 1;
  auto r3 = r2 >> 1;
  auto r4 = r3 >> 1;
  auto r5 = r4 >> 1;
  auto r6 = r5 >> 1;
  auto r7 = r6 >> 1;
  return !(1 & (r0 ^ r1 ^ r2 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7));
}

// Compute the flags produced from a subtraction.
static void UpdateFlagsSub(Flags &flags, uintptr_t lhs, uintptr_t rhs,
                           uintptr_t res, size_t size) {
  const auto sign_shift = 1ULL << (size - 1);
  const auto sign_lhs = (lhs >> sign_shift) & 1ULL;
  const auto sign_rhs = (rhs >> sign_shift) & 1ULL;
  const auto sign_res = (res >> sign_shift) & 1ULL;
  flags.sf = sign_res;
  flags.cf = lhs < rhs;
  flags.of = (2 == (sign_lhs ^ sign_rhs) + (sign_lhs ^ sign_res));
  flags.zf = (0 == res);
  flags.af = (0 != ((res ^ lhs ^ rhs) & 0x10ULL));
  flags.pf = ParityFlag(static_cast<uint8_t>(res));
}

#define STOS                                                                 \
  do {                                                                       \
    mem0 = ReadGPR(reg0);                                                    \
    WriteGPR(dest_reg,                                                       \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(dest_reg)) + \
                                   stringop_inc));                           \
    gModifiedRegs.set(dest_reg);                                             \
  } while (false)

#define SCAS                                                                 \
  do {                                                                       \
    const auto reg0_val = ReadGPR(reg0);                                     \
    const auto temp = reg0_val - mem0;                                       \
    const auto op_size = gEmu.effective_operand_width;                       \
    UpdateFlagsSub(aflag, reg0_val, mem0, temp, op_size);                    \
    WriteGPR(dest_reg,                                                       \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(dest_reg)) + \
                                   stringop_inc));                           \
    gModifiedRegs.set(dest_reg);                                             \
  } while (false)

#define LODS                                                                \
  do {                                                                      \
    WriteGPR(reg0, mem0);                                                   \
    WriteGPR(src_reg,                                                       \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(src_reg)) + \
                                   stringop_inc));                          \
    gModifiedRegs.set(src_reg);                                             \
  } while (false)

#define MOVS                                                                 \
  do {                                                                       \
    mem0 = mem1;                                                             \
    WriteGPR(src_reg,                                                        \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(src_reg)) +  \
                                   stringop_inc));                           \
    WriteGPR(dest_reg,                                                       \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(dest_reg)) + \
                                   stringop_inc));                           \
    gModifiedRegs.set(src_reg);                                              \
    gModifiedRegs.set(dest_reg);                                             \
  } while (false)

#define CMPS                                                                 \
  do {                                                                       \
    const auto temp = mem0 - mem1;                                           \
    const auto op_size = gEmu.effective_operand_width;                       \
    UpdateFlagsSub(aflag, mem0, mem1, temp, op_size);                        \
    WriteGPR(src_reg,                                                        \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(src_reg)) +  \
                                   stringop_inc));                           \
    WriteGPR(dest_reg,                                                       \
             static_cast<uint64_t>(static_cast<int64_t>(ReadGPR(dest_reg)) + \
                                   stringop_inc));                           \
    gModifiedRegs.set(src_reg);                                              \
    gModifiedRegs.set(dest_reg);                                             \
  } while (false)

#define REPNE(...)                \
  do {                            \
    if (count) {                  \
      __VA_ARGS__;                \
      count = count - 1;          \
      WriteGPR(count_reg, count); \
      if (count && !aflag.zf) {   \
        next_pc = curr_pc;        \
      }                           \
    }                             \
  } while (false)

#define REPE(...)                 \
  do {                            \
    if (count) {                  \
      __VA_ARGS__;                \
      count = count - 1;          \
      WriteGPR(count_reg, count); \
      if (count && aflag.zf) {    \
        next_pc = curr_pc;        \
      }                           \
    }                             \
  } while (false)

#define REP(...)                  \
  do {                            \
    if (count) {                  \
      __VA_ARGS__;                \
      count = count - 1;          \
      WriteGPR(count_reg, count); \
      if (count) {                \
        next_pc = curr_pc;        \
      }                           \
    }                             \
  } while (false)

// Figure out what the next program counter should be.
static bool Emulate(const Executor *executor, uintptr_t &next_pc,
                    ExecutorStatus &status) {
  status = ExecutorStatus::kGood;
  auto branch_target_pc = BranchTarget(next_pc);
  const auto curr_pc = ReadGPR(XED_REG_RIP);

  // Mask PCs to correct size.
  if (32 == executor->addr_size) {
    next_pc = static_cast<uint32_t>(next_pc);
    branch_target_pc = static_cast<uint32_t>(branch_target_pc);
  }

  // Get the flags (if this is a conditional branch).
  auto &aflag = ReadFlags();

  // Use for REP* and LOOP*.
  const auto count_reg = WidestRegister(executor, XED_REG_ECX);
  auto count = ReadGPR(count_reg);
  const auto src_reg = WidestRegister(executor, XED_REG_ESI);
  const auto dest_reg = WidestRegister(executor, XED_REG_EDI);
  const auto stack_reg = WidestRegister(executor, XED_REG_ESP);
  const auto reg0 = xed_decoded_inst_get_reg(gXedd, XED_OPERAND_REG0);
  const auto reg1 = xed_decoded_inst_get_reg(gXedd, XED_OPERAND_REG1);
  const auto reg2 = xed_decoded_inst_get_reg(gXedd, XED_OPERAND_REG2);
  auto &mem0 = *reinterpret_cast<uintptr_t *>(gMemory[0].data.bytes);
  auto &mem1 = *reinterpret_cast<uintptr_t *>(gMemory[1].data.bytes);
  const auto addr_size_bytes = executor->addr_size / 8;
  const auto op_size_bytes = (gEmu.effective_operand_width / 8);
  const auto simm0 = GetSignedImmediate();

  auto stringop_inc = static_cast<int64_t>(op_size_bytes);
  if (aflag.df) {
    stringop_inc = -stringop_inc;
  }

  switch (xed_decoded_inst_get_iform_enum(gXedd)) {
    case XED_IFORM_LEA_GPRv_AGEN:
      WriteGPR(reg0, gMemory[0].address);
      return true;

    // Conditional branches.
    case XED_IFORM_JNLE_RELBRb:
    case XED_IFORM_JNLE_RELBRz:
    case XED_IFORM_JNLE_RELBRd:
      if (!aflag.zf && aflag.sf == aflag.of) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNS_RELBRb:
    case XED_IFORM_JNS_RELBRz:
    case XED_IFORM_JNS_RELBRd:
      if (!aflag.sf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JL_RELBRb:
    case XED_IFORM_JL_RELBRz:
    case XED_IFORM_JL_RELBRd:
      if (aflag.sf != aflag.of) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNP_RELBRb:
    case XED_IFORM_JNP_RELBRz:
    case XED_IFORM_JNP_RELBRd:
      if (!aflag.pf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNZ_RELBRb:
    case XED_IFORM_JNZ_RELBRz:
    case XED_IFORM_JNZ_RELBRd:
      if (!aflag.zf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNB_RELBRb:
    case XED_IFORM_JNB_RELBRz:
    case XED_IFORM_JNB_RELBRd:
      if (!aflag.cf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNO_RELBRb:
    case XED_IFORM_JNO_RELBRz:
    case XED_IFORM_JNO_RELBRd:
      if (!aflag.of) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNL_RELBRb:
    case XED_IFORM_JNL_RELBRz:
    case XED_IFORM_JNL_RELBRd:
      if (aflag.sf == aflag.of) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JNBE_RELBRb:
    case XED_IFORM_JNBE_RELBRz:
    case XED_IFORM_JNBE_RELBRd:
      if (!aflag.cf & !aflag.zf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JBE_RELBRb:
    case XED_IFORM_JBE_RELBRz:
    case XED_IFORM_JBE_RELBRd:
      if (aflag.cf || aflag.zf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JZ_RELBRb:
    case XED_IFORM_JZ_RELBRz:
    case XED_IFORM_JZ_RELBRd:
      if (aflag.zf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JP_RELBRb:
    case XED_IFORM_JP_RELBRz:
    case XED_IFORM_JP_RELBRd:
      if (aflag.pf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JS_RELBRb:
    case XED_IFORM_JS_RELBRz:
    case XED_IFORM_JS_RELBRd:
      if (aflag.sf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JO_RELBRb:
    case XED_IFORM_JO_RELBRd:
    case XED_IFORM_JO_RELBRz:
      if (aflag.of) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JB_RELBRb:
    case XED_IFORM_JB_RELBRz:
    case XED_IFORM_JB_RELBRd:
      if (aflag.cf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JLE_RELBRb:
    case XED_IFORM_JLE_RELBRz:
    case XED_IFORM_JLE_RELBRd:
      if (aflag.zf || aflag.sf != aflag.of) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_LOOPNE_RELBRb:
      WriteGPR(count_reg, count - 1);
      if (count && !aflag.zf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_LOOPE_RELBRb:
      WriteGPR(count_reg, count - 1);
      if (count && aflag.zf) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_LOOP_RELBRb:
      WriteGPR(count_reg, count - 1);
      if (count) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JCXZ_RELBRb:
      if (!ReadGPR(XED_REG_CX)) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JECXZ_RELBRb:
      if (!ReadGPR(XED_REG_ECX)) {
        next_pc = branch_target_pc;
      }
      return true;

    case XED_IFORM_JRCXZ_RELBRb:
      if (!ReadGPR(XED_REG_RCX)) {
        next_pc = branch_target_pc;
      }
      return true;

    // Pretend to handle XBEGIN by always failing the transaction and
    // setting the error code to there being an internal buffer overflow
    // (capacity failure in the L1 cache).
    case XED_IFORM_XBEGIN_RELBRz:
      next_pc = branch_target_pc;
      *reinterpret_cast<uint64_t *>(gRegs[XED_REG_RAX].bytes) = 1 << 3;
      *reinterpret_cast<uint32_t *>(gRegs[XED_REG_EAX].bytes) = 1 << 3;
      return true;

    // Don't allow XABORT/XEND.
    case XED_IFORM_XABORT_IMMb:
    case XED_IFORM_XEND:
      status = ExecutorStatus::kErrorUnsupportedCFI;
      return false;

    case XED_IFORM_JMP_MEMv:
      next_pc = mem0;
      return true;

    case XED_IFORM_JMP_GPRv:
      next_pc = ReadGPR(reg0);
      return true;

    case XED_IFORM_JMP_RELBRz:
    case XED_IFORM_JMP_RELBRd:
    case XED_IFORM_JMP_RELBRb:
      next_pc = branch_target_pc;
      return true;

    case XED_IFORM_CALL_NEAR_RELBRz:
    case XED_IFORM_CALL_NEAR_RELBRd:
      mem0 = next_pc;
      next_pc = branch_target_pc;
      WriteGPR(stack_reg, ReadGPR(stack_reg) - addr_size_bytes);
      return true;

    case XED_IFORM_CALL_NEAR_MEMv:
      mem1 = next_pc;
      next_pc = mem0;
      WriteGPR(stack_reg, ReadGPR(stack_reg) - addr_size_bytes);
      return true;

    case XED_IFORM_CALL_NEAR_GPRv:
      mem0 = next_pc;
      next_pc = ReadGPR(reg0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) - addr_size_bytes);
      return true;

    case XED_IFORM_RET_NEAR:
      next_pc = mem0;
      WriteGPR(stack_reg, ReadGPR(stack_reg) + addr_size_bytes);
      return true;

    case XED_IFORM_RET_NEAR_IMMw:
      next_pc = mem0;
      WriteGPR(stack_reg, ReadGPR(stack_reg) + addr_size_bytes +
                              static_cast<uint16_t>(simm0));
      return true;

    // Far CALL/RET/JMP are not supported.
    case XED_IFORM_CALL_FAR_MEMp2:
    case XED_IFORM_CALL_FAR_PTRp_IMMw:
    case XED_IFORM_JMP_FAR_MEMp2:
    case XED_IFORM_JMP_FAR_PTRp_IMMw:
    case XED_IFORM_RET_FAR_IMMw:
    case XED_IFORM_RET_FAR:
      status = ExecutorStatus::kErrorUnsupportedCFI;
      return false;

    // We want to treat REP instructions as executing just a single loop of
    // the (internal) repetition loop.
    case XED_IFORM_REPE_SCASW:
    case XED_IFORM_REPE_SCASQ:
    case XED_IFORM_REPE_SCASD:
    case XED_IFORM_REPE_SCASB:
      REPE(SCAS);
      return true;

    case XED_IFORM_REP_LODSQ:
    case XED_IFORM_REP_LODSW:
    case XED_IFORM_REP_LODSB:
    case XED_IFORM_REP_LODSD:
      REP(LODS);
      return true;

    case XED_IFORM_REPNE_CMPSW:
    case XED_IFORM_REPNE_CMPSQ:
    case XED_IFORM_REPNE_CMPSB:
    case XED_IFORM_REPNE_CMPSD:
      REPNE(CMPS);
      return true;

    case XED_IFORM_REP_STOSD:
    case XED_IFORM_REP_STOSB:
    case XED_IFORM_REP_STOSW:
    case XED_IFORM_REP_STOSQ:
      REP(STOS);
      return true;

    case XED_IFORM_REPNE_SCASB:
    case XED_IFORM_REPNE_SCASD:
    case XED_IFORM_REPNE_SCASQ:
    case XED_IFORM_REPNE_SCASW:
      REPNE(SCAS);
      return true;

    case XED_IFORM_REP_MOVSQ:
    case XED_IFORM_REP_MOVSD:
    case XED_IFORM_REP_MOVSB:
    case XED_IFORM_REP_MOVSW:
      REP(MOVS);
      return true;

    case XED_IFORM_REPE_CMPSQ:
    case XED_IFORM_REPE_CMPSD:
    case XED_IFORM_REPE_CMPSB:
    case XED_IFORM_REPE_CMPSW:
      REPE(CMPS);
      return true;

    case XED_IFORM_STOSD:
    case XED_IFORM_STOSB:
    case XED_IFORM_STOSW:
    case XED_IFORM_STOSQ:
      STOS;
      return true;

    case XED_IFORM_SCASW:
    case XED_IFORM_SCASQ:
    case XED_IFORM_SCASD:
    case XED_IFORM_SCASB:
      SCAS;
      return true;

    case XED_IFORM_LODSB:
    case XED_IFORM_LODSQ:
    case XED_IFORM_LODSW:
    case XED_IFORM_LODSD:
      LODS;
      return true;

    case XED_IFORM_MOVSD:
    case XED_IFORM_MOVSB:
    case XED_IFORM_MOVSW:
    case XED_IFORM_MOVSQ:
      MOVS;
      return true;

    case XED_IFORM_CMPSQ:
    case XED_IFORM_CMPSW:
    case XED_IFORM_CMPSB:
    case XED_IFORM_CMPSD:
      CMPS;
      return true;

    case XED_IFORM_PUSH_MEMv:
      mem1 = mem0;
      WriteGPR(stack_reg, ReadGPR(stack_reg) - op_size_bytes);
      return true;

    case XED_IFORM_PUSH_GPRv_FFr6:
      mem0 = ReadGPR(reg0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) - op_size_bytes);
      return true;

    case XED_IFORM_PUSH_GPRv_50:
      mem0 = ReadGPR(reg0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) - op_size_bytes);
      return true;

    case XED_IFORM_PUSH_IMMz:
    case XED_IFORM_PUSH_IMMb:
      mem0 = static_cast<uint32_t>(simm0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) - op_size_bytes);
      return true;

    case XED_IFORM_POP_MEMv:
      mem0 = mem1;
      WriteGPR(stack_reg, ReadGPR(stack_reg) + op_size_bytes);
      return true;

    case XED_IFORM_POP_GPRv_8F:
    case XED_IFORM_POP_GPRv_58:
      WriteGPR(reg0, mem0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) + op_size_bytes);
      return true;

    case XED_IFORM_LEAVE:
      WriteGPR(reg1, ReadGPR(reg0));
      WriteGPR(reg0, mem0);
      return true;

    case XED_IFORM_PUSH_ES:
    case XED_IFORM_PUSH_CS:
    case XED_IFORM_PUSH_SS:
    case XED_IFORM_PUSH_DS:
    case XED_IFORM_PUSH_FS:
    case XED_IFORM_PUSH_GS:
      mem0 = ReadGPR(reg0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) - addr_size_bytes);
      return true;

    case XED_IFORM_POP_ES:
    case XED_IFORM_POP_SS:
    case XED_IFORM_POP_DS:
    case XED_IFORM_POP_FS:
    case XED_IFORM_POP_GS:
      WriteGPR(reg0, mem0);
      WriteGPR(stack_reg, ReadGPR(stack_reg) + addr_size_bytes);
      return true;

    case XED_IFORM_MOV_MEMw_SEG:
      mem0 = ReadGPR(reg0);
      return true;

    case XED_IFORM_MOV_GPRv_SEG:
      WriteGPR(reg0, ReadGPR(reg1));
      return true;

    case XED_IFORM_MOV_SEG_MEMw:
      WriteGPR(reg0, mem0);
      return true;

    case XED_IFORM_MOV_SEG_GPR16:
      WriteGPR(reg0, ReadGPR(reg1));
      return true;

    // TODO(pag): ID flag (for checking CPUID)?
    case XED_IFORM_PUSHF:
    case XED_IFORM_PUSHFD:
    case XED_IFORM_PUSHFQ:
      mem0 = aflag.flat;
      WriteGPR(stack_reg, ReadGPR(stack_reg) - addr_size_bytes);
      return true;

    // TODO(pag): ID flag (for checking CPUID)?
    case XED_IFORM_POPF:
    case XED_IFORM_POPFD:
    case XED_IFORM_POPFQ:
      aflag.flat = mem0;
      WriteGPR(stack_reg, ReadGPR(stack_reg) + addr_size_bytes);
      return true;

    // Don't even try to handle these; too much memory traffic.
    case XED_IFORM_PUSHA:
    case XED_IFORM_PUSHAD:
    case XED_IFORM_POPA:
    case XED_IFORM_POPAD:
    case XED_IFORM_ENTER_IMMw_IMMb:
      status = ExecutorStatus::kErrorUnsupportedStack;
      return false;

    case XED_IFORM_XLAT:
      WriteGPR(reg0, mem0);
      return true;

    case XED_IFORM_RDTSCP:
      WriteGPR(reg2, ReadValue<uint32_t>(XED_REG_TSCAUX));
      // fall-through
    case XED_IFORM_RDTSC: {
      uint64_t tsc = ReadValue<uint64_t>(XED_REG_TSC);
      WriteGPR(reg0, static_cast<uint32_t>(tsc));
      WriteGPR(reg1, tsc >> 32);
    }
      return true;

    default:
      return false;
  }
}

// Update the program counter register.
static void SetNextPC(const Executor *executor, uintptr_t next_pc) {
  *reinterpret_cast<uintptr_t *>(gRegs[XED_REG_RIP].bytes) = next_pc;
}

// Detect instructions that we can't emulate or execute based on their
// attributes.
static bool UsesUnsupportedAttributes(void) {
  return xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_RING0) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_PROTECTED_MODE) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_FAR_XFER) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_EXCEPTION_BR) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_X87_MMX_STATE_R) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_X87_MMX_STATE_W) ||
         xed_decoded_inst_get_attribute(gXedd,
                                        XED_ATTRIBUTE_X87_MMX_STATE_CW) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_XMM_STATE_R) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_XMM_STATE_W) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_XMM_STATE_CW) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_EXCEPTION_BR) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_KMASK) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_MASKOP) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_MASKOP_EVEX) ||
         xed_decoded_inst_get_attribute(gXedd, XED_ATTRIBUTE_MASK_AS_CONTROL) ||
         xed_decoded_inst_get_attribute(gXedd,
                                        XED_ATTRIBUTE_MASK_VARIABLE_MEMOP);
}

static bool UsesUnsupportedFeatures(const Executor *executor) {
  switch (xed_decoded_inst_get_category(gXedd)) {
    case XED_CATEGORY_SYSTEM:
      switch (xed_decoded_inst_get_iform_enum(gXedd)) {
        case XED_IFORM_RDTSC:
        case XED_IFORM_RDTSCP:
          return false;
        default:
          return true;
      }
    case XED_CATEGORY_3DNOW:
    case XED_CATEGORY_MPX:
    case XED_CATEGORY_AES:
    case XED_CATEGORY_RDRAND:
    case XED_CATEGORY_RDSEED:
    case XED_CATEGORY_SEGOP:
    case XED_CATEGORY_SYSCALL:
    case XED_CATEGORY_INTERRUPT:
    case XED_CATEGORY_SYSRET:
    case XED_CATEGORY_XSAVE:
    case XED_CATEGORY_XSAVEOPT:
    case XED_CATEGORY_IOSTRINGOP:
    case XED_CATEGORY_RDWRFSGS:
    case XED_CATEGORY_VTX:
      return true;
    case XED_CATEGORY_AVX:
    case XED_CATEGORY_AVX2:
    case XED_CATEGORY_AVX2GATHER:
      return !executor->has_avx || UsesUnsupportedAttributes();
    case XED_CATEGORY_AVX512:
    case XED_CATEGORY_AVX512_4FMAPS:
    case XED_CATEGORY_AVX512_4VNNIW:
    case XED_CATEGORY_AVX512_BITALG:
    case XED_CATEGORY_AVX512_VBMI:
      return !executor->has_avx512 || UsesUnsupportedAttributes();
    default:
      return UsesUnsupportedAttributes();
  }
}

#define READ_FLAG(field, name)                                      \
  if (read_flags.field) {                                           \
    if (!executor->ReadReg(name, 1, RegRequestHint::kConditionCode, \
                           flag_val)) {                             \
      return false;                                                 \
    }                                                               \
    aflag.field = !!(flag_val.bytes[0] & 1U);                       \
    flag_val.bytes[0] = 0;                                          \
  }

// Read in the flags, as if the individual flags themselves were registers.
static bool ReadFlags(const Executor *executor) {
  gWriteBackFlags.flat = 0;

  const auto rflags = xed_decoded_inst_get_rflags_info(gXedd);
  if (!rflags) {
    return true;
  }

  // Conditional writes to flags are implicit read dependencies.
  Flags read_flags;
  read_flags.flat = static_cast<uint16_t>(rflags->read.flat);
  if (rflags->may_write) {
    read_flags.flat |= rflags->written.flat;
  }

  const auto flags_reg = WidestRegister(executor, XED_REG_EFLAGS);
  auto &data = gRegs[XED_REG_RFLAGS];

  // Only write back written/undefined flags.
  gWriteBackFlags.flat = static_cast<uint16_t>(rflags->written.flat);

  gUsedRegs.set(flags_reg);
  if (gWriteBackFlags.flat) {
    gModifiedRegs.set(flags_reg);
  }

  Flags aflag;
  aflag.flat = 0;

  asm("pushfq;"
      "pop %0;"
      : "=m"(aflag.flat));

  Data flag_val = {{0}};
  READ_FLAG(cf, "CF")
  READ_FLAG(pf, "PF")
  READ_FLAG(af, "AF")
  READ_FLAG(zf, "ZF")
  READ_FLAG(sf, "SF")
  READ_FLAG(df, "DF")
  READ_FLAG(of, "OF")

  memcpy(&(data.bytes[0]), &aflag.flat, sizeof(aflag));
  return true;
}

#undef READ_FLAG
#define WRITE_FLAG(field, name)                   \
  if (gWriteBackFlags.field) {                    \
    flag_val.bytes[0] = aflag.field;              \
    if (!executor->WriteReg(name, 1, flag_val)) { \
      return false;                               \
    }                                             \
    flag_val.bytes[0] = 0;                        \
  }

// Write back the flags, as if the individual flags themselves were registers.
static bool WriteFlags(const Executor *executor) {
  const auto flags_reg = WidestRegister(executor, XED_REG_EFLAGS);
  const auto &data = gRegs[XED_REG_RFLAGS];
  if (!gModifiedRegs.test(flags_reg)) {
    return true;
  }

  gUsedRegs.reset(flags_reg);
  gModifiedRegs.reset(flags_reg);

  Flags aflag;
  aflag.flat = 0;
  memcpy(&aflag.flat, &(data.bytes[0]), sizeof(aflag));

  Data flag_val = {{0}};
  WRITE_FLAG(cf, "CF")
  WRITE_FLAG(pf, "PF")
  WRITE_FLAG(af, "AF")
  WRITE_FLAG(zf, "ZF")
  WRITE_FLAG(sf, "SF")
  WRITE_FLAG(df, "DF")
  WRITE_FLAG(of, "OF")

  gWriteBackFlags.flat = 0;
  return true;
}

#undef WRITE_FLAG

// Decode a `MEM0` operand into an absolute memory access.
static void DecodeMem0(unsigned i) {
  auto &op = gEmu.operands[i];
  auto &mem = gMemory[0];
  op.type = XED_ENCODER_OPERAND_TYPE_MEM;
  op.u.mem.disp.displacement = 0xFFFFFFFF;  // Placeholder.
  op.u.mem.disp.displacement_bits = 32;
  op.u.mem.base = XED_REG_RIP;
  op.width_bits = mem.size;

  mem.mem_op = &(op.u.mem);
}

// Create and return an alias for the stack pointer register for use by the
// instruction.
static xed_reg_enum_t GetStackPointerAlias(xed_reg_enum_t reg) {
  // Need to create an alias: these four registers are the most generally
  // usable, and we expect at least one of them to be free.
  if (XED_REG_INVALID == gStackPtrAlias) {
    if (!gStoreRegs.test(XED_REG_RAX)) {
      gStackPtrAlias = XED_REG_RAX;
    } else if (!gStoreRegs.test(XED_REG_RCX)) {
      gStackPtrAlias = XED_REG_RCX;
    } else if (!gStoreRegs.test(XED_REG_RDX)) {
      gStackPtrAlias = XED_REG_RDX;
    } else if (!gStoreRegs.test(XED_REG_RBX)) {
      gStackPtrAlias = XED_REG_RBX;
    } else {
      gStackPtrAlias = XED_REG_INVALID;  // Uh oh.
    }

    WriteGPR(gStackPtrAlias, ReadGPR(XED_REG_RSP));
  }

  // Scale the alias down to the desired size.
  auto offset = (gStackPtrAlias - XED_REG_GPR64_FIRST);
  switch (reg) {
    case XED_REG_SPL:
      return static_cast<xed_reg_enum_t>(offset + XED_REG_GPR8_FIRST);
    case XED_REG_SP:
      return static_cast<xed_reg_enum_t>(offset + XED_REG_GPR16_FIRST);
    case XED_REG_ESP:
      return static_cast<xed_reg_enum_t>(offset + XED_REG_GPR32_FIRST);
    case XED_REG_RSP:
      return gStackPtrAlias;
    default:
      return XED_REG_INVALID;
  }
}

// Decode the register into the high-level encoder interface.
static void DecodeRegN(unsigned i, xed_reg_enum_t reg) {
  // If the stack pointer is used in the instruction, then reschedule it to
  // a free register that can take its place.
  if (XED_REG_RSP == xed_get_largest_enclosing_register(reg)) {
    reg = GetStackPointerAlias(reg);
  }

  auto &op = gEmu.operands[i];
  op.type = XED_ENCODER_OPERAND_TYPE_REG;
  op.u.reg = reg;
  op.width_bits = xed_get_register_width_bits64(reg);
}

// Decode and `IMM0` operand into the high-level encoder interface.
static void DecodeImm0(unsigned i, xed_operand_enum_t op_name) {
  auto &op = gEmu.operands[i];
  if (XED_OPERAND_IMM0SIGNED == op_name ||
      xed_operand_values_get_immediate_is_signed(gXedd)) {
    op.type = XED_ENCODER_OPERAND_TYPE_SIMM0;
    op.u.imm0 = static_cast<uintptr_t>(
        static_cast<intptr_t>(xed_decoded_inst_get_signed_immediate(gXedd)));
  } else {
    op.type = XED_ENCODER_OPERAND_TYPE_IMM0;
    op.u.imm0 = xed_decoded_inst_get_unsigned_immediate(gXedd);
  }
  op.width_bits = xed_decoded_inst_get_immediate_width_bits(gXedd);
}

// Decode an `IMM1` operand into the high-level encoder interface.
static void DecodeImm1(unsigned i) {
  auto &op = gEmu.operands[i];
  op.type = XED_ENCODER_OPERAND_TYPE_IMM1;
  op.u.imm1 = xed_decoded_inst_get_second_immediate(gXedd);
  op.width_bits = xed_decoded_inst_get_immediate_width_bits(gXedd);
}

// Convert the decoded instruction into XED's high-level encoder interface, so
// that we can re-encode the instruction and JIT it.
static void CreateEncodableInstruction(const Executor *executor) {
  auto num_operands = xed_decoded_inst_noperands(gXedd);
  auto xedi = xed_decoded_inst_inst(gXedd);
  for (auto i = 0U; i < num_operands; ++i) {
    auto xedo = xed_inst_operand(xedi, i);
    auto vis = xed_operand_operand_visibility(xedo);
    if (XED_OPVIS_EXPLICIT != vis && XED_OPVIS_IMPLICIT != vis) {
      continue;
    }
    auto op_index = gEmu.noperands++;
    switch (auto op_name = xed_operand_name(xedo)) {
      case XED_OPERAND_MEM0:
        DecodeMem0(op_index);
        break;

      case XED_OPERAND_REG0:
      case XED_OPERAND_REG1:
      case XED_OPERAND_REG2:
      case XED_OPERAND_REG3:
        if (auto reg = xed_decoded_inst_get_reg(gXedd, op_name)) {
          DecodeRegN(op_index, reg);
        }
        break;

      case XED_OPERAND_IMM0SIGNED:
      case XED_OPERAND_IMM0:
        DecodeImm0(op_index, op_name);
        break;

      case XED_OPERAND_IMM1_BYTES:
      case XED_OPERAND_IMM1:
        DecodeImm1(op_index);
        break;

      default:
        break;
    }
  }
}

// Encode an instruction.
static bool EncodeInstruction(void) {
  xed_encoder_request_t xede;
  xed_encoder_request_zero_set_mode(&xede, &(gEmu.mode));
  return xed_convert_to_encoder_request(&xede, &gEmu) &&
         XED_ERROR_NONE == xed_encode(&xede, gExecArea, 15, &gEmuSize);
}

// Fill in the high-level encoder data structure with enough information to
// JIT this instruction.
static bool EncodeInstruction(const Executor *executor) {
  CreateEncodableInstruction(executor);

  // Make sure that we can return from our function :-D
  memset(gExecArea, 0xC3, 32);

  if (!EncodeInstruction()) {
    return false;
  }

  // If there's an explicit memory operand then we need to relativize its
  // operand (based on the instruction length) to then point to the memory
  // area.
  if (gMemory[0].present) {
    auto op = gMemory[0].mem_op;
    auto rip = reinterpret_cast<uintptr_t>(gExecArea) + gEmuSize;
    auto data = reinterpret_cast<uintptr_t>(&(gMemory[0].data.bytes[0]));
    op->disp.displacement = data - rip;
    return EncodeInstruction();

  } else {
    return true;
  }
}

#define COPY_FROM_MMX_32(i)                                               \
  do {                                                                    \
    if (gUsedRegs.test(XED_REG_MMX##i)) {                                 \
      memcpy(&(gFPU.fxsave32.st[i].mmx), gRegs[XED_REG_MMX##i].bytes, 8); \
      gFPU.fxsave32.st[i].infinity = static_cast<uint16_t>(~0U);          \
    }                                                                     \
  } while (0)

#define COPY_FROM_MMX_64(i)                                               \
  do {                                                                    \
    if (gUsedRegs.test(XED_REG_MMX##i)) {                                 \
      memcpy(&(gFPU.fxsave64.st[i].mmx), gRegs[XED_REG_MMX##i].bytes, 8); \
      gFPU.fxsave64.st[i].infinity = static_cast<uint16_t>(~0U);          \
    }                                                                     \
  } while (0)

#define COPY_TO_MMX_32(i)                                                 \
  do {                                                                    \
    if (gUsedRegs.test(XED_REG_MMX##i)) {                                 \
      memcpy(gRegs[XED_REG_MMX##i].bytes, &(gFPU.fxsave32.st[i].mmx), 8); \
    }                                                                     \
  } while (0)

#define COPY_TO_MMX_64(i)                                                 \
  do {                                                                    \
    if (gUsedRegs.test(XED_REG_MMX##i)) {                                 \
      memcpy(gRegs[XED_REG_MMX##i].bytes, &(gFPU.fxsave64.st[i].mmx), 8); \
    }                                                                     \
  } while (0)

static void CopyMMXStateToFPU(const Executor *executor) {
  if (32 == executor->addr_size) {
    COPY_FROM_MMX_32(0);
    COPY_FROM_MMX_32(1);
    COPY_FROM_MMX_32(2);
    COPY_FROM_MMX_32(3);
    COPY_FROM_MMX_32(4);
    COPY_FROM_MMX_32(5);
    COPY_FROM_MMX_32(6);
    COPY_FROM_MMX_32(7);
  } else {
    COPY_FROM_MMX_64(0);
    COPY_FROM_MMX_64(1);
    COPY_FROM_MMX_64(2);
    COPY_FROM_MMX_64(3);
    COPY_FROM_MMX_64(4);
    COPY_FROM_MMX_64(5);
    COPY_FROM_MMX_64(6);
    COPY_FROM_MMX_64(7);
  }
}

static void CopyMMXStateFromFPU(const Executor *executor) {
  if (32 == executor->addr_size) {
    COPY_TO_MMX_32(0);
    COPY_TO_MMX_32(1);
    COPY_TO_MMX_32(2);
    COPY_TO_MMX_32(3);
    COPY_TO_MMX_32(4);
    COPY_TO_MMX_32(5);
    COPY_TO_MMX_32(6);
    COPY_TO_MMX_32(7);
  } else {
    COPY_TO_MMX_64(0);
    COPY_TO_MMX_64(1);
    COPY_TO_MMX_64(2);
    COPY_TO_MMX_64(3);
    COPY_TO_MMX_64(4);
    COPY_TO_MMX_64(5);
    COPY_TO_MMX_64(6);
    COPY_TO_MMX_64(7);
  }
}
// Load in the FPU that will be emulated. This will save the native FPU just
// in case it's got any special rounding modes or other settings going on.
static void LoadFPU(const Executor *executor) {
  if (!gUsesFPU) return;
  if (32 == executor->addr_size) {
    asm(".byte 0x48; fxsave %0;"
        "fxrstor %1;"
        :
        : "m"(gNativeFPU), "m"(gFPU));
  } else {
    asm(".byte 0x48; fxsave %0;"
        ".byte 0x48; fxrstor %1;"
        :
        : "m"(gNativeFPU), "m"(gFPU));
  }
}

// Save the resulting FPU state to send it back to the user, and then restore
// the previous native FPU state.
static void StoreFPU(const Executor *executor) {
  if (!gUsesFPU) return;
  if (32 == executor->addr_size) {
    asm("fxsave %0;"
        ".byte 0x48; fxrstor %1;"
        :
        : "m"(gFPU), "m"(gNativeFPU));
  } else {
    asm(".byte 0x48; fxsave %0;"
        ".byte 0x48; fxrstor %1;"
        :
        : "m"(gFPU), "m"(gNativeFPU));
  }
}

// Save and restore the native state, and execute the JITed instruction by
// calling into the `gExecArea`.
static void ExecuteNative(void) {
  // Need locals because GCC doesn't like having things with function calls
  // in the `asm` constraint list.
  //
  // Note: XED does *not* return ZMM registers as the widest enclosing
  //       version of XMM or YMM registers.
  auto &XMM0 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM0)];
  auto &XMM1 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM1)];
  auto &XMM2 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM2)];
  auto &XMM3 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM3)];
  auto &XMM4 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM4)];
  auto &XMM5 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM5)];
  auto &XMM6 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM6)];
  auto &XMM7 = gRegs[xed_get_largest_enclosing_register(XED_REG_XMM7)];

  asm("push %24;"

      "movdqu %0, %%xmm0;"
      "movdqu %1, %%xmm1;"
      "movdqu %2, %%xmm2;"
      "movdqu %3, %%xmm3;"
      "movdqu %4, %%xmm4;"
      "movdqu %5, %%xmm5;"
      "movdqu %6, %%xmm6;"
      "movdqu %7, %%xmm7;"

      "xchg %8, %%rax;"
      "xchg %9, %%rbx;"
      "xchg %10, %%rcx;"
      "xchg %11, %%rdx;"
      "xchg %12, %%rbp;"
      "xchg %13, %%rsi;"
      "xchg %14, %%rdi;"
      "xchg %15, %%r8;"
      "xchg %16, %%r9;"
      "xchg %17, %%r10;"
      "xchg %18, %%r11;"
      "xchg %19, %%r12;"
      "xchg %20, %%r13;"
      "xchg %21, %%r14;"
      "xchg %22, %%r15;"

      "pushq %23;"
      "popfq;"

      "fnclex;"
      ".byte 0xff, 0x14, 0x24;"  // `CALL QWORD PTR [RSP]`.
      "fwait;"
      "fnclex;"

      "pushfq;"
      "popq %23;"

      "xchg %8, %%rax;"
      "xchg %9, %%rbx;"
      "xchg %10, %%rcx;"
      "xchg %11, %%rdx;"
      "xchg %12, %%rbp;"
      "xchg %13, %%rsi;"
      "xchg %14, %%rdi;"
      "xchg %15, %%r8;"
      "xchg %16, %%r9;"
      "xchg %17, %%r10;"
      "xchg %18, %%r11;"
      "xchg %19, %%r12;"
      "xchg %20, %%r13;"
      "xchg %21, %%r14;"
      "xchg %22, %%r15;"

      "movdqu %%xmm0, %0;"
      "movdqu %%xmm1, %1;"
      "movdqu %%xmm2, %2;"
      "movdqu %%xmm3, %3;"
      "movdqu %%xmm4, %4;"
      "movdqu %%xmm5, %5;"
      "movdqu %%xmm6, %6;"
      "movdqu %%xmm7, %7;"

      "add $8, %%rsp;"
      :
      : "m"(XMM0), "m"(XMM1), "m"(XMM2), "m"(XMM3), "m"(XMM4), "m"(XMM5),
        "m"(XMM6), "m"(XMM7), "m"(gRegs[XED_REG_RAX]), "m"(gRegs[XED_REG_RBX]),
        "m"(gRegs[XED_REG_RCX]), "m"(gRegs[XED_REG_RDX]),
        "m"(gRegs[XED_REG_RBP]), "m"(gRegs[XED_REG_RSI]),
        "m"(gRegs[XED_REG_RDI]), "m"(gRegs[XED_REG_R8]), "m"(gRegs[XED_REG_R9]),
        "m"(gRegs[XED_REG_R10]), "m"(gRegs[XED_REG_R11]),
        "m"(gRegs[XED_REG_R12]), "m"(gRegs[XED_REG_R13]),
        "m"(gRegs[XED_REG_R14]), "m"(gRegs[XED_REG_R15]),
        "m"(gRegs[XED_REG_RFLAGS]),
        "g"(reinterpret_cast<uintptr_t>(gExecArea)));
}

static void ExecuteNativeAVX(void) {
#ifdef _WIN32
  gExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;  // TODO(pag): Implement this!
#else
  gSignal = SIGILL;  // TODO(pag): Implement this!
#endif  //_WIN32
}

static void ExecuteNativeAVX512(void) {
#ifdef _WIN32
  gExceptionCode = EXCEPTION_ILLEGAL_INSTRUCTION;  // TODO(pag): Implement this!
#else
  gSignal = SIGILL;  // TODO(pag): Implement this!
#endif  //_WIN32
}

#ifdef _WIN32
LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS *ExceptionInfo) {
#ifdef _WIN64
#define Cip ExceptionInfo->ContextRecord->Rip
#define Csp ExceptionInfo->ContextRecord->Rsp
#else
#define Cip ExceptionInfo->ContextRecord->Eip
#define Csp ExceptionInfo->ContextRecord->Esp
#endif  //_WIN64
  auto execArea = (uintptr_t)gExecArea;
  if (Cip >= execArea && Cip < execArea + kPageSize) {
    gExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    // Emulate the RET
    Cip = *(uintptr_t *)Csp;
    Csp += sizeof(uintptr_t);
    return EXCEPTION_CONTINUE_EXECUTION;
  } else {
    return EXCEPTION_CONTINUE_SEARCH;
  }
#undef Csp
#undef Cip
}
#else
// Recover from a signal that was raised by executing the JITed instruction.
[[noreturn]] static void RecoverFromError(int sig) {
  gSignal = sig;
  siglongjmp(gRecoveryTarget, true);
}
#endif  //_WIN32

}  // namespace

Executor::Executor(size_t addr_size_, bool has_avx_, bool has_avx512_)
    : addr_size(addr_size_), has_avx(has_avx_), has_avx512(has_avx512_) {}

Executor::~Executor(void) {}

bool Executor::Init(void) {
  LockGuard locker(gExecutorLock);
  if (gIsInitialized) {
    return true;
  }

  // Initialize the XED decode/encode tables.
  xed_tables_init();

  // Make `gExecArea` into a page-aligned address pointing to somewhere in
  // `gExecArea_`.
  auto ea_addr = reinterpret_cast<uintptr_t>(&(gExecArea_[0]));
  auto ea_addr_rounded = (ea_addr + kPageSize - 1ULL) & ~(kPageSize - 1ULL);
  gExecArea = &(gExecArea_[ea_addr_rounded - ea_addr]);

  // Map some portion of the `gExecArea_` memory to be RWX. The idea is that
  // we want our executable area to be near our other data variables (e.g.
  // register storage) so that we can access them via RIP-relative addressing.
#ifdef _WIN32
  DWORD dwOldProtect = 0;
  auto ret = VirtualProtect(gExecArea, kPageSize, PAGE_EXECUTE_READWRITE,
                            &dwOldProtect);
  if (!ret) {
#else
  auto ret = mmap(gExecArea, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (MAP_FAILED == gExecArea || gExecArea != ret) {
#endif  //_WIN32
    gExecArea = nullptr;
    return false;
  }

  gWriteBackFlags.flat = 0;

  memset(&gRegs, 0, sizeof(gRegs));

#ifdef _WIN32
#else
  gSignalHandler.sa_handler = RecoverFromError;
  gSignalHandler.sa_flags = SA_ONSTACK;
  sigfillset(&(gSignalHandler.sa_mask));
#endif  //_WIN32

  gIsInitialized = true;

  return true;
}

uintptr_t Executor::ComputeAddress(const char *, uintptr_t base,
                                   uintptr_t index, uintptr_t scale,
                                   uintptr_t displacement, size_t size,
                                   MemRequestHint) const {
  return base + (index * scale) + displacement;
}

// Execute an instruction.
ExecutorStatus Executor::Execute(size_t max_num_executions) {
  if (!max_num_executions) {
    return ExecutorStatus::kGood;
  }

  Data idata;
  auto &bytes = idata.bytes;

  LockGuard locker(gExecutorLock);

  if (!gIsInitialized) {
    return ExecutorStatus::kErrorNotInitialized;
  }

  for (size_t num_executed = 0; num_executed < max_num_executions;
       ++num_executed) {
    gUsedRegs.reset();
    gModifiedRegs.reset();
    gStoreRegs.reset();
    gStackPtrAlias = XED_REG_INVALID;
    gUsesFPU = false;
    gUsesMMX = false;

    if (!ReadPC(this)) {
      return ExecutorStatus::kErrorReadReg;
    }

    const auto pc = ComputeAddress("CS", GetPC(this), 0, 0, 0, 8,
                                   MemRequestHint::kReadExecutable);

    // the maximum possible instruction length given our memory model
    size_t inst_length = 15;
    for (; inst_length; --inst_length) {
      if (ReadMem(pc, inst_length * 8, MemRequestHint::kReadExecutable,
                  idata)) {
        // A read succeeded and we have computed the maximum fetch length
        break;
      } else {
#ifdef PYTHON_BINDINGS
        // Ignore any exceptions generated by ReadMem
        // If they are not ignored here, they will stack for every iteration
        // of this loop and Python will get angry at us
        if (PyErr_Occurred()) {
          // TODO(artem): Debug print any 'unexpected' exceptions to warn the
          // user they are ignored
          PyErr_Clear();
        }
#endif
      }
    }

    if (!inst_length) {
      return ExecutorStatus::kErrorReadInstMem;
    }

    if (!DecodeInstruction(bytes, inst_length, addr_size)) {
      return ExecutorStatus::kErrorDecode;
    }

    // Reject some easy-to-reject stuff.
    if (UsesUnsupportedFeatures(this)) {
      return ExecutorStatus::kErrorExecute;
    }

    // Get only the flags we need. This treats the individual flags as if they
    // are registers.
    if (!ReadFlags(this)) {
      return ExecutorStatus::kErrorReadFlags;
    }

    if (!ReadRegisters(this)) {
      return ExecutorStatus::kErrorReadReg;
    }

    auto emulation_status = ExecutorStatus::kGood;
    auto next_pc = GetNextPC(this);

    if (XED_CATEGORY_NOP != xed_decoded_inst_get_category(gXedd) &&
        XED_CATEGORY_WIDENOP != xed_decoded_inst_get_category(gXedd)) {
      // Read in the FPU. We actually ignore the the embedded XMM registers
      // entirely.
      if (gUsesFPU && !this->ReadFPU(gFPU)) {
        return ExecutorStatus::kErrorReadFPU;
      }

      if (gUsesMMX) {
        CopyMMXStateToFPU(this);
      }

      // Read memory *after* reading in values of registers, so that we can
      // figure out all the memory addresses to be read.
      if (!ReadMemory(this)) {
        return ExecutorStatus::kErrorReadMem;
      }

      // Try to figure out what the target PC of the instruction is. If this
      // is a control-flow instruction then the target PC is the target of
      // the control-flow, otherwise it's just `next_pc`.
      //
      // Note:  This might determine that we shouldn't execute the instruction.
      //        This will happen if figuring out the next/target program counter
      //        requires us to emulate the instruction.
      if (!Emulate(this, next_pc, emulation_status)) {
        if (ExecutorStatus::kGood != emulation_status) {
          return emulation_status;
        } else if (!EncodeInstruction(this)) {
          return ExecutorStatus::kErrorExecute;
        } else {
#ifdef _WIN32
          gExceptionCode = 0;
          auto hExceptionHandler =
              AddVectoredExceptionHandler(1, VectoredHandler);

          LoadFPU(this);
          if (has_avx512) {
            ExecuteNativeAVX512();
          } else if (has_avx) {
            ExecuteNativeAVX();
          } else {
            ExecuteNative();
          }
          StoreFPU(this);

          RemoveVectoredExceptionHandler(hExceptionHandler);
#else
          gSignal = 0;
          sigaction(SIGILL, &gSignalHandler, &gSIGILL);
          sigaction(SIGBUS, &gSignalHandler, &gSIGBUS);
          sigaction(SIGSEGV, &gSignalHandler, &gSIGSEGV);
          sigaction(SIGFPE, &gSignalHandler, &gSIGFPE);

          LoadFPU(this);
          if (!sigsetjmp(gRecoveryTarget, true)) {
            if (has_avx512) {
              ExecuteNativeAVX512();
            } else if (has_avx) {
              ExecuteNativeAVX();
            } else {
              ExecuteNative();
            }
          }
          StoreFPU(this);

          sigaction(SIGILL, &gSIGILL, nullptr);
          sigaction(SIGBUS, &gSIGBUS, nullptr);
          sigaction(SIGSEGV, &gSIGSEGV, nullptr);
          sigaction(SIGFPE, &gSIGFPE, nullptr);
#endif  //_WIN32
        }
#ifdef _WIN32
        switch (gExceptionCode) {
          case 0:
            break;  // All good :-D

          case EXCEPTION_ACCESS_VIOLATION:
            return ExecutorStatus::kErrorFault;

          case EXCEPTION_FLT_DENORMAL_OPERAND:
          case EXCEPTION_FLT_DIVIDE_BY_ZERO:
          case EXCEPTION_FLT_INEXACT_RESULT:
          case EXCEPTION_FLT_INVALID_OPERATION:
          case EXCEPTION_FLT_OVERFLOW:
          case EXCEPTION_FLT_STACK_CHECK:
          case EXCEPTION_FLT_UNDERFLOW:
            return ExecutorStatus::kErrorFloatingPointException;

          case EXCEPTION_ILLEGAL_INSTRUCTION:
          default:
            return ExecutorStatus::kErrorExecute;
        }
#else
        switch (gSignal) {
          case 0:
            break;  // All good :-D

          case SIGSEGV:
          case SIGBUS:
            return ExecutorStatus::kErrorFault;

          case SIGFPE:
            return ExecutorStatus::kErrorFloatingPointException;

          case SIGILL:
          default:
            return ExecutorStatus::kErrorExecute;
        }
#endif  //_WIN32
      }

      // Done before writing back the registers so that a failure of the
      // instruction leaves no side-effects (on memory). This generally assumes
      // that writing registers can't fail.
      if (!WriteMemory(this)) {
        return ExecutorStatus::kErrorWriteMem;
      }

      if (gUsesFPU && !this->WriteFPU(gFPU)) {
        return ExecutorStatus::kErrorWriteFPU;
      }

      if (gUsesMMX) {
        CopyMMXStateFromFPU(this);
      }
    }

    if (!WriteFlags(this)) {
      return ExecutorStatus::kErrorWriteFlags;
    }

    // Write back any registers that were read or written.
    SetNextPC(this, next_pc);

    if (!WriteRegisters(this)) {
      return ExecutorStatus::kErrorWriteReg;
    }
  }

  return ExecutorStatus::kGood;
}

}  // namespace microx
