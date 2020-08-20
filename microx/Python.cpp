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

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <new>
#include <type_traits>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-register"
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <bytesobject.h>
#pragma clang diagnostic pop

#include "microx/Executor.h"

#if PY_MAJOR_VERSION == 2
#error "Python 2 builds are no longer supported"
#elif PY_MAJOR_VERSION > 3
#error "Building for an unsupported Python version"
#endif

namespace microx {
namespace {

struct PythonExecutorObject;

// Extends the executor to invoke Python methods to satisfy requests for
// data from the environment and respond with new values to place into the
// environment.
struct PythonExecutor : public Executor {
  PythonExecutor(PyObject *self_, unsigned addr_size);

  virtual ~PythonExecutor(void);

  bool ReadValue(PyObject *res, size_t num_bits, Data &val,
                 const char *usage) const;

  uintptr_t ComputeAddress(const char *seg_name, uintptr_t base,
                           uintptr_t index, uintptr_t scale,
                           uintptr_t displacement, size_t size,
                           MemRequestHint hint) const override;

  bool ReadReg(const char *name, size_t size, RegRequestHint hint,
               Data &val) const override;

  bool WriteReg(const char *name, size_t size, const Data &val) const override;

  bool ReadMem(uintptr_t addr, size_t size, MemRequestHint hint,
               Data &val) const override;

  bool WriteMem(uintptr_t addr, size_t size, const Data &val) const override;

  bool ReadFPU(FPU &val) const override;

  bool WriteFPU(const FPU &val) const override;

  PyObject *const self;
  mutable bool has_error{false};
  mutable PyObject *error{nullptr};
  mutable char error_message[512];
};

// Python representation for an instance of an executor.
struct PythonExecutorObject {
  PyObject_HEAD PythonExecutor *executor;
  std::aligned_storage<sizeof(PythonExecutor), alignof(PythonExecutor)>::type
      impl;
};

static int Executor_init(PyObject *self_, PyObject *args, PyObject *) {
  unsigned addr_size = 0;
  if (!PyArg_ParseTuple(args, "I", &addr_size)) {
    return -1;
  }

  if (64 != addr_size && 32 != addr_size) {
    PyErr_Format(
        PyExc_ValueError,
        "Invalid address size %u. Expected 32 or 64 as the address size.",
        addr_size);
    return -1;
  }

  auto self = reinterpret_cast<PythonExecutorObject *>(self_);
  self->executor = new (&(self->impl)) PythonExecutor(self_, addr_size);
  return 0;
}

// A reference to the MicroxError
static PyObject *MicroxError{nullptr};

// A reference to the InstructionDecodeError
static PyObject *InstructionDecodeError{nullptr};

// A reference to the InstructionFetchError
static PyObject *InstructionFetchError{nullptr};

// A reference to the AddressFaultError
static PyObject *AddressFaultError{nullptr};

// A reference to the UnsupportedError
static PyObject *UnsupportedError{nullptr};

// Initialize the exception references.
static bool CreateExceptions(PyObject *microx) {
  MicroxError = PyErr_NewException("microx_core.MicroxError", nullptr, nullptr);
  if (nullptr == MicroxError) {
    return false;
  }
  PyModule_AddObject(microx, "MicroxError", MicroxError);

  InstructionDecodeError = PyErr_NewException(
      "microx_core.InstructionDecodeError", MicroxError, nullptr);
  if (nullptr == InstructionDecodeError) {
    return false;
  }
  PyModule_AddObject(microx, "InstructionDecodeError", InstructionDecodeError);

  InstructionFetchError = PyErr_NewException(
      "microx_core.InstructionFetchError", MicroxError, nullptr);
  if (nullptr == InstructionFetchError) {
    return false;
  }
  PyModule_AddObject(microx, "InstructionFetchError", InstructionFetchError);

  AddressFaultError =
      PyErr_NewException("microx_core.AddressFaultError", MicroxError, nullptr);
  if (nullptr == AddressFaultError) {
    return false;
  }
  PyModule_AddObject(microx, "AddressFaultError", AddressFaultError);

  UnsupportedError =
      PyErr_NewException("microx_core.UnsupportedError", MicroxError, nullptr);
  if (nullptr == UnsupportedError) {
    return false;
  }
  PyModule_AddObject(microx, "UnsupportedError", UnsupportedError);

  return true;
}

// Emulate an instruction.
static PyObject *Executor_Execute(PyObject *self_, PyObject *args) {
  size_t num_execs = 0;

  if (!PyArg_ParseTuple(args, "K", &num_execs)) {
    PyErr_SetString(PyExc_TypeError,
                    "Invalid value passed to 'execute' method.");
    return nullptr;
  }

  auto self = reinterpret_cast<PythonExecutorObject *>(self_);

  self->executor->has_error = false;
  self->executor->error = nullptr;
  switch (auto error_code = self->executor->Execute(num_execs)) {
    case ExecutorStatus::kGood:
      break;

    case ExecutorStatus::kErrorNotInitialized:
      PyErr_SetString(PyExc_ValueError,
                      "Micro-execution environment is not initialized.");
      return nullptr;

    case ExecutorStatus::kErrorDecode:
      PyErr_SetString(InstructionDecodeError, "Unable to decode instruction.");
      return nullptr;
    case ExecutorStatus::kErrorUnsupportedFeatures:
    case ExecutorStatus::kErrorUnsupportedCFI:
    case ExecutorStatus::kErrorUnsupportedStack:
      PyErr_SetString(UnsupportedError,
                      "Instruction is not supported by microx.");
      return nullptr;
    case ExecutorStatus::kErrorExecute:
      PyErr_SetString(MicroxError, "Unable to micro-execute instruction.");
      return nullptr;

    case ExecutorStatus::kErrorFault:
      PyErr_SetString(AddressFaultError,
                      "Instruction faulted during micro-execution.");
      return nullptr;

    case ExecutorStatus::kErrorFloatingPointException:
      PyErr_SetString(PyExc_FloatingPointError,
                      "Instruction faulted during micro-execution.");
      return nullptr;

    case ExecutorStatus::kErrorReadInstMem:
      if (!PyErr_Occurred() && !self->executor->error) {
        PyErr_SetString(InstructionFetchError,
                        "Could not read instruction bytes.");
      }
      [[clang::fallthrough]];

    default:
      if (PyErr_Occurred()) {
        // Do nothing, we've got an error already.

      } else if (self->executor->error) {
        PyErr_SetString(self->executor->error, self->executor->error_message);
        self->executor->error = nullptr;

      } else {
        PyErr_Format(PyExc_RuntimeError,
                     "Unable to micro-execute instruction with status %u.",
                     static_cast<unsigned>(error_code));
      }
      return nullptr;
  }

  Py_RETURN_TRUE;
}

// Python representation for the type of an executor.
static PyTypeObject gExecutorType;

static PyMethodDef gModuleMethods[] = {
    {nullptr} /* Sentinel */
};

static PyMethodDef gExecutorMethods[] = {
    {"execute", Executor_Execute, METH_VARARGS,
     "Interpret a string of bytes as a machine instruction and perform a "
     "micro-execution of the instruction."},
    {nullptr} /* Sentinel */
};

PythonExecutor::PythonExecutor(PyObject *self_, unsigned addr_size)
    : Executor(addr_size), self(self_), error(nullptr) {}

PythonExecutor::~PythonExecutor(void) {}

template <typename T>
static void WriteData(Data &data, T val) {
  *reinterpret_cast<T *>(&(data.bytes[0])) = val;
}

// Convert a Python value into a `Data` object.
bool PythonExecutor::ReadValue(PyObject *res, size_t num_bits, Data &val,
                               const char *usage) const {
  if (has_error) {
    return false;
  }

  const auto num_bytes = std::min(sizeof(val), (num_bits + 7) / 8);
  if (PyBytes_Check(res)) {
    auto res_size = static_cast<size_t>(PyBytes_Size(res));
    if (num_bytes != res_size) {
      has_error = true;
      error = PyExc_ValueError;
      snprintf(error_message, sizeof(error_message),
               "Incorrect number of bytes returned for value from '%s'; "
               "wanted %zu bytes but got %zu bytes.",
               usage, num_bytes, res_size);
      return false;
    } else {
      memcpy(&(val.bytes[0]), PyBytes_AsString(res), num_bytes);
    }

  } else if (PyLong_Check(res)) {
    auto long_res = reinterpret_cast<PyLongObject *>(res);
    if (!_PyLong_AsByteArray(long_res, val.bytes, sizeof(val), true, false)) {
      return true;
    }
    if (PyErr_Occurred()) {
      has_error = true;
    }
    return false;
  } else if (PyLong_CheckExact(res)) {
    WriteData(val, PyLong_AsLong(res));
  } else if (PyFloat_Check(res)) {
    if (32 == num_bits) {
      WriteData(val, static_cast<float>(PyFloat_AsDouble(res)));
    } else {
      WriteData(val, PyFloat_AsDouble(res));
    }
  } else {
    error = PyExc_TypeError;
    snprintf(error_message, sizeof(error_message),
             "Cannot convert type '%s' into a byte sequence from '%s'.",
             res->ob_type->tp_name, usage);
    return false;
  }
  memset(&(val.bytes[num_bytes]), 0, sizeof(val) - num_bytes);
  return true;
}

// Perform address computation. The segment register name is passed in so
// that the extender can perform segmented address calculation.
uintptr_t PythonExecutor::ComputeAddress(const char *seg_name, uintptr_t base,
                                         uintptr_t index, uintptr_t scale,
                                         uintptr_t displacement, size_t size,
                                         MemRequestHint hint) const {
  if (has_error) {
    return false;
  }

  char usage[256];
  auto res =
      PyObject_CallMethod(self, "compute_address", "(s,K,K,K,K,I,i)", seg_name,
                          base, index, scale, displacement, size / 8, hint);

  auto ret_addr = this->Executor::ComputeAddress(seg_name, base, index, scale,
                                                 displacement, size, hint);

  if (res) {
    sprintf(usage,
            "compute_address(\"%s\", 0x%08" PRIx64 ", 0x%08" PRIx64
            ", 0x%08" PRIx64 ", 0x%08" PRIx64 ", %lu, %d)",
            seg_name, static_cast<uint64_t>(base), static_cast<uint64_t>(index),
            static_cast<uint64_t>(scale), static_cast<uint64_t>(displacement),
            size / 8, hint);
    Data val;
    auto ret = ReadValue(res, addr_size, val, usage);
    Py_DECREF(res);

    if (ret) {
      ret_addr = *reinterpret_cast<uintptr_t *>(val.bytes);
    }

  } else if (PyErr_Occurred()) {
    has_error = true;
  }

  return ret_addr;
}

// Read a register from the environment. The name of the register should make
// the size explicit.
bool PythonExecutor::ReadReg(const char *name, size_t size, RegRequestHint hint,
                             Data &val) const {
  if (has_error) {
    return false;
  }

  char usage[256];
  auto res = PyObject_CallMethod(self, "read_register", "(s,i)", name, hint);
  if (res) {
    sprintf(usage, "read_register(\"%s\")", name);
    auto ret = ReadValue(res, size, val, usage);
    Py_DECREF(res);
    return ret;
  } else {
    return false;
  }
}

bool PythonExecutor::WriteReg(const char *name, size_t size,
                              const Data &val) const {
  if (has_error) {
    return false;
  }

  auto ret = PyObject_CallMethod(self, "write_register", "(s,y#)", name,
                                 val.bytes, (size + 7) / 8);
  Py_XDECREF(ret);
  return nullptr != ret;
}

bool PythonExecutor::ReadMem(uintptr_t addr, size_t size, MemRequestHint hint,
                             Data &val) const {
  if (has_error) {
    return false;
  }

  char usage[256];
  auto res =
      PyObject_CallMethod(self, "read_memory", "(K,I,i)", addr, size / 8, hint);
  if (res) {
    sprintf(usage, "read_memory(0x%08" PRIx64 ", %lu, %d)",
            static_cast<uint64_t>(addr), (size / 8), hint);
    auto ret = ReadValue(res, size, val, usage);
    Py_DECREF(res);
    return ret;
  } else {
    return false;
  }
}

bool PythonExecutor::WriteMem(uintptr_t addr, size_t size,
                              const Data &val) const {
  if (has_error) {
    return false;
  }

  auto ret = PyObject_CallMethod(self, "write_memory", "(K,y#)", addr,
                                 val.bytes, size / 8);
  Py_XDECREF(ret);
  return nullptr != ret;
}

bool PythonExecutor::ReadFPU(FPU &val) const {
  if (has_error) {
    return false;
  }

  auto res = PyObject_CallMethod(self, "read_fpu", "()");
  if (res) {
    if (!PyBytes_Check(res)) {
      Py_DECREF(res);
      has_error = true;
      error = PyExc_ValueError;
      snprintf(error_message, sizeof(error_message),
               "Expected 'read_fpu' to return string.");
      return false;
    }
    auto res_size = static_cast<size_t>(PyBytes_Size(res));
    if (sizeof(FPU) != res_size) {
      if (!error) {
        error = PyExc_ValueError;
        snprintf(
            error_message, sizeof(error_message),
            "Incorrect number of bytes returned for value from 'read_fpu'; "
            "wanted %zu bytes but got %zu bytes.",
            sizeof(FPU), res_size);
      }
      return false;
    } else {
      memcpy(&(val.bytes[0]), PyBytes_AsString(res), sizeof(FPU));
    }
  }
  Py_XDECREF(res);
  return nullptr != res;
}

bool PythonExecutor::WriteFPU(const FPU &val) const {
  auto ret =
      PyObject_CallMethod(self, "write_fpu", "(z#)", val.bytes, sizeof(val));
  Py_XDECREF(ret);
  return nullptr != ret;
}

struct module_state {
  PyObject *error;
};

static struct PyModuleDef gMicroxModuleDef = {
    PyModuleDef_HEAD_INIT,
    "microx_core",
    "x86 and x86-64 micro-execution support.",
    sizeof(struct module_state),
    gModuleMethods,
    nullptr,
    nullptr,
    nullptr,
    nullptr};

PyMODINIT_FUNC PyInit_microx_core(void) {
  if (!Executor::Init()) {
    return nullptr;
  }

  auto microx = PyModule_Create(&gMicroxModuleDef);
  if (!microx) {
    return PyErr_NoMemory();
  }

  if (!CreateExceptions(microx)) {
    return PyErr_NoMemory();
  }

  // Initialize the `Executor` type. Easier to manually initialize the various
  // fields as opposed to trying to make sure the structure field initialization
  // is just right.
  memset(&gExecutorType, 0, sizeof(gExecutorType));
  gExecutorType.tp_name = "microx_core.Executor";
  gExecutorType.tp_basicsize = sizeof(PythonExecutorObject);
  gExecutorType.tp_alloc = PyType_GenericAlloc;
  gExecutorType.tp_new = PyType_GenericNew;
  gExecutorType.tp_init = Executor_init;
  gExecutorType.tp_flags =
      Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_TYPE_SUBCLASS;
  gExecutorType.tp_doc = "Instruction micro-executor.";
  gExecutorType.tp_methods = gExecutorMethods;
  gExecutorType.tp_base = &PyBaseObject_Type;
  if (0 != PyType_Ready(&gExecutorType)) {
    return nullptr;
  }

  Py_INCREF(&gExecutorType);
  PyModule_AddObject(microx, "Executor",
                     reinterpret_cast<PyObject *>(&gExecutorType));

  return microx;
}  // namespace

}  // namespace
}  // namespace microx
