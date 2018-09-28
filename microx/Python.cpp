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
#include <cstdint>
#include <new>
#include <type_traits>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-register"
#include <Python.h>
#pragma clang diagnostic pop

#include "microx/Executor.h"

namespace microx {
namespace {

struct PythonExecutorObject;

// Extends the executor to invoke Python methods to satisfy requests for
// data from the environment and respond with new values to place into the
// environment.
struct PythonExecutor : public Executor {
  PythonExecutor(PyObject *self_, unsigned addr_size);

  virtual ~PythonExecutor(void);

  bool ReadValue(PyObject *res, size_t num_bits, Data &val) const;

  virtual bool ReadReg(const char *name, size_t size, RegRequestHint hint,
                       Data &val) const override;

  virtual bool WriteReg(const char *name, size_t size,
                        const Data &val) const override;

  virtual bool ReadMem(const char *seg, uintptr_t addr, size_t size,
                       MemRequestHint hint, Data &val) const override;

  virtual bool WriteMem(const char *seg, uintptr_t addr, size_t size,
                        const Data &val) const override;

  virtual bool ReadFPU(FPU &val) const override;

  virtual bool WriteFPU(const FPU &val) const override;

  PyObject * const self;
  mutable PyObject *error;
  mutable char error_message[256];
};

// Python representation for an instance of an executor.
struct PythonExecutorObject {
  PyObject_HEAD
  PythonExecutor *executor;
  std::aligned_storage<sizeof(PythonExecutor),
                       alignof(PythonExecutor)>::type impl;
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

// Emulate an instruction.
static PyObject *Executor_Execute(PyObject *self_, PyObject *args) {
  uint8_t *instr_bytes = 0;
  uint32_t instr_num_bytes = 0;

  if (!PyArg_ParseTuple(args, "s#", &instr_bytes, &instr_num_bytes)) {
    return nullptr;
  }

  if (!instr_num_bytes) {
    PyErr_SetString(
        PyExc_ValueError,
        "Cannot micro-execute a zero-byte instruction.");
    return nullptr;
  }

  auto self = reinterpret_cast<PythonExecutorObject *>(self_);

  self->executor->error = nullptr;
  switch (self->executor->Execute(instr_bytes, instr_num_bytes)) {
    case ExecutorStatus::kGood:
      break;

    case ExecutorStatus::kErrorNotInitialized:
      PyErr_SetString(
          PyExc_ValueError,
          "Micro-execution environment is not initialized.");
      return nullptr;

    case ExecutorStatus::kErrorDecode:
    case ExecutorStatus::kErrorUnsupportedCFI:
    case ExecutorStatus::kErrorUnsupportedStack:
    case ExecutorStatus::kErrorExecute:
      PyErr_SetString(
          PyExc_RuntimeError,
          "Unable to micro-execute instruction.");
      return nullptr;

    case ExecutorStatus::kErrorFault:
      PyErr_SetString(
          PyExc_RuntimeError,
          "Instruction faulted during micro-execution.");
      return nullptr;

    case ExecutorStatus::kErrorFloatingPointException:
      PyErr_SetString(
          PyExc_FloatingPointError,
          "Instruction faulted during micro-execution.");
      return nullptr;

    default:
      if (self->executor->error) {
        PyErr_SetString(self->executor->error, self->executor->error_message);
        self->executor->error = nullptr;
      }
      return nullptr;
  }

  Py_INCREF(Py_True);
  return Py_True;
}

// Python representation for the type of an executor.
static PyTypeObject gExecutorType;

static PyMethodDef gModuleMethods[] = {
  {nullptr}  /* Sentinel */
};

static PyMethodDef gExecutorMethods[] = {
  {"Execute",
   Executor_Execute,
   METH_VARARGS,
   "Interpret a string of bytes as a machine instruction and perform a "
   "micro-execution of the instruction."},
  {nullptr}  /* Sentinel */
};

PythonExecutor::PythonExecutor(PyObject *self_, unsigned addr_size)
    : Executor(addr_size),
      self(self_),
      error(nullptr) {}

PythonExecutor::~PythonExecutor(void) {}

template <typename T>
static void WriteData(Data &data, T val) {
  *reinterpret_cast<T *>(&(data.bytes[0])) = val;
}

// Convert a Python value into a `Data` object.
bool PythonExecutor::ReadValue(
    PyObject *res, size_t num_bits, Data &val) const {
  const auto num_bytes = std::min(sizeof(val), (num_bits + 7) / 8);
  if (PyString_Check(res)) {
    auto res_size = static_cast<size_t>(PyString_Size(res));
    if (num_bytes != res_size) {
      error = PyExc_ValueError;
      snprintf(
          error_message, sizeof(error_message),
          "Incorrect number of bytes returned for value; "
          "wanted %zu bytes but got %zu bytes.",
          num_bytes, res_size);
      return false;
    } else {
      memcpy(&(val.bytes[0]), PyString_AsString(res), num_bytes);
    }

  } else if (PyInt_CheckExact(res)) {
    WriteData(val, PyInt_AsLong(res));

  } else if (PyLong_Check(res)) {
    auto long_res = reinterpret_cast<PyLongObject *>(res);
    if (0 != _PyLong_AsByteArray(long_res, val.bytes, num_bytes, true, false)){
      return false;
    }

  } else if (PyFloat_Check(res)) {
    if (32 == num_bits) {
      WriteData(val, static_cast<float>(PyFloat_AsDouble(res)));
    } else {
      WriteData(val, PyFloat_AsDouble(res));
    }
  } else {
    error = PyExc_TypeError;
    snprintf(
        error_message, sizeof(error_message),
        "Cannot convert type '%s' into a byte sequence.",
        res->ob_type->tp_name);
    return false;
  }
  memset(&(val.bytes[num_bytes]), 0, sizeof(val) - num_bytes);
  return true;
}

// Read a register from the environment. The name of the register should make
// the size explicit.
bool PythonExecutor::ReadReg(const char *name, size_t size,
                             RegRequestHint, Data &val) const {
  auto res = PyEval_CallMethod(self, "ReadReg", "(s)", name);
  if (res) {
    auto ret = ReadValue(res, size, val);
    Py_DECREF(res);
    return ret;
  } else {
    return false;
  }
}

bool PythonExecutor::WriteReg(const char *name, size_t size,
                              const Data &val) const {
  auto ret = PyEval_CallMethod(
      self, "WriteReg", "(s,s#)", name, val.bytes, (size + 7) / 8);
  Py_XDECREF(ret);
  return nullptr != ret;
}

bool PythonExecutor::ReadMem(const char *seg, uintptr_t addr, size_t size,
                             MemRequestHint hint, Data &val) const {
  auto res = PyEval_CallMethod(
      self, "ReadMem", "(s,K,I,i)", seg, addr, size / 8, hint);
  if (res) {
    auto ret = ReadValue(res, size, val);
    Py_DECREF(res);
    return ret;
  } else {
    return false;
  }
}

bool PythonExecutor::WriteMem(const char *seg, uintptr_t addr, size_t size,
                              const Data &val) const {
  auto ret = PyEval_CallMethod(
      self, "WriteMem", "(s,K,s#)", seg, addr, val.bytes, size / 8);
  Py_XDECREF(ret);
  return nullptr != ret;
}

bool PythonExecutor::ReadFPU(FPU &val) const {
  auto res = PyEval_CallMethod(self, "ReadFPU", "()");
  if (res) {
    if (!PyString_Check(res)) {
      Py_DECREF(res);
      error = PyExc_ValueError;
      snprintf(
          error_message, sizeof(error_message),
          "Expected ReadFPU to return string.");
      return false;
    }
    auto res_size = static_cast<size_t>(PyString_Size(res));
    if (sizeof(FPU) != res_size) {
      error = PyExc_ValueError;
      snprintf(
          error_message, sizeof(error_message),
          "Incorrect number of bytes returned for value; "
          "wanted %zu bytes but got %zu bytes.",
          sizeof(FPU), res_size);
      return false;
    } else {
      memcpy(&(val.bytes[0]), PyString_AsString(res), sizeof(FPU));
    }
  }
  Py_XDECREF(res);
  return nullptr != res;
}

bool PythonExecutor::WriteFPU(const FPU &val) const {
  auto ret = PyEval_CallMethod(
      self, "WriteFPU", "(s#)", val.bytes, sizeof(val));
  Py_XDECREF(ret);
  return nullptr != ret;
}

PyMODINIT_FUNC
initmicrox(void) {
  if (!Executor::Init()) {
    return;
  }

  auto m = Py_InitModule3(
      "microx",
      gModuleMethods,
      "x86 and x86-64 micro-execution support.");
  if (!m) {
    return;
  }
  enum {
    x = sizeof(PythonExecutorObject),
    y = sizeof(PythonExecutor),
    z = y
  };

  // Initialize the `Executor` type. Easier to manually initialize the various
  // fields as opposed to trying to make sure the structure field initialization
  // is just right.
  memset(&gExecutorType, 0, sizeof(gExecutorType));
  gExecutorType.tp_name = "microx.Executor";
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
    return;
  }

  Py_INCREF(&gExecutorType);
  PyModule_AddObject(
      m, "Executor", reinterpret_cast<PyObject *>(&gExecutorType));
}

}  // namespace
}  // namespace microx
