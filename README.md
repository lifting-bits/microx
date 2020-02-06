# microx - a micro execution framework
Microx is a single-instruction "micro execution" framework. Microx enables a program to safely execute an arbitrary x86 or x86-64 instruction. Microx does not take over or require a process context in order to execute an instruction. It is easily embedded within other programs, as exampled by the Python bindings.

The microx approach to safe instruction execution of arbitrary instructions is to require the user of microx to manage machine state. Microx is packaged as a C++ `Executor` class that must be extended. The Python bindings also present a class, `microx.Executor`, that must be extended. A program extending this class must implement methods such as `ReadReg` and `ReadMem`. When supplied with instruction bytes, microx will invoke the class methods in order to pull in the minimal requisite machine state to execute the instruction. After executing the instruction, microx will "report back" the state changes induced by the instruction's execution, again via methods like `WriteReg` and `WriteMem`.

The following lists some use-cases of microx:

* Speculative execution of code within a debugger-like system. In this scenario, microx can be used to execute instructions from the process being debugged, in such a way that the memory and state of the original program will be preserved.
* Binary symbolic execution. In this scenario, which was the original use-case of microx, a binary symbolic executor can use microx to safely execute an instruction that is not supported or modelled by the symbolic execution system. The use of microx will minimize the amount of symbolic state that may need to be concretized in order to execute the instruction. Microx was used in this fashion in a Python-based binary symbolic executor. Microx comes with Python bindings for this reason.
* Headless taint tracking. Taint tracking can be implemented with microx, much as it would be with Intel's PIN, but without a process context. Microx can be integrated into a disassembler such as IDA or Binary Ninja and used to execute instruction, performing taint tracking along the way.

Microx uses a combination of JIT-based dynamic binary translation and instruction emulation in order to safely execute x86 instructions. It is a 64-bit library, but it can execute 32-bit instructions that are not supported on 64-bit platforms. It can be easily embedded, as it performs no dynamic memory allocations, and is re-entrant.

Microx depends on [Intel's XED](https://intelxed.github.io/) instruction encoder and decoder.

## Compilation on Windows (MinGW)

To compile for Windows you can use MinGW, the following command should work (make sure to adjust for your Python version):

```
g++ -g -shared Executor.cpp Python.cpp -Lc:\Python37-64\libs -lpython37 -std=c++14 -I.. -I..\third_party\include -Ic:\Python37-64\include -Wno-attributes -lxed -L..\third_party\lib -o microx_core.pyd
```