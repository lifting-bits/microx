cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(microx)

set(CMAKE_CXX_STANDARD 11)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "${CMAKE_BINARY_DIR}"
      CACHE PATH "Default install directory" FORCE
  )
endif ()

if (MSVC)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

add_subdirectory(microx)
