cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(microx)

find_library(
  LIBXED
  NAMES xed
  PATHS ENV "XED_DIR"
  PATH_SUFFIXES "lib" REQUIRED
)

add_library("${PROJECT_NAME}" Executor.cpp)
target_include_directories(
  "${PROJECT_NAME}" PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<INSTALL_INTERFACE:include>
)
set_target_properties("${PROJECT_NAME}" PROPERTIES PUBLIC_HEADER "include/microx/Executor.h")

target_link_libraries("${PROJECT_NAME}" PRIVATE "${LIBXED}")
target_include_directories("${PROJECT_NAME}" SYSTEM PRIVATE "$ENV{XED_DIR}/include")

install(
  TARGETS "${PROJECT_NAME}"
  EXPORT microx-config
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include/microx"
)
export(
  TARGETS "${PROJECT_NAME}"
  NAMESPACE microx::
  FILE "${CMAKE_CURRENT_BINARY_DIR}/microx-config.cmake"
)
install(
  EXPORT microx-config
  DESTINATION "lib/cmake/microx"
  NAMESPACE microx::
  EXPORT_LINK_INTERFACE_LIBRARIES
)
