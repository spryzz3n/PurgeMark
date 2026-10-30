cmake_minimum_required(VERSION 3.20)
project(zerotrace VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "ZeroTrace talks to Linux block devices and only builds on Linux.")
endif()

option(ZT_BUILD_TESTS "Build unit tests" ON)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion)

add_library(ztcore
  core/src/ata.cpp
  core/src/device.cpp
  core/src/methods.cpp
  core/src/nvme.cpp
  core/src/probe.cpp
  core/src/safety.cpp
)
target_include_directories(ztcore PUBLIC core/include)

add_executable(zt cli/main.cpp)
target_link_libraries(zt PRIVATE ztcore)

if(ZT_BUILD_TESTS)
  enable_testing()
  foreach(t device identify)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE ztcore)
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()
endif()
