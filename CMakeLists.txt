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

find_package(OpenSSL 3.0 REQUIRED)
find_package(nlohmann_json 3.10 REQUIRED)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion)

add_library(ztcore
  core/src/ata.cpp
  core/src/blockio.cpp
  core/src/canonical_json.cpp
  core/src/certificate.cpp
  core/src/crypto.cpp
  core/src/device.cpp
  core/src/erase.cpp
  core/src/methods.cpp
  core/src/nvme.cpp
  core/src/overwrite.cpp
  core/src/probe.cpp
  core/src/safety.cpp
  core/src/verify.cpp
)
target_include_directories(ztcore PUBLIC core/include)
target_link_libraries(ztcore PUBLIC nlohmann_json::nlohmann_json PRIVATE OpenSSL::Crypto)

add_executable(zt
  cli/main.cpp
  cli/common.cpp
  cli/cmd_inspect.cpp
  cli/cmd_erase.cpp
  cli/cmd_cert.cpp
)
target_link_libraries(zt PRIVATE ztcore)

if(ZT_BUILD_TESTS)
  enable_testing()
  foreach(t device identify crypto erase)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE ztcore)
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()
endif()
