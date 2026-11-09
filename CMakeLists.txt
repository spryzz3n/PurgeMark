cmake_minimum_required(VERSION 3.25)
project(purgemark VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "PurgeMark talks to Linux block devices and only builds on Linux.")
endif()

option(PM_BUILD_TESTS "Build unit tests" ON)
option(PM_BUILD_TUI "Build the purgemark terminal UI" ON)

find_package(OpenSSL 3.0 REQUIRED)
find_package(nlohmann_json 3.10 REQUIRED)

# Strict warnings for our code only, not third-party sources.
add_library(pm_warnings INTERFACE)
target_compile_options(pm_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)

add_library(pmcore
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
target_include_directories(pmcore PUBLIC core/include)
target_link_libraries(pmcore PUBLIC nlohmann_json::nlohmann_json PRIVATE OpenSSL::Crypto pm_warnings)

add_executable(pmark
  cli/main.cpp
  cli/common.cpp
  cli/cmd_inspect.cpp
  cli/cmd_erase.cpp
  cli/cmd_cert.cpp
)
target_link_libraries(pmark PRIVATE pmcore pm_warnings)

# Terminal UI. Uses a system FTXUI if present, else fetches a pinned release.
if(PM_BUILD_TUI)
  find_package(ftxui 5 QUIET)
  if(NOT ftxui_FOUND)
    include(FetchContent)
    set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(FTXUI_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(ftxui
      GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
      GIT_TAG v5.0.0
      GIT_SHALLOW TRUE
      SYSTEM)
    FetchContent_MakeAvailable(ftxui)
  endif()
  add_executable(purgemark tui/main.cpp)
  target_link_libraries(purgemark PRIVATE pmcore pm_warnings ftxui::component ftxui::dom ftxui::screen)
endif()

if(PM_BUILD_TESTS)
  enable_testing()
  foreach(t device identify crypto erase)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE pmcore pm_warnings)
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()
endif()
