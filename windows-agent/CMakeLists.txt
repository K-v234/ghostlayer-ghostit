# CMakeLists.txt
# GhostIT C9 — Windows Agent Cross-Compile Build System
# Builds a Windows .exe from Ubuntu using mingw-w64
#
# Usage:
#   mkdir -p windows-agent/build && cd windows-agent/build
#   cmake .. -DCMAKE_TOOLCHAIN_FILE=../../cmake/mingw-w64.cmake
#   cmake --build . --config Release
#
# Output: windows-agent/build/GhostITAgent.exe
# Ghost Layer Technologies · Chennai · June 2026

cmake_minimum_required(VERSION 3.16)

project(GhostITAgent
    VERSION     1.0.0
    DESCRIPTION "GhostIT C9 Windows Monitoring Agent"
    LANGUAGES   C CXX
)

# ── C++ standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── Windows target version ────────────────────────────────────────────────────
# 0x0A00 = Windows 10 minimum (ETW-TI needs RS3+, eBPF needs Win11 22H2+)
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# ── Compiler flags ────────────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(
        -O2
        -Wall
        -Wextra
        -Wno-unused-parameter      # ETW callbacks have mandatory unused params
        -fstack-protector-strong   # Stack canaries
        -D_FORTIFY_SOURCE=2        # Buffer overflow detection
    )
endif()

# ── Source files ──────────────────────────────────────────────────────────────
set(GHOST_AGENT_SOURCES
    src/ghost_windows_service.cpp   # Entry point + SCM + watchdog
    src/etw_provider.cpp            # ETW-TI kernel event session
    src/divergence_detector.cpp     # eBPF vs ETW cross-check
    src/coverage_mode.cpp           # Win10/Win11 detection + badge
    src/pipeline_forwarder.cpp      # TCP send to Ubuntu 192.168.88.131:9000
    src/event_serializer.cpp        # ghost_event_t → JSON
)

set(GHOST_AGENT_HEADERS
    src/ghost_event.h               # 128-byte event struct (C-compatible)
    src/ghost_windows_service.h
    src/etw_provider.h
    src/divergence_detector.h
    src/coverage_mode.h
    src/pipeline_forwarder.h
    src/event_serializer.h
    src/process_hook.h
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(GhostITAgent
    ${GHOST_AGENT_SOURCES}
    ${GHOST_AGENT_HEADERS}
)

# ── Include directories ───────────────────────────────────────────────────────
target_include_directories(GhostITAgent PRIVATE
    src/
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/nlohmann   # nlohmann/json.hpp
)

# ── Windows SDK libraries ─────────────────────────────────────────────────────
# These are provided by mingw-w64 on Ubuntu
target_link_libraries(GhostITAgent PRIVATE
    tdh          # Trace Data Helper — ETW field decoding
    secur32      # Security support provider
    ole32        # COM (needed by some ETW internals)
    advapi32     # Windows service API (StartServiceCtrlDispatcher etc.)
    ws2_32       # Winsock2 — TCP pipeline forwarder
    kernel32     # Core Win32
    ntdll        # RtlGetVersion (coverage_mode)
)

# ── Static linking — single .exe, no DLL dependencies on customer machine ─────
set_target_properties(GhostITAgent PROPERTIES
    LINK_FLAGS "-static -static-libgcc -static-libstdc++"
)

# ── Output name and location ──────────────────────────────────────────────────
set_target_properties(GhostITAgent PROPERTIES
    OUTPUT_NAME   "GhostITAgent"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ── Strip debug symbols from Release build ────────────────────────────────────
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET GhostITAgent POST_BUILD
        COMMAND x86_64-w64-mingw32-strip
                "${CMAKE_BINARY_DIR}/bin/GhostITAgent.exe"
        COMMENT "Stripping debug symbols from release binary"
    )
endif()

# ── Version info embedded in binary ──────────────────────────────────────────
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in"
    "${CMAKE_BINARY_DIR}/version.h"
)
target_include_directories(GhostITAgent PRIVATE "${CMAKE_BINARY_DIR}")

# ── Print build summary ───────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "GhostIT C9 Windows Agent Build Configuration")
message(STATUS "  Version:    ${PROJECT_VERSION}")
message(STATUS "  Compiler:   ${CMAKE_CXX_COMPILER}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Output:     ${CMAKE_BINARY_DIR}/bin/GhostITAgent.exe")
message(STATUS "  Target:     Windows 10 RS3+ / Windows 11 22H2+")
message(STATUS "  Pipeline:   192.168.88.131:9000")
message(STATUS "")
