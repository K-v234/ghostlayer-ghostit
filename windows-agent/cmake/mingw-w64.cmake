# cmake/mingw-w64.cmake
# CMake toolchain file — cross-compile Windows x86_64 from Ubuntu using mingw-w64
# Ghost Layer Technologies · Chennai · June 2026

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# mingw-w64 compilers (installed: mingw-w64 13.0.0)
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER  x86_64-w64-mingw32-windres)

# Target environment — where mingw-w64 Windows headers/libs live
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)

# Search headers/libs only in the mingw sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
