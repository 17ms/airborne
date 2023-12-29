# Usage:
#   *) Install cross-compiler: `brew install mingw-w64`
#   *) cmake -DCMAKE_TOOLCHAIN_FILE=macos-mingw-w64-x86_64.cmake -B build -S .
#   *) make -C build

set(CMAKE_SYSTEM_NAME Windows)
set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

# Cross-compilers to use for C and C++
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
set(CMAKE_AR ${TOOLCHAIN_PREFIX}-ar)
set(CMAKE_RANLIB ${TOOLCHAIN_PREFIX}-ranlib)

# Target environment on the build host system (with Homebrew)
set(CMAKE_FIND_ROOT_PATH /opt/homebrew/Cellar/mingw-w64/11.0.1/toolchain-x86_64/${TOOLCHAIN_PREFIX})

# Search for programs in the build host directories (modifying default behavior of FIND_XXX())
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -Os")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -Os")
