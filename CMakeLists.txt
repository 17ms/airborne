cmake_minimum_required(VERSION 3.11)
project(
    airborne
    VERSION 0.1.0
    DESCRIPTION "Reflective DLL injection demonstration"
    LANGUAGES CXX
)

if(NOT CMAKE_SYSTEM_NAME MATCHES Windows)
    message(FATAL_ERROR "Use a cross compilation suitable toolchain with CMAKE_SYSTEM_NAME set to Windows")
endif()

if(NOT MSVC)
    add_compile_options("-Wall" "-Wextra")
else()
    # Level 4 warnings
    add_compile_options("/W4" "/WX")
endif()

# *) Reflective loader (DLL)
add_library(reflective_loader SHARED reflective_loader/loader.cpp reflective_loader/loader.hpp)

# *) Payload (DLL)
add_library(payload SHARED payload/payload.cpp)

# *) Injector (EXE)
add_executable(injector injector/injector.cpp)

# *) Shellcode generator (EXE)
# add_executable(shellcode_generator shellcode_generator/generator.c)
