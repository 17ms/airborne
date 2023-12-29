cmake_minimum_required(VERSION 3.11)
project(airborne)

include(FetchContent)

if(NOT CMAKE_SYSTEM_NAME MATCHES Windows)
    message(FATAL_ERROR "Use a cross compilation suitable toolchain with CMAKE_SYSTEM_NAME set to Windows")
endif()

if(NOT MSVC)
    add_compile_options("-Wall")
else()
    # Level 4 warnings
    add_compile_options("-W4")
endif()

# Discord API wrapper dependency
FetchContent_Declare(
    concord
    GIT_REPOSITORY https://github.com/Cogmasters/concord
    GIT_TAG        769bdb7 # v2.2.1 release
)
FetchContent_MakeAvailable(concord)

# *) Reflective loader (DLL)
add_library(reflective_loader SHARED reflective_loader/loader.c reflective_loader/loader.h)

# *) Payload (DLL)
add_library(payload SHARED payload/payload.c)

# *) Injector (EXE)
add_executable(injector injector/injector.c)
target_link_libraries(injector PRIVATE concord)

# *) Shellcode generator (EXE)
add_executable(shellcode_generator shellcode_generator/generator.c)
target_link_libraries(shellcode_generator PRIVATE concord)

# Include directories
target_include_directories(injector PRIVATE concord)
target_include_directories(shellcode_generator PRIVATE concord)
