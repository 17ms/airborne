cmake_minimum_required(VERSION 3.11)
project(
    airborne
    VERSION 0.1.0
    DESCRIPTION "Reflective DLL injection demonstration"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_SYSTEM_NAME MATCHES Windows)
    message(FATAL_ERROR "Use a cross compilation suitable toolchain with CMAKE_SYSTEM_NAME set to Windows")
endif()

# Build as Release by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT lto_supported OUTPUT error)

# Enable LTO if supported
if(lto_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(WARNING "LTO is not supported: ${error}")
endif()

if(NOT MSVC)
    add_compile_options("-Wall" "-Wextra" "-Os")
    set(CMAKE_EXE_LINKED_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s")
else()
    add_compile_options("/W4" "/WX" "/O1" "/GL")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /INCREMENTAL:NO /OPT:REF /OPT:ICF /PDBSTRIPPED")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /INCREMENTAL:NO /OPT:REF /OPT:ICF /PDBSTRIPPED")
endif()

# *) Shared modules
add_library(shared STATIC shared/crypto.cpp shared/crypto.hpp shared/futils.cpp shared/futils.hpp)

# *) Reflective loader (DLL)
add_library(loader SHARED reflective_loader/loader.cpp reflective_loader/loader.hpp)
target_link_libraries(loader PRIVATE shared)

# *) Payload (DLL)
add_library(payload SHARED payload/payload.cpp)

# *) Shellcode generator (EXE)
add_executable(generator generator/generator.cpp generator/generator.hpp)
target_link_libraries(generator PRIVATE shared)

# *) Injector (EXE)
add_executable(injector injector/injector.cpp)
target_link_libraries(injector PRIVATE shared)

if(NOT MSVC)
    foreach(target loader payload generator injector)
        add_custom_command(TARGET ${target} POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:${target}>) # Strip binaries
    endforeach()
endif()
