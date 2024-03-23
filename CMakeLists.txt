cmake_minimum_required( VERSION 3.16 )

project(xbox-fmalloc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

add_library( xbox-fmalloc SHARED dllmain.cpp fmalloc.cpp o1heap.c )
set_property(TARGET xbox-fmalloc PROPERTY
             MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_compile_definitions( xbox-fmalloc PRIVATE -D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN -DXBOXFMALLOC_EXPORTS -D_WINDOWS -D_USRDLL )
target_include_directories( xbox-fmalloc INTERFACE "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>" )
target_link_libraries( xbox-fmalloc PRIVATE onecore.lib)