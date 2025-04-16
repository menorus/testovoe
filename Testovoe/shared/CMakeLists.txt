add_library(shared STATIC
    shared_buffer.cpp
)

target_include_directories(shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
