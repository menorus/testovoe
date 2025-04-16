add_executable(demon_file_logger file_logger.cpp)
add_executable(demon_mem_logger mem_logger.cpp)

target_include_directories(demon_file_logger PRIVATE ${CMAKE_SOURCE_DIR}/shared)
target_include_directories(demon_mem_logger PRIVATE ${CMAKE_SOURCE_DIR}/shared)

target_link_libraries(demon_file_logger PRIVATE shared)
target_link_libraries(demon_mem_logger PRIVATE shared)
