add_library(intercept SHARED
    preload.cpp
)

target_include_directories(intercept PRIVATE
    ${CMAKE_SOURCE_DIR}/shared
)

target_link_libraries(intercept PRIVATE shared)

set_target_properties(intercept PROPERTIES OUTPUT_NAME "intercept")
