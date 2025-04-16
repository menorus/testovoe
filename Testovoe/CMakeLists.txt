cmake_minimum_required(VERSION 3.10)
project(libc_intercept CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_subdirectory(shared)
add_subdirectory(lib)
add_subdirectory(deamon)

include(GNUInstallDirs)

# Установка
install(TARGETS intercept
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(TARGETS demon_file_logger demon_mem_logger
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY shared/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/shared
    FILES_MATCHING PATTERN "*.h"
)

# CPack для .deb
include(CPack)

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME "libc-intercept")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Your Name <your@email>")
