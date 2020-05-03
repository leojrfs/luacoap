cmake_minimum_required (VERSION 3.5)
project (luacoap C)

include (ExternalProject)

set(LUA_VERSION "5.1" CACHE STRING "Version of Lua interpreter to link and install luaCoap to (-DLUA_VERSION)")
message(STATUS "Build and install for Lua version ${LUA_VERSION}")

set (luacoap_VERSION_MAJOR 0)
set (luacoap_VERSION_MINOR 2)
set (luacoap_VERSION_PATCH 2)

# Apply nyoci patch on Alpine 3.11
if (NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 9.2)
  set(PATCH_COMMAND_NYOCI patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patches/nyoci-001-Makefile-autoconf-archive.patch)
endif()

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")

ExternalProject_Add(nyoci
  GIT_REPOSITORY https://github.com/vwout/libnyoci
  GIT_TAG bae244bc7e836da9b35113c1254527455f80bf68
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/nyoci
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
  CONFIGURE_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/nyoci/bootstrap.sh &&
                    ${CMAKE_CURRENT_BINARY_DIR}/nyoci/configure --enable-tls --disable-nyocictl --disable-extra --disable-plugtest --disable-examples --prefix=<INSTALL_DIR>
  BUILD_COMMAND ${MAKE}
  UPDATE_COMMAND ""
  PATCH_COMMAND ${PATCH_COMMAND_NYOCI}
)

ExternalProject_Get_Property(nyoci install_dir)
set (libnyoci ${install_dir}/lib/libnyoci.a)
include_directories (${install_dir}/include)

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/")

find_package(Lua ${LUA_VERSION} REQUIRED)
include_directories (${LUA_INCLUDE_DIR})

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

## Source files
aux_source_directory (src src_files)

include_directories (include)
include_directories (${CURL_INCLUDE_DIRS})

add_library (coap SHARED ${src_files})
set_target_properties (coap PROPERTIES PREFIX ""
                                       POSITION_INDEPENDENT_CODE True)
set(LINK_FLAGS ${LINK_FLAGS} "-Wl,-whole-archive")
target_link_libraries (coap
  ${libnyoci}
  ${OPENSSL_SSL_LIBRARY}
  ${LUA_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT})

add_dependencies (coap 
  nyoci)

install (FILES 
  ${CMAKE_BINARY_DIR}/coap.so 
  DESTINATION lib/lua/${LUA_VERSION})

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME}-lua${LUA_VERSION})
set(CPACK_SET_DESTDIR TRUE)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Vwout")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl1.1")
set(CPACK_PACKAGE_VERSION_MAJOR ${luacoap_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${luacoap_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${luacoap_VERSION_PATCH})
set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/downloads")
include(CPack)
