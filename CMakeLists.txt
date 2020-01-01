cmake_minimum_required (VERSION 3.5)
project (luacoap C)

include (ExternalProject)

set(LUA_VERSION "5.1" CACHE STRING "Version of Lua interpreter to link and install luaCoap to (-DLUA_VERSION)")
message(STATUS "Build and install for Lua version ${LUA_VERSION}")

set (luacoap_VERSION_MAJOR 0)
set (luacoap_VERSION_MINOR 2)
set (luacoap_VERSION_PATCH 0)

ExternalProject_Add(nyoci
  GIT_REPOSITORY https://github.com/darconeous/libnyoci
  GIT_TAG 11a6e1b107cb1577cb0fffca7e3fd261f26da94a
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/nyoci
  CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
  CONFIGURE_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/nyoci/bootstrap.sh &&
  ${CMAKE_CURRENT_BINARY_DIR}/nyoci/configure --enable-tls --disable-nyocictl --prefix=<INSTALL_DIR>
  BUILD_COMMAND ${MAKE}
  UPDATE_COMMAND ""
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
add_library (coap SHARED ${src_files})
set_target_properties (coap PROPERTIES PREFIX "")
set_target_properties (coap PROPERTIES CMAKE_POSITION_INDEPENDENT_CODE True)

set(LINK_FLAGS ${LINK_FLAGS} "-Wl,-whole-archive")
target_link_libraries (coap ${libnyoci} ${OPENSSL_SSL_LIBRARY} ${LUA_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
add_dependencies (coap nyoci)

install (FILES ${CMAKE_BINARY_DIR}/coap.so DESTINATION lib/lua/${LUA_VERSION})

set (CPACK_GENERATOR "DEB")
set (CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
set (CPACK_SET_DESTDIR TRUE)
set (CPACK_DEBIAN_PACKAGE_MAINTAINER "Alfonso Ros")
set (CPACK_PACKAGE_VERSION_MAJOR ${luacoap_VERSION_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${luacoap_VERSION_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${luacoap_VERSION_PATCH})
set (CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/downloads")
include (CPack)
