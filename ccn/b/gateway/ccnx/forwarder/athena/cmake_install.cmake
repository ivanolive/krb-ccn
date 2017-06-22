# Install script for directory: /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena.a")
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_TCP.so.1.0"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_TCP.so.1"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_TCP.so"
    )
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so"
    )
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_ETH.so.1.0"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_ETH.so.1"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_ETH.so"
    )
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_Fragmenter_BEFS.so.1.0"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_Fragmenter_BEFS.so.1"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_Fragmenter_BEFS.so"
    )
endif()

if("${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_TEMPLATE.so.1.0"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_TEMPLATE.so.1"
    "/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_TEMPLATE.so"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test/cmake_install.cmake")
  include("/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/cmake_install.cmake")

endif()

