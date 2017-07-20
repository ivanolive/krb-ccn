# Install script for directory: /home/ivan/Desktop/krb-ccn/ccn/gateway/ccnx/forwarder/athena

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

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena.a")
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TCP.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TCP.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TCP.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_TCP.so.1.0"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_TCP.so.1"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_TCP.so"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TCP.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TCP.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TCP.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib:"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_UDP.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_UDP.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_UDP.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_UDP.so.1"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_UDP.so"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_UDP.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_UDP.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_UDP.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib:"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_ETH.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_ETH.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_ETH.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_ETH.so.1.0"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_ETH.so.1"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_ETH.so"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_ETH.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_ETH.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_ETH.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib:"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_Fragmenter_BEFS.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_Fragmenter_BEFS.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_Fragmenter_BEFS.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_Fragmenter_BEFS.so.1.0"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_Fragmenter_BEFS.so.1"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_Fragmenter_BEFS.so"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_Fragmenter_BEFS.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_Fragmenter_BEFS.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_Fragmenter_BEFS.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib:"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(NOT CMAKE_INSTALL_COMPONENT OR "${CMAKE_INSTALL_COMPONENT}" STREQUAL "Unspecified")
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TEMPLATE.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TEMPLATE.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TEMPLATE.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "/usr/local/lib")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE SHARED_LIBRARY FILES
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1.0"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1"
    "/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TEMPLATE.so.1.0"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TEMPLATE.so.1"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libathena_TEMPLATE.so"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHANGE
           FILE "${file}"
           OLD_RPATH "/home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib:"
           NEW_RPATH "/usr/local/lib")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test/cmake_install.cmake")
  include("/home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/cmake_install.cmake")

endif()

