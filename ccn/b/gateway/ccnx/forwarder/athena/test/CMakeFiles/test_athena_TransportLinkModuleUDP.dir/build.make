# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.2

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ivan/Desktop/krb-ccn/ccn

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ivan/Desktop/krb-ccn/ccn/b

# Include any dependencies generated for this target.
include gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/depend.make

# Include the progress variables for this target.
include gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/progress.make

# Include the compile flags for this target's objects.
include gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/flags.make

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/flags.make
gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o: ../gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ivan/Desktop/krb-ccn/ccn/b/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o"
	cd /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o   -c /home/ivan/Desktop/krb-ccn/ccn/gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP.c

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.i"
	cd /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/ivan/Desktop/krb-ccn/ccn/gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP.c > CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.i

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.s"
	cd /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test && /usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/ivan/Desktop/krb-ccn/ccn/gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP.c -o CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.s

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.requires:
.PHONY : gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.requires

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.provides: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.requires
	$(MAKE) -f gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/build.make gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.provides.build
.PHONY : gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.provides

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.provides.build: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o

# Object files for target test_athena_TransportLinkModuleUDP
test_athena_TransportLinkModuleUDP_OBJECTS = \
"CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o"

# External object files for target test_athena_TransportLinkModuleUDP
test_athena_TransportLinkModuleUDP_EXTERNAL_OBJECTS =

gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/build.make
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: gateway/ccnx/forwarder/athena/libathena.a
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/liblongbow.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/liblongbow-textplain.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /usr/lib/x86_64-linux-gnu/libevent.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /usr/lib/x86_64-linux-gnu/libssl.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /usr/lib/x86_64-linux-gnu/libcrypto.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/libccnx_api_portal.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/libccnx_transport_rta.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/libccnx_api_control.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/libccnx_api_notify.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/libccnx_common.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: /home/ivan/Desktop/projects/ccnx/CCNx_Distillery/usr/lib/libparc.so
gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable test_athena_TransportLinkModuleUDP"
	cd /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_athena_TransportLinkModuleUDP.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/build: gateway/ccnx/forwarder/athena/test/test_athena_TransportLinkModuleUDP
.PHONY : gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/build

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/requires: gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/test_athena_TransportLinkModuleUDP.c.o.requires
.PHONY : gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/requires

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/clean:
	cd /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test && $(CMAKE_COMMAND) -P CMakeFiles/test_athena_TransportLinkModuleUDP.dir/cmake_clean.cmake
.PHONY : gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/clean

gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/depend:
	cd /home/ivan/Desktop/krb-ccn/ccn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/Desktop/krb-ccn/ccn /home/ivan/Desktop/krb-ccn/ccn/gateway/ccnx/forwarder/athena/test /home/ivan/Desktop/krb-ccn/ccn/b /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test /home/ivan/Desktop/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : gateway/ccnx/forwarder/athena/test/CMakeFiles/test_athena_TransportLinkModuleUDP.dir/depend

