# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.6

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


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
CMAKE_SOURCE_DIR = /home/ivan/workspace/krb-ccn/krb-ccn/ccn

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b

# Include any dependencies generated for this target.
include gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/depend.make

# Include the progress variables for this target.
include gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/progress.make

# Include the compile flags for this target's objects.
include gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/flags.make

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/flags.make
gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o: ../gateway/ccnx/forwarder/athena/athena_Fragmenter.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o   -c /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/athena_Fragmenter.c

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.i"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/athena_Fragmenter.c > CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.i

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.s"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/athena_Fragmenter.c -o CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.s

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.requires:

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.requires

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.provides: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.requires
	$(MAKE) -f gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/build.make gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.provides.build
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.provides

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.provides.build: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o


gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/flags.make
gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o: ../gateway/ccnx/forwarder/athena/athena_TransportLinkModuleUDP.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o   -c /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/athena_TransportLinkModuleUDP.c

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.i"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/athena_TransportLinkModuleUDP.c > CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.i

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.s"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/athena_TransportLinkModuleUDP.c -o CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.s

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.requires:

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.requires

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.provides: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.requires
	$(MAKE) -f gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/build.make gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.provides.build
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.provides

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.provides.build: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o


# Object files for target athena_UDP.shared
athena_UDP_shared_OBJECTS = \
"CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o" \
"CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o"

# External object files for target athena_UDP.shared
athena_UDP_shared_EXTERNAL_OBJECTS =

gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o
gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o
gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/build.make
gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C shared library libathena_UDP.so"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/athena_UDP.shared.dir/link.txt --verbose=$(VERBOSE)
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -E cmake_symlink_library libathena_UDP.so.1.0 libathena_UDP.so.1 libathena_UDP.so

gateway/ccnx/forwarder/athena/libathena_UDP.so.1: gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate gateway/ccnx/forwarder/athena/libathena_UDP.so.1

gateway/ccnx/forwarder/athena/libathena_UDP.so: gateway/ccnx/forwarder/athena/libathena_UDP.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate gateway/ccnx/forwarder/athena/libathena_UDP.so

# Rule to build all files generated by this target.
gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/build: gateway/ccnx/forwarder/athena/libathena_UDP.so

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/build

# Object files for target athena_UDP.shared
athena_UDP_shared_OBJECTS = \
"CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o" \
"CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o"

# External object files for target athena_UDP.shared
athena_UDP_shared_EXTERNAL_OBJECTS =

gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o
gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o
gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/build.make
gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/relink.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C shared library CMakeFiles/CMakeRelink.dir/libathena_UDP.so"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/athena_UDP.shared.dir/relink.txt --verbose=$(VERBOSE)
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -E cmake_symlink_library CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0 CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1 CMakeFiles/CMakeRelink.dir/libathena_UDP.so

gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1: gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1

gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so: gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so

# Rule to relink during preinstall.
gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/preinstall: gateway/ccnx/forwarder/athena/CMakeFiles/CMakeRelink.dir/libathena_UDP.so

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/preinstall

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/requires: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_Fragmenter.c.o.requires
gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/requires: gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/athena_TransportLinkModuleUDP.c.o.requires

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/requires

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/clean:
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -P CMakeFiles/athena_UDP.shared.dir/cmake_clean.cmake
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/clean

gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/depend:
	cd /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/workspace/krb-ccn/krb-ccn/ccn /home/ivan/workspace/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena /home/ivan/workspace/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_UDP.shared.dir/depend

