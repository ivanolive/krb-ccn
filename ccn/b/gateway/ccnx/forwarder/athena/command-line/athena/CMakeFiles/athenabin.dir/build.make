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
CMAKE_SOURCE_DIR = /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b

# Include any dependencies generated for this target.
include gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/depend.make

# Include the progress variables for this target.
include gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/progress.make

# Include the compile flags for this target's objects.
include gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/flags.make

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/flags.make
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o: ../gateway/ccnx/forwarder/athena/command-line/athena/athena_main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/athenabin.dir/athena_main.c.o   -c /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/command-line/athena/athena_main.c

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/athenabin.dir/athena_main.c.i"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/command-line/athena/athena_main.c > CMakeFiles/athenabin.dir/athena_main.c.i

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/athenabin.dir/athena_main.c.s"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/command-line/athena/athena_main.c -o CMakeFiles/athenabin.dir/athena_main.c.s

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.requires:

.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.requires

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.provides: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.requires
	$(MAKE) -f gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/build.make gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.provides.build
.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.provides

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.provides.build: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o


# Object files for target athenabin
athenabin_OBJECTS = \
"CMakeFiles/athenabin.dir/athena_main.c.o"

# External object files for target athenabin
athenabin_EXTERNAL_OBJECTS =

gateway/ccnx/forwarder/athena/command-line/athena/athena: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o
gateway/ccnx/forwarder/athena/command-line/athena/athena: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/build.make
gateway/ccnx/forwarder/athena/command-line/athena/athena: gateway/ccnx/forwarder/athena/libathena.a
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/liblongbow.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/liblongbow-textplain.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /usr/lib/x86_64-linux-gnu/libevent.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /usr/lib/x86_64-linux-gnu/libssl.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /usr/lib/x86_64-linux-gnu/libcrypto.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_api_portal.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_transport_rta.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_api_control.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_api_notify.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_common.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libparc.so
gateway/ccnx/forwarder/athena/command-line/athena/athena: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable athena"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/athenabin.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/build: gateway/ccnx/forwarder/athena/command-line/athena/athena

.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/build

# Object files for target athenabin
athenabin_OBJECTS = \
"CMakeFiles/athenabin.dir/athena_main.c.o"

# External object files for target athenabin
athenabin_EXTERNAL_OBJECTS =

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/build.make
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: gateway/ccnx/forwarder/athena/libathena.a
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/liblongbow.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/liblongbow-textplain.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /usr/lib/x86_64-linux-gnu/libevent.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /usr/lib/x86_64-linux-gnu/libssl.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /usr/lib/x86_64-linux-gnu/libcrypto.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_api_portal.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_transport_rta.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_api_control.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_api_notify.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libccnx_common.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: /home/ivan/Desktop/projects/CCNx_Distillery/usr/lib/libparc.so
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/relink.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable CMakeFiles/CMakeRelink.dir/athena"
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/athenabin.dir/relink.txt --verbose=$(VERBOSE)

# Rule to relink during preinstall.
gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/preinstall: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/CMakeRelink.dir/athena

.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/preinstall

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/requires: gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/athena_main.c.o.requires

.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/requires

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/clean:
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena && $(CMAKE_COMMAND) -P CMakeFiles/athenabin.dir/cmake_clean.cmake
.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/clean

gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/depend:
	cd /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/gateway/ccnx/forwarder/athena/command-line/athena /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena /home/ivan/workspace/krb-ccn/krb-ccn/krb-ccn/ccn/b/gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : gateway/ccnx/forwarder/athena/command-line/athena/CMakeFiles/athenabin.dir/depend

