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
CMAKE_SOURCE_DIR = /home/ivan/Desktop/projects/ccvpn/ccvpn

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ivan/Desktop/projects/ccvpn/ccvpn/b

# Include any dependencies generated for this target.
include gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/depend.make

# Include the progress variables for this target.
include gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/progress.make

# Include the compile flags for this target's objects.
include gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/flags.make

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/flags.make
gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o: ../gateway/ccnx/forwarder/athena/athena_TransportLinkModuleTEMPLATE.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ivan/Desktop/projects/ccvpn/ccvpn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o"
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o   -c /home/ivan/Desktop/projects/ccvpn/ccvpn/gateway/ccnx/forwarder/athena/athena_TransportLinkModuleTEMPLATE.c

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.i"
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ivan/Desktop/projects/ccvpn/ccvpn/gateway/ccnx/forwarder/athena/athena_TransportLinkModuleTEMPLATE.c > CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.i

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.s"
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ivan/Desktop/projects/ccvpn/ccvpn/gateway/ccnx/forwarder/athena/athena_TransportLinkModuleTEMPLATE.c -o CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.s

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.requires:

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.requires

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.provides: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.requires
	$(MAKE) -f gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/build.make gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.provides.build
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.provides

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.provides.build: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o


# Object files for target athena_TEMPLATE.shared
athena_TEMPLATE_shared_OBJECTS = \
"CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o"

# External object files for target athena_TEMPLATE.shared
athena_TEMPLATE_shared_EXTERNAL_OBJECTS =

gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o
gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/build.make
gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1.0: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ivan/Desktop/projects/ccvpn/ccvpn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library libathena_TEMPLATE.so"
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/athena_TEMPLATE.shared.dir/link.txt --verbose=$(VERBOSE)
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -E cmake_symlink_library libathena_TEMPLATE.so.1.0 libathena_TEMPLATE.so.1 libathena_TEMPLATE.so

gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1: gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1

gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so: gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so.1.0
	@$(CMAKE_COMMAND) -E touch_nocreate gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so

# Rule to build all files generated by this target.
gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/build: gateway/ccnx/forwarder/athena/libathena_TEMPLATE.so

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/build

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/requires: gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/athena_TransportLinkModuleTEMPLATE.c.o.requires

.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/requires

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/clean:
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena && $(CMAKE_COMMAND) -P CMakeFiles/athena_TEMPLATE.shared.dir/cmake_clean.cmake
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/clean

gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/depend:
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/Desktop/projects/ccvpn/ccvpn /home/ivan/Desktop/projects/ccvpn/ccvpn/gateway/ccnx/forwarder/athena /home/ivan/Desktop/projects/ccvpn/ccvpn/b /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena /home/ivan/Desktop/projects/ccvpn/ccvpn/b/gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : gateway/ccnx/forwarder/athena/CMakeFiles/athena_TEMPLATE.shared.dir/depend
