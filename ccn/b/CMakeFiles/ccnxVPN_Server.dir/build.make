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
include CMakeFiles/ccnxVPN_Server.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ccnxVPN_Server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ccnxVPN_Server.dir/flags.make

CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o: CMakeFiles/ccnxVPN_Server.dir/flags.make
CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o: ../producer/ccnxVPN_Producer.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ivan/Desktop/krb-ccn/ccn/b/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o   -c /home/ivan/Desktop/krb-ccn/ccn/producer/ccnxVPN_Producer.c

CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/ivan/Desktop/krb-ccn/ccn/producer/ccnxVPN_Producer.c > CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.i

CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/ivan/Desktop/krb-ccn/ccn/producer/ccnxVPN_Producer.c -o CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.s

CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.requires:
.PHONY : CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.requires

CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.provides: CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.requires
	$(MAKE) -f CMakeFiles/ccnxVPN_Server.dir/build.make CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.provides.build
.PHONY : CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.provides

CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.provides.build: CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o

CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o: CMakeFiles/ccnxVPN_Server.dir/flags.make
CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o: ../ccnxVPN_Common.c
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ivan/Desktop/krb-ccn/ccn/b/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o   -c /home/ivan/Desktop/krb-ccn/ccn/ccnxVPN_Common.c

CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -E /home/ivan/Desktop/krb-ccn/ccn/ccnxVPN_Common.c > CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.i

CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_FLAGS) -S /home/ivan/Desktop/krb-ccn/ccn/ccnxVPN_Common.c -o CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.s

CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.requires:
.PHONY : CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.requires

CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.provides: CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.requires
	$(MAKE) -f CMakeFiles/ccnxVPN_Server.dir/build.make CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.provides.build
.PHONY : CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.provides

CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.provides.build: CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o

# Object files for target ccnxVPN_Server
ccnxVPN_Server_OBJECTS = \
"CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o" \
"CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o"

# External object files for target ccnxVPN_Server
ccnxVPN_Server_EXTERNAL_OBJECTS =

ccnxVPN_Server: CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o
ccnxVPN_Server: CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o
ccnxVPN_Server: CMakeFiles/ccnxVPN_Server.dir/build.make
ccnxVPN_Server: CMakeFiles/ccnxVPN_Server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable ccnxVPN_Server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ccnxVPN_Server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ccnxVPN_Server.dir/build: ccnxVPN_Server
.PHONY : CMakeFiles/ccnxVPN_Server.dir/build

CMakeFiles/ccnxVPN_Server.dir/requires: CMakeFiles/ccnxVPN_Server.dir/producer/ccnxVPN_Producer.c.o.requires
CMakeFiles/ccnxVPN_Server.dir/requires: CMakeFiles/ccnxVPN_Server.dir/ccnxVPN_Common.c.o.requires
.PHONY : CMakeFiles/ccnxVPN_Server.dir/requires

CMakeFiles/ccnxVPN_Server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ccnxVPN_Server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ccnxVPN_Server.dir/clean

CMakeFiles/ccnxVPN_Server.dir/depend:
	cd /home/ivan/Desktop/krb-ccn/ccn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/Desktop/krb-ccn/ccn /home/ivan/Desktop/krb-ccn/ccn /home/ivan/Desktop/krb-ccn/ccn/b /home/ivan/Desktop/krb-ccn/ccn/b /home/ivan/Desktop/krb-ccn/ccn/b/CMakeFiles/ccnxVPN_Server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ccnxVPN_Server.dir/depend

