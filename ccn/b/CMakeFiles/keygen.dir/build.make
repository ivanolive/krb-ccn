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
include CMakeFiles/keygen.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/keygen.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/keygen.dir/flags.make

CMakeFiles/keygen.dir/athena_keygen.c.o: CMakeFiles/keygen.dir/flags.make
CMakeFiles/keygen.dir/athena_keygen.c.o: ../athena_keygen.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ivan/Desktop/projects/ccvpn/ccvpn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/keygen.dir/athena_keygen.c.o"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/keygen.dir/athena_keygen.c.o   -c /home/ivan/Desktop/projects/ccvpn/ccvpn/athena_keygen.c

CMakeFiles/keygen.dir/athena_keygen.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/keygen.dir/athena_keygen.c.i"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ivan/Desktop/projects/ccvpn/ccvpn/athena_keygen.c > CMakeFiles/keygen.dir/athena_keygen.c.i

CMakeFiles/keygen.dir/athena_keygen.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/keygen.dir/athena_keygen.c.s"
	/usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ivan/Desktop/projects/ccvpn/ccvpn/athena_keygen.c -o CMakeFiles/keygen.dir/athena_keygen.c.s

CMakeFiles/keygen.dir/athena_keygen.c.o.requires:

.PHONY : CMakeFiles/keygen.dir/athena_keygen.c.o.requires

CMakeFiles/keygen.dir/athena_keygen.c.o.provides: CMakeFiles/keygen.dir/athena_keygen.c.o.requires
	$(MAKE) -f CMakeFiles/keygen.dir/build.make CMakeFiles/keygen.dir/athena_keygen.c.o.provides.build
.PHONY : CMakeFiles/keygen.dir/athena_keygen.c.o.provides

CMakeFiles/keygen.dir/athena_keygen.c.o.provides.build: CMakeFiles/keygen.dir/athena_keygen.c.o


# Object files for target keygen
keygen_OBJECTS = \
"CMakeFiles/keygen.dir/athena_keygen.c.o"

# External object files for target keygen
keygen_EXTERNAL_OBJECTS =

keygen: CMakeFiles/keygen.dir/athena_keygen.c.o
keygen: CMakeFiles/keygen.dir/build.make
keygen: CMakeFiles/keygen.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ivan/Desktop/projects/ccvpn/ccvpn/b/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable keygen"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/keygen.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/keygen.dir/build: keygen

.PHONY : CMakeFiles/keygen.dir/build

CMakeFiles/keygen.dir/requires: CMakeFiles/keygen.dir/athena_keygen.c.o.requires

.PHONY : CMakeFiles/keygen.dir/requires

CMakeFiles/keygen.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/keygen.dir/cmake_clean.cmake
.PHONY : CMakeFiles/keygen.dir/clean

CMakeFiles/keygen.dir/depend:
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/Desktop/projects/ccvpn/ccvpn /home/ivan/Desktop/projects/ccvpn/ccvpn /home/ivan/Desktop/projects/ccvpn/ccvpn/b /home/ivan/Desktop/projects/ccvpn/ccvpn/b /home/ivan/Desktop/projects/ccvpn/ccvpn/b/CMakeFiles/keygen.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/keygen.dir/depend

