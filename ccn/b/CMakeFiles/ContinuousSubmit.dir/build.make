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

# Utility rule file for ContinuousSubmit.

# Include the progress variables for this target.
include CMakeFiles/ContinuousSubmit.dir/progress.make

CMakeFiles/ContinuousSubmit:
	/usr/local/bin/ctest -D ContinuousSubmit

ContinuousSubmit: CMakeFiles/ContinuousSubmit
ContinuousSubmit: CMakeFiles/ContinuousSubmit.dir/build.make

.PHONY : ContinuousSubmit

# Rule to build all files generated by this target.
CMakeFiles/ContinuousSubmit.dir/build: ContinuousSubmit

.PHONY : CMakeFiles/ContinuousSubmit.dir/build

CMakeFiles/ContinuousSubmit.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ContinuousSubmit.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ContinuousSubmit.dir/clean

CMakeFiles/ContinuousSubmit.dir/depend:
	cd /home/ivan/Desktop/projects/ccvpn/ccvpn/b && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ivan/Desktop/projects/ccvpn/ccvpn /home/ivan/Desktop/projects/ccvpn/ccvpn /home/ivan/Desktop/projects/ccvpn/ccvpn/b /home/ivan/Desktop/projects/ccvpn/ccvpn/b /home/ivan/Desktop/projects/ccvpn/ccvpn/b/CMakeFiles/ContinuousSubmit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ContinuousSubmit.dir/depend

