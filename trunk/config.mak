#
# Configure these
#

# If you haven't defined PIN_HOME, you can set it in the following line
#PIN_HOME="/opt/pin"

# C++ compiler to use
CXX=g++
# C compiler to use
CC=gcc

# Use Pin's safecopy for rolling back memory
SAFECOPY_RESTORE=1
# Build for debugging
DEBUG_BUILD=0
# Thread blocking rescue point support
BLOCKINGRP=0
# Pin target OS
PIN_TARGET=TARGET_LINUX
# libcrossdev directory
LIBCROSSDEV_DIR=$(HOME)/Projects/libcrossdev/trunk
