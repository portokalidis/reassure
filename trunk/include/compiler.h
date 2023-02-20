#ifndef COMPILER_H
#define COMPILER_H

#ifdef TARGET_LINUX
# define LINUX_PACKED __attribute__ ((__packed__))
#else
# define LINUX_PACKED
#endif

#endif