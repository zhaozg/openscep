#ifndef HAVE_CONFIG_H_
#define HAVE_CONFIG_H_
/* default log facility to use						*/
#undef	LOG_FACILITY
#ifndef LOG_FACILITY
#define LOG_FACILITY LOG_USER
#endif /* LOG_FACILITY */

/* do we have the altzone variable (need in solaris)			*/
#undef	HAVE_ALTZONE

#define inline  __inline
#define HAVE_STRCHR 1
#define HAVE_STRRCHR 1
#define S_ISDIR(s) ((s) & _S_IFDIR)
#define strncasecmp strnicmp
#define strcasecmp stricmp

#define W_OK 0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#endif//HAVE_CONFIG_H_
