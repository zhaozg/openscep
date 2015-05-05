/*
**  openscep_vers.c -- Version Information for OpenSCEP (syntax: C/C++)
**  [automatically generated and maintained by GNU shtool]
*/

#ifdef _OPENSCEP_VERS_C_AS_HEADER_

#ifndef _OPENSCEP_VERS_C_
#define _OPENSCEP_VERS_C_

#define OPENSCEP_VERSION 0x004202

typedef struct {
    const int   v_hex;
    const char *v_short;
    const char *v_long;
    const char *v_tex;
    const char *v_gnu;
    const char *v_web;
    const char *v_sccs;
    const char *v_rcs;
} openscep_version_t;

extern openscep_version_t openscep_version;

#endif /* _OPENSCEP_VERS_C_ */

#else /* _OPENSCEP_VERS_C_AS_HEADER_ */

#define _OPENSCEP_VERS_C_AS_HEADER_
#include "openscep_vers.c"
#undef  _OPENSCEP_VERS_C_AS_HEADER_

openscep_version_t openscep_version = {
    0x004202,
    "0.4.2",
    "0.4.2 (26-Feb-2002)",
    "This is OpenSCEP, Version 0.4.2 (26-Feb-2002)",
    "OpenSCEP 0.4.2 (26-Feb-2002)",
    "OpenSCEP/0.4.2",
    "@(#)OpenSCEP 0.4.2 (26-Feb-2002)",
    "$Id: openscep_vers.c,v 1.20 2002/02/25 23:08:39 afm Exp $"
};

#endif /* _OPENSCEP_VERS_C_AS_HEADER_ */

