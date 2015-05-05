/*
 * openscep_vers.h -- version info declarations, version info itself is
 *                    maintained by shtool in lib/openscep_vers.c
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: openscep_vers.h,v 1.1 2001/03/04 22:31:09 afm Exp $
 */
#ifndef _OPENSCEP_VERS_H
#define _OPENSCEP_VERS_H

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
#endif /* _OPENSCEP_VERS_H */
