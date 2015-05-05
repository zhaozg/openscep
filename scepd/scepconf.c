/*
 * scepconf.c -- get configuration information from the openscep configuration
 *               file, mainly for use in scripts
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scepconf.c,v 1.1.1.1 2001/03/03 22:23:22 afm Exp $
 */
#include <stdlib.h>
#include <stdio.h>
#include <config.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/err.h>

char	*conffile = OPENSCEPDIR "/openscep.cnf";

extern char	*optarg;
extern int	optind;
int	debug = 0;

int	main(int argc, char *argv[]) {
	LHASH	*conf;
	long	eline;
	char	*section = NULL, *variable = NULL, *value;
	int	c, n;

	/* parse command line						*/
	while (EOF != (c = getopt(argc, argv, "df:")))
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'f':
			conffile = optarg;
			break;
		}

	if (debug)
		fprintf(stderr, "%s:%d: configuration file is '%s'\n",
			__FILE__, __LINE__, conffile);

	/* there should be one or two more arguments			*/
	n = argc - optind;
	if ((n < 1) || (n > 2)) {
		fprintf(stderr, "%s:%d: wrong number of arguments\n",
			__FILE__, __LINE__);
		exit(EXIT_FAILURE);
	}
	switch (n) {
	case 2:
		section = argv[optind++];
	case 1:
		variable = argv[optind];
		break;
	}

	/* load the configuration file					*/
	conf = CONF_load(NULL, conffile, &eline);
	if (conf == NULL) {
		ERR_load_crypto_strings();
		fprintf(stderr, "unable to load configuration, line %ld\n",
			eline);
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	/* get the configuration value from the file			*/
	if (debug)
		fprintf(stderr, "%s:%d: looking for '%s' in section '%s'\n",
			__FILE__, __LINE__, variable,
			(section) ? section : "(null)");
	value = CONF_get_string(conf, section, variable);
	if (value == NULL) {
		if (debug)
			fprintf(stderr, "%s:%d: no value found\n", __FILE__,
				__LINE__);
		exit(EXIT_FAILURE);
	}
	if (debug)
		fprintf(stderr, "%s:%d [%s]%s = %s\n", __FILE__, __LINE__,
			(section) ? section : "-", variable, value);
	printf("%s\n", value);
	exit(EXIT_SUCCESS);
}
