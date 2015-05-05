/*
 * grant.c -- grant a certificate during automatic enrollment
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: grant.c,v 1.3 2001/03/26 10:36:41 afm Exp $
 */
#include <config.h>
#include <grant.h>
#include <init.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

/*
 * this function implements the CAs sign operation, with all the extensions
 * required for SCEP. In particular, it allows to issue certificates with
 * a distinguished name different from the one in the request. We can
 * make sure here that the distinguished name can be put into our directory.
 */
int	cert_grant(scep_t *scep) {
	char	*cmd;
	int	st;
	pid_t	pid;

	/* XXX there is some missing stuff here XXX			*/
	/* get the subject name from the request			*/

	/* get the public key from the request				*/

	/* verify that the public key from the request matches the req	*/

	/* make sure the certificate does not exist yet			*/

	/* check the command 						*/
	cmd = CONF_get_string(scep->conf, "scepd", "grantcmd");
	if (cmd == NULL) {
		BIO_printf(bio_err, "%s:%d: no grant command name defined\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* run the external program that does the granting		*/
	pid = fork();
	if (pid < 0) {
		BIO_printf(bio_err, "%s:%d: cannot fork: %s (%d)\n",
			__FILE__, __LINE__, strerror(errno), errno);
		goto err;
	}
	if (pid > 0) {
		/* parent, wait for the new child			*/
		if (pid != waitpid(pid, &st, 0)) {
			BIO_printf(bio_err, "%s:%d: wait failed: %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
			goto err;
		}

		/* make sure the command exited normally		*/
		if (!WIFEXITED(st)) {
			BIO_printf(bio_err, "%s:%d: grant command failed\n",
				__FILE__, __LINE__);
			goto err;
		}
	
		/* check the exit status of the grant command		*/
		if (WEXITSTATUS(st)) {
			BIO_printf(bio_err, "%s:%d: certificate grant cmd "
				"'%s' failed\n", __FILE__, __LINE__, cmd);
			goto err;
		}
		syslog(LOG_DEBUG, "%s:%d: certificate granted automatically",
			__FILE__, __LINE__);
	} else {
		/* make sure child will not write anything to stdout	*/
		dup2(2, 1);

		/* the child, try to execute the grant command		*/
		execl(CONF_get_string(scep->conf, "scepd", "grantcmd"),
			"scepgrant", scep->transId, NULL);
		BIO_printf(bio_err, "%s:%d: cannot exec the grant command: "
			"%s (%d)\n", __FILE__, __LINE__, strerror(errno),
			errno);
		exit(EXIT_FAILURE);
	}
	return 0;

err:
	syslog(LOG_ERR, "%s:%d: granting certificate failed", __FILE__,
		__LINE__);
	return -1;
}
