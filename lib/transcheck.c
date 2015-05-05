/*
 * transcheck.c -- check the state of the current transaction
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: transcheck.c,v 1.1 2002/02/19 23:40:07 afm Exp $
 */
#include <transcheck.h>
#include <config.h>
#include <init.h>
#include <openssl/bio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

/*
 * see whether a transaction is granted with this transaction id
 */
int	transcheck_granted(scep_t *scep) {
	char		filename[1024];
	struct stat	sb;
	
	/* check whether a certificate for the same key finerprint      */
	/* has already been granted				     */
	snprintf(filename, sizeof(filename), "%s/granted/%s.info", OPENSCEPDIR,
		scep->transId);
	if (stat(filename, &sb) == 0) {
		BIO_printf(bio_err, "%s:%d: request for this transID already "
			"granted\n", __FILE__, __LINE__);
		syslog(LOG_INFO, "%s:%d: request for this transid already "
			"granted", __FILE__, __LINE__);
		return 1;
	}
	return 0;
}

/*
 * see whether a transaction is pending with this transaction id
 */
int	transcheck_pending(scep_t *scep) {
	char		filename[1024];
	struct stat	sb;
	
        /* check for a request with the same transaction ID in the      */
        /* queue                                                        */
        snprintf(filename, sizeof(filename), "%s/pending/%s.info", OPENSCEPDIR,
                scep->transId);
        if (stat(filename, &sb) == 0) {
                BIO_printf(bio_err, "%s:%d: already a request with same id: "
                        "'%s'\n", __FILE__, __LINE__, scep->transId);
                syslog(LOG_INFO, "%s:%d: PKCSReq for pending certificate",
                        __FILE__, __LINE__);
                /* give a pending reply                                 */
                return 1;
        }
	return 0;
}

/*
 * see whether a transaction is rejected with this transaction id
 */
int	transcheck_rejected(scep_t *scep) {
	char		filename[1024];
	struct stat	sb;
	
        /* check for a request with the same transaction ID in the      */
        /* queue                                                        */
        snprintf(filename, sizeof(filename), "%s/rejected/%s.info", OPENSCEPDIR,
                scep->transId);
        if (stat(filename, &sb) == 0) {
                BIO_printf(bio_err, "%s:%d: already a request with same id: "
                        "'%s'\n", __FILE__, __LINE__, scep->transId);
                syslog(LOG_INFO, "%s:%d: PKCSReq for rejectd certificate",
                        __FILE__, __LINE__);
                /* give a pending reply                                 */
                return 1;
        }
	return 0;
}


