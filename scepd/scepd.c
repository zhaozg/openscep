/*
 * scepd.c -- main process for SCEP implementation
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scepd.c,v 1.11 2002/02/19 23:40:08 afm Exp $
 */
#include <config.h>
#include <scep.h>
#include <init.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ldap.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/times.h>
#include <scepldap.h>
#include <decode.h>
#include <encode.h>
#include <getcert.h>
#include <getcrl.h>
#include <getcertinitial.h>
#include <pkcsreq.h>
#include <certrep.h>
#include <proxy.h>
#include <v2request.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*

This processes does the following:

1. decode a PKCS#7 signed data message from the standard input
2. extract the signed attributes from the the message, which indicate
   the type of request
3. decrypt the enveloped data PKCS#7 inside
4. branch to different actions depending on the type of the message:
	- PKCSReq
	- GetCertInitial
	- GetCert
	- GetCRL
	- v2 PKCSReq or Proxy request
5. envelop (PKCS#7) the reply data from the previous step
6. sign the reply data (PKCS#7) from the previous step
7. output the result as a der encoded block on stdout

*/

static void	logtimes(struct tms *start) {
	struct tms	end;
	long		ticks;

	/* find the number of clock ticks per second			*/
	if ((ticks = sysconf(_SC_CLK_TCK)) < 0) {
		if (debug)
			fprintf(stderr, "%s:%d: cannot determine clock ticks\n",
				__FILE__, __LINE__);
		ticks = 100;
	}

	/* find the end time						*/
	times(&end);

	/* compute elapsed times					*/
	syslog(LOG_INFO, "times scepd: %.2f user %.2f system, "
		"children: %.2f user %.2f system", 
		(end.tms_utime - start->tms_utime)/(double)ticks,
		(end.tms_stime - start->tms_stime)/(double)ticks,
		(end.tms_cutime - start->tms_cutime)/(double)ticks,
		(end.tms_cstime - start->tms_cstime)/(double)ticks);
}

int	main(int argc, char *argv[]) {
	scep_t		scep;
	int		c, rc, bytes, fd;
	char		filename[1024];
	BIO		*inbio = NULL, *outbio, *membio;
	char		*conffile;
	struct tms	start;

	/* start timekeeping						*/
	times(&start);

	/* clean out the scep structure (some fields will be set by	*/
	/* command line parsing routine)				*/
	scep_clear(&scep);
	if (debug)
		fprintf(stderr, "%s:%d: cleared scep structure\n",
			__FILE__, __LINE__);

	/* initialize the OpenSSL library				*/
	scepinit();
	if (debug)
		fprintf(stderr, "%s:%d: initialized libraries\n",
			__FILE__, __LINE__);

	/* set umask to something not dangerous				*/
	umask(022);

	/* read the command line arguments, if any			*/
	while (EOF != (c = getopt(argc, argv, "df:")))
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'f':
			conffile = optarg;
			if (debug)
				fprintf(stderr, "%s:%d: config file is %s\n",
					__FILE__, __LINE__, conffile);
			break;
		}

	/* read the configuration file					*/
	scep_config(&scep, (conffile) ? conffile : OPENSCEPDIR "/openscep.cnf");

	/* initialize the LDAP backend					*/
	scep_ldap_init(&scep);

	/* read the stuff from standard input and write it to a request	*/
	/* file so that debugging becomes simpler			*/
	inbio = BIO_new(BIO_s_file());
	BIO_set_fp(inbio, stdin, BIO_NOCLOSE);
	membio = BIO_new(BIO_s_mem());
	do {
		unsigned char	buffer[1024];
		bytes = BIO_read(inbio, buffer, sizeof(buffer));
		if (bytes > 0) {
			BIO_write(membio, buffer, bytes);
			if (debug)
				BIO_printf(bio_err, "%s:%d: writing chunk of"
					"size %d\n", __FILE__, __LINE__, bytes);
		} else 
			BIO_printf(bio_err, "%s:%d: no more data from inbio\n",
				__FILE__, __LINE__);
		
	} while (bytes > 0);
	BIO_flush(membio);

	/* the decode call does the following three things		*/
	/* - verify the signed data PKCS#7				*/
	/* - extract the signed attributes				*/
	/* - decrypt the enveloped data					*/
	scep.request.base64 = 1;
	if (decode(&scep, membio) < 0) {
		BIO_printf(bio_err, "%s:%d: decode failed\n", __FILE__,
			__LINE__);
		syslog(LOG_ERR, "%s:%d: scepd failed to decode request",
			__FILE__, __LINE__);
		goto err;
	}
	BIO_free(membio);

	/* inform the debug log about the message we have received	*/
	if (debug) {
		char	name[1024];
		BIO_printf(bio_err, "%s:%d: message with transaction id %s\n",
			__FILE__, __LINE__, scep.transId);
		X509_NAME_oneline(X509_get_subject_name((scep.selfsignedcert)
			? scep.selfsignedcert : scep.clientcert), name, 1024);
		BIO_printf(bio_err, "%s:%d: sender is %s\n", __FILE__, __LINE__,
			name);
	}

	/* swap nonces and create a reply nonce				*/
	if (scep.recipientNonce) {
		free(scep.recipientNonce);
	}
	scep.recipientNonce = scep.senderNonce;
	scep.recipientNonceLength = scep.senderNonceLength;
	scep.senderNonceLength = 16;
	scep.senderNonce = (unsigned char *)malloc(scep.senderNonceLength);
	RAND_bytes(scep.senderNonce, scep.senderNonceLength);

	/* branch according to message type				*/
	if (scep.request.messageType == NULL) {
		syslog(LOG_ERR, "%s:%d: message of undefined type received",
			__FILE__, __LINE__);
		BIO_printf(bio_err, "%s:%d: undefined message type\n",
			__FILE__, __LINE__);
		goto err;
	}
	scep.reply.messageType = SCEP_MESSAGE_TYPE_CERTREP;
	switch (atoi(scep.request.messageType)) {
	case MSG_CERTREP:	/* CertRep */
		syslog(LOG_WARNING, "%s:%d: CertRep message, should not happen",
			__FILE__, __LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: CertRep message received\n",
				__FILE__, __LINE__);
		rc = certrep(&scep);
		break;
	case MSG_V2PROXY:
		/* proxy requests are checked during decoding		*/
		/* at this point, we have an acceptable proxy request	*/
		/* so we can fall through to a v2 request		*/
	case MSG_V2REQUEST:	/* v2 request received			*/
		/* XXX fixme: implement version 2 */
		rc = v2request(&scep);
		break;
	case MSG_PKCSREQ:	/* PKCSReq 				*/
		syslog(LOG_INFO, "%s:%d: PKCSReq message received", __FILE__,
			__LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: PKCSReq message received\n",
				__FILE__, __LINE__);
		rc = pkcsreq(&scep);
		break;
	case MSG_GETCERTINITIAL:	/* GetCertInitial 		*/
		syslog(LOG_INFO, "%s:%d: GetCertInitial message received",
			__FILE__, __LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: GetCertInitial message "
				"received\n", __FILE__, __LINE__);
		rc = getcertinitial(&scep);
		break;
	case MSG_GETCERT:	/* GetCert 				*/
		syslog(LOG_INFO, "%s:%d: GetCert message received",
			__FILE__, __LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: GetCert message received\n",
				__FILE__, __LINE__);
		rc = getcert(&scep);
		break;
	case MSG_GETCRL:	/* GetCRL 				*/
		syslog(LOG_INFO, "%s:%d: GetCRL message received", __FILE__,
			__LINE__);
		if (debug)
			BIO_printf(bio_err, "%s:%d: GetCRL message received\n",
				__FILE__, __LINE__);
		rc = getcrl(&scep);
		break;
	default:
		syslog(LOG_WARNING, "%s:%d: message of unknown type: %s",
			__FILE__, __LINE__, scep.request.messageType);
		BIO_printf(bio_err, "%s:%d: unknown message type: %s\n",
			__FILE__, __LINE__, scep.request.messageType);
		scep.reply.failinfo = SCEP_FAILURE_BADREQUEST;
	}

prepreply:
	if (debug)
		BIO_printf(bio_err, "%s:%d: reply prepared, encoding follows\n",
			__FILE__, __LINE__);

	if (rc < 0) {
		/* create a failure reply by setting the failinfo field	*/
		BIO_printf(bio_err, "%s:%d: bad return code from handler\n",
			__FILE__, __LINE__);
		scep.reply.failinfo = SCEP_FAILURE_BADREQUEST;
	}

	/* encode the reply						*/
	if (encode(&scep) < 0) {
		BIO_printf(bio_err, "%s:%d: encoding failed\n", __FILE__,
			__LINE__);
		syslog(LOG_ERR, "%s:%d: scepd failed to encode the reply",
			__FILE__, __LINE__);
		goto err;
	}

	/* print a HTTP header						*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: preparing reply headers\n",
			__FILE__, __LINE__);
	printf("Content-Transfer-Encoding: 8bit\r\n");
	printf("Content-Type: application/x-pki-message\r\n");
	printf("Content-Length: %d\r\n\r\n", scep.reply.length);
	fflush(stdout);
	if (debug)
		BIO_printf(bio_err, "%s:%d: headers sent\n", __FILE__,
			__LINE__);

	/* return the result PKCS#7 as DER on stdout			*/
	if (scep.reply.length != (bytes = write(fileno(stdout), scep.reply.data,
		scep.reply.length))) {
		BIO_printf(bio_err, "%s:%d: message write incomplete "
			"%d != %d\n", __FILE__, __LINE__, scep.reply.data,
			bytes);
	}
	printf("\r\n"); 	/* make sure message is properly closed	*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: %d bytes of content sent\n",
			__FILE__, __LINE__, bytes);

	/* write the same data also to a file for debugging		*/
	if (debug) {
		snprintf(filename, sizeof(filename), "%s/%d.pkireply.der",
			tmppath, getpid());
		fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		write(fd, scep.reply.data, scep.reply.length);
		close(fd);
		BIO_printf(bio_err, "%s:%d: reply written to file %s\n",
			__FILE__, __LINE__, filename);
	}
	BIO_free(outbio);

	/* successful completion					*/
	ERR_print_errors(bio_err); /* just in case something is still there */
	syslog(LOG_DEBUG, "%s:%d: scepd successfully completed",
		__FILE__, __LINE__);
	logtimes(&start);
	exit(EXIT_SUCCESS);

	/* but we may as well fail					*/
err:
	ERR_print_errors(bio_err);
	syslog(LOG_DEBUG, "%s:%d: scepd failed", __FILE__, __LINE__);
	logtimes(&start);
	exit(EXIT_FAILURE);
}
