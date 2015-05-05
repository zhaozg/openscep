/*
 * http.c -- extremely simplified HTTP implementation for posting SCEP
 *           requests and receiving replies
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: http.c,v 1.8 2002/02/19 23:40:06 afm Exp $
 */
#include <config.h>
#include <http.h>
#include <scep.h>
#include <init.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <arpa/inet.h>

/*
 * parse the url given in the second argument and fill in the h member
 * of the scep structure
 */
int	parseurl(scep_t *scep, char *url) {
	char	*host, *path, *port;

	/* set default port						*/
	scep->h.httpport = 80;

	/* url must begin with http://					*/
	if (strncmp(url, "http://", 7)) {
		BIO_printf(bio_err, "%s:%d: URL '%s' does not begin with "
			"'http://'\n", __FILE__,  __LINE__, url);
		goto err;
	}
	host = strdup(url + 7);

	/* look for the first /, this is where the path starts		*/
	path = strchr(host, '/');
	if (path == NULL) {
		BIO_printf(bio_err, "%s:%d: no path component, assuming '/'\n",
			__FILE__, __LINE__);
		scep->h.httppath = "/";
	} else {
		scep->h.httppath = strdup(path);
		*path = '\0';
	}

	/* look for a colon in the hostname, this is where the port	*/
	/* starts			 				*/
	port = strchr(host, ':');
	if (port != NULL) {
		*port = '\0';
		port++;
		scep->h.httpport = atoi(port);
	}
	
	/* remainder is the host part					*/
	scep->h.httphost = host;
	return 0;

	if (debug)
		BIO_printf(bio_err, "%s:%d: URL: %s|%d|%s\n", __FILE__,
			__LINE__, scep->h.httphost, scep->h.httpport,
			scep->h.httppath);

	/* error return							*/
err:
	ERR_print_errors(bio_err);
	return -1;
}

/*
 * urlencode -- encode characters that should not appear in an URL
 */
char	*urlencode(const char *string) {
	char	*result, *p, *q;
	int	l;

	/* allocate a suitable block of memory				*/
	l = 3 * strlen(string) + 1;
	result = (char *)malloc(l);
	memset(result, 0, l);

	/* copy bytes one by one					*/
	for (p = string, q = result; *p; p++) {
		switch (*p) {
		case '\n':
			strcpy(q, "%0A"); q += 3;
			break;
		case '+':
			strcpy(q, "%2B"); q += 3;
			break;
		case '-':
			strcpy(q, "%2D"); q += 3;
			break;
		case '=':
			strcpy(q, "%3D"); q += 3;
			break;
		default:
			*(q++) = *p;
			break;
		}
	}
	return result;
}

/*
 * open a connection to the HTTP server and send the client message to
 * the server, wait for the reply
 */
BIO	*getrequest(scep_t *scep) {
	int			s, bytes, used, rc, l;
	struct sockaddr_in	sa;
	struct hostent		*hep;
	char			headers[20480];
	char			*buffer;
	char			*p;
	BIO			*bio;

	/* connect to the server					*/
	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		BIO_printf(bio_err, "%s:%d: cannot allocate socket for HTTP\n",
			__FILE__, __LINE__);
		goto err;
	}
	if (NULL == (hep = gethostbyname(scep->h.httphost))) {
		BIO_printf(bio_err, "%s:%d: cannot resolve name '%s': "
			"%s (%d)\n", __FILE__, __LINE__, scep->h.httphost,
			strerror(errno), errno);
		goto err;
	}
	memcpy(&sa.sin_addr, hep->h_addr, hep->h_length);
	sa.sin_port = htons(scep->h.httpport);
	sa.sin_family = AF_INET;
	if (debug)
		BIO_printf(bio_err, "%s:%d: connecting to %s:%hd -> %s\n",
			__FILE__, __LINE__, scep->h.httphost, ntohs(sa.sin_port),
			inet_ntoa(sa.sin_addr));

	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		BIO_printf(bio_err, "%s:%d: cannot connect to remote host: "
			"%s (%d)\n", __FILE__, __LINE__, strerror(errno),
			errno);
		goto err;
	}

	/* correctly encode the base 64 representation of the request	*/
	p = urlencode(scep->request.data);
	if (debug)
		BIO_printf(bio_err, "%s:%d: request data is '%24.24s...%24.24s'\n",
			__FILE__, __LINE__, p, p + strlen(p) - 24);
	if (debug > 1) {
		char	filename[64];
		FILE	*scepfile;
		snprintf(filename, sizeof(filename), "%s/%d-scep.b64", tmppath,
			getpid());
		if (NULL != (scepfile = fopen(filename, "w"))) {
			fputs(scep->request.data, scepfile);
			fclose(scepfile);
		}
	}

	/* formulate the HTTP request					*/
	snprintf(headers, sizeof(headers),
		"GET %s/pkiclient.exe?operation=PKIOperation&message=%s "
		"HTTP/1.0\r\n\r\n", scep->h.httppath, p);
	if (debug)
		BIO_printf(bio_err, "%s:%d: request is '%68.68s...%21.21s'\n",
			__FILE__, __LINE__,
			headers, headers + strlen(headers) - 21);
	write(s, headers, strlen(headers));

	/* read reply from the server until it closes the connection	*/
	buffer = (char *)malloc(1024);
	used = 0;
	while ((bytes = read(s, &buffer[used], 1024)) > 0) {
		used += bytes;
		buffer = (char *)realloc(buffer, used + 1024);
	}
	buffer[used] = '\0';

	/* get the first line from the reply				*/
	sscanf(buffer, "%s %d ", headers, &rc);
	if (debug)
		BIO_printf(bio_err, "%s:%d: HTTP return code: %d\n", __FILE__,
			__LINE__, rc);
	if (rc >= 300) {
		BIO_printf(bio_err, "%s:%d: HTTP return code %d >= 300\n",
			__FILE__, __LINE__, rc);
		goto err;
	}

	/* check the MIME type of the reply				*/
	if (strstr(buffer, "application/x-pki-message") == NULL) {
		BIO_printf(bio_err, "%s:%d: reply seems to have wrong content "
			"type\n", __FILE__, __LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: reply type correct\n", __FILE__,
			__LINE__);

	/* extract the data portion of the reply			*/
	if ((p = strstr(buffer, "\n\n"))) p += 2;
	if (p == NULL)
		if ((p = strstr(buffer, "\n\r\n\r"))) p += 4;
	if (p == NULL)
		if ((p = strstr(buffer, "\r\n\r\n"))) p += 4;
	if (p == NULL) {
		BIO_printf(bio_err, "%s:%d: reply content marker (two "
			"consecutive newlines) not found\n", __FILE__,
			__LINE__);
		goto err;
	}
	if (debug)
		BIO_printf(bio_err, "%s:%d: reply from server: %*.*s\n",
			__FILE__, __LINE__, p - buffer, p - buffer, buffer);

	if (debug)
		BIO_printf(bio_err, "%s:%d: header length: %d\n", __FILE__,
			__LINE__, p - buffer);
	l = used - (p - buffer);
	if (debug)
		BIO_printf(bio_err, "%s:%d: reply content has length %d\n",
			__FILE__, __LINE__, l);

	/* pack this data into a bio					*/
	bio = BIO_new_mem_buf(p, l);
	return bio;

	/* error reply							*/
err:
	ERR_print_errors(bio_err);
	return NULL;
}
