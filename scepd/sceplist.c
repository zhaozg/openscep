/*
 * sceplist.c -- create various lists about SCEP certifictes
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: sceplist.c,v 1.1 2002/02/17 11:53:41 afm Exp $
 */
#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <scep.h>
#include <init.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

#define SORT_TRANSID	1
#define	SORT_NAME	2
#define	SORT_NOTBEFORE	3
#define	SORT_NOTAFTER	4
#define	SORT_SERIAL	5

#define	SELECT_PENDING	0
#define	SELECT_GRANTED	1
#define	SELECT_REJECTED	2
#define	SELECT_REVOKED	3

int	sortorder = SORT_NAME;
int	itemselect = SELECT_PENDING;
int	html = 0;
int	reverse = 1;
int	ctimeformat = 0;

extern int	optind;
extern char	*optarg;

#define	ITEM_TYPE_CERT	1
#define	ITEM_TYPE_REQ	2

char	*selectname[4] = {
	"pending", "granted", "rejected", "revoked"
};

typedef struct scepitem {
	int 	type;
	void	*key;	/* type depends on the sort order		*/
	char	*transid;
	union {
		X509		*x509;
		X509_REQ	*req;
		void		*any;
	} data;
} scepitem_t;

/*
 * declarations of functions defined in this file, to keep the compiler
 * quiet
 */
static char		*asn1_time_to_string(ASN1_TIME *tm);
static scepitem_t	*readitem(char *transid);
static void		display_item(scepitem_t *ip);
static void		display_cert(scepitem_t *ip);
static void		display_req(scepitem_t *ip);

static int		cmp_string(scepitem_t **, scepitem_t **);
static int		cmp_asn1_integer(scepitem_t **, scepitem_t **);

static int	cmp_string(scepitem_t **a, scepitem_t **b) {
	return reverse * strcmp((char *)(*a)->key, (char *)(*b)->key);
}

static int	cmp_asn1_integer(scepitem_t **a, scepitem_t **b) {
	return reverse * ASN1_INTEGER_cmp((ASN1_INTEGER *)(*a)->key,
		(ASN1_INTEGER *)(*b)->key);
}

int	(*compare)(scepitem_t **, scepitem_t **) = cmp_string;

/*
 * convert at ASN1_TIME structure to a string, but still in ASN1 format
 */
static char	*asn1_time_to_string(ASN1_TIME *tm) {
	char	*result;
	/* the data portion of a generalized time is a string so we	*/
	/* only have to make sure it is y2k safe			*/
	result = (char *)malloc(tm->length + 1);
	result[tm->length] = '\0';
	memcpy(result, tm->data, tm->length);
	return result;
}

/*
 * convert ASN1 time string to a struct tm
 */
extern time_t	timezone; /* compiler does not like it inside func */
#ifdef HAVE_ALTZONE
extern time_t	altzone;
#endif /* HAVE_ALTZONE */
static time_t	asn1_time_to_time(ASN1_TIME *tm) {
	struct tm	rtm;
	char		work[3];
	time_t		rt;

	/* prepare work and result buffers for the conversions		*/
	memset(work, '\0', sizeof(work));
	memset(&rtm, 0, sizeof(struct tm));

	/* convert ASN1 time string to struct tm structure elements	*/
	memcpy(work, tm->data + 10, 2);
	rtm.tm_sec = atoi(work);
	memcpy(work, tm->data + 8, 2);
	rtm.tm_min = atoi(work);
	memcpy(work, tm->data + 6, 2);
	rtm.tm_hour = atoi(work);
	memcpy(work, tm->data + 4, 2);
	rtm.tm_mday = atoi(work);
	memcpy(work, tm->data + 2, 2);
	rtm.tm_mon = atoi(work);
	memcpy(work, tm->data, 2);
	rtm.tm_year = atoi(work);
	if (rtm.tm_year < 70)
		rtm.tm_year += 100;

	/* set the time zone to GMT, as mktime uses the local time zone	*/
	timezone = 0;
#ifdef HAVE_ALTZONE
	altzone = 0;
#endif /* HAVE_ALTZONE */

	/* use mktime to normalize the structure and t convert to a	*/
	/* time_t value							*/
	rt = mktime(&rtm);

	/* reset the time zone to local settings			*/
	tzset();

	return rt;
}

/*
 * convert an ASN1 time structure to a ctime type date string
 */
static char	*asn1_time_to_ctime(ASN1_TIME *tm) {
	char	*ctimeresult, *a;
	time_t	t;

	t = asn1_time_to_time(tm);
	a = ctime(&t);
	ctimeresult = (char *)malloc(strlen(a) + 1);
	memcpy(ctimeresult, a, strlen(a) + 1);
	return ctimeresult;
}

static scepitem_t	*readitem(char *transid) {
	scepitem_t	*si;
	BIO		*bio;
	char		filename[1024];
	char		oneline[1024];
	X509_NAME	*name;

	/* allocate a new structure					*/
	si = (scepitem_t *)malloc(sizeof(scepitem_t));

	/* first create a copy of the transid				*/
	si->transid = strdup(transid);

	/* make sure that it has the right length			*/
	si->transid[32] = '\0';

	/* find the appropriate file: request or certificate		*/
	switch (itemselect) {
	case SELECT_PENDING:
	case SELECT_REJECTED:
		si->type = ITEM_TYPE_REQ;
		break;
	case SELECT_GRANTED:
	case SELECT_REVOKED:
		si->type = ITEM_TYPE_CERT;
		break;
	}

	/* create the filename for the item				*/
	snprintf(filename, sizeof(filename), "%s/%s/%s.der", OPENSCEPDIR,
		selectname[itemselect], si->transid);
	if (debug)
		fprintf(stderr, "%s:%d: trying file '%s'\n", __FILE__, __LINE__,
			filename);

	/* open the file and read the contents				*/
	bio = BIO_new(BIO_s_file());
	if (BIO_read_filename(bio, filename) < 0) {
		fprintf(stderr, "%s:%d: cannot open file %s\n", __FILE__,
			__LINE__, filename);
		return NULL;
	}
	switch (si->type) {
	case ITEM_TYPE_REQ:
		si->data.req = d2i_X509_REQ_bio(bio, NULL);
		break;
	case ITEM_TYPE_CERT:
		si->data.x509 = d2i_X509_bio(bio, NULL);
		break;
	}
	if (si->data.any == NULL) {
		fprintf(stderr, "%s:%d: cannot decode item, trans id %s\n",
			__FILE__, __LINE__, si->transid);
		ERR_print_errors(bio_err);
		return NULL;
	} else {
		if (debug)
			BIO_printf(bio_err, "%s:%d: got new item\n", __FILE__,
				__LINE__);
	}

	/* extract key information from request or certificate		*/
	switch (sortorder) {
	case SORT_TRANSID:
		si->key = strdup(si->transid);
		break;
	case SORT_NAME:
		name = (si->type == ITEM_TYPE_REQ)
			? X509_REQ_get_subject_name(si->data.req)
			: X509_get_subject_name(si->data.x509);
		X509_NAME_oneline(name, oneline, sizeof(oneline));
		si->key = strdup(oneline);
		break;
	case SORT_NOTBEFORE:
		si->key = asn1_time_to_string(X509_get_notBefore(
			si->data.x509));
		break;
	case SORT_NOTAFTER:
		si->key = asn1_time_to_string(X509_get_notAfter(si->data.x509));
		break;
	case SORT_SERIAL:
		si->key = X509_get_serialNumber(si->data.x509);
		break;
	}

	/* return the completely filled in item				*/
	return si;
}

static void	display_cert(scepitem_t *ip) {
	char		subject[1024], issuer[1024];
	char		*notbefore, *notafter;
	char		*serial, *n;
	int		l;
	BIO		*a;

	X509_NAME_oneline(X509_get_subject_name(ip->data.x509), subject,
		sizeof(subject));
	X509_NAME_oneline(X509_get_issuer_name(ip->data.x509), issuer,
		sizeof(issuer));
	a = BIO_new(BIO_s_mem());
	i2a_ASN1_INTEGER(a, X509_get_serialNumber(ip->data.x509));
	l = BIO_get_mem_data(a, &n);
	serial = (char *)malloc(l + 1);
	serial[l] = '\0';
	memcpy(serial, n, l);
	BIO_free(a);
	if (ctimeformat) {
		notbefore = asn1_time_to_ctime(X509_get_notBefore(
			ip->data.x509));
		notafter = asn1_time_to_ctime(X509_get_notAfter(
			ip->data.x509));
	} else {
		notbefore = asn1_time_to_string(X509_get_notBefore(
			ip->data.x509));
		notafter = asn1_time_to_string(X509_get_notAfter(
			ip->data.x509));
	}

	if (html) {
		printf("<tr>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"</tr>\n",
			subject, serial, notbefore, notafter
		);
	} else {
		printf("%s\t%s\t%s\t%s\n", notbefore, notafter, serial,
			subject);
	}
	
	free(notbefore); free(notafter);
}

static void	display_req(scepitem_t *ip) {
	char	subject[1024];
	char	*fingerprint = "";
	X509_NAME_oneline(X509_REQ_get_subject_name(ip->data.req), subject,
		sizeof(subject));
	if (html) {
		printf("<tr>\n"
			"<td>%s</td>\n"
			"<td>%s</td>\n"
			"</tr>\n", subject, fingerprint);
	} else {
		printf("%s\t%s\n", subject, fingerprint);
	}
}

static void	display_item(scepitem_t *ip) {
	switch (ip->type) {
	case ITEM_TYPE_CERT:
		display_cert(ip);
		break;
	case ITEM_TYPE_REQ:
		display_req(ip);
		break;
	}
}

int	main(int argc, char *argv[]) {
	int		c;
	scep_t		scep;	/* mainly used to hold configuration	*/
	char		*notbefore = NULL, *notafter = NULL;
	char		workdir[1024];
	int		items = 0;
	scepitem_t	**itemlist = NULL;
	scepitem_t	**ip;
	DIR		*dir;
	struct dirent	*d;

	/* parse command line						*/
	while (EOF != (c = getopt(argc, argv, "abcdghnprstvx")))
		switch (c) {
		case 'a':
			sortorder = SORT_NOTAFTER;
			compare = cmp_string;
			break;
		case 'b':
			sortorder = SORT_NOTBEFORE;
			compare = cmp_string;
			break;
		case 'c':
			ctimeformat = 1;
			break;
		case 'd':
			debug++;
			break;
		case 'g':
			itemselect = SELECT_GRANTED;
			break;
		case 'h':
			html = 1;
			break;
		case 'n':
			sortorder = SORT_NAME;
			compare = cmp_string;
			break;
		case 'p':
			itemselect = SELECT_PENDING;
			break;
		case 'r':
			itemselect = SELECT_REJECTED;
			break;
		case 's':
			sortorder = SORT_SERIAL;
			compare = cmp_asn1_integer;
			break;
		case 't':
			sortorder = SORT_TRANSID;
			compare = cmp_string;
			break;
		case 'v':
			itemselect = SELECT_REVOKED;
			break;
		case 'x':
			reverse *= -1;
			break;
		}

	/* remaining arguments are range types				*/
	if (argc > optind) {
		notbefore = argv[optind++];
	}
	if (argc > optind) {
		notafter = argv[optind];
	}

	/* perform OpenSCEP initialization				*/
	scepinit();
	scep_config(&scep, OPENSCEPDIR "/openscep.cnf");

	/* select the working directory based on the command line args	*/
	snprintf(workdir, sizeof(workdir), OPENSCEPDIR "/%s",
		selectname[itemselect]);
	

	/* retrieve all matching items from that directory, put them 	*/
	/* in an array of pointers					*/
	snprintf(workdir, sizeof(workdir), "%s/%s", OPENSCEPDIR,
		selectname[itemselect]);
	if (NULL == (dir = opendir(workdir))) {
		fprintf(stderr, "%s:%d: cannot open directory %s: %s (%d)\n",
			__FILE__, __LINE__, workdir, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	while ((d = readdir(dir))) {
		/* look for der files only				*/
		if (0 == strcmp(d->d_name + 32, ".der")) {
			items++;
			itemlist = (scepitem_t **)realloc(itemlist,
				sizeof(scepitem_t *) * (items + 1));
			itemlist[items - 1] = readitem(d->d_name);
			itemlist[items] = NULL;
		}
	}

	/* perform a sort						*/
	if (debug) {
		BIO_printf(bio_err, "%s:%d: sorting %d items in array at %p\n",
			__FILE__, __LINE__, items, itemlist);
	}
	qsort(itemlist, items, sizeof(scepitem_t *),
		(int (*)(const void *, const void *))compare);

	/* display the result						*/
	if (itemlist)
		for (ip = itemlist; *ip; ip++) {
			/* display this item				*/
			display_item(*ip);
		}

	/* that's it							*/
	exit(EXIT_SUCCESS);
}
