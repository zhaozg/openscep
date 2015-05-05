/*
 * fingerprint.c -- computer a fingerprint of a block of memory as 
 *                  a printable string
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 * 
 * $Id: fingerprint.c,v 1.5 2002/02/19 23:40:06 afm Exp $
 */
#include <fingerprint.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <init.h>
#include <string.h>

static int	fp_blanks = 0;

/*
 * compare two fingerprints
 *
 * if they differ inlength, it is most probably because one contains blanks
 * for better readability, while the other consists of hex characters only
 */
int	fingerprint_cmp(const char *f1, const char *f2) {
	int	l1, l2;
	l1 = strlen(f1); l2 = strlen(f2);
	if (l1 == l2) {
		return strcasecmp(f1, f2);
	}
	if (l1 > l2) {
		return ((strncasecmp(f1, f2, 8) != 0) ||
			(strncasecmp(f1 + 9, f2 + 8, 8) != 0) ||
			(strncasecmp(f1 + 18, f2 + 16, 8) != 0) ||
			(strncasecmp(f1 + 27, f2 + 24, 8) != 0));
	} else {
		return ((strncasecmp(f2, f1, 8) != 0) ||
			(strncasecmp(f2 + 9, f1 + 8, 8) != 0) ||
			(strncasecmp(f2 + 18, f1 + 16, 8) != 0) ||
			(strncasecmp(f2 + 27, f1 + 24, 8) != 0));
	}
	return 0;
}

static char	*printable_fingerprint(unsigned char *fp) {
	unsigned char	*rp, *p;
	int		i;

	/* prepare a printable version of the fingerprint		*/
	rp = (unsigned char *)malloc(2 * MD5_DIGEST_LENGTH + 1 + fp_blanks * 3);
	p = rp;
	for (i = 0; i < MD5_DIGEST_LENGTH; i++, p += 2) {
		if (fp_blanks)
			if ((i > 0) && ((i % 4) == 0)) p += 1;
		sprintf((char *)p, "%02X ", fp[i]);
	}
	rp[2 * MD5_DIGEST_LENGTH + 3 * fp_blanks] = '\0';
	if (debug)
		BIO_printf(bio_err, "%s:%d: the fingerprint is '%s'\n",
			__FILE__, __LINE__, rp);
	return rp;
}

char	*fingerprint(unsigned char *data, int length) {
	MD5_CTX		c;
	unsigned char	md[MD5_DIGEST_LENGTH];

	/* debug message to inform debugger what we are doing		*/
	if (debug)
		BIO_printf(bio_err, "%s:%d: computing MD5 fingerprint\n",
			__FILE__, __LINE__);

	/* compute the fingerprint of the data found in content/length	*/
	/* fields of the scep structure					*/
	MD5_Init(&c);
	MD5_Update(&c, data, length);
	MD5_Final(md, &c);

	return printable_fingerprint(md);
}

char	*x509_key_fingerprint(X509_REQ *req) {
	unsigned char	*data;
	int		length;
	char		*fp;
	BIO		*bio;

	/* prepare a memory bio						*/
	bio = BIO_new(BIO_s_mem());

	/* write the public key to the bio				*/
	i2d_PUBKEY_bio(bio, X509_REQ_get_pubkey(req));

	/* retrieve the memory pointer of the bio			*/
	length = BIO_get_mem_data(bio, &data);

	/* compute the hash of the memory block				*/
	fp = fingerprint(data, length);

	/* free the bio, or a memory leak will result			*/
	BIO_free(bio);
	return fp;
}

char	*key_fingerprint(EVP_PKEY *key) {
	X509_REQ	*req;
	char		*result;

	/* create a dummy request					*/
	req = X509_REQ_new();

	/* set the public key for this request				*/
	X509_REQ_set_pubkey(req, key);

	/* create the fingerprint for this request			*/
	result = x509_key_fingerprint(req);

	/* free the request						*/
	
	/* return the fingerprint					*/
	return result;
}
