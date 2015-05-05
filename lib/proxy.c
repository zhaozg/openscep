/*
 * proxy.c -- handle proxy requests
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: proxy.c,v 1.2 2002/02/24 21:40:01 afm Exp $
 */
#include <stdlib.h>
#include <init.h>
#include <scep.h>
#include <proxy.h>
#include <openssl/evp.h>

/*
 * proxy_authenticator	compute the proxy authenticator hash value
 *
 * this value is the MD5 hash of the DER form request payload concatenated with
 * the community string
 * the caller is responsible for deallocating the returned pointer
 */
ASN1_OCTET_STRING	*proxy_authenticator(scepmsg_t *msg, char *community) {
	MD5_CTX			ctx;
	unsigned char		md[MD5_DIGEST_LENGTH];
	ASN1_OCTET_STRING	*ao;

	/* get the DER form of the payload message			*/
	if (msg->data == NULL)
		return NULL;

	/* check for the community string				*/
	if (community == NULL)
		return NULL;

	/* create an MD5 context to compute the MD5 hash		*/
	MD5_Init(&ctx);

	/* add the data in the payload DER to the MD5 hash		*/
	MD5_Update(&ctx, msg->data, msg->length);

	/* add the community string to the MD5 hash			*/
	MD5_Update(&ctx, community, strlen(community));

	/* retrieve the hash value					*/
	MD5_Final(md, &ctx);

	/* return a new ASN1_OCTET_STRING				*/
	ao = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(ao, md, MD5_DIGEST_LENGTH);
	return ao;
}

/*
 * proxy_check		verify that the community string for this scep server
 *			is acceptable, but only if the community was set.
 */
int	proxy_check(scep_t *scep, scepmsg_t *msg, ASN1_OCTET_STRING *auth) {
	int			rc = 0;
	ASN1_OCTET_STRING	*a1;

	/* if no proxy community is set, we cannot accept the request	*/
	if (NULL == scep->community) {
		BIO_printf(bio_err, "%s:%d: community not set, cannot check "
			"proxy\n", __FILE__, __LINE__);
		goto finish;
	}

	/* compute the authenticator for the message we have		*/
	a1 = proxy_authenticator(msg, scep->community);
	if (a1 == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot compute authenticator\n",
			__FILE__, __LINE__);
		goto finish;
	}

	/* the two strings must concide					*/
	/* configured string must coincide				*/
	if (0 == ASN1_OCTET_STRING_cmp(a1, auth)) {
		if (debug)
			BIO_printf(bio_err, "%s:%d: proxy authenticators match\n",
				__FILE__, __LINE__);
		rc = 1;
		goto finish;
	}

	/* at this point we can be sure that the proxy authentication	*/
	/* did happen and was successful				*/
	BIO_printf(bio_err, "%s:%d: proxy authenticators fail to match\n",
		__FILE__, __LINE__);
finish:
	return rc;
}
