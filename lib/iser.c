/*
 * iser.c -- de- and encode issuer and serial from/to a bio
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: iser.c,v 1.2 2002/02/19 23:40:06 afm Exp $
 */
#include <config.h>
#include <iser.h>
#include <init.h>

#if 0
PKCS7_ISSUER_AND_SERIAL	*d2i_PKCS7_ISSUER_AND_SERIAL_bio(
	PKCS7_ISSUER_AND_SERIAL **is, BIO *b) {
	unsigned char		buffer[2048];
	unsigned char		*pp;
	int			l;
	PKCS7_ISSUER_AND_SERIAL	*i;

	/* read what you can get from the bio				*/
	l = BIO_read(b, buffer, sizeof(buffer));
	if (l <= 0) {
		BIO_printf(bio_err, "%s:%d: no data from bio\n", __FILE__,
			__LINE__);
		goto err;
	}

	/* convert the contents of the buffer to a PKCS7_bla structure	*/
	pp = buffer;
	i = d2i_PKCS7_ISSUER_AND_SERIAL(is, &pp, l);
	if (i == NULL) {
		BIO_printf(bio_err, "%s:%d: cannot decode issuer and serial\n",
			__FILE__, __LINE__);
		goto err;
	}

	/* return the decode issuer and serial				*/
	return i;

	/* error return							*/
err:
	BIO_printf(bio_err, "%s:%d: decoding of issuer and serial failed\n",
		__FILE__, __LINE__);
	return NULL;
}

int	i2d_PKCS7_ISSUER_AND_SERIAL_bio(BIO *b, PKCS7_ISSUER_AND_SERIAL *is) {
	int		l;
	unsigned char	*data, *pp;

	/* find out how much space ISSUER_AND_SERIAL will consume	*/
	l = i2d_PKCS7_ISSUER_AND_SERIAL(is, NULL);
	if (l <= 0)
		return -1;

	/* allocate temporary space on the stack			*/
	pp = data = (unsigned char *)alloca(l);

	/* convert the ISSUER_AND_SERIAL to a DER block in memory	*/
	if (0 >= i2d_PKCS7_ISSUER_AND_SERIAL(is, &pp))
		return -1;

	/* write the data to the output bio				*/
	BIO_write(b, data, l);
	BIO_flush(b);

	/* return the size of the block written				*/
	return l;
}
#endif /* 0 */
