/*
 * spki2file.c -- convert an SPKI request and a X509_NAME into the input
 *                file openssl requires to grant an SPKI request
 *
 * (c) 2002 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: spki2file.c,v 1.1 2002/02/19 23:40:07 afm Exp $
 */
#include <spki2file.h>
#include <init.h>
#include <http.h>

int	spki2file(char *filename, X509_NAME *name,
		unsigned char *spkidata, int spkilength) {
	BIO	*membio, *b64, *outbio, *outfile;
	char	*data = NULL, *urldata;
	long	length;
	int	n, i, rc = -1;

	/* create a BIO for the data					*/
	outfile = BIO_new(BIO_s_file());
	if (BIO_write_filename(outfile, filename) < 0) {
		BIO_printf(bio_err, "%s:%d: cannot open file '%s'\n",
			__FILE__, __LINE__, filename);
		goto err;
	}

	/* check all possible attribute in the name, and write them	*/
	/* to the info file as name=value pairs				*/
	n = X509_NAME_entry_count(name);
	for (i = 0; i < n; i++) {
		X509_NAME_ENTRY	*ne;
		ASN1_OBJECT	*o;
		ASN1_STRING	*as;
		ne = X509_NAME_get_entry(name, i);
		o = X509_NAME_ENTRY_get_object(ne);
		as = X509_NAME_ENTRY_get_data(ne);
		BIO_printf(outfile, "%s=%*.*s\n", OBJ_nid2ln(OBJ_obj2nid(o)),
			as->length, as->length, as->data);
		if (debug)
			BIO_printf(bio_err, "%s:%d: adding attribute "
				"%s=%*.*s\n", __FILE__, __LINE__,
				OBJ_nid2ln(OBJ_obj2nid(o)),
				as->length, as->length, as->data);
	}

	/* convert the spki into base64					*/
	membio = BIO_new(BIO_s_mem());
	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	outbio = BIO_push(b64, membio);
	BIO_write(outbio, spkidata, spkilength);
	BIO_flush(outbio);
	BIO_set_flags(membio, BIO_FLAGS_MEM_RDONLY);
	length = BIO_get_mem_data(membio, &data);
	if (debug)
		BIO_printf(bio_err, "%s:%d: written %d base64 bytes\n",
			__FILE__, __LINE__, length);

	/* write the encoded SPKI to the file				*/
	BIO_printf(outfile, "SPKAC=%s\n", data);
	free(data);

	/* if we get to this point, the everything is ok		*/
	rc = 0;

	/* close the file						*/
err:
	BIO_free(outfile);
	return rc;
}
