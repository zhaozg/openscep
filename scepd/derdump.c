/*
 * derdump -- display a DER encoded data structure 
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: derdump.c,v 1.3 2001/10/30 13:54:53 afm Exp $
 */
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <init.h>
#include <openscep_vers.h>

extern int	optind;
extern char	*optarg;

int	base64 = 0;

static void	usage(void) {
	printf("usage: derdump [ -i ] [ -b ] [ file ]\n");
	printf("read data from file (or stdin) and dump ASN.1 structure\n");
	printf("options: -i  indent ASN.1 structure for better readability\n");
	printf("         -b  input data is base64 encoded\n");
	printf("         -h  display this message and exit\n");
	printf("         -p  strip PEM headers\n");
	printf("         -V  display version\n");
}

int	main(int argc, char *argv[]) {
	BIO		*inbio, *outbio, *b64 = NULL, *readbio, *membio;
	int		bytes = 0, indent = 1, c;
	long		length;
	unsigned char	*data = NULL;
	char		*name = NULL, *header = NULL;
	char		*filename = NULL;
	int		pem = 0;

	/* parse command line arguments					*/
	while ((c = getopt(argc, argv, "bdhipV")) != EOF)
		switch (c) {
		case 'b':
			b64 = BIO_new(BIO_f_base64());
			break;
		case 'd':
			debug++;
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			indent = 0;
			break;
		case 'p':
			pem = 1;
			break;
		case 'V':
			printf("This is derdump from %s\n",
				openscep_version.v_gnu);
		}

	/* initialize the openssl libraries as with scepdump, to add	*/
	/* the scep specific object ids					*/
	scepinit();

	/* check for a filename argument				*/
	if (argc - optind > 0)
		filename = argv[optind];

	/* open input file or read from standard input			*/
	inbio = BIO_new(BIO_s_file());
	if (filename) {
		if (0 >= BIO_read_filename(inbio, filename)) {
			ERR_print_errors(bio_err);
			exit(EXIT_FAILURE);
		}
	} else {
		BIO_set_fp(inbio, stdin, BIO_NOCLOSE | BIO_FP_TEXT);
	}

	/* prepare a BIO to write output				*/
	outbio = BIO_new(BIO_s_file());
	BIO_set_fp(outbio, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	/* if in PEM mode, read data using PEM_read_bio			*/
	if (pem) {
		if (!PEM_read_bio(inbio, &name, &header, &data, &length)) {
			fprintf(stderr, "%s:%d: it seems this wasn't PEM "
				"after all\n", __FILE__, __LINE__);
			exit(EXIT_FAILURE);
		}
		if (debug) {
			fprintf(stderr, "%s:%d: found PEM structure '%s' of "
				"length %ld\n", __FILE__, __LINE__,
				name, length);
		}
		if (name)
			printf("PEM named '%s' contains the following DER:\n",
				name);
		OPENSSL_free(name); OPENSSL_free(header);
		goto data;
	}

	/* read DER or base 64 data					*/
	if (b64 != NULL) {
		readbio = BIO_push(inbio, b64);
	} else {
		readbio = inbio;
	}

	/* create a memory bio to read the input into			*/
	membio = BIO_new(BIO_s_mem());
	do {
		unsigned char	buffer[1024];
		bytes = BIO_read(inbio, buffer, sizeof(buffer));
		if (bytes > 0)
			BIO_write(membio, buffer, bytes);
	} while (bytes > 0);
	BIO_flush(membio);

	/* get the memory data from the memory BIO			*/
	length = BIO_get_mem_data(membio, &data);

	/* turn the memory over to us					*/
	BIO_set_flags(membio, BIO_FLAGS_MEM_RDONLY);

data:
	/* recursively display all data					*/
	ASN1_parse_dump(outbio, data, length, indent, 1);

	/* that's it							*/
	exit(EXIT_SUCCESS);
}
