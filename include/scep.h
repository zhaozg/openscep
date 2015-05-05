/*
 * scep.h -- global data types used in all 
 *
 * (c) 2001 Dr. Andreas Mueller, Beratung und Entwicklung
 *
 * $Id: scep.h,v 1.10 2002/02/19 23:40:05 afm Exp $
 */
#ifndef _SCEP_H
#define _SCEP_H

#include <isasu.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/conf.h>
#include <lber.h>
#include <ldap.h>
#include <payload.h>

#define	FORMAT_ASN1	1
#define	FORMAT_PEM	3

typedef struct {
	char	*ldaphost;	/* LDAP host name			*/
	int	ldapport;	/* LDAP port, usually 389		*/
	char	*binddn;	/* bind distinguished name, NULL = anon	*/
	char	*bindpw;	/* bind password, NULL = anon		*/
	char	*ldapbase;	/* base for SCEP			*/
	LDAP	*ldap;		/* active ldap connection, if available	*/
} scepldap_t;

typedef struct {
	char	*httphost;
	int	httpport;
	char	*httppath;
} scephttp_t;

typedef struct {
	/* when decoding/encode, the base 64 flag indicates whether	*/
	/* we should use base64 encoding				*/
	int			base64;

	/* p7 and si contain information about the outer signed PKCS#7	*/
	PKCS7			*p7;
	PKCS7_SIGNER_INFO	*si;
	char			*messageType;
	char			*pkiStatus;
	char			*failinfo;

	/* data and lengthh contain the raw payload of the packet	*/
	/* this is either a PKCS#10 (v1 SCEP) or a payload_t (v2 SCEP)	*/
	unsigned char		*data;
	int			length;

	/* depending on message type, the contents of the message are	*/
	/* different							*/
	union {
		/* union discriminated by the messageType 		*/
		X509_REQ		*req;		/* PKCSReq	*/
		issuer_and_subject_t	*is;	/* GetCertInitial	*/
		PKCS7_ISSUER_AND_SERIAL	*iser;		/* GetCert	*/
		PKCS7			*p7;	/* GetCRL, CertRep	*/
		void			*unknown;	/* ???		*/
		payload_t		*payload;	/* 17/18	*/
	} rd;
} scepmsg_t;

typedef struct {
	int		client;		/* indicates client or server	*/

	/* name of the SCEP instance					*/
	char		*name;

	/* attributes of the transaction				*/
	char		*transId;
	unsigned char	*senderNonce;		/* 16 bytes */
	int		senderNonceLength;
	unsigned char	*recipientNonce;	/* 16 bytes */
	int		recipientNonceLength;

	/* OpenSSL configuration file contents				*/
	LHASH		*conf;

	/* signer/client information different from requestor for v2	*/
	X509		*selfsignedcert;
	X509		*clientcert;
	EVP_PKEY	*clientpkey;	/* client private/public key and*/
	EVP_PKEY	*clientpubkey;	/* public key exlusively	*/
	X509_REQ	*clientreq;	/* X.509 request, used in client*/

	/* in v.2, the requestor may be different from the client	*/
	X509_REQ	*requestorreq;	/* X.509 of requestor		*/
	NETSCAPE_SPKI	*requestorspki;	/* netscape type requests	*/
	EVP_PKEY	*requestorpubkey;

	/* CA information 						*/
	X509		*cacert;
	EVP_PKEY	*capkey;
	X509_CRL	*crl;
	int		automatic;

	/* raw information from the request 				*/
	scepmsg_t	request;
	char		*fingerprint;	/* request fingerprint		*/
	char		*keyfingerprt;	/* request key fingerprint	*/

	/* contents of the request _received_				*/
	scepmsg_t	reply;

	/* LDAP store to use 						*/
	scepldap_t	l;

	/* HTTP server info port					*/
	scephttp_t	h;

	/* some flags controlling the processing done by OpenSCEP	*/
	int		check_transid;

	/* proxy community						*/
	char			*community;
	ASN1_OCTET_STRING	*authenticator;
} scep_t;

#define	SCEP_MESSAGE_TYPE_PKCSREQ		"19"
#define	SCEP_MESSAGE_TYPE_V2REQUEST		"17"
#define	SCEP_MESSAGE_TYPE_V2PROXY		"18"
#define	SCEP_MESSAGE_TYPE_CERTREP		"3"
#define	SCEP_MESSAGE_TYPE_GETCERTINITIAL	"20"
#define	SCEP_MESSAGE_TYPE_GETCERT		"21"
#define SCEP_MESSAGE_TYPE_GETCRL		"22"

#define MSG_V2REQUEST				17
#define	MSG_V2PROXY				18
#define MSG_PKCSREQ				19
#define	MSG_CERTREP				3
#define MSG_GETCERTINITIAL			20
#define MSG_GETCERT				21
#define MSG_GETCRL				22

#define	SCEP_PKISTATUS_SUCCESS			"0"
#define	SCEP_PKISTATUS_FAILURE			"2"
#define	SCEP_PKISTATUS_PENDING			"3"

#define	PKI_SUCCESS				0
#define PKI_FAILURE				2
#define PKI_PENDING				3

#define	SCEP_FAILURE_BADALG			"0"
#define	SCEP_FAILURE_BADMESSAGECHECK		"1"
#define	SCEP_FAILURE_BADREQUEST			"2"
#define	SCEP_FAILURE_BADTIME			"3"
#define	SCEP_FAILURE_BADCERTID			"4"

#define FAIL_BADALG				0
#define FAIL_BADMESSAGECHECK			1
#define FAIL_BADREQUEST				2
#define FAIL_BADTIME				3
#define FAIL_BADCERTID				4

#define	SCEP_MESSAGE_is(a, b) (!strcmp(a, b))
#define SCEP_PKISTATUS_is(a, b) (!strcmp(a, b))
#define	SCEP_FAILURE_is(a, b) (!strcmp(a, b))

#define	SCEP_TYPE(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_MESSAGE_TYPE_PKCSREQ, a)) ? "PKCSReq" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_V2REQUEST, a)) ? "v2Request" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_V2PROXY, a)) ? "v2Proxy" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_CERTREP, a)) ? "CertRep" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCERTINITIAL, a)) ? "GetCertInitial" : (\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCERT, a)) ? "GetCert" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCRL, a)) ? "GetCRL" : "unknown"))))))))

#define SCEP_STATUS(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_PKISTATUS_SUCCESS, a)) ? "SUCCESS" : (		\
(0 == strcmp(SCEP_PKISTATUS_FAILURE, a)) ? "FAILURE" : (		\
(0 == strcmp(SCEP_PKISTATUS_PENDING, a)) ? "PENDING" : "(unknown)"))))

#define	SCEP_FAILURE(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_FAILURE_BADALG, a)) ? "BadAlg" : (			\
(0 == strcmp(SCEP_FAILURE_BADMESSAGECHECK, a)) ? "BadMessageCheck" : (	\
(0 == strcmp(SCEP_FAILURE_BADREQUEST, a)) ? "BadRequest" : (		\
(0 == strcmp(SCEP_FAILURE_BADTIME, a)) ? "BadTime" : (			\
(0 == strcmp(SCEP_FAILURE_BADCERTID, a)) ? "BadCertID" : "(unknown)"))))))

#endif /* _SCEP_H */
