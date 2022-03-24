#ifndef _IPXE_DHE_H
#define _IPXE_DHE_H

/** @file
 *
 * DHE public-key cryptography
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdarg.h>
#include <ipxe/crypto.h>
#include <ipxe/bigint.h>
#include <ipxe/asn1.h>
#include <ipxe/tables.h>

/** RSA digestAlgorithm sequence contents */
#define RSA_DIGESTALGORITHM_CONTENTS( ... )				\
	ASN1_OID, VA_ARG_COUNT ( __VA_ARGS__ ), __VA_ARGS__,		\
	ASN1_NULL, 0x00

/** RSA digestAlgorithm sequence */
#define RSA_DIGESTALGORITHM( ... )					\
	ASN1_SEQUENCE,							\
	VA_ARG_COUNT ( RSA_DIGESTALGORITHM_CONTENTS ( __VA_ARGS__ ) ),	\
	RSA_DIGESTALGORITHM_CONTENTS ( __VA_ARGS__ )

/** RSA digest prefix */
#define RSA_DIGEST_PREFIX( digest_size )				\
	ASN1_OCTET_STRING, digest_size

/** RSA digestInfo prefix */
#define RSA_DIGESTINFO_PREFIX( digest_size, ... )			\
	ASN1_SEQUENCE,							\
	( VA_ARG_COUNT ( RSA_DIGESTALGORITHM ( __VA_ARGS__ ) ) +	\
	  VA_ARG_COUNT ( RSA_DIGEST_PREFIX ( digest_size ) ) +		\
	  digest_size ),						\
	RSA_DIGESTALGORITHM ( __VA_ARGS__ ),				\
	RSA_DIGEST_PREFIX ( digest_size )

/** An RSA digestInfo prefix */
struct rsa_digestinfo_prefix {
	/** Digest algorithm */
	struct digest_algorithm *digest;
	/** Prefix */
	const void *data;
	/** Length of prefix */
	size_t len;
};

/** RSA digestInfo prefix table */
#define RSA_DIGESTINFO_PREFIXES \
	__table ( struct rsa_digestinfo_prefix, "rsa_digestinfo_prefixes" )

/** Declare an RSA digestInfo prefix */
#define __rsa_digestinfo_prefix __table_entry ( RSA_DIGESTINFO_PREFIXES, 01 )

/** An RSA context */
struct dhe_context {
	/** Allocated memory */
	void *dynamic;
	/** DHE Prime */
    bigint_element_t * prime;
	/** Number of elements in prime*/
	unsigned int prime_size;
	/** DHE Generator from server */
    bigint_element_t * generator;
	/** Number of elements in generator */
	unsigned int generator_size;
    /** Server public value (g^X mod p) */
    bigint_element_t * server_pubval;
    /** Number of elements in server pubkey */
    unsigned int server_pubval_size;
	/** Client diffieHellman parameter */
	bigint_element_t * client_dh_param;
	/** Number of elements in client DH param */
	unsigned int client_dh_param_size;
	/** Temporary working space for modular exponentiation */
	void *tmp;
	/** Max length any value in context can have */
	size_t max_len;
	void * premaster_secret;
};

/** RSA context size */
#define DHE_CTX_SIZE sizeof ( struct dhe_context )

extern struct pubkey_algorithm dhe_algorithm;

#endif /* _IPXE_RSA_H */
