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

int dhe_generate_client_value(void *ctx);

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
	/** Generator size */
	unsigned int generator_size;
    /** Server public value (g^X mod p) */
    bigint_element_t * server_pubval;
	/** Client diffieHellman parameter */
	bigint_element_t * client_dh_param;
	/** Temporary working space for modular exponentiation */
	void *tmp;
	/** Max length any value in context can have */
	size_t max_len;
	void * mult_tmp;
	bigint_element_t * random;
	unsigned int random_size;

	void * premaster_secret;

	int init;
};

/** RSA context size */
#define DHE_CTX_SIZE sizeof ( struct dhe_context )

extern struct pubkey_algorithm dhe_algorithm;

#endif /* _IPXE_RSA_H */
