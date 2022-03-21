/*
 * Copyright (C) 2012 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <ipxe/asn1.h>
#include <ipxe/crypto.h>
#include <ipxe/bigint.h>
#include <ipxe/random_nz.h>
#include <ipxe/dhe.h>
#include <ipxe/rsa.h>

/** @file
 *
 * Diffie-Hellman public-key cryptography
 *
 * DHE is documented in RFC.
 */

/* Disambiguate the various error causes */
#define EACCES_VERIFY \
	__einfo_error ( EINFO_EACCES_VERIFY )
#define EINFO_EACCES_VERIFY \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "RSA signature incorrect" )

// Generate secret from data in context

/**
 * DHE does not need many of the function pointers in the pubkey_algorithm struct. This function returns 0 and nothing else.
 * 
 * @ret int - 0
 */
static int placeholder()
{
	return 0;
}

static int dhe_generate_client_value(void *ctx)
{
	struct dhe_context * context = ctx;
	context->client_dh_param = /*instead of zalloc/malloc, use bigint_init*/zalloc(context->prime_size * sizeof(bigint_element_t));
	context->client_dh_param_size = context->prime_size;
	long int random_num = random();
	bigint_t ( bigint_required_size ( sizeof ( random_num ) ) ) * random_bigint;
	bigint_init(random_bigint, &random_num, sizeof(random_num));
	bigint_t (context -> generator_size) * base = ( ( void * ) context->generator );
	bigint_t (context -> prime_size) * prime = ( ( void * ) context->prime );
	bigint_t (context -> client_dh_param_size) * output = ( ( void * ) context->client_dh_param );
	bigint_mod_exp ( base, prime, random_bigint, output, context->tmp);
}

/**
 * Verify signed digest value using RSA
 *
 * @v ctx		RSA context
 * @v digest		Digest algorithm
 * @v value		Digest value
 * @v signature		Signature
 * @v signature_len	Signature length
 * @ret rc		Return status code
 */
static int rsa_verify ( void *ctx, struct digest_algorithm *digest,
			const void *value, const void *signature,
			size_t signature_len ) {
	struct rsa_context *context = ctx;
	void *temp;
	void *expected;
	void *actual;
	int rc;

	/* Sanity check */
	if ( signature_len != context->max_len ) {
		DBGC ( context, "RSA %p signature incorrect length (%zd "
		       "bytes, should be %zd)\n",
		       context, signature_len, context->max_len );
		return -ERANGE;
	}
	DBGC ( context, "RSA %p verifying %s digest:\n",
	       context, digest->name );
	DBGC_HDA ( context, 0, value, digest->digestsize );
	DBGC_HDA ( context, 0, signature, signature_len );

	/* Decipher the signature (using the big integer input buffer
	 * as temporary storage)
	 */
	temp = context->input0;
	expected = temp;
	rsa_cipher ( context, signature, expected );
	DBGC ( context, "RSA %p deciphered signature:\n", context );
	DBGC_HDA ( context, 0, expected, context->max_len );

	/* Encode digest (using the big integer output buffer as
	 * temporary storage)
	 */
	temp = context->output0;
	actual = temp;
	if ( ( rc = rsa_encode_digest ( context, digest, value, actual ) ) !=0 )
		return rc;

	/* Verify the signature */
	if ( memcmp ( actual, expected, context->max_len ) != 0 ) {
		DBGC ( context, "RSA %p signature verification failed\n",
		       context );
		return -EACCES_VERIFY;
	}

	DBGC ( context, "RSA %p signature verified successfully\n", context );
	return 0;
}

/** RSA public-key algorithm */
struct pubkey_algorithm dhe_algorithm = {
	.name		= "dhe",
	.ctxsize	= DHE_CTX_SIZE,
	.init		= placeholder,
	.max_len	= placeholder,
	.encrypt	= placeholder,
	.decrypt	= placeholder,
	.sign		= placeholder,
	.verify		= rsa_verify,
	.final		= placeholder,
	.match		= placeholder,
};

/* Drag in objects via rsa_algorithm */
REQUIRING_SYMBOL ( rsa_algorithm );

/* Drag in crypto configuration */
REQUIRE_OBJECT ( config_crypto );
