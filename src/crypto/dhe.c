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
//#include <math.h>
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

static void dhe_free ( struct dhe_context * context ) {
	free ( context -> dynamic );
	context->dynamic = NULL;
}

static int dhe_alloc ( struct dhe_context *context, size_t prime_size ) {
	unsigned int size = bigint_required_size ( prime_size );
	bigint_t ( size ) * client_pubval;
	bigint_t ( size ) * server_pubval;
	size_t tmp_len = bigint_mod_exp_tmp_len ( client_pubval, server_pubval ); 
	struct {
		bigint_t ( size ) client_pubval;
		bigint_t ( size ) server_pubval;
		bigint_t ( size ) prime;
		bigint_t ( 1 ) generator; // generator is always 2
		uint8_t tmp[tmp_len];
	} __attribute__ (( packed )) * dynamic;

	dhe_free ( context );

	dynamic = malloc ( sizeof ( *dynamic ) );
	if ( !dynamic )
		return -ENOMEM;

	context->dynamic = dynamic;
	context->prime = &dynamic->prime.element[0];
	context->prime_size = prime_size;
	context->generator = &dynamic->generator.element[0];
	context->server_pubval = &dynamic->server_pubval.element[0];
	context->client_dh_param = &dynamic->client_pubval.element[0];
	context->tmp = &dynamic->tmp;
	context->max_len = size;

	return 0;
}

static int dhe_init ( void * ctx, const void *key, size_t key_len ) { // For DHE, key is NULL and key_len is defaulted to 0 since they are unneeded
	struct dhe_context * context = ctx;
	int rc = 0;

	if (key_len)
	{
		rc = -1;
		goto err_alloc;
	}
		
	if (key != NULL)
	{
		rc = -1;
		goto err_alloc;
	}

	memset ( context, 0, sizeof ( *context ));

	if ( ( rc = dhe_alloc ( context, DHE_PRIME_LENGTH ) ) != 0 )
		return rc;

	return 0;

 err_alloc:
	return rc;
}

int dhe_generate_client_value(void *ctx)
{
	struct dhe_context * context = ctx;
	uint32_t random_num = random();
	context->random = &random_num;
	bigint_t ( bigint_required_size ( sizeof ( random_num ) ) ) * random_bigint = (void *) &random_num; // this needs to be checked
	bigint_init(random_bigint, &random_num, sizeof(random_num));
	
	bigint_t (context -> generator_size) * base = ( ( void * ) context->generator );
	bigint_t (context -> max_len) * prime = ( ( void * ) context->prime );
	bigint_t (context -> max_len) * output = ( ( void * ) context->client_dh_param );
	bigint_mod_exp ( base, prime, random_bigint, output, context->tmp);
	//bigint_done (output, context->client_dh_param, context->prime_size);
	
	bigint_t (context -> max_len) * server_pubval = ( (void *) context->server_pubval);
	bigint_t (context -> max_len) * premaster_secret_output = context -> premaster_secret;
	bigint_mod_multiply( output, server_pubval, prime, premaster_secret_output, context->tmp);
	//bigint_done(output, context->premaster_secret, context->prime_size);

	return 0;
}

static size_t dhe_max_length(void * ctx)
{
	struct dhe_context * context = ctx;

	return context->max_len;
}

static void dhe_final ( void *ctx ) {
	struct dhe_context *context = ctx;

	dhe_free ( context );
}

/** RSA public-key algorithm */
struct pubkey_algorithm dhe_algorithm = {
	.name		= "dhe",
	.ctxsize	= DHE_CTX_SIZE,
	.init		= dhe_init,
	.max_len	= dhe_max_length,
	.encrypt	= placeholder,
	.decrypt	= placeholder,
	.sign		= placeholder,
	.verify		= placeholder,
	.final		= dhe_final,
	.match		= placeholder,
};

/* Drag in objects via rsa_algorithm */
REQUIRING_SYMBOL ( dhe_algorithm );

/* Drag in crypto configuration */
REQUIRE_OBJECT ( config_crypto );
