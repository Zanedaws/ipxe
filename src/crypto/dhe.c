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
	bigint_t (context -> server_pubval_size) * server_pubval = ( (void *) context->server_pubval);
	bigint_t (context -> prime_size) * premaster_secret_output = context -> premaster_secret;
	bigint_mod_multiply( output, server_pubval, prime, premaster_secret_output, context->tmp);
	context->premaster_secret = premaster_secret_output;
}

static int dhe_max_length(void * ctx)
{
	struct dhe_context * context = ctx;

	return context->max_len;
}

/** RSA public-key algorithm */
struct pubkey_algorithm dhe_algorithm = {
	.name		= "dhe",
	.ctxsize	= DHE_CTX_SIZE,
	.init		= placeholder,
	.max_len	= dhe_max_length,
	.encrypt	= placeholder,
	.decrypt	= placeholder,
	.sign		= placeholder,
	.verify		= placeholder,
	.final		= placeholder,
	.match		= placeholder,
};

/* Drag in objects via rsa_algorithm */
REQUIRING_SYMBOL ( rsa_algorithm );

/* Drag in crypto configuration */
REQUIRE_OBJECT ( config_crypto );
