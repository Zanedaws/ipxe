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

static uint64_t dhe_power( uint64_t base, uint64_t power, uint64_t prime ) // might need to switch to uint32_t
{
	return ( ( uint64_t ) pow( base, power ) ) % prime; // base ^ power, size?
}

/** RSA public-key algorithm */
struct pubkey_algorithm dhe_algorithm = {
	.name		= "dhe",
	.ctxsize	= DHE_CTX_SIZE,
	.init		= rsa_init,
	.max_len	= rsa_max_len,
	.encrypt	= rsa_encrypt,
	.decrypt	= rsa_decrypt,
	.sign		= rsa_sign,
	.verify		= rsa_verify,
	.final		= rsa_final,
	.match		= rsa_match,
};

/* Drag in objects via rsa_algorithm */
REQUIRING_SYMBOL ( rsa_algorithm );

/* Drag in crypto configuration */
REQUIRE_OBJECT ( config_crypto );
