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

/** @file
 *
 * AES tests
 *
 * These test vectors are provided by NIST as part of the
 * Cryptographic Toolkit Examples, downloadable from:
 *
 *    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_Core_All.pdf
 *    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_ECB.pdf
 *    http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/AES_CBC.pdf
 *
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <assert.h>
#include <string.h>
#include <ipxe/aes.h>
#include <ipxe/test.h>
#include "cipher_test.h"

/** Key used for NIST 128-bit test vectors */
#define AES_KEY_NIST_128						\
	KEY ( 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab,	\
	      0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c )

/** Key used for NIST 192-bit test vectors */
#define AES_KEY_NIST_192						\
	KEY ( 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8,	\
	      0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8,	\
	      0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b )

/** Key used for NIST 256-bit test vectors */
#define AES_KEY_NIST_256						\
	KEY ( 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,	\
	      0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35,	\
	      0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,	\
	      0xa3, 0x09, 0x14, 0xdf, 0xf4 )

/** Key used for NIST AES_GCM256-bit test vectors #example 4*/
#define AES_KEY_GCM_NIST_256						\
	KEY ( 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d,	\
	      0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff,	\
	      0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f,	\
	      0x94, 0x67, 0x30, 0x83, 0x08 )

/** Dummy initialisation vector used for NIST ECB-mode test vectors */
#define AES_IV_NIST_DUMMY						\
	IV ( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	\
	     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 )

/** Initialisation vector used for NIST CBC-mode test vectors */
#define AES_IV_NIST_CBC							\
	IV ( 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	\
	     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f )

/** Initialisation vector used for NIST GCM-mode test vectors example #4 */
#define AES_IV_NIST_GCM							\
	IV ( 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde,	\
	     0xca, 0xf8, 0x88 )

/** The authenticated dat used for NIST GCM-mode test vectors example #4 */
#define AES_GCM_A_DATA
	A ( 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,	\
		0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,	\
		0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,	\
		0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,	\
		0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,	\
		0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,	\
		0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,	\
		0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 )

/** Plaintext used for NIST test vectors */
#define AES_PLAINTEXT_NIST						\
	PLAINTEXT ( 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,	\
		    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,	\
		    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,	\
		    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,	\
		    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,	\
		    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,	\
		    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,	\
		    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 )

/**AES_256-GCM Plaintext from NIST documentation example #4 */
#define AES_GCM_PLAINTEXT_NIST
	PLAINTEXT ( 0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, \
			0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, \
			0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, \
			0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, \
			0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, \
			0x2f, 0xcf, 0x0E, 0x24, 0x49, 0xa6, 0xb5, 0x25, \
			0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, \ 
			0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55 )

/** AES-128-ECB (same test as AES-128-Core) */
CIPHER_TEST ( aes_128_ecb, &aes_ecb_algorithm,
	AES_KEY_NIST_128, AES_IV_NIST_DUMMY, AES_PLAINTEXT_NIST,
	CIPHERTEXT ( 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
		     0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
		     0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
		     0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
		     0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
		     0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
		     0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
		     0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4 ) );

/** AES-128-CBC */
CIPHER_TEST ( aes_128_cbc, &aes_cbc_algorithm,
	AES_KEY_NIST_128, AES_IV_NIST_CBC, AES_PLAINTEXT_NIST,
	CIPHERTEXT ( 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
		     0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
		     0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
		     0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
		     0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
		     0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
		     0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
		     0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 ) );

/** AES-192-ECB (same test as AES-192-Core) */
CIPHER_TEST ( aes_192_ecb, &aes_ecb_algorithm,
	AES_KEY_NIST_192, AES_IV_NIST_DUMMY, AES_PLAINTEXT_NIST,
	CIPHERTEXT ( 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
		     0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
		     0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
		     0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef,
		     0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
		     0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e,
		     0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
		     0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e ) );

/** AES-192-CBC */
CIPHER_TEST ( aes_192_cbc, &aes_cbc_algorithm,
	AES_KEY_NIST_192, AES_IV_NIST_CBC, AES_PLAINTEXT_NIST,
	CIPHERTEXT ( 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
		     0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
		     0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
		     0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
		     0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
		     0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
		     0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
		     0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd ) );

/** AES-256-ECB (same test as AES-256-Core) */
CIPHER_TEST ( aes_256_ecb, &aes_ecb_algorithm,
	AES_KEY_NIST_256, AES_IV_NIST_DUMMY, AES_PLAINTEXT_NIST,
	CIPHERTEXT ( 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
		     0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
		     0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
		     0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
		     0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
		     0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
		     0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
		     0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7 ) );

/** AES-256-CBC */
CIPHER_TEST ( aes_256_cbc, &aes_cbc_algorithm,
	AES_KEY_NIST_256, AES_IV_NIST_CBC, AES_PLAINTEXT_NIST,
	CIPHERTEXT ( 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
		     0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
		     0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
		     0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
		     0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
		     0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
		     0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
		     0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b ) );

/** AES-256-GCM */
CIPHER_TEST ( aes_256_gcm, &aes_gcm_algorithm,
	AES_KEY_GCM_NIST_256, AES_IV_NIST_GCM, AES_GCM_PLAINTEXT_NIST, AES_GCM_A_DATA
	CIPHERTEXT ( 0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
		     0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
		     0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
		     0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
		     0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
		     0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
		     0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
		     0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad ) );

/**
 * 
 * Perform AES self-test
 *
 */
static void aes_test_exec ( void ) {
	struct cipher_algorithm *ecb = &aes_ecb_algorithm;
	struct cipher_algorithm *cbc = &aes_cbc_algorithm;
	unsigned int keylen;

	/* Correctness tests */
	cipher_ok ( &aes_128_ecb );
	cipher_ok ( &aes_128_cbc );
	cipher_ok ( &aes_192_ecb );
	cipher_ok ( &aes_192_cbc );
	cipher_ok ( &aes_256_ecb );
	cipher_ok ( &aes_256_cbc );

	/* Speed tests */
	for ( keylen = 128 ; keylen <= 256 ; keylen += 64 ) {
		DBG ( "AES-%d-ECB encryption required %ld cycles per byte\n",
		      keylen, cipher_cost_encrypt ( ecb, ( keylen / 8 ) ) );
		DBG ( "AES-%d-ECB decryption required %ld cycles per byte\n",
		      keylen, cipher_cost_decrypt ( ecb, ( keylen / 8 ) ) );
		DBG ( "AES-%d-CBC encryption required %ld cycles per byte\n",
		      keylen, cipher_cost_encrypt ( cbc, ( keylen / 8 ) ) );
		DBG ( "AES-%d-CBC decryption required %ld cycles per byte\n",
		      keylen, cipher_cost_decrypt ( cbc, ( keylen / 8 ) ) );
	}
}

/** AES self-test */
struct self_test aes_test __self_test = {
	.name = "aes",
	.exec = aes_test_exec,
};
