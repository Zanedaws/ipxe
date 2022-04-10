/*
 * Copyright (C) 2022 Andrew Lewis <>
 * Copyright (C) 2022 Zane Dawson <>
 * Copyright (C) 2022 Christopher Prabhakar <>
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

#include <string.h>
#include <assert.h>
#include <ipxe/crypto.h>
#include <ipxe/gcm.h>

/** @file
 *
 * Galois Counter Mode
 *
 */

/**
 * XOR data blocks
 *
 * @v src		Input data
 * @v dst		Second input data and output data buffer
 * @v len		Length of data
 */
static void gcm_xor ( const void *src, void *dst, size_t len ) {
	const uint32_t *srcl = src;
	uint32_t *dstl = dst;
	unsigned int i;

	/* Assume that block sizes will always be dword-aligned, for speed */
	assert ( ( len % sizeof ( *srcl ) ) == 0 );

	for ( i = 0 ; i < ( len / sizeof ( *srcl ) ) ; i++ )
		dstl[i] ^= srcl[i];
}
/**
 * GCM mult for hash function
 *
 * @v ctx		context
 * @v src		Input data
 */
static void gcm_mult(void *ctx, const void *src){
	// Need to make context for gcm where there is room for a 128-bit input vector as well as an ouput vector
	x[16];
	output[16];

	int i, j;
	uchar lo, high , rem;
	uint64_t zg, zl;

	lo = (uchar)( x[15] & 0x0f);
	hi = (uchar)(x[15]>> 4);
	zh = ctx->HH[lo];
	zl = ctx->HL[lo];


	for( i = 15; i >= 0; i-- ) {
        lo = (uchar) ( x[i] & 0x0f );
        hi = (uchar) ( x[i] >> 4 );

		if( i != 15 ) {
            rem = (uchar) ( zl & 0x0f );
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = ( zh >> 4 );
            zh ^= (uint64_t) last4[rem] << 48;
            zh ^= ctx->HH[lo];
            zl ^= ctx->HL[lo];
        }
        rem = (uchar) ( zl & 0x0f );
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zh ^= (uint64_t) last4[rem] << 48;
        zh ^= ctx->HH[hi];
        zl ^= ctx->HL[hi];
	}
}
/**
 * GCM mult for hash function
 *
 * @v ctx		gcm context
 * @v src		Input data vector
 */
static void ghash(void *ctx, const void *src) {
	int BLOCK_SIZE = 32;
	uint8_t * hash_subkey; // 256 bit block for hashsubkey
	uint8_t * input; // input can be any number of blocks
	int input_len; // size of input in bytes
	uint8_t ghash_out[BLOCK_SIZE];
	uint8_t temp[BLOCK_SIZE];

	uint8_t * input_pos = input;

	int input_blocks = input_len / BLOCK_SIZE;

	for (int i = 0; i < input_blocks; i++)
	{
		gcm_xor(input_pos, ghash_out, BLOCK_SIZE);
		input_pos += BLOCK_SIZE;

		gf_mult(ghash_out, hash_subkey, temp);
		memcpy(ghash_out, temp, BLOCK_SIZE);
	}

	if (input + input_len > input_pos) // checking for leftover data, not full block
	{
		size_t last = input + input_len - input_pos;

		memcpy(temp, input_pos, last);
		memset(temp + last, 0, sizeof(temp) - last);

		gcm_xor(temp, ghash_out, BLOCK_SIZE);
		gf_mult(ghash_out, hash_subkey, temp);
		memcpy(ghash_out, temp, BLOCK_SIZE);
	}

}

/**
 * Encrypt data
 *
 * @v ctx		Context
 * @v src		Data to encrypt
 * @v dst		Buffer for encrypted data
 * @v len		Length of data
 * @v raw_cipher	Underlying cipher algorithm
 * @v cbc_ctx		CBC context
 */
void gcm_encrypt ( void *ctx, const void *src, void *dst, size_t len,
		   struct cipher_algorithm *raw_cipher, void *cbc_ctx ) {
	size_t blocksize = raw_cipher->blocksize;

	assert ( ( len % blocksize ) == 0 );

	while ( len ) {
		cbc_xor ( src, cbc_ctx, blocksize );
		cipher_encrypt ( raw_cipher, ctx, cbc_ctx, dst, blocksize );
		memcpy ( cbc_ctx, dst, blocksize );
		dst += blocksize;
		src += blocksize;
		len -= blocksize;
	}
}

/**
 * Decrypt data
 *
 * @v ctx		Context
 * @v src		Data to decrypt
 * @v dst		Buffer for decrypted data
 * @v len		Length of data
 * @v raw_cipher	Underlying cipher algorithm
 * @v cbc_ctx		CBC context
 */
void gcm_decrypt ( void *ctx, const void *src, void *dst, size_t len,
		   struct cipher_algorithm *raw_cipher, void *cbc_ctx ) {
	size_t blocksize = raw_cipher->blocksize;
	uint8_t next_cbc_ctx[blocksize];

	assert ( ( len % blocksize ) == 0 );

	while ( len ) {
		memcpy ( next_cbc_ctx, src, blocksize );
		cipher_decrypt ( raw_cipher, ctx, src, dst, blocksize );
		cbc_xor ( cbc_ctx, dst, blocksize );
		memcpy ( cbc_ctx, next_cbc_ctx, blocksize );
		dst += blocksize;
		src += blocksize;
		len -= blocksize;
	}
}
