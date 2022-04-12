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

static uint8_t get_bit(uint8_t byte, int index)
{
	// Returns the bit at specified index
	// 0 being LSB, 7 being MSB
	if (index > 7 || index < 0)
	{
		return -1;
	}
	uint8_t mask = 1;
	return ((byte >> index) & mask);
}

static void right_shift(uint8_t * bits, size_t byte_len)
{
	// Right shifts the bit string by 1 bit
	uint8_t append_bit = 0;
	uint8_t floating_bit = 0;

	for (int i = 0; i < (byte_len); i++)
	{	
		floating_bit = bits[i] & 0x01;
		bits[i] >>= 1;
		bits[i] |= (append_bit << 7);
		append_bit = floating_bit;
	}
}

static void gcm_inc32(uint8_t *block)
{
	//incoming block is always 256 bits
	int BLOCK_SIZE = 16;
	uint32_t * input = (uint32_t *) block;
	uint32_t val = input[(BLOCK_SIZE / 4) - 1];
	val++;
	input[(BLOCK_SIZE / 4) - 1] = val;
}

/**
 * GCM mult for hash function
 *
 * @v ctx		context
 * @v src		Input data
 */
static void gcm_mult(void *ctx __unused, const uint8_t * x, const uint8_t * y){
	// Need to make context for gcm where there is room for a 128-bit input vector as well as an ouput vector
	// Calculates x * y
	const int BLOCK_SIZE = 16;
	uint8_t output[BLOCK_SIZE];
	uint8_t y_copy[BLOCK_SIZE];

	memset(output, 0, BLOCK_SIZE);
	memcpy(y_copy, y, BLOCK_SIZE);

	for (int i = 0; i < BLOCK_SIZE; i++) // By byte
	{
		for (int j = 7; j > -1; j--) // By bit
		{
			if(get_bit(x[i], j))
			{
				gcm_xor(y_copy, output, BLOCK_SIZE);
			}

			if(y_copy[BLOCK_SIZE - 1] & 1)
			{
				right_shift(y_copy, BLOCK_SIZE);
				y_copy[0] ^= 0xe1; // Constant from NIST standards
			}
			else
			{
				right_shift(y_copy, BLOCK_SIZE);
			}
		}
	}

	/*int i, j;
	uint8_t lo, high , rem;
	//uint64_t zg, zl;

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
	}*/
}

/**
 * GCM mult for hash function
 *
 * @v ctx		gcm context
 * @v src		Input data vector
 */
static void ghash(void *ctx, const void *src) {
	int BLOCK_SIZE = 16;
	uint8_t * hash_subkey; // 128 bit block for hashsubkey
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

static void gctr(void * cipher, void * ctx, const uint8_t * nonce, const uint8_t * bit_string, size_t bit_string_len /* in bits */, uint8_t * output)
{	
	// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	
	const int BLOCK_SIZE = 16; //bytes
	struct cipher_algorithm * aes = cipher;
	uint8_t * output_pos = output;
	uint8_t * bit_string_pos = bit_string;

	if (bit_string_len == 0) 
	{
		return;
	}

	size_t n = bit_string_len / (BLOCK_SIZE * 8);
	uint8_t counter_block[BLOCK_SIZE];

	memcpy(counter_block, nonce, BLOCK_SIZE);

	for (int i = 0; i < n; i++)
	{
		cipher_encrypt(aes, ctx, counter_block, output_pos, BLOCK_SIZE);
		gcm_xor(output_pos, bit_string_pos, BLOCK_SIZE);
		bit_string_pos += BLOCK_SIZE;
		output_pos += BLOCK_SIZE;
		gcm_inc32(counter_block);
	}

	size_t last = bit_string + bit_string_len - bit_string_pos;
	uint8_t temp[BLOCK_SIZE];
	if (last)
	{
		cipher_encrypt(aes, ctx, counter_block, temp, BLOCK_SIZE); // if error, make sure to pad incoming partial block
		for (int i = 0; i < last; i++)
		{
			*output_pos++ = *bit_string_pos++ ^ temp[i];
		}
	}
}

static void gcm_init_hash_subkey(void * cipher, void * ctx, uint8_t * hash_subkey)
{
	struct cipher_algorithm * aes = cipher;
	const int BLOCK_SIZE = 16;

	memset(hash_subkey, 0, BLOCK_SIZE);
	cipher_encrypt(aes, ctx, hash_subkey, hash_subkey, BLOCK_SIZE);
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
