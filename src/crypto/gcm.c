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
#include <ipxe/aes.h>

//comment

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

static void gcm_inc32(uint8_t *block, size_t blocksize)
{
	uint32_t * input = (uint32_t *) block;
	uint32_t val = input[(blocksize / 4) - 1];
	val++;
	input[(blocksize / 4) - 1] = val;
}

static void gcm_init_hash_subkey(void * cipher, void * ctx, uint8_t * hash_subkey)
{
	struct cipher_algorithm * aes = cipher;
	size_t blocksize = aes->blocksize;

	memset(hash_subkey, 0, blocksize);
	cipher_encrypt(aes, ctx, hash_subkey, hash_subkey, blocksize);
}

static void gcm_create_j0(void * ctx, uint8_t * hash_subkey, uint8_t * j0, size_t blocksize)
{
	struct aes_gcm_context * context = ctx;
	uint8_t * iv;
	size_t iv_len;

	uint8_t len_buffer[blocksize]; 
	
	if (iv_len == 12)
	{
		memcpy(j0, iv, iv_len);
		memset(j0 + iv_len, 0, blocksize - iv_len);
		j0[blocksize - 1] = 0x01;
	}
	else
	{
		memset(j0, 0, blocksize);
		ghash(ctx, hash_subkey, iv, iv_len, j0, blocksize);
		memset(len_buffer, 0, 8);
		uint32_t iv_bits = iv_len * 8;
		memcpy(len_buffer + 12, &iv_bits, sizeof(iv_bits)); 
		ghash(ctx, hash_subkey, len_buffer, sizeof(len_buffer), j0, blocksize);
	}
}

static void gcm_create_s(void * ctx, uint8_t * hash_subkey, uint8_t * auth_data, size_t aad_len, uint8_t * ciphertext, size_t ciphertext_len, uint8_t * s, size_t blocksize)
{
	uint8_t len_buffer[blocksize]; 

	// need to check for padding of aad
	memset(s, 0, blocksize);

	if (aad_len)
	{
		size_t pad_bytes = blocksize - (aad_len % blocksize);
		uint8_t new_aad[aad_len + pad_bytes];
		memset(new_aad, 0, aad_len + pad_bytes);
		memcpy(new_aad, auth_data, aad_len);
		ghash(ctx, hash_subkey, new_aad, aad_len + pad_bytes, s, blocksize); // is length of aad passed into ghash orig length or padded length?
	}

	ghash(ctx, hash_subkey, ciphertext, ciphertext_len, s, blocksize);

	memset(len_buffer, 0, 4);
	uint32_t aad_bits = aad_len * 8;
	memcpy(len_buffer + 4, &aad_bits, sizeof(aad_bits));
	uint32_t zero = 0;
	memcpy(len_buffer + 8, &zero, 4);
	uint32_t cipher_bits = ciphertext_len * 8;
	memcpy(len_buffer + 12, &cipher_bits, sizeof(cipher_bits)); 

	ghash(ctx, hash_subkey, len_buffer, sizeof(len_buffer), s, blocksize);
}

/**
 * GCM mult for hash function
 *
 * @v ctx		context
 * @v src		Input data
 */
static void gcm_mult(const uint8_t * x, const uint8_t * y, uint8_t * output, size_t blocksize){
	// Need to make context for gcm where there is room for a 128-bit input vector as well as an ouput vector
	// Calculates x * y
	//uint8_t temp[blocksize];
	uint8_t y_copy[blocksize];

	memset(output, 0, blocksize);
	memcpy(y_copy, y, blocksize);

	for (uint16_t i = 0; i < blocksize; i++) // By byte
	{
		for (int j = 7; j > -1; j--) // By bit
		{
			if(get_bit(x[i], j))
			{
				gcm_xor(y_copy, output, blocksize);
			}

			if(y_copy[blocksize - 1] & 1)
			{
				right_shift(y_copy, blocksize);
				y_copy[0] ^= 0xe1; // Constant from NIST standards
			}
			else
			{
				right_shift(y_copy, blocksize);
			}
		}
	}
}

/**
 * GCM mult for hash function
 *
 * @v ctx		gcm context
 * @v src		Input data vector
 */
static void ghash(void *ctx, uint8_t * hash_subkey, const uint8_t *input, const int input_len, uint8_t * output, size_t blocksize) {

	// input can be any number of blocks
	// size of input in bytes
	//uint8_t ghash_out[blocksize];

	uint8_t temp[blocksize];
	uint8_t * input_pos = input;
	int input_blocks = input_len / blocksize;

	memset(output, 0, blocksize);

	for (int i = 0; i < input_blocks; i++)
	{
		gcm_xor(input_pos, output, blocksize);
		input_pos += blocksize;

		gcm_mult(hash_subkey, output, temp, blocksize);
		memcpy(output, temp, blocksize);
	}

	if (input + input_len > input_pos) // checking for leftover data, not full block
	{
		size_t last = input + input_len - input_pos;

		memcpy(temp, input_pos, last);
		memset(temp + last, 0, sizeof(temp) - last);

		gcm_xor(temp, output, blocksize);
		gcm_mult(output, hash_subkey, temp, blocksize);
		memcpy(output, temp, blocksize);
	}

}

static void gcm_gctr(void * cipher, void * ctx, const uint8_t * nonce, uint8_t * bit_string, size_t bit_string_len, uint8_t * output)
{	
	// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	
	struct cipher_algorithm * aes = cipher;
	uint8_t * output_pos = output;
	uint8_t * bit_string_pos = bit_string;

	size_t blocksize = aes->blocksize;

	if (bit_string_len == 0) 
	{
		return;
	}

	size_t n = bit_string_len / blocksize;
	uint8_t counter_block[blocksize];

	memcpy(counter_block, nonce, blocksize);

	for (uint16_t i = 0; i < n; i++)
	{
		cipher_encrypt(aes, ctx, counter_block, output_pos, blocksize);
		gcm_xor(output_pos, bit_string_pos, blocksize);
		bit_string_pos += blocksize;
		output_pos += blocksize;
		gcm_inc32(counter_block, blocksize);
	}

	size_t last = bit_string + bit_string_len - bit_string_pos;
	uint8_t temp[blocksize];
	if (last)
	{
		cipher_encrypt(aes, ctx, counter_block, temp, blocksize); // if error, make sure to pad incoming partial block
		for (int i = 0; i < last; i++)
		{
			*output_pos++ = *bit_string_pos++ ^ temp[i];
		}
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
<<<<<<< HEAD
void gcm_encrypt_aek ( struct cipher_algorithm *raw_cipher, void *ctx, const void * src, size_t len, void * dst, uint8_t * iv, uint8_t * aad, size_t aad_len, size_t blocksize ) {
	
	struct aes_context * context = ctx;
=======
void gcm_encrypt ( void *ctx, const void *src, void *dst, size_t len,
		   struct cipher_algorithm *raw_cipher, void *gcm_ctx ) {
	size_t blocksize = raw_cipher->blocksize;

	assert ( ( len % blocksize ) == 0 );
>>>>>>> 7626c2c47497f6004165b6472f4c5c81b63cc0be

	// inputs;
	uint8_t * key = context->encrypt.key;
	size_t key_len;

	switch ( context->rounds ) {
	case ( 11 ) :
		key_len = 128 / 8;
		break;
	case ( 13 ) :
		key_len = 192 / 8;
		break;
	case ( 15 ) :
		key_len = 256 / 8;
		break;
	default:
		key_len = -1;
	}

	// PT -> GCM -> (C, T)
	// Output: [(C0, T0), (C1, T1), ...]

	//uint8_t * iv = (uint8_t *) init_vec;
	size_t iv_len = blocksize;

	uint8_t * add_auth_data;
	size_t aad_len;

	// outputs
	uint8_t tag[blocksize];
	uint8_t ciphertext[blocksize];
	size_t ciphertext_len = blocksize;

	uint8_t hash_subkey[blocksize];
	uint8_t j0[blocksize];
	uint8_t s[blocksize];

	gcm_init_hash_subkey(raw_cipher, ctx, hash_subkey);
	gcm_create_j0(ctx, hash_subkey, j0, blocksize);

	gcm_inc32(j0, blocksize);
	gcm_gctr(raw_cipher, ctx, j0, src, len, ciphertext);
	gcm_create_s(ctx, hash_subkey, add_auth_data, aad_len, ciphertext, ciphertext_len, s, blocksize);
	gcm_gctr(raw_cipher, ctx, j0, s, sizeof(s), tag);
}

void gcm_encrypt ( void *ctx, const void *src, void *dst, size_t len,
		   struct cipher_algorithm *raw_cipher, void *gcm_ctx )
{
	size_t blocksize = raw_cipher->blocksize;
	struct aes_context * context = ctx;

	assert ( ( len % blocksize ) == 0 );

	while (len)
	{
		gcm_encrypt_aek(raw_cipher, ctx, src, len, dst, gcm_ctx, context->aad, context->aad_len, blocksize);
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
