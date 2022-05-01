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
#include <stdio.h>

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

	for (uint16_t i = 0; i < (byte_len); i++)
	{	
		floating_bit = bits[i] & 0x01;
		bits[i] >>= 1;
		bits[i] |= (append_bit << 7);
		append_bit = floating_bit;
	}
}

static void gcm_inc32(uint8_t *j0, uint8_t * out, size_t blocksize )
{
	memcpy(out, j0, blocksize);
	printf("Out:\n");
	for (uint16_t i = 0; i < blocksize; i++)
	{
		printf("%x", out[i]);
		if ((i + 1) % 4 == 0)
		{
			printf(" ");
		}
	}
	printf("\n");
	uint32_t input = j0[blocksize - 4] << 24 | j0[blocksize - 3] << 16 | j0[blocksize - 2] << 8 | j0[blocksize - 1];
	input++;
	out[blocksize - 4] = (input & 0xff000000) >> 24;
	out[blocksize - 3] = (input & 0x00ff0000) >> 16;
	out[blocksize - 2] = (input & 0x0000ff00) >> 8;
	out[blocksize - 1] = (input & 0x000000ff);
}

static void gcm_init_hash_subkey(void * cipher, void * ctx, uint8_t * hash_subkey)
{
	struct cipher_algorithm * aes_cipher = cipher;
	size_t blocksize = aes_cipher->blocksize;

	memset(hash_subkey, 0, blocksize);
	struct aes_context * aes = (struct aes_context *) ctx;
	DBGC(aes, "Called cipher encrypt from gcm init hash subkey\n");
	cipher_encrypt(aes_cipher, ctx, hash_subkey, hash_subkey, blocksize);
}

/**
 * GCM mult for hash function
 *
 * @v ctx		context
 * @v src		Input data
 */
static void gcm_mult( uint8_t * x, uint8_t * y, uint8_t * output, size_t blocksize){
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

static void ghash(uint8_t * hash_subkey, const uint8_t *input, int input_len, uint8_t * output, size_t blocksize) {

	// input can be any number of blocks
	// size of input in bytes
	//uint8_t ghash_out[blocksize];

	uint8_t temp[blocksize];
	const uint8_t * input_pos = input;
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

static void gcm_create_j0(uint8_t * hash_subkey __unused, uint8_t * iv, size_t iv_len, uint8_t * j0, size_t blocksize)
{	
	//if (iv_len == 12)
	//{
	memset(j0, 0, blocksize);
	for (uint16_t i = 0; i < iv_len; i++)
	{
		j0[i] = iv[i];
	}
	//memcpy(j0, iv, iv_len);
	j0[15] = 1;
	
	/*}
	else
	{
		memset(j0, 0, blocksize);
		ghash(hash_subkey, iv, iv_len, j0, blocksize);
		memset(len_buffer, 0, 8);
		uint32_t iv_bits = iv_len * 8;
		memcpy(len_buffer + 12, &iv_bits, sizeof(iv_bits)); 
		ghash(hash_subkey, len_buffer, sizeof(len_buffer), j0, blocksize);
	}*/
}

static void gcm_create_s(uint8_t * hash_subkey, uint8_t * auth_data, size_t aad_len, const uint8_t * ciphertext, size_t ciphertext_len, uint8_t * s, size_t blocksize)
{
	//uint8_t len_buffer[blocksize]; 

	uint8_t len_buf[blocksize];
	memset(len_buf, 0, blocksize);
	memset(s, 0, blocksize);
	ghash(hash_subkey, auth_data, aad_len, s, blocksize);
	ghash(hash_subkey, ciphertext, ciphertext_len, s, blocksize);
	uint32_t mask = 0xe0000000;

	uint32_t aad_len_temp[2];
	aad_len_temp[0] = 0;
	aad_len_temp[1] = aad_len;
	aad_len_temp[0] = (aad_len_temp[1] & mask) >> 29;
	aad_len_temp[1] <<= 3;

	uint32_t cipher_len_temp[2];
	cipher_len_temp[0] = 0;
	cipher_len_temp[1] = ciphertext_len;
	cipher_len_temp[0] = (cipher_len_temp[1] & mask) >> 29;
	cipher_len_temp[1] <<= 3;

	for(uint16_t i = 0; i < blocksize; i++)
	{
		printf("%x", len_buf[i]);
		if((i + 1) % 4 == 0)
		{
			printf(" ");
		}
	}
	printf("\n");
	memcpy(len_buf, aad_len_temp, 8);
	memcpy(len_buf + 8, cipher_len_temp, 8);
	ghash(hash_subkey, len_buf, blocksize, s, blocksize);
	// need to check for padding of aad
	/*memset(s, 0, blocksize);
	size_t pad_bytes_aad = 0;
	if (aad_len % blocksize)
	{
		pad_bytes_aad = blocksize - (aad_len % blocksize);
	}
	size_t s_temp_len = aad_len + pad_bytes_aad + ciphertext_len + 16;
	uint8_t s_temp[s_temp_len];
	memset(s_temp, 0, s_temp_len);
	size_t location = 0;

	memcpy(s_temp, auth_data, aad_len);
	location += aad_len;
	location += pad_bytes_aad;
	memcpy(s_temp + location, ciphertext, ciphertext_len);
	location += ciphertext_len;

	uint32_t mask = 0xe0000000;

	uint32_t aad_len_temp[2];
	aad_len_temp[0] = 0;
	aad_len_temp[1] = aad_len;
	aad_len_temp[0] = (aad_len_temp[1] & mask) >> 29;
	aad_len_temp[1] <<= 3;

	uint32_t cipher_len_temp[2];
	cipher_len_temp[0] = 0;
	cipher_len_temp[1] = ciphertext_len;
	cipher_len_temp[0] = (cipher_len_temp[1] & mask) >> 29;
	cipher_len_temp[1] <<= 3;

	printf("aad_len: %zx\n", aad_len);
	printf("aad_len array: %x ", aad_len_temp[0]);
	printf("%x\n", aad_len_temp[1]);

	memcpy(s_temp + location, len_buf, blocksize);*/

	/*if (sizeof(size_t) == 64)
	{
		memcpy(s_temp + location, &aad_len, 64);
		location += 64;
		memcpy(s_temp + location, &ciphertext_len, 64);
	}
	else
	{
		location += 32;
		memcpy(s_temp + location, &aad_len, 32);
		location += 64;
		memcpy(s_temp + location, &ciphertext_len, 32);
	}*/

	//ghash(hash_subkey, s_temp, s_temp_len, s, blocksize);

	/*memset(len_buffer, 0, 4);
	uint32_t aad_bits = aad_len * 8;
	memcpy(len_buffer + 4, &aad_bits, sizeof(aad_bits));
	uint32_t zero = 0;
	memcpy(len_buffer + 8, &zero, 4);
	uint32_t cipher_bits = ciphertext_len * 8;
	memcpy(len_buffer + 12, &cipher_bits, sizeof(cipher_bits)); 

	ghash(hash_subkey, len_buffer, sizeof(len_buffer), s, blocksize);*/
}

/**
 * GCM mult for hash function
 *
 * @v ctx		gcm context
 * @v src		Input data vector
 */


static void gcm_gctr(void * cipher, void * ctx, uint8_t * nonce, const uint8_t * bit_string, size_t bit_string_len, uint8_t * output)
{	
	// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	
	struct cipher_algorithm * aes_cipher = cipher;
	uint8_t * output_pos = output;
	const uint8_t * bit_string_pos = bit_string;

	size_t blocksize = aes_cipher->blocksize;

	if (bit_string_len == 0) 
	{
		return;
	}

	size_t n = bit_string_len / blocksize;
	uint8_t counter_block[blocksize];

	memcpy(counter_block, nonce, blocksize);

	for (uint16_t i = 0; i < n; i++)
	{
		cipher_encrypt(aes_cipher, ctx, counter_block, output_pos, blocksize);
		gcm_xor(bit_string_pos, output_pos, blocksize);
		bit_string_pos += blocksize;
		output_pos += blocksize;
		gcm_inc32(counter_block, counter_block, blocksize);
	}

	size_t last = bit_string + bit_string_len - bit_string_pos;
	uint8_t temp[blocksize];
	if (last)
	{
		cipher_encrypt(aes_cipher, ctx, counter_block, temp, blocksize); // if error, make sure to pad incoming partial block
		for (uint16_t i = 0; i < last; i++)
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
void gcm_encrypt_aek ( struct cipher_algorithm *raw_cipher, void *ctx, const void * src, size_t len, void * dst, uint8_t * iv, uint8_t * aad, size_t aad_len, size_t blocksize ) {
	
	// PT -> GCM -> (C, T)
	// Output: [(C0, T0), (C1, T1), ...]

	//uint8_t * iv = (uint8_t *) init_vec;
	size_t iv_len = 12;

	// outputs
	uint8_t tag[blocksize];
	uint8_t ciphertext[len];
	size_t ciphertext_len = blocksize;

	uint8_t hash_subkey[blocksize];
	uint8_t j0[blocksize];
	uint8_t j0_inc[blocksize];
	uint8_t s[blocksize];

	gcm_init_hash_subkey(raw_cipher, ctx, hash_subkey);
	gcm_create_j0(hash_subkey, iv, iv_len, j0, blocksize);

	printf("J0:\n");
	for (uint16_t i = 0; i < blocksize; i++)
	{
		printf("%x", j0[i]);
		if ((i + 1) % 4 == 0)
		{
			printf(" ");
		}
	}

	printf("\n");

	printf("aad_len main: %zd\n", aad_len);

	gcm_inc32(j0, j0_inc, blocksize);
	gcm_gctr(raw_cipher, ctx, j0_inc, src, len, ciphertext);
	gcm_create_s(hash_subkey, aad, aad_len, ciphertext, ciphertext_len, s, blocksize);
	printf("S:\n");
	for (uint16_t i = 0; i < blocksize; i++)
	{
		printf("%x", s[i]);
		if ((i + 1) % 4 == 0)
		{
			printf(" ");
		}
	}

	printf("\n");
	gcm_gctr(raw_cipher, ctx, j0, s, sizeof(s), tag); // tag should be truncated to specified tag size (which may be determined by key)

	/**
	 * Algorithm 4: GCM-AEK (IV, P, A)
		Prerequisites:
		approved block cipher CIPH with a 128-bit block size;
		key K;
		definitions of supported input-output lengths;
		supported tag length t associated with the key. 
	 * 
	 */
	memcpy(dst, ciphertext, len);
	dst += len;
	memcpy(dst, tag, blocksize);

}

int gcm_decrypt_adk ( struct cipher_algorithm *raw_cipher, void *ctx, const void * src, size_t len, void * dst, 
			uint8_t * iv, uint8_t * aad, size_t aad_len, size_t blocksize, const void * tag_in )
{
	size_t iv_len = 12;
	struct aes_context * aes = (struct aes_context *) ctx;

	// outputs
	uint8_t tag[blocksize];

	uint8_t hash_subkey[blocksize];
	uint8_t j0[blocksize];
	uint8_t j0_inc[blocksize];
	uint8_t s[blocksize];
	uint8_t * cipher_src = (uint8_t *) src;

	DBGC(aes, "Before hash\n");
	gcm_init_hash_subkey(raw_cipher, ctx, hash_subkey);
	gcm_create_j0(hash_subkey, iv, iv_len, j0, blocksize);
	gcm_inc32(j0, j0_inc, blocksize);
	gcm_gctr(raw_cipher, ctx, j0_inc, src, len, dst);

	gcm_create_s(hash_subkey, aad, aad_len, cipher_src, len, s, blocksize);
	gcm_gctr(raw_cipher, ctx, j0, s, sizeof(s), tag);

	if (memcmp(tag, tag_in, blocksize) != 0)
	{
		return -1;
	}

	return 0;
}

void gcm_encrypt ( void *ctx, const void *src, void *dst, size_t len,
			struct cipher_algorithm *raw_cipher, void * iv, void * aad, size_t aad_len )
{
	size_t blocksize = raw_cipher->blocksize;
	
	assert ( ( len % blocksize ) == 0 );

	gcm_encrypt_aek(raw_cipher, ctx, src, len, dst, iv, aad, aad_len, blocksize);
	/*while (len)
	{
		gcm_encrypt_aek(raw_cipher, ctx, src, len, dst, gcm_ctx, aes->aad, aes->aad_len, blocksize);
		dst += blocksize; // two blocks of output are created from 1 block of input (plaintext -> ciphertext, tag), first increment is within gcm_encrypt_aek
		src += blocksize;
		len -= blocksize;
	}*/
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
		   struct cipher_algorithm *raw_cipher, void * iv, void * aad, size_t aad_len ) {
	size_t blocksize = raw_cipher->blocksize;

	assert ( ( len % blocksize ) == 0 );

	gcm_decrypt_adk(raw_cipher, ctx, src, len, dst, iv, aad, aad_len, blocksize, src + blocksize);
	/*while ( len ) {
		gcm_decrypt_adk(raw_cipher, ctx, src, len, dst, gcm_ctx, context->aad, context->aad_len, blocksize, src + blocksize);
		dst += blocksize;
		src += (2 * blocksize);
		len -= blocksize;
	}*/
}
