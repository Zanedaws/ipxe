#ifndef _IPXE_GCM_H
#define _IPXE_GCM_H

/** @file
 *
 * Galois Counter Mode
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <ipxe/crypto.h>
#include <ipxe/aes.h>

/**
 * Set key
 *
 * @v ctx		Context
 * @v key		Key
 * @v keylen		Key length
 * @v raw_cipher	Underlying cipher algorithm
 * @v gcm_ctx		GCM context
 * @ret rc		Return status code
 */
static inline int gcm_setkey ( void *ctx, const void *key, size_t keylen,
			       struct cipher_algorithm *raw_cipher,
			       void *gcm_ctx __unused ) {

	return cipher_setkey ( raw_cipher, ctx, key, keylen );
}

/**
 * Set initialisation vector
 *
 * @v ctx		Context
 * @v iv		Initialisation vector
 * @v raw_cipher	Underlying cipher algorithm
 * @v gcm_ctx		GCM context
 */
static inline void gcm_setiv ( void *ctx __unused, const void *iv,
			       struct cipher_algorithm *raw_cipher __unused,
			       void *gcm_ctx ) {
	memcpy ( gcm_ctx, iv, 12 );
}

static inline void gcm_setaad ( void * ctx __unused, const void *aad, size_t aad_len, struct cipher_algorithm *raw_cipher __unused, void * gcm_ctx)
{
	if (aad_len > 512)
		aad_len = 512;

	memcpy ( gcm_ctx, aad, aad_len );
}

extern void gcm_encrypt ( void *ctx, const void *src, void *dst,
			  size_t len, struct cipher_algorithm *raw_cipher,
			  void *iv, void * aad, size_t aad_len );
extern void gcm_decrypt ( void *ctx, const void *src, void *dst,
			  size_t len, struct cipher_algorithm *raw_cipher,
			  void *iv, void * aad, size_t aad_len  );

/**
 * Create a cipher-block chaining mode of behaviour of an existing cipher
 *
 * @v _gcm_name		Name for the new GCM cipher
 * @v _gcm_cipher	New cipher algorithm
 * @v _raw_cipher	Underlying cipher algorithm
 * @v _raw_context	Context structure for the underlying cipher
 * @v _blocksize	Cipher block size
 */

// GCM_CIPHER ( aes_gcm, aes_gcm_algorithm,  aes_algorithm, struct aes_context, AES_BLOCKSIZE );

#define GCM_CIPHER( _gcm_name, _gcm_cipher, _raw_cipher, _raw_context,	\
		    _blocksize )					\
struct _gcm_name ## _context {						\
	_raw_context raw_ctx;						\
	uint8_t iv[12];					\
	uint8_t aad[512];					\
	size_t aad_len;					\
};									\
static int _gcm_name ## _setkey ( void *ctx, const void *key,		\
				  size_t keylen ) {			\
	struct _gcm_name ## _context * _gcm_name ## _ctx = ctx;		\
	return gcm_setkey ( &_gcm_name ## _ctx->raw_ctx, key, keylen,	\
			    &_raw_cipher, &_gcm_name ## _ctx );\
}									\
static void _gcm_name ## _setiv ( void *ctx, const void *iv ) {		\
	struct _gcm_name ## _context * _gcm_name ## _ctx = ctx;		\
	gcm_setiv ( &_gcm_name ## _ctx->raw_ctx, iv,			\
		    &_raw_cipher, &aes_gcm_ctx->iv );		\
}									\
static void _gcm_name ## _setaad ( void * ctx, const void * aad, size_t aad_len) {	\
	struct _gcm_name ## _context * _gcm_name ## _ctx = ctx;					\
	aes_gcm_ctx->aad_len = aad_len;	\
	gcm_setaad ( &_gcm_name ## _ctx->raw_ctx, aad, aad_len, &_raw_cipher, &aes_gcm_ctx->aad ); \
}						\
static void _gcm_name ## _encrypt ( void *ctx, const void *src,		\
				    void *dst, size_t len ) {		\
	struct _gcm_name ## _context * _gcm_name ## _ctx = ctx;		\
	gcm_encrypt ( &_gcm_name ## _ctx->raw_ctx, src, dst, len,	\
		      &_raw_cipher, &aes_gcm_ctx->iv, &aes_gcm_ctx->aad, aes_gcm_ctx->aad_len);		\
}									\
static void _gcm_name ## _decrypt ( void *ctx, const void *src,		\
				    void *dst, size_t len ) {		\
	struct _gcm_name ## _context * _gcm_name ## _ctx = ctx;		\
	gcm_decrypt ( &_gcm_name ## _ctx->raw_ctx, src, dst, len,	\
		      &_raw_cipher, &aes_gcm_ctx->iv, &aes_gcm_ctx->aad, aes_gcm_ctx->aad_len );		\
}									\
struct cipher_algorithm _gcm_cipher = {					\
	.name		= #_gcm_name,					\
	.ctxsize	= sizeof ( struct _gcm_name ## _context ),	\
	.blocksize	= _blocksize,					\
	.setkey		= _gcm_name ## _setkey,				\
	.setiv		= _gcm_name ## _setiv,				\
	.setaad	    = _gcm_name ## _setaad,			\
	.encrypt	= _gcm_name ## _encrypt,			\
	.decrypt	= _gcm_name ## _decrypt,			\
};

#endif /* _IPXE_GCM_H */
