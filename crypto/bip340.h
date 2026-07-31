/**
 * Copyright (c) 2021 The Bitcoin ABC developers
 * Copyright (c) 2026 KeepKey
 *
 * BIP-340 Schnorr signatures over secp256k1, as used by Taproot (BIP-341).
 * Derived from schnorr.h.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __BIP340_H__
#define __BIP340_H__

#include <stddef.h>
#include <stdint.h>

#include "ecdsa.h"
#include "sha2.h"

/* A BIP-340 signature is always 64 bytes: bytes(R.x) || bytes(s) */
#define BIP340_SIG_LENGTH 64

/* BIP-340 public keys are x-only */
#define BIP340_XONLY_LENGTH 32

/** Start a BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || ...).
 *
 * The caller streams the message with sha256_Update() and finishes with
 * sha256_Final().  Exposed because BIP-341 sighash and BIP-86 key tweaking
 * both need to hash more data than fits in a single buffer.
 */
void bip340_tagged_hash_init(SHA256_CTX *ctx, const char *tag);

/** One-shot BIP-340 tagged hash of a contiguous message. */
void bip340_tagged_hash(const char *tag, const uint8_t *msg, size_t msg_len,
                        uint8_t hash[SHA256_DIGEST_LENGTH]);

/** Derive the x-only public key for a private key.
 *
 * Returns 0 on success.  pub_key is zeroed on failure, as with bip340_sign().
 */
int bip340_get_xonly_pubkey(const ecdsa_curve *curve, const uint8_t *priv_key,
                            uint8_t pub_key[BIP340_XONLY_LENGTH]);

/** BIP-341 taproot_tweak_pubkey with an empty merkle root.
 *
 * Q = lift_x(internal) + int(tagged_hash("TapTweak", internal)) * G, which is
 * the key-path-only case every BIP-86 wallet address uses.  There is no
 * script-tree variant here because nothing needs one yet.
 *
 *  In:  internal: x-only internal public key
 *  Out: output:   x-only output public key, the P2TR witness program
 *
 * Returns 0 on success, nonzero on failure.
 */
int bip340_tweak_pubkey(const ecdsa_curve *curve,
                        const uint8_t internal[BIP340_XONLY_LENGTH],
                        uint8_t output[BIP340_XONLY_LENGTH]);

/** Produce a BIP-340 signature over msg.
 *
 *  In:  priv_key: 32 bytes, must be in [1, n-1]
 *       msg:      message of msg_len bytes (a 32-byte sighash, for Taproot)
 *       aux:      32 bytes of auxiliary randomness, or NULL for 32 zero bytes
 *  Out: sig:      BIP340_SIG_LENGTH bytes, zeroed on failure
 *
 * Returns 0 on success, nonzero on failure.
 */
int bip340_sign(const ecdsa_curve *curve, const uint8_t *priv_key,
                const uint8_t *msg, size_t msg_len, const uint8_t *aux,
                uint8_t *sig);

/** Verify a BIP-340 signature against an x-only public key.
 *
 * Returns 0 if the signature is valid, nonzero otherwise.
 */
int bip340_verify(const ecdsa_curve *curve,
                  const uint8_t pub_key[BIP340_XONLY_LENGTH],
                  const uint8_t *msg, size_t msg_len, const uint8_t *sig);

#endif
