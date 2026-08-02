/**
 * Copyright (c) 2021 The Bitcoin ABC developers
 * Copyright (c) 2026 KeepKey
 *
 * BIP-340 Schnorr signatures over secp256k1.
 *
 * Derived from schnorr.c (Bitcoin ABC's BCH variant), with the four
 * differences BIP-340 mandates: even-y selection instead of a Jacobi symbol
 * test, tagged-hash nonce derivation instead of RFC6979, an x-only public key
 * in the challenge, and negation of the private key when P has odd y.
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

#include "bip340.h"

#include <string.h>

#include "bignum.h"
#include "memzero.h"

void bip340_tagged_hash_init(SHA256_CTX *ctx, const char *tag) {
  uint8_t tag_hash[SHA256_DIGEST_LENGTH] = {0};

  sha256_Raw((const uint8_t *)tag, strlen(tag), tag_hash);

  sha256_Init(ctx);
  sha256_Update(ctx, tag_hash, sizeof(tag_hash));
  sha256_Update(ctx, tag_hash, sizeof(tag_hash));
}

void bip340_tagged_hash(const char *tag, const uint8_t *msg, size_t msg_len,
                        uint8_t hash[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx = {0};

  bip340_tagged_hash_init(&ctx, tag);
  sha256_Update(&ctx, msg, msg_len);
  sha256_Final(&ctx, hash);
}

int bip340_get_xonly_pubkey(const ecdsa_curve *curve, const uint8_t *priv_key,
                            uint8_t pub_key[BIP340_XONLY_LENGTH]) {
  uint8_t compressed[33] = {0};

  if (ecdsa_get_public_key33(curve, priv_key, compressed) != 0) {
    memzero(pub_key, BIP340_XONLY_LENGTH);
    return 1;
  }

  memcpy(pub_key, compressed + 1, BIP340_XONLY_LENGTH);
  return 0;
}

// t = int(tagged_hash("TapTweak", internal || merkle_root)).  merkle_root is
// NULL for the key-path-only case (BIP-86), where the hash covers the internal
// key alone.  BIP-341 requires t < n.
static int calc_tweak(const ecdsa_curve *curve,
                      const uint8_t internal[BIP340_XONLY_LENGTH],
                      const uint8_t *merkle_root, bignum256 *t) {
  SHA256_CTX ctx = {0};
  uint8_t tweak[SHA256_DIGEST_LENGTH] = {0};

  bip340_tagged_hash_init(&ctx, "TapTweak");
  sha256_Update(&ctx, internal, BIP340_XONLY_LENGTH);
  if (merkle_root != NULL) {
    sha256_Update(&ctx, merkle_root, 32);
  }
  sha256_Final(&ctx, tweak);

  bn_read_be(tweak, t);
  return bn_is_less(t, &curve->order) ? 0 : 1;
}

int bip340_tweak_pubkey(const ecdsa_curve *curve,
                        const uint8_t internal[BIP340_XONLY_LENGTH],
                        const uint8_t *merkle_root,
                        uint8_t output[BIP340_XONLY_LENGTH]) {
  uint8_t compressed[33] = {0};
  curve_point P = {0}, T = {0};
  bignum256 t = {0};

  // t == 0 needs no special case: scalar_multiply() returns the point at
  // infinity and point_add() then leaves P alone, giving Q = P as the spec
  // says.
  if (calc_tweak(curve, internal, merkle_root, &t) != 0) {
    return 1;
  }

  // P = lift_x(internal).  ecdsa_read_pubkey rejects x >= p and x values that
  // are not on the curve.
  compressed[0] = 0x02;
  memcpy(compressed + 1, internal, BIP340_XONLY_LENGTH);
  if (!ecdsa_read_pubkey(curve, compressed, &P)) {
    return 2;
  }

  // Q = P + t * G
  if (scalar_multiply(curve, &t, &T) != 0) {
    return 3;
  }
  point_add(curve, &T, &P);
  if (point_is_infinity(&P)) {
    return 4;
  }

  bn_write_be(&P.x, output);
  return 0;
}

int bip340_tweak_seckey(const ecdsa_curve *curve,
                        const uint8_t priv_key[32],
                        const uint8_t *merkle_root, uint8_t output[32]) {
  uint8_t compressed[33] = {0};
  bignum256 d = {0}, t = {0};
  int ret = 1;

  // d0 = int(sk), rejected unless it is in [1, n-1]
  bn_read_be(priv_key, &d);
  if (bn_is_zero(&d) || !bn_is_less(&d, &curve->order)) {
    goto cleanup;
  }

  // P = d0 * G.  The compressed prefix is 0x03 exactly when P.y is odd.
  if (ecdsa_get_public_key33(curve, priv_key, compressed) != 0) {
    goto cleanup;
  }

  // d = d0 if has_even_y(P), else n - d0.  As in bip340_sign(), the bn_mod()
  // after bn_cnegate() is mandatory: the result is otherwise in [n, 2n) and
  // carries the wrong parity.
  bn_cnegate(compressed[0] == 0x03, &d, &curve->order);
  bn_mod(&d, &curve->order);

  if (calc_tweak(curve, compressed + 1, merkle_root, &t) != 0) {
    goto cleanup;
  }

  // output = (d + t) mod n
  bn_addmod(&d, &t, &curve->order);
  bn_mod(&d, &curve->order);
  if (bn_is_zero(&d)) {
    // The tweaked key would be invalid; BIP-341 leaves this to the caller.
    goto cleanup;
  }
  bn_write_be(&d, output);
  ret = 0;

cleanup:
  memzero(&d, sizeof(d));
  memzero(&t, sizeof(t));
  memzero(compressed, sizeof(compressed));
  if (ret != 0) {
    memzero(output, 32);
  }
  return ret;
}

void bip341_sighash(uint8_t hash_type, uint32_t version, uint32_t lock_time,
                    const uint8_t sha_prevouts[32],
                    const uint8_t sha_amounts[32],
                    const uint8_t sha_scriptpubkeys[32],
                    const uint8_t sha_sequences[32],
                    const uint8_t sha_outputs[32], uint32_t input_index,
                    uint8_t hash[SHA256_DIGEST_LENGTH]) {
  const uint8_t zero = 0;
  uint8_t le[4] = {0};
  SHA256_CTX ctx = {0};

  bip340_tagged_hash_init(&ctx, "TapSighash");

  sha256_Update(&ctx, &zero, 1);       // sighash epoch 0
  sha256_Update(&ctx, &hash_type, 1);  // nHashType

  // The transaction integers go out little-endian, written explicitly rather
  // than by casting so the encoding does not depend on host byte order.
  le[0] = version & 0xff;
  le[1] = (version >> 8) & 0xff;
  le[2] = (version >> 16) & 0xff;
  le[3] = (version >> 24) & 0xff;
  sha256_Update(&ctx, le, 4);  // nVersion

  le[0] = lock_time & 0xff;
  le[1] = (lock_time >> 8) & 0xff;
  le[2] = (lock_time >> 16) & 0xff;
  le[3] = (lock_time >> 24) & 0xff;
  sha256_Update(&ctx, le, 4);  // nLockTime

  sha256_Update(&ctx, sha_prevouts, 32);
  sha256_Update(&ctx, sha_amounts, 32);
  sha256_Update(&ctx, sha_scriptpubkeys, 32);
  sha256_Update(&ctx, sha_sequences, 32);
  sha256_Update(&ctx, sha_outputs, 32);

  sha256_Update(&ctx, &zero, 1);  // spend_type: no annex, no tapscript

  le[0] = input_index & 0xff;
  le[1] = (input_index >> 8) & 0xff;
  le[2] = (input_index >> 16) & 0xff;
  le[3] = (input_index >> 24) & 0xff;
  sha256_Update(&ctx, le, 4);  // input_index

  sha256_Final(&ctx, hash);
}

// e = int(tagged_hash("BIP0340/challenge", Rx || Px || msg)) mod n
static void calc_e(const ecdsa_curve *curve, const uint8_t Rx[32],
                   const uint8_t Px[BIP340_XONLY_LENGTH], const uint8_t *msg,
                   size_t msg_len, bignum256 *e) {
  SHA256_CTX ctx = {0};
  uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

  bip340_tagged_hash_init(&ctx, "BIP0340/challenge");
  sha256_Update(&ctx, Rx, 32);
  sha256_Update(&ctx, Px, BIP340_XONLY_LENGTH);
  sha256_Update(&ctx, msg, msg_len);
  sha256_Final(&ctx, hash);

  bn_read_be(hash, e);
  bn_fast_mod(e, &curve->order);
  bn_mod(e, &curve->order);
}

int bip340_sign(const ecdsa_curve *curve, const uint8_t *priv_key,
                const uint8_t *msg, size_t msg_len, const uint8_t *aux,
                uint8_t *sig) {
  static const uint8_t zero_aux[32] = {0};
  uint8_t compressed[33] = {0};
  uint8_t d_bytes[32] = {0}, t[32] = {0};
  uint8_t rand[SHA256_DIGEST_LENGTH] = {0};
  SHA256_CTX ctx = {0};
  curve_point R = {0};
  bignum256 d = {0}, k = {0}, e = {0}, s = {0};
  int ret = 1;

  // d' = int(sk), rejected unless it is in [1, n-1]
  bn_read_be(priv_key, &d);
  if (bn_is_zero(&d) || !bn_is_less(&d, &curve->order)) {
    goto cleanup;
  }

  // P = d' * G.  The compressed prefix is 0x03 exactly when P.y is odd.
  if (ecdsa_get_public_key33(curve, priv_key, compressed) != 0) {
    goto cleanup;
  }

  // d = d' if has_even_y(P), else n - d'.
  // bn_cnegate() leaves its result in [n, 2n), NOT reduced.  The bn_mod() is
  // mandatory, not defensive: n is odd, so an unreduced value carries the
  // wrong parity and any later even-y test on it silently inverts.
  bn_cnegate(compressed[0] == 0x03, &d, &curve->order);
  bn_mod(&d, &curve->order);
  bn_write_be(&d, d_bytes);

  // t = bytes(d) XOR tagged_hash("BIP0340/aux", aux).  XOR over the big-endian
  // encodings rather than the limb representation, which is redundant.
  bip340_tagged_hash("BIP0340/aux", aux ? aux : zero_aux, sizeof(zero_aux), t);
  for (size_t i = 0; i < sizeof(t); i++) {
    t[i] ^= d_bytes[i];
  }

  // rand = tagged_hash("BIP0340/nonce", t || bytes(P.x) || msg)
  bip340_tagged_hash_init(&ctx, "BIP0340/nonce");
  sha256_Update(&ctx, t, sizeof(t));
  sha256_Update(&ctx, compressed + 1, BIP340_XONLY_LENGTH);
  sha256_Update(&ctx, msg, msg_len);
  sha256_Final(&ctx, rand);

  // k' = int(rand) mod n, which must be nonzero
  bn_read_be(rand, &k);
  bn_fast_mod(&k, &curve->order);
  bn_mod(&k, &curve->order);
  if (bn_is_zero(&k)) {
    goto cleanup;
  }

  // R = k' * G;  k = k' if has_even_y(R), else n - k'
  if (scalar_multiply(curve, &k, &R) != 0) {
    goto cleanup;
  }
  bn_cnegate(bn_is_odd(&R.y), &k, &curve->order);
  bn_mod(&k, &curve->order);  // see the note on the bn_cnegate() above

  bn_write_be(&R.x, sig);

  calc_e(curve, sig, compressed + 1, msg, msg_len, &e);

  // s = (k + e * d) mod n
  bn_copy(&d, &s);
  bn_multiply(&e, &s, &curve->order);
  bn_addmod(&s, &k, &curve->order);
  bn_mod(&s, &curve->order);
  bn_write_be(&s, sig + 32);

  // BIP-340 recommends verifying before releasing the signature: a glitched
  // scalar multiplication would otherwise hand out the private key.
  ret = bip340_verify(curve, compressed + 1, msg, msg_len, sig) == 0 ? 0 : 1;

cleanup:
  memzero(&d, sizeof(d));
  memzero(&k, sizeof(k));
  memzero(&s, sizeof(s));
  memzero(&ctx, sizeof(ctx));
  memzero(d_bytes, sizeof(d_bytes));
  memzero(t, sizeof(t));
  memzero(rand, sizeof(rand));
  if (ret != 0) {
    memzero(sig, BIP340_SIG_LENGTH);
  }
  return ret;
}

int bip340_verify(const ecdsa_curve *curve,
                  const uint8_t pub_key[BIP340_XONLY_LENGTH],
                  const uint8_t *msg, size_t msg_len, const uint8_t *sig) {
  uint8_t compressed[33] = {0};
  curve_point P = {0}, sG = {0}, R = {0};
  bignum256 r = {0}, s = {0}, e = {0};

  bn_read_be(sig, &r);
  bn_read_be(sig + 32, &s);

  // Invalid if r >= p or s >= n.
  if (!bn_is_less(&r, &curve->prime) || !bn_is_less(&s, &curve->order)) {
    return 1;
  }

  // P = lift_x(pub_key): the point with that x coordinate and even y.
  // ecdsa_read_pubkey rejects x >= p and x values that are not on the curve.
  compressed[0] = 0x02;
  memcpy(compressed + 1, pub_key, BIP340_XONLY_LENGTH);
  if (!ecdsa_read_pubkey(curve, compressed, &P)) {
    return 2;
  }

  calc_e(curve, sig, pub_key, msg, msg_len, &e);
  // Deviation from BIP-340, which specifies R = sG for e == 0.  The negation
  // below would turn e == 0 into n, which point_multiply() rejects outright,
  // so this branch only makes the rejection explicit.  Unreachable in
  // practice: e is a hash output, so e == 0 has probability 2^-256.
  if (bn_is_zero(&e)) {
    return 3;
  }

  // R = s * G - e * P.  s == 0 is in range per BIP-340 and needs no guard:
  // scalar_multiply() special-cases the zero scalar to the point at infinity
  // (ecdsa.c) and point_add() returns early on an infinite left operand, so
  // R = -eP falls out exactly as the spec requires.
  bn_subtract(&curve->order, &e, &e);
  if (scalar_multiply(curve, &s, &sG) != 0) {
    return 4;
  }
  if (point_multiply(curve, &e, &P, &R) != 0) {
    return 5;
  }
  point_add(curve, &sG, &R);

  if (point_is_infinity(&R)) {
    return 6;
  }
  if (bn_is_odd(&R.y)) {  // has_even_y(R)
    return 7;
  }
  if (!bn_is_equal(&r, &R.x)) {
    return 8;
  }

  return 0;
}
