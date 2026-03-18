/**
 * Copyright (c) 2025 KeepKey
 *
 * Pallas elliptic curve for Zcash Orchard.
 * y^2 = x^3 + 5 over Fp
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

#ifndef __PALLAS_H__
#define __PALLAS_H__

#include <stdint.h>

#include "bignum.h"
#include "ecdsa.h"

/*
 * The ecdsa_curve struct is kept for compatibility but the generic
 * point_multiply()/bn_multiply() must NOT be used with Pallas because
 * the trezor-crypto bignum library assumes primes in [2^256 - 2^224, 2^256].
 * Use the pallas_* functions below instead.
 */
extern const ecdsa_curve pallas;

/* Pallas field prime (~254 bits) */
extern const bignum256 pallas_prime;

/* Pallas group order (~254 bits) */
extern const bignum256 pallas_order;

/* Pallas generator point G = (-1 mod p, 2) */
extern const curve_point pallas_G;

/* --- Field arithmetic mod p (Barrett reduction) --- */

/* x = k * x mod p */
void pallas_mul_mod_p(bignum256 *x, const bignum256 *k);

/* x = x mod p (simple reduction for values < 2^261) */
void pallas_mod_p(bignum256 *x);

/* x = x^(-1) mod p (Fermat's little theorem) */
void pallas_inv_mod_p(bignum256 *x);

/* res = (a + b) mod p */
void pallas_add_mod_p(const bignum256 *a, const bignum256 *b, bignum256 *res);

/* res = (a - b) mod p */
void pallas_sub_mod_p(const bignum256 *a, const bignum256 *b, bignum256 *res);

/* n = sqrt(n) mod p (Tonelli-Shanks). Returns 0 on success, -1 if no sqrt. */
int pallas_sqrt_mod_p(bignum256 *n);

/* --- Scalar arithmetic mod q (Barrett reduction) --- */

/* x = k * x mod q */
void pallas_mul_mod_q(bignum256 *x, const bignum256 *k);

/* x = x mod q (simple reduction for values < 2^261) */
void pallas_mod_q(bignum256 *x);

/* a = (a + b) mod q */
void pallas_add_mod_q(bignum256 *a, const bignum256 *b);

/* --- Point operations on Pallas curve --- */

/* res = k * G */
void pallas_scalar_mult_G(const bignum256 *k, curve_point *res);

/* res = k * P */
void pallas_point_mult(const bignum256 *k, const curve_point *p,
                       curve_point *res);

/* res = P + Q */
void pallas_point_add(const curve_point *p, const curve_point *q,
                      curve_point *res);

#endif
