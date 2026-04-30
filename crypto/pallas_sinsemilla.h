/**
 * Copyright (c) 2026 KeepKey
 *
 * Minimal Sinsemilla primitives needed for Zcash Orchard key derivation.
 */

#ifndef __PALLAS_SINSEMILLA_H__
#define __PALLAS_SINSEMILLA_H__

#include <stdint.h>

/*
 * Compute Commit^ivk.Output = SinsemillaShortCommit(
 *     "z.cash:Orchard-CommitIvk", I2LEBSP_255(ak) || I2LEBSP_255(nk), rivk)
 *
 * ak and nk are canonical Pallas base-field encodings. rivk is a canonical
 * Pallas scalar-field encoding. ivk_out receives the 32-byte LE Pallas
 * base-field output; callers must reject zero where required by Orchard IVKs.
 */
int pallas_sinsemilla_commit_ivk(const uint8_t ak[32], const uint8_t nk[32],
                                 const uint8_t rivk[32],
                                 uint8_t ivk_out[32]);

#endif
