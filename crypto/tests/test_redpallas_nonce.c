/* Exercise the exact static nonce helper; dead-section elimination keeps
 * unrelated signing code out of this focused secret-flow executable. */
#include "../redpallas.c"
#include "redpallas_nonce_vectors.h"
#include <stdio.h>

#if VALGRIND
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>
#endif

int main(void) {
  pallas_ct_counts baseline = {0};
#if VALGRIND
  if (!RUNNING_ON_VALGRIND) return 2;
#endif
  for (size_t i = 0; i < sizeof(nonce_vectors) / sizeof(nonce_vectors[0]); i++) {
    uint8_t input[64], result[32];
    bignum256 scalar;
    pallas_ct_counts counts;
    memcpy(input, nonce_vectors[i].input, sizeof(input));
    pallas_ct_test_reset_counts();
#if VALGRIND
    VALGRIND_MAKE_MEM_UNDEFINED(input, sizeof(input));
#endif
    pallas_from_uniform_bytes(input, &scalar);
    bn_write_le(&scalar, result);
    pallas_ct_test_get_counts(&counts);
#if VALGRIND
    VALGRIND_MAKE_MEM_DEFINED(input, sizeof(input));
    VALGRIND_MAKE_MEM_DEFINED(result, sizeof(result));
    VALGRIND_MAKE_MEM_DEFINED(&scalar, sizeof(scalar));
#endif
    if (memcmp(result, nonce_vectors[i].expected, sizeof(result)) != 0) {
      fprintf(stderr, "nonce reduction vector %zu failed\n", i);
      return 1;
    }
    /* Zero counts mean the variable-time helpers ran: equal schedules alone
     * would still match. */
    if (counts.field_mul == 0) {
      fprintf(stderr, "nonce reduction bypassed fixed-schedule arithmetic\n");
      return 1;
    }
    if (i == 0) baseline = counts;
    if (memcmp(&baseline, &counts, sizeof(counts)) != 0) {
      fprintf(stderr, "nonce reduction schedule changed at vector %zu\n", i);
      return 1;
    }
    memzero(&scalar, sizeof(scalar));
  }
  printf("RedPallas nonce reduction: %zu vectors and equal schedules PASS\n",
         sizeof(nonce_vectors) / sizeof(nonce_vectors[0]));
  return 0;
}
