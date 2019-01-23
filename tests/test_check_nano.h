#if USE_NANO
START_TEST(test_bip32_nano_vector_1)
{
    const char *mnemonic = "edge defense waste choose enrich upon flee junk siren film clown finish luggage leader kid quick brick print evidence swap drill paddle truly occur";
    const char *password = "some password";

    uint8_t seed[64];
    mnemonic_to_seed(mnemonic, password, seed, NULL);

    HDNode node;
    hdnode_from_seed(seed, sizeof(seed), ED25519_BLAKE2B_NANO_NAME, &node);
    hdnode_private_ckd_prime(&node, 44);
    hdnode_private_ckd_prime(&node, 165);
    hdnode_private_ckd_prime(&node, 0);
    hdnode_fill_public_key(&node);

    ck_assert_mem_eq(node.private_key, fromhex("3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143"), 32);
    ck_assert_mem_eq(node.public_key+1, fromhex("5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4"), 32);
}
END_TEST

START_TEST(test_base32_nano)
{
    const char *in_hex = "0000005114aad86a390897d2a91b33b931b3a59a7df9e63eb3694f9430122f5622ae505c6ff6b58e";
    const char *out = "11111nanode8ngaakzbck8smq6ru9bethqwyehomf79sae1k7xd47dkidjqzffeg";

    uint8_t in[40];
    memcpy(in, fromhex(in_hex), sizeof(in));

    char buffer[96];

    ck_assert(base32_encode(in, sizeof(in), buffer, sizeof(buffer), BASE32_ALPHABET_NANO) != NULL);
    ck_assert_str_eq(buffer, out);

    ck_assert(base32_decode(out, strlen(out), (uint8_t *)buffer, sizeof(buffer), BASE32_ALPHABET_NANO) != NULL);
    ck_assert_mem_eq(buffer, in, sizeof(in));
}
END_TEST
#endif
