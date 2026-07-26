# KeepKey trezor-crypto downstream

This `crypto/` subtree is the cryptographic dependency consumed by KeepKey
firmware through the `keepkey/trezor-firmware` submodule. KeepKey release
commits pin this repository by immutable commit SHA.

## Provenance

- Previous RC18 crypto pin: `keepkey/trezor-firmware@0837875b9f5ce29f5d29f2a8ad3798787bd25b61`
- Orchard/AES baseline: `keepkey/trezor-firmware@56f404e452bc7738cd3b3e14454dfecb25c083bf`
- Upstream audit reference: `trezor/trezor-firmware@90e07df785d6b812e030cf841f75d8a641ab466b`
- Audit date: 2026-07-25
- License: MIT; see `LICENSE`

The baseline contains the KeepKey AES-small-tables and Orchard/Pallas work.
The release branch additionally contains the security backports, constant-time
Pallas implementation, and KeepKey adaptations recorded in
`SECURITY_BACKPORTS.md` and its commit history.

The complete `crypto/` subtree is retained, including its tests. KeepKey
firmware does not compile or release Trezor Core, Legacy firmware, Python,
storage, or other monorepo components from this repository.

## Updating

Do not treat a mechanical monorepo merge as a security review. Audit crypto
changes explicitly:

1. Fetch `https://github.com/trezor/trezor-firmware.git`.
2. Review `git log --no-merges <last-audited-sha>..upstream/main -- crypto`.
3. Classify each correctness or security change for the KeepKey build and
   document the decision in `SECURITY_BACKPORTS.md`.
4. Apply applicable changes in an isolated branch, preserving upstream commit
   IDs in commit messages.
5. Run the standalone optimized, sanitizer, and secret-taint suites.
6. Pin the tested commit in KeepKey firmware and run the complete regular and
   bitcoin-only firmware matrices.

At the RC18 audit point, this fork was 7,996 commits behind the Trezor
monorepo, while the KeepKey default branch carried 30 downstream commits that
touched 18 crypto files. A mechanical merge produced six direct conflicts on
the RC18 baseline, but modern upstream crypto differed from the tested RC18
tree across 156 files. Upstream synchronization is therefore tracked as a
separate modernization effort rather than mixed into the RC18 release.

## Standalone verification

From this repository's `crypto/` directory on macOS with Homebrew `check`:

```sh
make clean
make VALGRIND=0 \
  OPTFLAGS='-O3 -g -I/opt/homebrew/include -Wno-error=unterminated-string-initialization' \
  tests/test_check tests/test_pallas_ct
./tests/test_check
./tests/test_pallas_ct
```

ASan and UBSan:

```sh
make clean
make CC='clang -fsanitize=address,undefined' VALGRIND=0 \
  OPTFLAGS='-O1 -g -fno-omit-frame-pointer -I/opt/homebrew/include -Wno-error=unterminated-string-initialization -Wno-error=deprecated-declarations' \
  tests/test_check tests/test_pallas_ct
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./tests/test_check
ASAN_OPTIONS=halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./tests/test_pallas_ct
```

The RC18 audit passed all 158 standalone checks in optimized and sanitizer
configurations. The dedicated Pallas constant-time harness, Valgrind secret
taint gate, KeepKey ARM build, and Cortex-M3 disassembly gate also passed.
