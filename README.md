# msha

SHA-1 and SHA-256 in pure [Mere](https://github.com/merelang/mere), over `bytes`.

```
import "msha/sha1.mere";      // sha1_hex  : bytes -> str
                              // sha1_hex2 : bytes -> bytes -> str
import "msha/sha256.mere";    // sha256_hex, sha256_hex2
```

`..._hex2 a b` is the digest of `a ++ b` without building `a ++ b`. It exists
for git, whose object id is the SHA-1 of a short header followed by the whole
content. Padding is never built either: each byte of the padded message is
computed, so hashing uses the memory of the message schedule and nothing more.

Both run on the interpreter (63-bit int) and on C. Every intermediate stays
below 2^62, which is why the interpreter's narrower int still gives the same
digests; verify.sh asks both.

## The CLI

```
msha 1 <file>          # like `shasum -a 1`
msha 256 <file>        # like `shasum -a 256`
msha 1s <file> <k>     # the file hashed as two parts split at byte k
```

On C, 10 MiB hash in about 0.2 s (Apple M-series).

## Checking it

```
MERE=/path/to/mere-checkout sh verify.sh            # against shasum
MERE=/path/to/mere-checkout sh verify.sh --poison   # the checks can fail
```

Every length from 0 to 130 (each padding shape, both sides of the 64- and
128-byte boundaries) on the interpreter and C, 1 MiB of random bytes on C, and
the two-part entry points split at six places. `--poison` changes one constant
per digest and requires the checks to fail for that digest only.
