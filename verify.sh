#!/bin/sh
# verify.sh — msha's digests against shasum, on the interpreter and on C.
#
#   MERE=/path/to/mere-checkout sh verify.sh [--poison]
#
#   every length 0..130     each padding shape: the 0x80 and the length in the
#                           same block (<= 55), split across two (56..63),
#                           and the block boundaries either side of 64 and 128
#   1 MiB of random bytes   many blocks, every byte value (C only: the
#                           interpreter takes minutes at this size)
#   two parts               the ...hex2 entry points, split at 0, 1, 63, 64,
#                           65 and the end -- the boundary reads a different
#                           input and must not be visible in the digest
#
# --poison builds a copy with one constant changed per digest and requires
# the checks to fail for THAT digest only: a harness that compared a digest
# with itself, or one that failed for any reason, would not pass it.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
[ -n "${MERE:-}" ] || { echo "usage: MERE=/path/to/mere-checkout sh verify.sh" >&2; exit 2; }
M="$MERE/_build/default/bin/mere.exe"
[ -x "$M" ] || { echo "verify: $M not found (dune build?)" >&2; exit 2; }
command -v shasum >/dev/null || { echo "verify: shasum not found -- cannot check" >&2; exit 2; }
CC="${CC:-cc}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/in"
python3 - "$TMP/in" <<'PY'
import os, sys
d = sys.argv[1]
for n in range(131):
    open(f"{d}/len{n}", "wb").write(bytes((i * 7 + n) % 256 for i in range(n)))
open(f"{d}/big", "wb").write(os.urandom(1 << 20))
PY

# ⚠ sh has no locals: this function's loop variable is NOT `alg`. It was, and
#   the --poison loop below also iterates `alg` -- so after the first poisoned
#   run the outer loop read the inner one's last value, and the sha1 poison
#   was judged as sha256's ("caught for the wrong reason", with sha1 failing).
run_checks() {  # $1 = directory holding msha.mere and its imports
  src="$1"
  "$M" -c "$src/msha.mere" > "$TMP/msha.c" 2>"$TMP/err" || { echo "FAIL verify: mere -c"; cat "$TMP/err"; return 1; }
  "$CC" -O2 -w "$TMP/msha.c" -o "$TMP/msha" || { echo "FAIL verify: cc"; return 1; }
  bad=0
  for d in 1 256; do
    n=0
    while [ $n -le 130 ]; do
      f="$TMP/in/len$n"
      want="$(shasum -a $d "$f" | cut -d' ' -f1)"
      got="$("$M" "$src/msha.mere" $d "$f" | cut -d' ' -f1)"
      [ "$got" = "$want" ] || { echo "FAIL sha$d (interp) length $n: $got, want $want"; bad=$((bad + 1)); }
      got="$("$TMP/msha" $d "$f" | cut -d' ' -f1)"
      [ "$got" = "$want" ] || { echo "FAIL sha$d (c) length $n: $got, want $want"; bad=$((bad + 1)); }
      n=$((n + 1))
    done
    f="$TMP/in/big"
    want="$(shasum -a $d "$f" | cut -d' ' -f1)"
    got="$("$TMP/msha" $d "$f" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || { echo "FAIL sha$d (c) 1 MiB: $got, want $want"; bad=$((bad + 1)); }
    f="$TMP/in/len130"
    want="$(shasum -a $d "$f" | cut -d' ' -f1)"
    for k in 0 1 63 64 65 130; do
      got="$("$M" "$src/msha.mere" ${d}s "$f" $k | cut -d' ' -f1)"
      [ "$got" = "$want" ] || { echo "FAIL sha$d (interp) two parts at $k: $got"; bad=$((bad + 1)); }
      got="$("$TMP/msha" ${d}s "$f" $k | cut -d' ' -f1)"
      [ "$got" = "$want" ] || { echo "FAIL sha$d (c) two parts at $k: $got"; bad=$((bad + 1)); }
    done
  done
  [ $bad -eq 0 ] || { echo "verify: $bad problem(s)"; return 1; }
  echo "ok | sha1 and sha256: 131 lengths x interp/C, 1 MiB on C, 6 split points"
}

if [ "${1:-}" = "--poison" ]; then
  for alg in 1 256; do
    mkdir -p "$TMP/p$alg"; cp "$DIR"/*.mere "$TMP/p$alg/"
    if [ $alg = 1 ]; then from='else 0xCA62C1D6 in'; to='else 0xCA62C1D7 in'; file=sha1.mere; other=256
    else from='let _ = vec_push h 0x5BE0CD19 in'; to='let _ = vec_push h 0x5BE0CD18 in'; file=sha256.mere; other=1; fi
    python3 - "$TMP/p$alg/$file" "$from" "$to" <<'PY' || { echo "FAIL poison sha$alg: fragment not found in $file"; exit 1; }
import sys
p, a, b = sys.argv[1:]
s = open(p).read()
if s.count(a) != 1: sys.exit(1)
open(p, "w").write(s.replace(a, b))
PY
    if run_checks "$TMP/p$alg" > "$TMP/poison.log" 2>&1; then echo "FAIL poison sha$alg: the broken digest passed"; exit 1; fi
    grep -q "^FAIL sha$alg " "$TMP/poison.log" || { echo "FAIL poison sha$alg: CAUGHT FOR THE WRONG REASON"; head -3 "$TMP/poison.log"; exit 1; }
    if grep -q "^FAIL sha$other " "$TMP/poison.log"; then echo "FAIL poison sha$alg: sha$other failed too"; exit 1; fi
    echo "ok | poison caught (sha$alg with one constant changed)"
  done
  echo "verify --poison: ok"; exit 0
fi

run_checks "$DIR" || exit 1
echo "verify: ok"
