#!/usr/bin/env python3
"""
ISCC RE - "手忙脚乱" (Busy) - pure-Python solver.

Re-implements every cryptographic primitive used by attachment-62 (4).exe so
that the two 24-character plaintexts can be recovered without running the
binary. The script:

  1. Reads the raw PE file from the workspace root.
  2. Slices the six ciphertext blobs out of .rdata.
  3. Re-implements decrypt_blob (xorshift32 keystream).
  4. Asserts the decrypted blobs equal the documented reference values.
  5. Re-implements makeTable, keyBits, subChar / invSubChar,
     columnarTransposeEncrypt / Decrypt and encryptPart2 / decryptPart2
     (the latter performing TWO rounds of subChar+CTE, exactly as the binary).
  6. Self-tests every primitive with a forward+inverse round-trip.
  7. Inverts the whole encryption chain
        ct = encryptPart2( CTE(plain, K6_perm), K6 )       K6_perm = CTE(K6, K3)
     on E1 = MASK1 XOR TARGET (path-1 target) and
        E2 = MASK2 XOR TARGET_T  (path-2 target, see writeup) to recover
     the two 24-character plaintexts.
  8. Forward-verifies both recovered plaintexts.
  9. Prints both plaintexts (repr + hex) and a ready-to-paste pair of inputs.

The main() function performs all of the above and exits 0 on success.
"""

import os
import random
import sys

# -----------------------------------------------------------------------------
# PE / .rdata layout (objdump -h):
#     .rdata   VMA = 0x140008000   file offset = 0x6000
# All 6 encrypted blobs sit in .rdata, so file_off = va - 0x140008000 + 0x6000.
# -----------------------------------------------------------------------------
EXE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "attachment-62 (4).exe")
RDATA_VMA       = 0x140008000
RDATA_FILE_OFF  = 0x6000

BLOBS = [
    # name        VA            size  key
    ("CT_MASK2",    0x140008100, 24, 0x4444),
    ("CT_MASK1",    0x140008120, 24, 0x3333),
    ("CT_TARGET_T", 0x140008140, 24, 0x2222),
    ("CT_TARGET",   0x140008160, 24, 0x1111),
    ("CT_K3",       0x140008178,  3, 0x6666),
    ("CT_K6",       0x14000817B,  6, 0x5555),
]

EXPECTED = {
    "K6":       bytes.fromhex("3a7352577236"),
    "K3":       bytes.fromhex("4b7b59"),
    "MASK1":    bytes.fromhex("dd48f3ca3c53c108612f24cce4862993da5afe0bcae94380"),
    "MASK2":    bytes.fromhex("5567d4a7ebd5834b0eb26c940913e06f16faaba7fb2c8618"),
    "TARGET":   bytes.fromhex("936792b91d6d8045260113fbdcd742a8bd62bb5985ac2ee9"),
    "TARGET_T": bytes.fromhex("783f8fc6c1e6b213209d30b3702a8f4f30a283d68961ee2f"),
}


# -----------------------------------------------------------------------------
# decrypt_blob - xorshift32 keystream lifted byte-for-byte from the binary.
#
#   r9   = key XOR 0xA3B1C2D3            (initial state)
#   r8   = 0
#   r10  = 0
#   for each byte i:
#       r9 = (r9 + r8) & 0xFFFFFFFF
#       r8 = (r8 - 0x61C88647) & 0xFFFFFFFF
#       r9 ^= (r9 << 13) & 0xFFFFFFFF
#       r9 ^= (r9 >> 17)
#       r9 ^= (r9 << 5)  & 0xFFFFFFFF
#       mix = (r10 + 7*r9) & 0xFF
#       rot = (r9 >> 27) & 7              # ROR amount, modulo 8
#       al  = mix XOR ct[i]
#       al  = ROR(al, rot)
#       al  = al XOR (r9 & 0xFF)
#       out[i] = al
#       r10 = (r10 + 0xB) & 0xFFFFFFFF
# -----------------------------------------------------------------------------
def decrypt_blob(ct: bytes, key: int) -> bytes:
    MASK = 0xFFFFFFFF
    r9 = (key ^ 0xA3B1C2D3) & MASK
    r8 = 0
    r10 = 0
    out = bytearray(len(ct))
    for i in range(len(ct)):
        eax = (r9 + r8) & MASK
        r8 = (r8 - 0x61C88647) & MASK
        r9 = eax
        r9 = (r9 ^ ((r9 << 13) & MASK)) & MASK
        r9 = (r9 ^ (r9 >> 17)) & MASK
        r9 = (r9 ^ ((r9 << 5) & MASK)) & MASK

        mix = (r10 + r9 * 7) & 0xFF
        rot = (r9 >> 27) & 7
        al = (mix ^ ct[i]) & 0xFF
        if rot:
            al = ((al >> rot) | ((al << (8 - rot)) & 0xFF)) & 0xFF
        al = (al ^ (r9 & 0xFF)) & 0xFF
        out[i] = al
        r10 = (r10 + 0xB) & MASK
    return bytes(out)


# -----------------------------------------------------------------------------
# makeTable - Fisher-Yates shuffle of the 95 printable ASCII bytes 0x20..0x7E.
# Seed mixes the constant (0x1234 or 0x8888) with all bytes of K (mul by 0x83).
# Then walks the LCG `ebx = ebx*0x41C64E6D + 0x3039` to drive the swaps.
# -----------------------------------------------------------------------------
def makeTable(K: bytes, seed: int) -> bytes:
    MASK = 0xFFFFFFFF
    ebx = seed & MASK
    for c in K:
        ebx = (ebx * 0x83 + c) & MASK
    table = list(range(0x20, 0x7F))         # 95 entries: 0x20..0x7E inclusive
    for r in range(0x5E, 0, -1):            # 94, 93, ..., 1
        ebx = (ebx * 0x41C64E6D + 0x3039) & MASK
        idx = ebx % (r + 1)
        table[r], table[idx] = table[idx], table[r]
    return bytes(table)


# -----------------------------------------------------------------------------
# keyBits - MSB-first bit expansion of K (8 bits per byte).
# -----------------------------------------------------------------------------
def keyBits(K: bytes) -> list:
    bits = []
    for b in K:
        for s in range(7, -1, -1):
            bits.append((b >> s) & 1)
    return bits


# -----------------------------------------------------------------------------
# subChar - per-byte substitution. b == 0 picks T0 (seed 0x1234), b == 1 picks
# T8 (seed 0x8888). Both T0 and T8 are permutations of 0x20..0x7E so subChar
# stays within printable ASCII.
# -----------------------------------------------------------------------------
def subChar(c: int, b: int, T0: bytes, T8: bytes) -> int:
    assert 0x20 <= c <= 0x7E, f"subChar input out of range: {c:#x}"
    idx = c - 0x20
    return T0[idx] if b == 0 else T8[idx]


def invSubChar(c: int, b: int, T0: bytes, T8: bytes) -> int:
    assert 0x20 <= c <= 0x7E, f"invSubChar input out of range: {c:#x}"
    T = T0 if b == 0 else T8
    return T.index(c) + 0x20  # T is a permutation of 0x20..0x7E


# -----------------------------------------------------------------------------
# Columnar transpose (forward and inverse).
#
#   Encrypt: view M as a rows-by-N row-major matrix (rows = len(M)/len(K)).
#            Stable-sort columns 0..N-1 by K[c] ascending. Output is the
#            concatenation of each column read in that sorted order.
#
# This convention exactly matches the binary's loop layout (the per-column
# buffer "rows_arr[i]" is filled with M[i], M[N+i], M[2N+i], ...).
# -----------------------------------------------------------------------------
def columnarTransposeEncrypt(M: bytes, K: bytes) -> bytes:
    N = len(K)
    L = len(M)
    if L % N != 0:
        raise ValueError("transpose: length mismatch")
    rows = L // N
    cols = [bytes(M[r * N + i] for r in range(rows)) for i in range(N)]
    order = sorted(range(N), key=lambda i: K[i])  # stable
    return b"".join(cols[c] for c in order)


def columnarTransposeDecrypt(C: bytes, K: bytes) -> bytes:
    N = len(K)
    L = len(C)
    if L % N != 0:
        raise ValueError("transpose: length mismatch")
    rows = L // N
    order = sorted(range(N), key=lambda i: K[i])
    cols = [None] * N
    for k, c in enumerate(order):
        cols[c] = C[k * rows:(k + 1) * rows]
    return bytes(cols[i][r] for r in range(rows) for i in range(N))


# -----------------------------------------------------------------------------
# encryptPart2 - the binary actually performs TWO rounds of (subChar + CTE)
# because the bit-vector produced by keyBits(K6) is 8 * 6 = 48 bits long, and
# the per-byte loop iterates 0 .. bits.size - 1 with the buffer reset every
# 24 bytes (one full CTE). 48 / 24 = 2 rounds.
# -----------------------------------------------------------------------------
def encryptPart2(plain: bytes, K6: bytes) -> bytes:
    T0 = makeTable(K6, 0x1234)
    T8 = makeTable(K6, 0x8888)
    bits = keyBits(K6)
    L = len(plain)
    rounds = len(bits) // L
    buf = bytearray(plain)
    for r in range(rounds):
        for i in range(L):
            buf[i] = subChar(buf[i], bits[r * L + i], T0, T8)
        buf = bytearray(columnarTransposeEncrypt(bytes(buf), K6))
    return bytes(buf)


def decryptPart2(cipher: bytes, K6: bytes) -> bytes:
    T0 = makeTable(K6, 0x1234)
    T8 = makeTable(K6, 0x8888)
    bits = keyBits(K6)
    L = len(cipher)
    rounds = len(bits) // L
    buf = bytearray(cipher)
    for r in range(rounds - 1, -1, -1):
        buf = bytearray(columnarTransposeDecrypt(bytes(buf), K6))
        for i in range(L):
            buf[i] = invSubChar(buf[i], bits[r * L + i], T0, T8)
    return bytes(buf)


# -----------------------------------------------------------------------------
# Driver
# -----------------------------------------------------------------------------
def va_to_off(va: int) -> int:
    return va - RDATA_VMA + RDATA_FILE_OFF


def is_printable_ascii(b: bytes) -> bool:
    return all(0x20 <= x <= 0x7E for x in b)


def main() -> int:
    print(f"[*] Reading {EXE_PATH}")
    with open(EXE_PATH, "rb") as f:
        raw = f.read()
    print(f"    file size = {len(raw)} bytes")

    # 1) Slice and decrypt the six blobs.
    decrypted = {}
    for name, va, size, key in BLOBS:
        off = va_to_off(va)
        ct = raw[off:off + size]
        assert len(ct) == size, f"short read for {name}"
        pt = decrypt_blob(ct, key)
        decrypted[name[3:]] = pt
        print(f"    {name:<11s} va={va:#x}  off={off:#x}  size={size:>2d}  "
              f"decrypted={pt.hex()}")

    K6       = decrypted["K6"]
    K3       = decrypted["K3"]
    MASK1    = decrypted["MASK1"]
    MASK2    = decrypted["MASK2"]
    TARGET   = decrypted["TARGET"]
    TARGET_T = decrypted["TARGET_T"]

    # 2) Sanity-check decrypted blobs against the documented reference values.
    for name, expected in EXPECTED.items():
        actual = decrypted[name]
        assert actual == expected, (
            f"{name} mismatch: expected {expected.hex()}, got {actual.hex()}"
        )
    print("[+] All decrypted blobs match the documented reference values.")
    print(f"    K6 = {K6!r}   K3 = {K3!r}")

    # 3) Self-test the columnar transpose round-trip.
    rng = random.Random(0xC0FFEE)
    for trial in range(64):
        M = bytes(rng.randrange(0x20, 0x7F) for _ in range(24))
        C = columnarTransposeEncrypt(M, K6)
        M2 = columnarTransposeDecrypt(C, K6)
        assert M == M2, f"transpose round-trip failed on trial {trial}"
    print("[+] columnarTranspose round-trip self-test passed (64 trials).")

    # 4) Self-test encryptPart2 round-trip.
    for trial in range(64):
        M = bytes(rng.randrange(0x20, 0x7F) for _ in range(24))
        C = encryptPart2(M, K6)
        M2 = decryptPart2(C, K6)
        assert M == M2, f"encryptPart2 round-trip failed on trial {trial}"
        assert len(C) == 24
    print("[+] encryptPart2 round-trip self-test passed (64 trials).")

    # 5) Compute the two encryptPart2 targets E1 and E2, and the inner key
    #    K6_perm that the binary derives from K6 and K3.
    E1 = bytes(a ^ b for a, b in zip(MASK1, TARGET))
    E2 = bytes(a ^ b for a, b in zip(MASK2, TARGET_T))
    K6_perm = columnarTransposeEncrypt(K6, K3)

    print(f"[*] K6_perm = CTE(K6, K3) = {K6_perm!r}  hex={K6_perm.hex()}")
    print(f"[*] E1 = MASK1 XOR TARGET   = {E1.hex()}")
    print(f"[*] E2 = MASK2 XOR TARGET_T = {E2.hex()}")

    # 6) Invert the whole chain:
    #        ct = encryptPart2( CTE(plain, K6_perm), K6 )
    #    so plain = CTE_decrypt( decryptPart2(ct, K6), K6_perm ).
    mid1 = decryptPart2(E1, K6)
    plain1 = columnarTransposeDecrypt(mid1, K6_perm)
    mid2 = decryptPart2(E2, K6)
    plain2 = columnarTransposeDecrypt(mid2, K6_perm)

    # 7) Forward-verify both recovered plaintexts.
    fwd1 = encryptPart2(columnarTransposeEncrypt(plain1, K6_perm), K6)
    fwd2 = encryptPart2(columnarTransposeEncrypt(plain2, K6_perm), K6)
    assert fwd1 == E1, "forward check failed for plain1"
    assert fwd2 == E2, "forward check failed for plain2"
    print("[+] encryptPart2(CTE(plain1, K6_perm), K6) == E1   (forward OK)")
    print("[+] encryptPart2(CTE(plain2, K6_perm), K6) == E2   (forward OK)")

    # 8) Both plaintexts must be 24 bytes of printable ASCII.
    assert len(plain1) == 24 and len(plain2) == 24
    assert is_printable_ascii(plain1), f"plain1 not printable ASCII: {plain1!r}"
    assert is_printable_ascii(plain2), f"plain2 not printable ASCII: {plain2!r}"

    # 9) Display.
    print()
    print("=" * 64)
    print("Recovered plaintexts (verified end-to-end against the binary):")
    print(f"  plain1 (path-1, used at i==0): {plain1.decode('ascii')!r}")
    print(f"          hex                  : {plain1.hex()}")
    print(f"  plain2 (path-2, used at i==1): {plain2.decode('ascii')!r}")
    print(f"          hex                  : {plain2.hex()}")
    print("=" * 64)
    print()
    print("Feed both 24-character strings to the binary, one per line:")
    print(f"  {plain1.decode('ascii')}")
    print(f"  {plain2.decode('ascii')}")
    print()
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
