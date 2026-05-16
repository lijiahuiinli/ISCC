#!/usr/bin/env python3
"""
ISCC 'busy' (手忙脚乱) - pure-Python solver.

Re-implements every cryptographic primitive used by attachment-62 (4).exe so
that the two 24-character plaintexts can be recovered without running the
binary. The script:

  1. Reads the raw PE file from the workspace root.
  2. Slices the six ciphertext blobs out of .rdata.
  3. Re-implements decrypt_blob (xorshift32 keystream).
  4. Asserts the decrypted blobs equal the documented reference values.
  5. Re-implements makeTable, keyBits, subChar / invSubChar,
     columnarTransposeEncrypt / Decrypt and encryptPart2 / decryptPart2.
  6. Self-tests transpose and encryptPart2 round-trips on random messages.
  7. Inverts encryptPart2 on E1 = MASK1 XOR TARGET and E2 = MASK2 XOR TARGET_T
     to recover plain1 and plain2.
  8. Self-verifies by re-running encryptPart2 forward.
  9. Prints both plaintexts (repr + hex) and the inferred flag.
"""

import os
import random
import sys

# -----------------------------------------------------------------------------
# PE / .rdata layout. From `objdump -h`:
#   .rdata  VMA = 0x140008000   file offset = 0x6000
# All blobs sit in .rdata so file_off = va - 0x140008000 + 0x6000.
# -----------------------------------------------------------------------------
EXE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "attachment-62 (4).exe")
RDATA_VMA = 0x140008000
RDATA_FILE_OFF = 0x6000

BLOBS = [
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
# decrypt_blob: xorshift32 keystream lifted byte-for-byte from the disassembly.
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
# makeTable / keyBits / subChar / invSubChar
# -----------------------------------------------------------------------------
def makeTable(K: bytes, seed: int) -> bytes:
    MASK = 0xFFFFFFFF
    ebx = seed & MASK
    for c in K:
        ebx = (ebx * 0x83 + c) & MASK
    table = list(range(0x20, 0x7F))  # 95 entries: 0x20..0x7E inclusive
    for r in range(0x5E, 0, -1):     # 94, 93, ..., 1
        ebx = (ebx * 0x41C64E6D + 0x3039) & MASK
        idx = ebx % (r + 1)
        table[r], table[idx] = table[idx], table[r]
    return bytes(table)


def keyBits(K: bytes) -> list:
    bits = []
    for b in K:
        for s in range(7, -1, -1):
            bits.append((b >> s) & 1)
    return bits


def subChar(c: int, b: int, T0: bytes, T8: bytes) -> int:
    assert 0x20 <= c <= 0x7E, f"subChar input out of range: {c:#x}"
    idx = c - 0x20
    return T0[idx] if b == 0 else T8[idx]


def invSubChar(c: int, b: int, T0: bytes, T8: bytes) -> int:
    assert 0x20 <= c <= 0x7E, f"invSubChar input out of range: {c:#x}"
    T = T0 if b == 0 else T8
    idx = T.index(c)  # T is a permutation of 0x20..0x7E
    return idx + 0x20


# -----------------------------------------------------------------------------
# Columnar transpose - exact convention from the binary's loop order.
#
# The forward routine writes N "row-strings" (rows_arr) where:
#     rows_arr[i] = M[i], M[N+i], M[2N+i], ..., M[(rows-1)*N + i]
# i.e. rows_arr[i] is the i-th *column* of M when M is viewed as a rows x N
# row-major matrix.  Then it stable-sorts indices 0..N-1 by K[idx] and
# concatenates rows_arr[order[0]] .. rows_arr[order[N-1]].
# -----------------------------------------------------------------------------
def columnarTransposeEncrypt(M: bytes, K: bytes) -> bytes:
    N = len(K)
    L = len(M)
    assert L % N == 0, "message length must be a multiple of key length"
    rows = L // N
    cols = [bytes(M[r * N + i] for r in range(rows)) for i in range(N)]
    order = sorted(range(N), key=lambda i: K[i])  # stable
    return b"".join(cols[c] for c in order)


def columnarTransposeDecrypt(C: bytes, K: bytes) -> bytes:
    N = len(K)
    L = len(C)
    assert L % N == 0, "ciphertext length must be a multiple of key length"
    rows = L // N
    order = sorted(range(N), key=lambda i: K[i])
    cols = [None] * N
    for k, c in enumerate(order):
        cols[c] = C[k * rows:(k + 1) * rows]
    return bytes(cols[i][r] for r in range(rows) for i in range(N))


# -----------------------------------------------------------------------------
# encryptPart2 / decryptPart2
# -----------------------------------------------------------------------------
def encryptPart2(plain: bytes, K6: bytes) -> bytes:
    T0 = makeTable(K6, 0x1234)
    T8 = makeTable(K6, 0x8888)
    bits = keyBits(K6)
    sub = bytes(subChar(plain[i], bits[i], T0, T8) for i in range(len(plain)))
    return columnarTransposeEncrypt(sub, K6)


def decryptPart2(cipher: bytes, K6: bytes) -> bytes:
    T0 = makeTable(K6, 0x1234)
    T8 = makeTable(K6, 0x8888)
    bits = keyBits(K6)
    sub = columnarTransposeDecrypt(cipher, K6)
    return bytes(invSubChar(sub[i], bits[i], T0, T8) for i in range(len(sub)))


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
        # Friendly variable name (strip the CT_ prefix).
        decrypted[name[3:]] = pt
        print(f"    {name:<11s} va={va:#x}  off={off:#x}  size={size:>2d}  "
              f"decrypted={pt.hex()}")

    K6 = decrypted["K6"]
    K3 = decrypted["K3"]
    MASK1 = decrypted["MASK1"]
    MASK2 = decrypted["MASK2"]
    TARGET = decrypted["TARGET"]
    TARGET_T = decrypted["TARGET_T"]

    # 2) Sanity-check against the reference values.
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

    # 5) Solve.
    E1 = bytes(a ^ b for a, b in zip(MASK1, TARGET))
    E2 = bytes(a ^ b for a, b in zip(MASK2, TARGET_T))
    print(f"[*] E1 = MASK1 ^ TARGET   = {E1.hex()}")
    print(f"[*] E2 = MASK2 ^ TARGET_T = {E2.hex()}")

    plain1 = decryptPart2(E1, K6)
    plain2 = decryptPart2(E2, K6)

    # 6) Forward-verify both recovered plaintexts.
    assert encryptPart2(plain1, K6) == E1, "forward check failed for plain1"
    assert encryptPart2(plain2, K6) == E2, "forward check failed for plain2"
    print("[+] encryptPart2(plain1, K6) == E1   (forward verification OK)")
    print("[+] encryptPart2(plain2, K6) == E2   (forward verification OK)")

    # 7) Both plaintexts must be 24 bytes of printable ASCII.
    assert len(plain1) == 24 and len(plain2) == 24
    p1_printable = is_printable_ascii(plain1)
    p2_printable = is_printable_ascii(plain2)
    print(f"[*] plain1 printable={p1_printable}  plain2 printable={p2_printable}")
    assert p1_printable, f"plain1 not printable ASCII: {plain1!r}"
    assert p2_printable, f"plain2 not printable ASCII: {plain2!r}"

    # 8) Display.
    print()
    print("=" * 64)
    print(f"plain1 (path1): {plain1!r}")
    print(f"        hex   : {plain1.hex()}")
    print(f"plain2 (path2): {plain2!r}")
    print(f"        hex   : {plain2.hex()}")
    print("=" * 64)

    # 9) Try to spot the flag(s).
    candidates = []
    for label, pt in (("plain1", plain1), ("plain2", plain2)):
        s = pt.decode("ascii")
        if "ISCC{" in s or "isCC{" in s.lower():
            candidates.append((label, s))
    if candidates:
        for label, s in candidates:
            print(f"[FLAG] {label}: {s}")
    else:
        # Try concatenations as a fallback.
        joined12 = (plain1 + plain2).decode("ascii")
        joined21 = (plain2 + plain1).decode("ascii")
        if "ISCC{" in joined12:
            print(f"[FLAG] plain1+plain2: {joined12}")
        elif "ISCC{" in joined21:
            print(f"[FLAG] plain2+plain1: {joined21}")
        else:
            print("[!] No 'ISCC{' substring detected; both plaintexts are "
                  "printed above as candidates.")

    print()
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
