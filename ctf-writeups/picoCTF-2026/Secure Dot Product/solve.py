#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  PicoCTF – "Secure Dot Product"  |  solve.py                    ║
║  Flag: picoCTF{n0t_so_s3cure_.x_w1th_sh@512_40aa9102}           ║
╚══════════════════════════════════════════════════════════════════╝

CHALLENGE SUMMARY
─────────────────
The server holds a random 32-byte AES-256 key K = [k0, k1, …, k31].
It encrypts a flag with K (AES-CBC) and prints the IV + ciphertext.

It then offers a "trusted dot-product oracle":
  • It shows 5 pre-signed (vector, SHA-512 hash) pairs.
  • We submit any vector V and its salted hash H.
  • If SHA-512(salt ∥ V[1:-1]) == H the server returns V · K (dot product).
  • One wrong hash → connection closes.

The salt is 256 bytes of random data we never see.

VULNERABILITIES EXPLOITED
──────────────────────────
1. SHA-512 Length Extension Attack
   SHA-512(salt ∥ msg) can be extended to SHA-512(salt ∥ msg ∥ pad ∥ extra)
   without knowing the salt, as long as we know len(salt).
   We use hashpumpy to forge hashes for extended vectors.

2. parse_vector Sanitizer strips minus signs
   The server sanitizes input keeping only [0-9 , [ ]].
   This strips '-', so negative numbers become positive after parsing.
   We account for this when computing key bytes.

3. Tuple vs List parse quirk
   Sanitized input with no brackets (e.g. "62,173,1") is parsed as a
   TUPLE by ast.literal_eval, which fails the isinstance(parsed, list)
   check. Fix: wrap the forged payload in [ ] so sanitize keeps them.
   The server hashes vector_input[1:-1], so the wrapper brackets are
   stripped before hashing — the forged hash still validates. ✓

ATTACK PLAN
───────────
Phase 1 – Collect base equations
  Submit all 5 trusted vectors as-is (hashes already valid).
  Each gives one linear equation:  san(V) · K = dot_result
  where san(V) replaces each element with its absolute value.

Phase 2 – Recover k[S]..k[31] via length extension
  Using the shortest trusted vector (length S), forge hashes for
  extended vectors: [san(V)..., 0, …, 0, 1] with 1 at position i.
  Each returns: san(V)·K + k[i] = dot_i
  Since san(V)·K = base_dot (already known), we get: k[i] = dot_i - base_dot

Phase 3 – Recover k[0]..k[S-1] via Gaussian elimination
  After subtracting the now-known k[S..31] contributions from all
  5 base equations, we have a small S×S (or overdetermined) system.
  Solve with exact rational Gaussian elimination.

Phase 4 – Decrypt
  Build key_bytes = bytes([k0, k1, …, k31])
  AES-CBC decrypt with the recovered key and the server's IV.

INSTALL
───────
  sudo dnf install -y gcc-c++ cmake make python3-devel openssl-devel
  pip install pwntools hashpumpy pycryptodome
"""

import ast
from fractions import Fraction
from pwn import *
import hashpumpy
from Crypto.Cipher import AES

# ── Configuration ─────────────────────────────────────────────────────────────
HOST         = "lonely-island.picoctf.net"
PORT         = 49733       # Update to your challenge port
SALT_LEN     = 256         # SALT_SIZE in remote.py — the SHA-512 prefix length
MAX_SHORTEST = 5           # Skip connection if shortest vector > 5 elements.
                           # With S <= 5 unknowns and 5 equations we can always
                           # solve the linear system uniquely.
TIMEOUT      = 15          # Seconds per network recv call
# ─────────────────────────────────────────────────────────────────────────────


def sanitize(s: str) -> str:
    """
    Mirror the server's parse_vector sanitizer.
    Keeps only digits, commas, and square brackets.
    This strips: minus signs, spaces, and any non-ASCII bytes from SHA padding.

    Example: "[-62, -173]"  →  "[62,173]"
             "-62, -173, 1" →  "62,173,1"   ← no brackets = TUPLE, not list!
    """
    return "".join(c for c in s if c in '0123456789,[]')


def recv_banner(r):
    """
    Read the server's opening banner and extract:
      - iv:      AES IV (bytes)
      - ct:      ciphertext (bytes)
      - vectors: list of (vec_str, hash_hex) tuples

    vec_str is the raw string like "[-62, -173]" including brackets.
    """
    r.recvuntil(b"IV: ", timeout=TIMEOUT)
    iv = bytes.fromhex(r.recvline().strip().decode())

    r.recvuntil(b"Ciphertext: ", timeout=TIMEOUT)
    ct = bytes.fromhex(r.recvline().strip().decode())

    r.recvuntil(b"won't leak my key:\n", timeout=TIMEOUT)

    vectors = []
    for _ in range(5):
        raw = r.recvline(timeout=TIMEOUT).decode().strip()
        # Each line looks like: ([-62, -173], 'cfa65d...')
        # rfind on ", '" splits at the last comma-quote, separating vector from hash.
        idx = raw.rfind(", '")
        vec_str = raw[1:idx]               # strip leading '('
        h       = raw[idx+3:].rstrip("')") # strip trailing "')"
        vectors.append((vec_str, h))

    return iv, ct, vectors


def parse_san(vec_str):
    """
    Apply sanitize() and ast.literal_eval to a vec_str.
    Returns the parsed list, or None if it fails or isn't a non-empty list.
    Used to determine the effective coefficient vector after sanitization.
    """
    try:
        p = ast.literal_eval(sanitize(vec_str))
        if isinstance(p, list) and len(p) > 0:
            return p
    except Exception:
        pass
    return None


def do_query(r, payload: bytes, hash_hex: str) -> int:
    """
    Submit one vector query to the server and return the dot product result.

    Server loop structure (from remote.py):
        print("=" * 56)                     # separator printed FIRST
        vector_input = input("Enter your vector: ")
        vector_input = vector_input.encode().decode('unicode_escape')
        vector = parse_vector(vector_input)
        vector_hash = hash_vector(vector_input)  # hashes BEFORE sanitizing
        input_hash = input("Enter its salted hash: ")
        if vector_hash != input_hash:
            print("Untrusted vector detected!")
            break
        print("The computed dot product is: " + str(dot_product(vector)))

    Note: recvuntil(b"Enter your vector: ") consumes the separator line too.
    """
    r.recvuntil(b"Enter your vector: ", timeout=TIMEOUT)
    r.sendline(payload)

    r.recvuntil(b"Enter its salted hash: ", timeout=TIMEOUT)
    r.sendline(hash_hex.encode())

    resp = r.recvline(timeout=TIMEOUT).decode().strip()
    if "Untrusted" in resp or "Invalid" in resp:
        raise RuntimeError(f"Server rejected: {resp}")

    return int(resp.split()[-1])


def ext_query(r, hash0, inner0, append_str, label=""):
    """
    Forge a valid (vector, hash) pair using SHA-512 length extension,
    then submit it and return the dot product.

    HOW LENGTH EXTENSION WORKS HERE:
      hash0  = SHA-512(salt ∥ inner0)   where salt is SALT_LEN=256 bytes
      hashpumpy computes:
        new_hash = SHA-512(salt ∥ inner0 ∥ sha_padding ∥ append_str)
        new_msg  = inner0 ∥ sha_padding ∥ append_str   (everything after salt)

    The server will verify:
        SHA-512(salt ∥ new_msg[1:-1]) == new_hash
    BUT we wrap new_msg in [ ], so new_msg[1:-1] = original new_msg content. ✓

    ENCODING PIPELINE (critical detail):
      new_msg contains raw bytes (including 0x80, 0x00 SHA padding bytes).
      Server does: input_str.encode().decode('unicode_escape')
      So we must send each byte as the TEXT escape \\xNN (4 ASCII chars):
        raw byte 0x80  →  send the 4 chars  \  x  8  0
        raw byte 0x2d  →  send the 4 chars  \  x  2  d
      Then server's decode('unicode_escape') reconstructs the original bytes.
      The SHA padding bytes (0x80, 0x00...) become actual non-digit bytes,
      which sanitize() strips, leaving only our appended digits.

    BRACKET WRAPPING (the critical bug fix):
      new_msg has no [ ] because inner0 = vec_str[1:-1] had them stripped.
      Without brackets: sanitize("62,173,1") → ast.literal_eval → TUPLE (62,173,1)
      Server's isinstance(parsed, list) fails → "Invalid vector".
      Fix: wrap in [ ] → sanitize("[62,173,1]") → LIST [62, 173, 1] ✓
      Server hashes vector_input[1:-1], stripping our wrapper → hash still matches ✓
    """
    new_hash, new_msg = hashpumpy.hashpump(hash0, inner0, append_str, SALT_LEN)

    # Encode every byte as the 4-char text escape \\xNN
    escaped_inner = "".join(f"\\x{b:02x}" for b in new_msg)

    # Wrap in [ ] — makes sanitize produce a list, not a tuple
    payload = ("[" + escaped_inner + "]").encode('ascii')

    if label:
        log.debug(f"  ext_query {label}: {len(payload)} bytes")

    return do_query(r, payload, new_hash), new_hash


def gauss_exact(mat, n):
    """
    Exact Gaussian elimination over the rationals using Python's Fraction type.
    No floating-point rounding errors — solutions are exact integers.

    mat: augmented matrix (rows × n+1), each row = [coeffs... | rhs]
    n:   number of unknowns
    Returns: list of n integer solutions [x0, x1, ..., x_{n-1}]
    Raises ValueError if underdetermined or non-integer solution found.
    """
    m = [[Fraction(x) for x in row] for row in mat]
    pivot_rows = []
    col = row = 0

    while row < len(m) and col < n:
        # Find a non-zero pivot in column `col` at or below current row
        pr = next((r2 for r2 in range(row, len(m)) if m[r2][col] != 0), None)
        if pr is None:
            col += 1   # entire column is zero — skip
            continue
        m[row], m[pr] = m[pr], m[row]      # swap to bring pivot to current row
        pivot_rows.append((row, col))

        # Eliminate all other rows in this column
        for r2 in range(len(m)):
            if r2 != row and m[r2][col] != 0:
                fac = m[r2][col] / m[row][col]
                for c in range(n + 1):
                    m[r2][c] -= fac * m[row][c]
        row += 1; col += 1

    if len(pivot_rows) < n:
        raise ValueError(f"Underdetermined: {len(pivot_rows)} pivots for {n} unknowns")

    # Back-substitute: each pivot row now has exactly one non-zero coefficient
    sol = [Fraction(0)] * n
    for (r2, c) in pivot_rows:
        sol[c] = m[r2][n] / m[r2][c]

    # Verify integer solutions (key bytes must be integers)
    result = []
    for i, v in enumerate(sol):
        if v.denominator != 1:
            raise ValueError(f"Non-integer solution k[{i}] = {v}")
        result.append(int(v))
    return result


def attempt(port):
    """
    One full connection attempt. Returns the flag string on success, None to retry.

    Returns None (triggering a retry) when:
      - All 5 trusted vectors are too long (shortest > MAX_SHORTEST = 5).
        With S unknowns and only 5 equations, S > 5 is underdetermined.
      - Gaussian elimination fails (linearly dependent vectors — rare).
      - Any recovered key byte is outside [0, 255] (wrong solution).
    """
    r = remote(HOST, port, level='warn')

    try:
        iv, ct, vectors = recv_banner(r)
    except Exception as e:
        r.close()
        log.warning(f"Banner parse failed: {e}")
        return None

    # Compute the sanitized form of each vector and sort by length (shortest first)
    parsed_vecs = []
    for vs, h in vectors:
        p = parse_san(vs)
        if p:
            parsed_vecs.append((vs, h, p))
    parsed_vecs.sort(key=lambda x: len(x[2]))

    shortest_len = len(parsed_vecs[0][2])
    log.info(f"Vector lengths: {[len(x[2]) for x in parsed_vecs]}  shortest={shortest_len}")

    # If shortest vector is too long, the linear system will be underdetermined.
    # Probability of needing to retry: ~43% per connection (see analysis in writeup).
    if shortest_len > MAX_SHORTEST:
        log.warning(f"Shortest={shortest_len} > {MAX_SHORTEST}, retrying...")
        r.close()
        return None

    # ── Phase 1: Collect base equations from all 5 trusted vectors ────────
    # Each trusted vector V gives: san(V) · K = dot_result
    # where san(V) replaces every element with its absolute value (sanitizer strips '-').
    log.info("Phase 1: collecting base equations from trusted vectors...")
    equations = []   # list of ([coefficients × 32], dot_value)

    for idx, (vs, h, san) in enumerate(parsed_vecs):
        dot = do_query(r, vs.encode(), h)
        coeffs = [0] * 32
        for j, c in enumerate(san[:32]):
            coeffs[j] = c   # sanitized (positive) coefficients
        equations.append((coeffs, dot))
        log.info(f"  vec[{idx}] len={len(san):2d}  dot={dot}")

    # ── Phase 2: Recover k[S]..k[31] via length extension ─────────────────
    # We extend the shortest vector's hash with append_str = ", 0,...,0, 1"
    # The extended vector (after sanitize) looks like:
    #   [san0[0], san0[1], ..., san0[S-1], 0, ..., 0, 1]
    #                                              ↑ position i
    # So: dot_i = san(V)·K + k[i] = base_dot + k[i]
    # Therefore: k[i] = dot_i - base_dot  ← simple subtraction!
    vec0_str, hash0, san0 = parsed_vecs[0]
    inner0   = vec0_str[1:-1]   # strip [ ] for hashpumpy (matches how server hashes)
    base_dot = equations[0][1]  # san(V)·K, known from Phase 1
    S        = shortest_len

    log.info(f"Phase 2: extending to recover k[{S}]..k[31] ({32-S} queries)...")
    k = [0] * 32

    for i in range(S, 32):
        # append_str puts 0s between the base vector and the 1 at position i
        append_str = ", " + ", ".join(["0"] * (i - S) + ["1"])
        dot_i, _   = ext_query(r, hash0, inner0, append_str, label=f"k[{i}]")
        k[i]       = dot_i - base_dot
        log.info(f"  k[{i:2d}] = {k[i]}")

    # ── Phase 3: Recover k[0]..k[S-1] via Gaussian elimination ───────────
    # Subtract the now-known k[S..31] contributions from each base equation.
    # This leaves a small S×S (or 5×S overdetermined) integer system.
    # Example for S=2: two equations, two unknowns → unique solution.
    log.info(f"Phase 3: solving {len(equations)} equations for k[0..{S-1}]...")
    aug = []
    for coeffs, dot in equations:
        # rhs = dot - (contributions from already-recovered k[S..31])
        rhs = dot - sum(coeffs[j] * k[j] for j in range(S, 32))
        aug.append([coeffs[j] for j in range(S)] + [rhs])

    try:
        sol = gauss_exact(aug, S)
    except ValueError as e:
        log.error(f"Gaussian elimination failed: {e}")
        r.close()
        return None

    for j, v in enumerate(sol):
        k[j] = v
        log.info(f"  k[{j:2d}] = {v}")

    # ── Validate all key bytes are in [0, 255] ────────────────────────────
    # AES key bytes must be valid. Out-of-range means the system had
    # linearly dependent equations (rare) or a bug — just reconnect.
    bad = [(i, v) for i, v in enumerate(k) if not (0 <= v <= 255)]
    if bad:
        log.warning(f"Out-of-range key bytes: {bad[:5]} — retrying")
        r.close()
        return None

    key_bytes = bytes(k)
    log.success(f"Recovered key: {key_bytes.hex()}")

    # ── Phase 4: Decrypt the flag ─────────────────────────────────────────
    cipher    = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ct)
    pad_len   = decrypted[-1]        # PKCS#7: last byte = number of padding bytes
    flag      = decrypted[:-pad_len]
    r.close()
    return flag.decode(errors='replace')


def main():
    """
    Keep retrying until we get a solvable instance (shortest vector ≤ 5).
    Expected wait: ~1.7 connections on average.
    P(shortest ≤ 5 in 5 random vectors from [1,32]) ≈ 57%
    """
    n = 0
    while True:
        n += 1
        log.info(f"=== Attempt {n} ===")
        try:
            flag = attempt(PORT)
        except Exception as e:
            log.warning(f"Attempt {n} error: {e}")
            flag = None
        if flag:
            print(f"\n{'='*60}")
            print(f"FLAG: {flag}")
            print(f"{'='*60}\n")
            return
        import time; time.sleep(1)


if __name__ == "__main__":
    main()
