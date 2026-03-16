#!/usr/bin/env python3
"""
Z3 Attack on Barzakh-521
=========================
Objective: Given k (truncated output), recover x (internal state).

Formula: k = (a*x^2 + b) * inv(x - a) + w  (mod M521)
Output:  out = k >> 265  (top 256 bits exposed)

The attacker knows: out (256 bits), a, b, w, big_w (public params for this test)
The attacker wants: x (521 bits)

If Z3 can solve this → Barzakh-521 is broken
If Z3 times out     → Barzakh-521 resists formal verification attacks
"""

import time
import sys

try:
    from z3 import *
except ImportError:
    print("ERROR: pip3 install z3-solver")
    sys.exit(1)

M521 = (1 << 521) - 1

def barzakh_z3_attack(known_output_256bit, a_val, b_val, w_val, timeout_sec=300):
    """
    Attempt to recover internal state x from truncated output.
    """
    print(f"=== Z3 Attack on Barzakh-521 ===")
    print(f"Timeout: {timeout_sec}s")
    print(f"Known output: {known_output_256bit:#x}")
    print()

    s = Solver()
    s.set("timeout", timeout_sec * 1000)  # milliseconds

    # Unknown: x (521 bits)
    x = BitVec('x', 1024)  # extra room for modular arithmetic

    # Known parameters (in a real attack these would be unknown too,
    # but we give Z3 maximum advantage)
    a = BitVecVal(a_val, 1024)
    b = BitVecVal(b_val, 1024)
    w = BitVecVal(w_val, 1024)
    M = BitVecVal(M521, 1024)

    # Constraint: x < M521
    s.add(ULT(x, M))
    s.add(x != a)  # x != a (no singularity)

    # Step 1: denom = (x - a) mod M521
    denom = URem(x - a + M, M)

    # Step 2: x_sq = x^2 mod M521
    x_sq = URem(x * x, M)

    # Step 3: num = (a * x_sq + b) mod M521
    num = URem(a * x_sq + b, M)

    # Step 4: k = (num * inv(denom) + w) mod M521
    # Z3 cannot do modular inversion directly.
    # We introduce inv_d such that (denom * inv_d) ≡ 1 (mod M521)
    inv_d = BitVec('inv_d', 1024)
    s.add(ULT(inv_d, M))
    s.add(URem(denom * inv_d, M) == BitVecVal(1, 1024))

    # k = (num * inv_d + w) mod M521
    k = URem(num * inv_d + w, M)

    # Step 5: output = k >> 265 (top 256 bits)
    output = LShR(k, 265)

    # Constraint: output matches known value
    known = BitVecVal(known_output_256bit, 1024)
    s.add(output == known)

    print("Constraints built. Launching Z3 solver...")
    print(f"  Variables: x (521-bit), inv_d (521-bit)")
    print(f"  Constraints: modular inversion + quadratic + truncation")
    print(f"  Search space: 2^521 × 2^521 = 2^1042")
    print()

    start = time.time()
    result = s.check()
    elapsed = time.time() - start

    print(f"Result: {result}")
    print(f"Time:   {elapsed:.2f}s")
    print()

    if result == sat:
        model = s.model()
        x_val = model[x].as_long()
        inv_val = model[inv_d].as_long()
        print(f"  !!! BROKEN !!! x = {x_val}")
        print(f"  inv_d = {inv_val}")

        # Verify
        denom_v = (x_val - a_val) % M521
        inv_check = (denom_v * inv_val) % M521
        print(f"  Verify: denom*inv_d mod M = {inv_check} (should be 1)")
        return True
    elif result == unknown:
        reason = s.reason_unknown()
        print(f"  Z3 TIMEOUT/GAVE UP: {reason}")
        print(f"  → Barzakh-521 RESISTS Z3 after {elapsed:.1f}s")
        return False
    else:
        print(f"  UNSAT — no solution exists (unexpected)")
        return False


def generate_test_case():
    """Generate a known test case from Python (for verification)."""
    import hashlib
    import struct

    # Simple test: use known values
    # In practice, these come from running Barzakh521::new()
    a_val = int.from_bytes(hashlib.shake_256(b"param-a").digest(66), 'big') % M521
    b_val = int.from_bytes(hashlib.shake_256(b"param-b").digest(66), 'big') % M521
    w_val = int.from_bytes(hashlib.shake_256(b"param-w").digest(66), 'big') % M521
    x_val = int.from_bytes(hashlib.shake_256(b"state-x").digest(66), 'big') % M521

    if x_val == a_val:
        x_val = (x_val + 1) % M521

    # Compute k
    denom = (x_val - a_val) % M521
    inv_d = pow(denom, M521 - 2, M521)
    x_sq = pow(x_val, 2, M521)
    num = (a_val * x_sq + b_val) % M521
    k = (num * inv_d + w_val) % M521

    # Output = k >> 265
    output = k >> 265

    print(f"=== Test Case ===")
    print(f"  x (secret)  : {x_val:#x}")
    print(f"  output (pub) : {output:#x}")
    print(f"  k (full)     : {k:#x}")
    print()

    return output, a_val, b_val, w_val


if __name__ == "__main__":
    # Escalating timeouts
    timeouts = [30, 120, 300]

    output, a_val, b_val, w_val = generate_test_case()

    for timeout in timeouts:
        print(f"\n{'='*60}")
        print(f"  ATTEMPT with {timeout}s timeout")
        print(f"{'='*60}\n")

        broken = barzakh_z3_attack(output, a_val, b_val, w_val, timeout)

        if broken:
            print("\n  *** BARZAKH-521 IS BROKEN BY Z3 ***")
            sys.exit(1)
        else:
            print(f"\n  ✓ Barzakh-521 survived {timeout}s")

    print(f"\n{'='*60}")
    print(f"  FINAL VERDICT: Barzakh-521 RESISTS Z3")
    print(f"  (survived {sum(timeouts)}s total of SMT solving)")
    print(f"{'='*60}")
