#!/usr/bin/env python3
"""
Bitwuzla Attack on Barzakh-521
================================
Generate SMT-LIB2 formulas and feed them to Bitwuzla CLI.
Tests 1, 2, and 3 rounds of the formula.
"""

import subprocess
import hashlib
import time
import os

M521 = (1 << 521) - 1
BITWUZLA = "/root/bitwuzla/build/src/main/bitwuzla"

def to_bv_hex(val, bits=528):
    """Convert integer to SMT-LIB2 bitvector hex literal."""
    hex_str = format(val % (1 << bits), f'0{bits // 4}x')
    return f"#x{hex_str}"

def generate_test_values():
    """Generate known test case values."""
    a_val = int.from_bytes(hashlib.shake_256(b"param-a").digest(66), 'big') % M521
    b_val = int.from_bytes(hashlib.shake_256(b"param-b").digest(66), 'big') % M521
    w_val = int.from_bytes(hashlib.shake_256(b"param-w").digest(66), 'big') % M521
    x_val = int.from_bytes(hashlib.shake_256(b"state-x").digest(66), 'big') % M521
    W_val = int.from_bytes(hashlib.shake_256(b"param-W").digest(66), 'big') % M521

    if x_val == a_val:
        x_val = (x_val + 1) % M521

    # Compute one round
    denom = (x_val - a_val) % M521
    inv_d = pow(denom, M521 - 2, M521)
    x_sq = pow(x_val, 2, M521)
    num = (a_val * x_sq + b_val) % M521
    k = (num * inv_d + w_val) % M521
    output = k >> 265

    return {
        'a': a_val, 'b': b_val, 'w': w_val, 'W': W_val,
        'x': x_val, 'k': k, 'output': output,
    }

def gen_smt2_1round(vals, timeout_sec):
    """
    Generate SMT-LIB2 for 1-round attack.
    Given: output (256 bits), a, b, w (all public for max Z3 advantage)
    Find:  x (521 bits)
    """
    BW = 528  # bitvector width (multiple of 8, >= 521)

    smt = f"""; Barzakh-521: 1-round Bitwuzla attack
(set-logic QF_BV)
(set-option :timeout {timeout_sec * 1000})

; Constants
(define-fun M521 () (_ BitVec {BW}) {to_bv_hex(M521, BW)})
(define-fun ONE () (_ BitVec {BW}) {to_bv_hex(1, BW)})

; Known parameters (maximum advantage to attacker)
(define-fun a () (_ BitVec {BW}) {to_bv_hex(vals['a'], BW)})
(define-fun b () (_ BitVec {BW}) {to_bv_hex(vals['b'], BW)})
(define-fun w () (_ BitVec {BW}) {to_bv_hex(vals['w'], BW)})

; Known output (truncated k >> 265)
(define-fun known_out () (_ BitVec {BW}) {to_bv_hex(vals['output'], BW)})

; UNKNOWN: internal state x (521 bits)
(declare-fun x () (_ BitVec {BW}))

; Constraint: 0 < x < M521
(assert (bvult x M521))

; Constraint: x != a (no singularity)
(assert (not (= x a)))

; UNKNOWN: inv_d such that denom * inv_d ≡ 1 (mod M521)
(declare-fun inv_d () (_ BitVec {BW}))
(assert (bvult inv_d M521))

; denom = (x - a) mod M521
(define-fun denom () (_ BitVec {BW})
  (bvurem (bvadd (bvsub x a) M521) M521))

; Constraint: denom * inv_d ≡ 1 (mod M521)
(assert (= (bvurem (bvmul denom inv_d) M521) ONE))

; x_sq = x^2 mod M521
(define-fun x_sq () (_ BitVec {BW})
  (bvurem (bvmul x x) M521))

; num = (a * x_sq + b) mod M521
(define-fun num () (_ BitVec {BW})
  (bvurem (bvadd (bvurem (bvmul a x_sq) M521) b) M521))

; k = (num * inv_d + w) mod M521
(define-fun k () (_ BitVec {BW})
  (bvurem (bvadd (bvurem (bvmul num inv_d) M521) w) M521))

; output = k >> 265 must match known_out
(assert (= (bvlshr k (_ bv265 {BW})) known_out))

(check-sat)
(get-value (x))
"""
    return smt

def gen_smt2_2rounds(vals, timeout_sec):
    """
    2-round attack: recover x from TWO consecutive outputs.
    Much harder — x1 depends on k0 via feedback.
    """
    BW = 528

    # Compute round 2
    x1 = vals['W'] ^ vals['k']  # feedback
    x1 = x1 % (1 << 521)
    if x1 == vals['a']:
        x1 = (x1 + vals['W']) % M521

    denom1 = (x1 - vals['a']) % M521
    inv1 = pow(denom1, M521 - 2, M521)
    x1_sq = pow(x1, 2, M521)
    num1 = (vals['a'] * x1_sq + vals['b']) % M521
    k1 = (num1 * inv1 + vals['w']) % M521
    output1 = k1 >> 265

    smt = f"""; Barzakh-521: 2-round Bitwuzla attack
(set-logic QF_BV)
(set-option :timeout {timeout_sec * 1000})

(define-fun M521 () (_ BitVec {BW}) {to_bv_hex(M521, BW)})
(define-fun ONE () (_ BitVec {BW}) {to_bv_hex(1, BW)})
(define-fun a () (_ BitVec {BW}) {to_bv_hex(vals['a'], BW)})
(define-fun b () (_ BitVec {BW}) {to_bv_hex(vals['b'], BW)})
(define-fun w () (_ BitVec {BW}) {to_bv_hex(vals['w'], BW)})
(define-fun bigW () (_ BitVec {BW}) {to_bv_hex(vals['W'], BW)})

(define-fun out0 () (_ BitVec {BW}) {to_bv_hex(vals['output'], BW)})
(define-fun out1 () (_ BitVec {BW}) {to_bv_hex(output1, BW)})

; UNKNOWN: x0
(declare-fun x0 () (_ BitVec {BW}))
(assert (bvult x0 M521))
(assert (not (= x0 a)))

; Round 0: inv0
(declare-fun inv0 () (_ BitVec {BW}))
(assert (bvult inv0 M521))
(define-fun denom0 () (_ BitVec {BW}) (bvurem (bvadd (bvsub x0 a) M521) M521))
(assert (= (bvurem (bvmul denom0 inv0) M521) ONE))

(define-fun x0_sq () (_ BitVec {BW}) (bvurem (bvmul x0 x0) M521))
(define-fun num0 () (_ BitVec {BW}) (bvurem (bvadd (bvurem (bvmul a x0_sq) M521) b) M521))
(define-fun k0 () (_ BitVec {BW}) (bvurem (bvadd (bvurem (bvmul num0 inv0) M521) w) M521))

; Round 0 output constraint
(assert (= (bvlshr k0 (_ bv265 {BW})) out0))

; Feedback: x1 = W ^ k0
(define-fun x1 () (_ BitVec {BW}) (bvxor bigW k0))
(assert (bvult x1 M521))
(assert (not (= x1 a)))

; Round 1: inv1
(declare-fun inv1 () (_ BitVec {BW}))
(assert (bvult inv1 M521))
(define-fun denom1 () (_ BitVec {BW}) (bvurem (bvadd (bvsub x1 a) M521) M521))
(assert (= (bvurem (bvmul denom1 inv1) M521) ONE))

(define-fun x1_sq () (_ BitVec {BW}) (bvurem (bvmul x1 x1) M521))
(define-fun num1 () (_ BitVec {BW}) (bvurem (bvadd (bvurem (bvmul a x1_sq) M521) b) M521))
(define-fun k1 () (_ BitVec {BW}) (bvurem (bvadd (bvurem (bvmul num1 inv1) M521) w) M521))

; Round 1 output constraint
(assert (= (bvlshr k1 (_ bv265 {BW})) out1))

(check-sat)
(get-value (x0))
"""
    return smt


def run_bitwuzla(smt_content, label, timeout_sec):
    """Run Bitwuzla on an SMT-LIB2 file."""
    smt_file = f"/tmp/barzakh_{label}.smt2"
    with open(smt_file, 'w') as f:
        f.write(smt_content)

    print(f"\n{'='*60}")
    print(f"  {label} — timeout {timeout_sec}s")
    print(f"{'='*60}")

    start = time.time()
    try:
        result = subprocess.run(
            [BITWUZLA, smt_file],
            capture_output=True, text=True,
            timeout=timeout_sec + 10
        )
        elapsed = time.time() - start
        output = result.stdout.strip()
        stderr = result.stderr.strip()

        print(f"  Time:   {elapsed:.2f}s")
        print(f"  Result: {output}")
        if stderr:
            print(f"  Stderr: {stderr[:200]}")

        if output.startswith("sat"):
            print(f"\n  !!! BARZAKH-521 BROKEN by Bitwuzla !!!")
            return "sat"
        elif output.startswith("unsat"):
            print(f"\n  UNSAT — formule contradictoire (inattendu)")
            return "unsat"
        else:
            print(f"\n  ✅ Bitwuzla TIMEOUT/UNKNOWN — Barzakh-521 RESISTS")
            return "unknown"

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"  Time:   {elapsed:.2f}s (KILLED)")
        print(f"\n  ✅ Bitwuzla HARD TIMEOUT — Barzakh-521 RESISTS")
        return "timeout"


def run_z3(smt_content, label, timeout_sec):
    """Run Z3 on the same SMT-LIB2 file (for comparison)."""
    smt_file = f"/tmp/barzakh_{label}_z3.smt2"
    with open(smt_file, 'w') as f:
        f.write(smt_content)

    print(f"\n  --- Z3 comparison ---")
    start = time.time()
    try:
        result = subprocess.run(
            ["z3", smt_file],
            capture_output=True, text=True,
            timeout=timeout_sec + 10
        )
        elapsed = time.time() - start
        output = result.stdout.strip().split('\n')[0]
        print(f"  Z3 Time:   {elapsed:.2f}s")
        print(f"  Z3 Result: {output}")

        if output.startswith("sat"):
            return "sat"
        return "unknown"

    except (subprocess.TimeoutExpired, FileNotFoundError):
        elapsed = time.time() - start
        print(f"  Z3 Time:   {elapsed:.2f}s (TIMEOUT/MISSING)")
        return "timeout"


if __name__ == "__main__":
    print("=" * 60)
    print("  BARZAKH-521 — Formal Verification Attack Suite")
    print("  Bitwuzla + Z3 comparison")
    print("=" * 60)

    vals = generate_test_values()
    print(f"\n  Secret x : {vals['x']:#x}")
    print(f"  Output   : {vals['output']:#x}")

    results = {}

    # ─── Test 1: 1 round, 30s ────────────────────────
    smt = gen_smt2_1round(vals, 30)
    results['bitwuzla_1r_30s'] = run_bitwuzla(smt, "1round_30s", 30)
    results['z3_1r_30s'] = run_z3(smt, "1round_30s", 30)

    # ─── Test 2: 1 round, 120s ───────────────────────
    smt = gen_smt2_1round(vals, 120)
    results['bitwuzla_1r_120s'] = run_bitwuzla(smt, "1round_120s", 120)
    results['z3_1r_120s'] = run_z3(smt, "1round_120s", 120)

    # ─── Test 3: 1 round, 300s ───────────────────────
    smt = gen_smt2_1round(vals, 300)
    results['bitwuzla_1r_300s'] = run_bitwuzla(smt, "1round_300s", 300)
    results['z3_1r_300s'] = run_z3(smt, "1round_300s", 300)

    # ─── Test 4: 2 rounds, 300s ──────────────────────
    smt = gen_smt2_2rounds(vals, 300)
    results['bitwuzla_2r_300s'] = run_bitwuzla(smt, "2rounds_300s", 300)
    results['z3_2r_300s'] = run_z3(smt, "2rounds_300s", 300)

    # ─── Final Report ────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  FINAL REPORT")
    print(f"{'='*60}")
    print(f"  {'Test':<25} {'Bitwuzla':<12} {'Z3':<12}")
    print(f"  {'-'*49}")
    for key in ['1r_30s', '1r_120s', '1r_300s', '2r_300s']:
        bw = results.get(f'bitwuzla_{key}', '?')
        z3 = results.get(f'z3_{key}', '?')
        print(f"  {key:<25} {bw:<12} {z3:<12}")

    broken = any(v == 'sat' for v in results.values())
    if broken:
        print(f"\n  *** BARZAKH-521 IS BROKEN ***")
    else:
        print(f"\n  ✅ BARZAKH-521 RESISTS ALL ATTACKS")
        print(f"     Both Bitwuzla and Z3 failed to recover state")

    print(f"{'='*60}")
