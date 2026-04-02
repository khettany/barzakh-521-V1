// Barzakh-521: CSPRNG over GF(2^521-1)
// Copyright (C) 2026 Abdelghaffour Khettany. All rights reserved.
// License: AGPL v3 (Standard edition)
// Patent: OMPIC / PCT — Pending

use sha3::{
    Shake256,
    digest::{Update, ExtendableOutput, XofReader},
};
use zeroize::Zeroize;

const LIMBS: usize = 9;
const TOP_BITS: u32 = 9;
const TOP_MASK: u64 = (1u64 << TOP_BITS) - 1;
pub const BATCH_SIZE: usize = 8;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct F521(pub [u64; 9]);

impl Zeroize for F521 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for F521 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl F521 {
    pub const ZERO: F521 = F521([0; LIMBS]);
    pub const ONE: F521 = F521([1, 0, 0, 0, 0, 0, 0, 0, 0]);
    pub const M521: F521 = F521([
        u64::MAX, u64::MAX, u64::MAX, u64::MAX,
        u64::MAX, u64::MAX, u64::MAX, u64::MAX,
        TOP_MASK,
    ]);

    // ================================================================
    // HELPERS CONSTANT-TIME
    // ================================================================

    /// Retourne 0xFFFFFFFFFFFFFFFF si x == 0, 0x0000000000000000 sinon
    #[inline(always)]
    fn ct_mask_zero(x: u64) -> u64 {
        let non_zero = (x | x.wrapping_neg()) >> 63;
        non_zero.wrapping_sub(1)
    }

    /// Sélectionne a si mask == 0, b si mask == 0xFFF...F
    #[inline(always)]
    fn ct_select(a: &F521, b: &F521, mask: u64) -> F521 {
        let mut r = [0u64; LIMBS];
        for i in 0..LIMBS {
            r[i] = a.0[i] ^ (mask & (a.0[i] ^ b.0[i]));
        }
        F521(r)
    }

    /// Retourne 1 si self == 0, 0 sinon (constant-time)
    #[inline(always)]
    pub fn ct_is_zero(&self) -> u64 {
        let mut acc = 0u64;
        for i in 0..LIMBS { acc |= self.0[i]; }
        let non_zero = (acc | acc.wrapping_neg()) >> 63;
        non_zero ^ 1
    }

    // ================================================================
    // FONCTIONS PUBLIQUES (usage non-crypto, gardées telles quelles)
    // ================================================================

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u64;
        for i in 0..LIMBS { acc |= self.0[i]; }
        acc == 0
    }

    #[inline(always)]
    pub fn is_even(&self) -> bool {
        self.0[0] & 1 == 0
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut limbs = [0u64; LIMBS];
        for (i, &b) in bytes.iter().rev().enumerate() {
            let li = i / 8;
            if li < LIMBS {
                limbs[li] |= (b as u64) << ((i % 8) * 8);
            }
        }
        let mut r = F521(limbs);
        r.full_reduce();
        r
    }

    pub fn to_bytes_be(&self, out: &mut [u8]) {
        let n = out.len();
        for i in 0..n {
            let byte_idx = n - 1 - i;
            let limb_idx = byte_idx / 8;
            let shift = (byte_idx % 8) * 8;
            if limb_idx < LIMBS {
                out[i] = (self.0[limb_idx] >> shift) as u8;
            } else {
                out[i] = 0;
            }
        }
    }

    // ================================================================
    // FULL_REDUCE — constant-time (2 passes toujours exécutées)
    // ================================================================
    #[inline(always)]
    fn full_reduce(&mut self) {
        // Passe 1 : toujours exécutée (si hi == 0, on ajoute 0)
        let hi = self.0[8] >> TOP_BITS;
        self.0[8] &= TOP_MASK;
        let mut carry = hi as u128;
        for i in 0..LIMBS {
            carry += self.0[i] as u128;
            self.0[i] = carry as u64;
            carry >>= 64;
        }

        // Passe 2 : toujours exécutée
        let hi2 = self.0[8] >> TOP_BITS;
        self.0[8] &= TOP_MASK;
        let mut c = hi2 as u128;
        for i in 0..LIMBS {
            c += self.0[i] as u128;
            self.0[i] = c as u64;
            c >>= 64;
        }

        // Check == M521 : constant-time (pas de if)
        let mut eq_acc = 0u64;
        for i in 0..LIMBS {
            eq_acc |= self.0[i] ^ Self::M521.0[i];
        }
        let mask = Self::ct_mask_zero(eq_acc);
        for i in 0..LIMBS {
            self.0[i] &= !mask;
        }
    }

    // ================================================================
    // MERSENNE_REDUCE_WIDE — constant-time
    // ================================================================
    #[inline(always)]
    fn mersenne_reduce_wide(p: &[u64; 18]) -> Self {
        let mut lo = [0u64; LIMBS];
        lo[..8].copy_from_slice(&p[..8]);
        lo[8] = p[8] & TOP_MASK;

        let mut hi = [0u64; LIMBS];
        for i in 0..8 {
            hi[i] = (p[i + 8] >> TOP_BITS) | (p[i + 9] << (64 - TOP_BITS));
        }
        hi[8] = p[16] >> TOP_BITS;

        let mut r = [0u64; LIMBS];
        let mut carry = 0u128;
        for i in 0..LIMBS {
            carry += lo[i] as u128 + hi[i] as u128;
            r[i] = carry as u64;
            carry >>= 64;
        }

        // Toujours replier le carry (même si carry == 0)
        let mut c = carry;
        for i in 0..LIMBS {
            c += r[i] as u128;
            r[i] = c as u64;
            c >>= 64;
        }

        let mut out = F521(r);
        out.full_reduce();
        out
    }

    // ================================================================
    // ADD_MOD — constant-time
    // ================================================================
    #[inline(always)]
    pub fn add_mod(&self, other: &Self) -> Self {
        let mut r = [0u64; LIMBS];
        let mut carry = 0u128;
        for i in 0..LIMBS {
            carry += self.0[i] as u128 + other.0[i] as u128;
            r[i] = carry as u64;
            carry >>= 64;
        }

        // Toujours replier le carry
        let mut c = carry;
        for i in 0..LIMBS {
            c += r[i] as u128;
            r[i] = c as u64;
            c >>= 64;
        }

        let mut out = F521(r);
        out.full_reduce();
        out
    }

    // ================================================================
    // SUB_MOD — constant-time (masque au lieu de branchement)
    // ================================================================
    #[inline(always)]
    pub fn sub_mod(&self, other: &Self) -> Self {
        let mut r = [0u64; LIMBS];
        let mut borrow: u64 = 0;
        for i in 0..LIMBS {
            let (s1, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (s2, b2) = s1.overflowing_sub(borrow);
            r[i] = s2;
            borrow = (b1 as u64) | (b2 as u64);
        }

        // mask = 0xFFF...F si underflow, 0 sinon
        let mask = 0u64.wrapping_sub(borrow);

        let mut carry = 0u128;
        for i in 0..LIMBS {
            carry += r[i] as u128 + (Self::M521.0[i] & mask) as u128;
            r[i] = carry as u64;
            carry >>= 64;
        }

        let mut out = F521(r);
        out.full_reduce();
        out
    }

    // ================================================================
    // MUL_MOD — INCHANGÉ (déjà constant-time)
    // ================================================================
    #[inline(always)]
    pub fn mul_mod(&self, other: &Self) -> Self {
        let mut result = [0u64; 18];
        for i in 0..LIMBS {
            let ai = self.0[i] as u128;
            let mut carry: u64 = 0;
            for j in 0..LIMBS {
                let wide = ai * (other.0[j] as u128)
                    + result[i + j] as u128
                    + carry as u128;
                result[i + j] = wide as u64;
                carry = (wide >> 64) as u64;
            }
            result[i + LIMBS] = carry;
        }
        Self::mersenne_reduce_wide(&result)
    }

    // ================================================================
    // SQR_MOD — INCHANGÉ (déjà constant-time)
    // ================================================================
    #[inline(always)]
    pub fn sqr_mod(&self) -> Self {
        let a = &self.0;
        let mut result = [0u64; 18];

        for i in 0..LIMBS {
            let ai = a[i] as u128;
            let mut carry: u64 = 0;
            for j in (i + 1)..LIMBS {
                let cross = ai * (a[j] as u128)
                    + result[i + j] as u128
                    + carry as u128;
                result[i + j] = cross as u64;
                carry = (cross >> 64) as u64;
            }
            if i + LIMBS < 18 {
                result[i + LIMBS] += carry;
            }
        }

        let mut top_bit: u64 = 0;
        for i in 0..18 {
            let new_top = result[i] >> 63;
            result[i] = (result[i] << 1) | top_bit;
            top_bit = new_top;
        }

        let mut carry = 0u128;
        for i in 0..LIMBS {
            let sq = (a[i] as u128) * (a[i] as u128);
            carry += result[2 * i] as u128 + (sq as u64) as u128;
            result[2 * i] = carry as u64;
            carry >>= 64;
            carry += result[2 * i + 1] as u128 + (sq >> 64);
            result[2 * i + 1] = carry as u64;
            carry >>= 64;
        }

        Self::mersenne_reduce_wide(&result)
    }

    // ================================================================
    // XOR — constant-time (masque pour check M521)
    // ================================================================
    #[inline(always)]
    pub fn xor(&self, other: &Self) -> Self {
        let mut r = [0u64; LIMBS];
        for i in 0..LIMBS { r[i] = self.0[i] ^ other.0[i]; }
        let mut out = F521(r);

        let mut eq_acc = 0u64;
        for i in 0..LIMBS {
            eq_acc |= out.0[i] ^ Self::M521.0[i];
        }
        let mask = Self::ct_mask_zero(eq_acc);
        for i in 0..LIMBS {
            out.0[i] &= !mask;
        }
        out
    }

    // ================================================================
    // SHR — INCHANGÉ (shift amount est une constante publique)
    // ================================================================
    #[inline(always)]
    pub fn shr(&self, n: u32) -> Self {
        let limb_off = (n / 64) as usize;
        let bit_off = n % 64;
        let mut r = [0u64; LIMBS];
        if bit_off == 0 {
            for i in limb_off..LIMBS { r[i - limb_off] = self.0[i]; }
        } else {
            for i in limb_off..LIMBS {
                r[i - limb_off] = self.0[i] >> bit_off;
                if i + 1 < LIMBS {
                    r[i - limb_off] |= self.0[i + 1] << (64 - bit_off);
                }
            }
        }
        F521(r)
    }

    // ================================================================
    // INV_MOD — INCHANGÉ (chaîne fixe de sqr+mul, déjà constant-time)
    // x^(M521-2) = x^(2^521-3)
    // ================================================================
    pub fn inv_mod(&self) -> Self {
        let r1 = self.clone();
        let r2 = r1.sqr_mod().mul_mod(&r1);
        let r3 = r2.sqr_mod().mul_mod(&r1);
        let r4 = r3.sqr_mod().mul_mod(&r1);

        let mut r7 = r4.clone();
        for _ in 0..3 { r7 = r7.sqr_mod(); }
        r7 = r7.mul_mod(&r4);

        let r8 = r7.sqr_mod().mul_mod(&r1);

        let mut r16 = r8.clone();
        for _ in 0..8 { r16 = r16.sqr_mod(); }
        r16 = r16.mul_mod(&r8);

        let mut r32 = r16.clone();
        for _ in 0..16 { r32 = r32.sqr_mod(); }
        r32 = r32.mul_mod(&r16);

        let mut r64 = r32.clone();
        for _ in 0..32 { r64 = r64.sqr_mod(); }
        r64 = r64.mul_mod(&r32);

        let mut r128 = r64.clone();
        for _ in 0..64 { r128 = r128.sqr_mod(); }
        r128 = r128.mul_mod(&r64);

        let mut r256 = r128.clone();
        for _ in 0..128 { r256 = r256.sqr_mod(); }
        r256 = r256.mul_mod(&r128);

        let mut r512 = r256.clone();
        for _ in 0..256 { r512 = r512.sqr_mod(); }
        r512 = r512.mul_mod(&r256);

        let mut r519 = r512.clone();
        for _ in 0..7 { r519 = r519.sqr_mod(); }
        r519 = r519.mul_mod(&r7);

        let mut result = r519;
        result = result.sqr_mod();
        result = result.sqr_mod();
        result = result.mul_mod(&r1);
        result
    }

    // ================================================================
    // BATCH_INV — INCHANGÉ (Montgomery's trick)
    // ================================================================
    pub fn batch_inv(vals: &[F521]) -> Vec<F521> {
        let n = vals.len();
        if n == 0 { return vec![]; }

        let mut prefix = Vec::with_capacity(n);
        prefix.push(vals[0].clone());
        for i in 1..n {
            prefix.push(prefix[i - 1].mul_mod(&vals[i]));
        }

        let mut inv = prefix[n - 1].inv_mod();
        let mut result = vec![F521::ZERO; n];

        for i in (1..n).rev() {
            result[i] = prefix[i - 1].mul_mod(&inv);
            inv = inv.mul_mod(&vals[i]);
        }
        result[0] = inv;
        result
    }
}

// ================================================================
// BARZAKH-521 CSPRNG
// ================================================================
pub struct Barzakh521 {
    x: F521,
    a: F521,
    b: F521,
    w: F521,
    big_w: F521,
}

impl Zeroize for Barzakh521 {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.a.zeroize();
        self.b.zeroize();
        self.w.zeroize();
        self.big_w.zeroize();
    }
}

impl Drop for Barzakh521 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Barzakh521 {
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        let mut reader = hasher.finalize_xof();

        let read_field = |reader: &mut dyn XofReader| -> F521 {
            let mut b = [0u8; 66];
            reader.read(&mut b);
            F521::from_bytes_be(&b)
        };

        let x = read_field(&mut reader);
        let a = read_field(&mut reader);
        let b = read_field(&mut reader);
        let mut w = read_field(&mut reader);
        let big_w = read_field(&mut reader);

        // Forcer w impair — constant-time (pas de if)
        // Équivalent à : if w.is_even() { w = w + 1 }
        let lsb = w.0[0] & 1;
        let add_one = lsb ^ 1;  // 1 si pair, 0 si impair
        let to_add = F521([add_one, 0, 0, 0, 0, 0, 0, 0, 0]);
        w = w.add_mod(&to_add);

        Barzakh521 { x, a, b, w, big_w }
    }

    // ================================================================
    // K(x) = (ax² + b) / (x - a) + w  (mod M521)
    // Sortie : 256 MSB de k
    // ================================================================
    pub fn next_u256(&mut self) -> [u8; 32] {
        let x_sq = self.x.sqr_mod();
        let ax2 = self.a.mul_mod(&x_sq);
        let num = ax2.add_mod(&self.b);

        let mut denom = self.x.sub_mod(&self.a);

        // Singularité x == a : constant-time
        // Si denom == 0 → denom = 1 (évite division par zéro)
        // Probabilité : 1/M521 ≈ 2^-521 (négligeable)
        let is_zero = denom.ct_is_zero();
        let mask = 0u64.wrapping_sub(is_zero);
        denom = F521::ct_select(&denom, &F521::ONE, mask);

        let inv = denom.inv_mod();
        let quot = num.mul_mod(&inv);
        let k = quot.add_mod(&self.w);

        // Mise à jour état
        self.x = self.big_w.xor(&k);

        // Sortie : 256 MSB (décalage droit de 265 bits)
        let out_field = k.shr(265);
        let mut out = [0u8; 32];
        out_field.to_bytes_be(&mut out);
        out
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset + 32 <= dest.len() {
            let block = self.next_u256();
            dest[offset..offset + 32].copy_from_slice(&block);
            offset += 32;
        }
        if offset < dest.len() {
            let block = self.next_u256();
            dest[offset..].copy_from_slice(&block[..dest.len() - offset]);
        }
    }
}

// ================================================================
// BATCH MODE (8 lanes parallèles)
// ================================================================
pub struct Barzakh521Batch {
    lanes: [Barzakh521; BATCH_SIZE],
}

impl Barzakh521Batch {
    pub fn new(seed: &[u8]) -> Self {
        let lanes = std::array::from_fn(|i| {
            let mut s = Vec::with_capacity(seed.len() + 1);
            s.extend_from_slice(seed);
            s.push(i as u8);
            Barzakh521::new(&s)
        });
        Barzakh521Batch { lanes }
    }

    pub fn next_batch(&mut self) -> Vec<u8> {
        let mut out = vec![0u8; BATCH_SIZE * 32];
        for (i, lane) in self.lanes.iter_mut().enumerate() {
            let block = lane.next_u256();
            out[i * 32..(i + 1) * 32].copy_from_slice(&block);
        }
        out
    }
}
