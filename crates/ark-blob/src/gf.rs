//! Galois Field GF(2^8) arithmetic with Rijndael / AES polynomial 0x11d (x^8 + x^4 + x^3 + x + 1).
//! Precomputes exp and log lookup tables for fast multiplication and inversion,
//! and provides 4-bit nibble tables for SIMD table-lookup (AVX2 / NEON) or fast 64-bit word operations.

pub const GF_SIZE: usize = 256;
const POLYNOMIAL: u16 = 0x11d;

// Global tables for GF(2^8)
pub struct Gf256 {
    pub exp: [u8; 512],
    pub log: [u8; 256],
    pub inv: [u8; 256],
}

impl Gf256 {
    pub const fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut inv = [0u8; 256];

        let mut x: u16 = 1;
        let mut i = 0;
        while i < 255 {
            exp[i] = x as u8;
            exp[i + 255] = x as u8;
            log[x as usize] = i as u8;

            x <<= 1;
            if (x & 0x100) != 0 {
                x ^= POLYNOMIAL;
            }
            i += 1;
        }
        exp[510] = exp[255];
        exp[511] = exp[256];

        // 0 has log 0 by convention, but never use log(0) directly
        log[0] = 0;

        let mut a = 1;
        while a < 256 {
            let log_a = log[a] as usize;
            let inv_a = exp[255 - log_a];
            inv[a] = inv_a;
            a += 1;
        }
        inv[0] = 0;

        Self { exp, log, inv }
    }

    #[inline(always)]
    pub fn add(a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline(always)]
    pub fn sub(a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline(always)]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let idx = self.log[a as usize] as usize + self.log[b as usize] as usize;
            self.exp[idx]
        }
    }

    #[inline(always)]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        assert!(b != 0, "Division by zero in GF(2^8)");
        if a == 0 {
            0
        } else {
            let log_a = self.log[a as usize] as usize;
            let log_b = self.log[b as usize] as usize;
            let idx = (log_a + 255) - log_b;
            self.exp[idx]
        }
    }

    #[inline(always)]
    pub fn inv(&self, a: u8) -> u8 {
        assert!(a != 0, "Inverse of zero in GF(2^8)");
        self.inv[a as usize]
    }
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

pub static GF: Gf256 = Gf256::new();

/// Precomputed 16-entry low and high nibble multiplication tables for constant coefficient `coeff`.
#[derive(Clone, Copy)]
pub struct MulTable {
    pub low: [u8; 16],
    pub high: [u8; 16],
}

impl MulTable {
    pub fn new(coeff: u8) -> Self {
        let mut low = [0u8; 16];
        let mut high = [0u8; 16];
        for i in 0..16 {
            low[i] = GF.mul(i as u8, coeff);
            high[i] = GF.mul((i as u8) << 4, coeff);
        }
        Self { low, high }
    }

    #[inline(always)]
    pub fn mul_byte(&self, b: u8) -> u8 {
        let l = (b & 0x0f) as usize;
        let h = ((b >> 4) & 0x0f) as usize;
        self.low[l] ^ self.high[h]
    }
}

/// Multiply buffer `src` by `coeff` in GF(2^8) and XOR result into `dst`.
/// Uses SIMD where available (AVX2 on x86_64, NEON on aarch64) with fallback to chunked table lookups.
pub fn mul_slice_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len());
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        // Just XOR src into dst
        xor_slice(src, dst);
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            unsafe {
                neon_mul_slice_add(coeff, src, dst);
                return;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                avx2_mul_slice_add(coeff, src, dst);
                return;
            }
        }
    }

    fallback_mul_slice_add(coeff, src, dst);
}

/// Multiply buffer `src` by `coeff` in GF(2^8) and store into `dst`.
pub fn mul_slice(coeff: u8, src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len());
    if coeff == 0 {
        dst.fill(0);
        return;
    }
    if coeff == 1 {
        dst.copy_from_slice(src);
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            unsafe {
                neon_mul_slice(coeff, src, dst);
                return;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe {
                avx2_mul_slice(coeff, src, dst);
                return;
            }
        }
    }

    fallback_mul_slice(coeff, src, dst);
}

pub fn xor_slice(src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len());
    let len = src.len();
    let mut i = 0;

    // Fast 64-bit XOR loop
    while i + 8 <= len {
        let s_chunk = u64::from_ne_bytes(src[i..i + 8].try_into().unwrap());
        let d_chunk = u64::from_ne_bytes(dst[i..i + 8].try_into().unwrap());
        dst[i..i + 8].copy_from_slice(&(s_chunk ^ d_chunk).to_ne_bytes());
        i += 8;
    }

    while i < len {
        dst[i] ^= src[i];
        i += 1;
    }
}

fn fallback_mul_slice_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    let tbl = MulTable::new(coeff);
    let len = src.len();
    let mut i = 0;
    while i < len {
        dst[i] ^= tbl.mul_byte(src[i]);
        i += 1;
    }
}

fn fallback_mul_slice(coeff: u8, src: &[u8], dst: &mut [u8]) {
    let tbl = MulTable::new(coeff);
    let len = src.len();
    let mut i = 0;
    while i < len {
        dst[i] = tbl.mul_byte(src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn neon_mul_slice_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    use std::arch::aarch64::*;

    let tbl = MulTable::new(coeff);
    let low_table = vld1q_u8(tbl.low.as_ptr());
    let high_table = vld1q_u8(tbl.high.as_ptr());
    let mask_low = vdupq_n_u8(0x0f);

    let len = src.len();
    let mut i = 0;

    while i + 16 <= len {
        let s = vld1q_u8(src.as_ptr().add(i));
        let d = vld1q_u8(dst.as_ptr().add(i));

        let lo = vandq_u8(s, mask_low);
        let hi = vshrq_n_u8(s, 4);

        let res_lo = vqtbl1q_u8(low_table, lo);
        let res_hi = vqtbl1q_u8(high_table, hi);

        let prod = veorq_u8(res_lo, res_hi);
        let out = veorq_u8(d, prod);
        vst1q_u8(dst.as_mut_ptr().add(i), out);

        i += 16;
    }

    while i < len {
        dst[i] ^= tbl.mul_byte(src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn neon_mul_slice(coeff: u8, src: &[u8], dst: &mut [u8]) {
    use std::arch::aarch64::*;

    let tbl = MulTable::new(coeff);
    let low_table = vld1q_u8(tbl.low.as_ptr());
    let high_table = vld1q_u8(tbl.high.as_ptr());
    let mask_low = vdupq_n_u8(0x0f);

    let len = src.len();
    let mut i = 0;

    while i + 16 <= len {
        let s = vld1q_u8(src.as_ptr().add(i));

        let lo = vandq_u8(s, mask_low);
        let hi = vshrq_n_u8(s, 4);

        let res_lo = vqtbl1q_u8(low_table, lo);
        let res_hi = vqtbl1q_u8(high_table, hi);

        let prod = veorq_u8(res_lo, res_hi);
        vst1q_u8(dst.as_mut_ptr().add(i), prod);

        i += 16;
    }

    while i < len {
        dst[i] = tbl.mul_byte(src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn avx2_mul_slice_add(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let tbl = MulTable::new(coeff);
    // Duplicate 16-byte low and high tables into 256-bit registers
    let low128 = _mm_loadu_si128(tbl.low.as_ptr() as *const __m128i);
    let high128 = _mm_loadu_si128(tbl.high.as_ptr() as *const __m128i);
    let low_tbl256 = _mm256_set_m128i(low128, low128);
    let high_tbl256 = _mm256_set_m128i(high128, high128);
    let mask_low = _mm256_set1_epi8(0x0f);

    let len = src.len();
    let mut i = 0;

    while i + 32 <= len {
        let s = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        let d = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);

        let lo = _mm256_and_si256(s, mask_low);
        let hi = _mm256_and_si256(_mm256_srli_epi64(s, 4), mask_low);

        let res_lo = _mm256_shuffle_epi8(low_tbl256, lo);
        let res_hi = _mm256_shuffle_epi8(high_tbl256, hi);

        let prod = _mm256_xor_si256(res_lo, res_hi);
        let out = _mm256_xor_si256(d, prod);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, out);

        i += 32;
    }

    while i < len {
        dst[i] ^= tbl.mul_byte(src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn avx2_mul_slice(coeff: u8, src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let tbl = MulTable::new(coeff);
    let low128 = _mm_loadu_si128(tbl.low.as_ptr() as *const __m128i);
    let high128 = _mm_loadu_si128(tbl.high.as_ptr() as *const __m128i);
    let low_tbl256 = _mm256_set_m128i(low128, low128);
    let high_tbl256 = _mm256_set_m128i(high128, high128);
    let mask_low = _mm256_set1_epi8(0x0f);

    let len = src.len();
    let mut i = 0;

    while i + 32 <= len {
        let s = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);

        let lo = _mm256_and_si256(s, mask_low);
        let hi = _mm256_and_si256(_mm256_srli_epi64(s, 4), mask_low);

        let res_lo = _mm256_shuffle_epi8(low_tbl256, lo);
        let res_hi = _mm256_shuffle_epi8(high_tbl256, hi);

        let prod = _mm256_xor_si256(res_lo, res_hi);
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, prod);

        i += 32;
    }

    while i < len {
        dst[i] = tbl.mul_byte(src[i]);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_basic_properties() {
        assert_eq!(Gf256::add(5, 5), 0);
        assert_eq!(Gf256::sub(5, 5), 0);
        assert_eq!(GF.mul(0, 100), 0);
        assert_eq!(GF.mul(100, 0), 0);
        assert_eq!(GF.mul(1, 42), 42);
        assert_eq!(GF.mul(42, 1), 42);

        for a in 1..256 {
            let inv_a = GF.inv(a as u8);
            assert_eq!(GF.mul(a as u8, inv_a), 1, "Failed for a = {}", a);
        }
    }

    #[test]
    fn test_mul_slice_equivalence() {
        let coeff = 0x57;
        let src: Vec<u8> = (0..256).map(|x| x as u8).collect();
        let mut dst_fallback = vec![0u8; 256];
        let mut dst_simd = vec![0u8; 256];

        fallback_mul_slice(coeff, &src, &mut dst_fallback);
        mul_slice(coeff, &src, &mut dst_simd);
        assert_eq!(dst_fallback, dst_simd);

        let mut dst_add_fallback = vec![0x33u8; 256];
        let mut dst_add_simd = vec![0x33u8; 256];

        fallback_mul_slice_add(coeff, &src, &mut dst_add_fallback);
        mul_slice_add(coeff, &src, &mut dst_add_simd);
        assert_eq!(dst_add_fallback, dst_add_simd);
    }
}
