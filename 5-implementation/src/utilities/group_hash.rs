#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Utilities - Group Hash
//!
//! This module implements a hash function over Z_p using the `num-bigint' and `sha3' libraries.

use std::io::Error;
use std::fmt::Debug;

#[allow(unused_imports)]
use num_traits::{One, Num};

use std::ops::Sub;
use num_bigint::BigUint;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use k256::{ProjectivePoint, AffinePoint, Scalar, U256, FieldBytes};
use k256::elliptic_curve::{DecompressPoint, ops::Reduce};
use k256::elliptic_curve::subtle::Choice;
use sha2::{Digest, Sha256};

/// Interface for a hash function over a group.
pub trait GroupHash {
    /// Type of the output of the hash function.
    type HashOutput;

    /// Compute the hash of an input U that can be converted into bytes.
    fn compute_hash<U: AsRef<[u8]> + Debug>(&self, input: U) -> Result<Self::HashOutput, Error>;
}

/// Structure implementing the hash function over Z_p.
pub struct HashZp
{
    p: BigUint,     // Modulus, prime order of the group
    n: u32          // Bit length of the XOF output
}
impl HashZp
{
    /// General new function.
    pub fn new(p: &BigUint, n: u32) -> Result<Self, Error> {
        assert!(n % 8 == 0, "The bit length of the output must be a multiple of 8.");

        let MAX_BIGUINT: BigUint = BigUint::from(2_u64).pow(n).sub(BigUint::one());
        assert!(*p <= MAX_BIGUINT);  // p < 2^n

        Ok(Self {
            p: p.clone(),
            n: n
        })
    }
}
impl GroupHash for HashZp
{
    type HashOutput = BigUint;

    /// Hashes a general input U that can be converted into bytes.
    fn compute_hash<U: AsRef<[u8]> + Debug>(&self, input: U) -> Result<BigUint, Error> {
        let mut hasher = Shake256::default(); // Use SHAKE256
        hasher.update(input.as_ref());  // Convert input to byte slice

        // Create an XOF reader to read 2048 bits (256 bytes) of output
        let mut reader = hasher.finalize_xof();
        let output_size = (self.n / 8) as usize;
        let mut output = vec![0u8; output_size];  // 2048 bits (256 bytes) of output
        reader.read(&mut output);

        // Convert the result (byte array) to BigUint modulo p
        Ok(BigUint::from_bytes_be(&output) % &self.p)
    }
}

/// Structure implementing a hash function over the elliptic curve P-256 using the try-and-increment method.
pub struct HashP256
{
    i: usize
}
impl HashP256
{
    /// General new function.
    pub fn new(count: usize) -> Result<Self, Error> {
        Ok(Self {
            i: count
        })
    }
}
impl GroupHash for HashP256
{
    type HashOutput = ProjectivePoint;

    /// Hashes a general input U that can be converted into bytes using the try-and-increment method.
    fn compute_hash<U: AsRef<[u8]> + Debug>(&self, input: U) -> Result<ProjectivePoint, Error> {
        // Step 1: Hash the message to get a 256-bit candidate value.
        let hash = Sha256::digest(input);
        let mut candidate_bytes = [0u8; 32];
        candidate_bytes.copy_from_slice(&hash);

        // Step 2: Try to interpret the candidate as a valid x-coordinate for the curve.
        let mut x_candidate = U256::from_be_slice(&candidate_bytes);

        for _ in 0..self.i {
            // Convert the x_candidate into bytes for the AffinePoint decompression.
            let x_scalar = Scalar::from_uint_reduced(x_candidate);
            let x_bytes = FieldBytes::from(&x_scalar);

            // Attempt to create an AffinePoint with even and then odd y parity.
            let is_y_odd = Choice::from(0);
            let point_ct = AffinePoint::decompress(&x_bytes.into(), is_y_odd);
            if point_ct.is_some().into() {
                return Ok(ProjectivePoint::from(point_ct.unwrap()));
            }

            let is_y_odd = Choice::from(1);
            let point_ct = AffinePoint::decompress(&x_bytes.into(), is_y_odd);
            if point_ct.is_some().into() {
                return Ok(ProjectivePoint::from(point_ct.unwrap()));
            }

            // If not a valid point, increment the candidate and try again.
            x_candidate = x_candidate.saturating_add(&U256::from(1u32));
        }

        Err(Error::new(std::io::ErrorKind::TimedOut, "Could not find a valid point on the curve."))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn hash_zp() {
        // Modulus of ffdhe2048
        let hex_modulus = "FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
            D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
            7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
            2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
            984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
            30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
            B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
            0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
            9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
            3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
            886B4238 61285C97 FFFFFFFF FFFFFFFF";
        let clean_hex_modulus: String = hex_modulus.chars().filter(|c| !c.is_whitespace()).collect();
        let modulus = BigUint::from_str_radix(&clean_hex_modulus, 16).unwrap();
        
        // Bit length of the prime
        let bit_length = 2048_u32;

        // Testing the Hash function
        let hasher = HashZp::new(&modulus, bit_length).unwrap();
        let output = hasher.compute_hash("testing").unwrap().to_bytes_be();
        let hex_string = output.iter().map(|byte| format!("{:02X}", byte)).collect::<String>();
        
        // Checking result
        // Expected hash is from https://emn178.github.io/online-tools/shake256/?input=testing&input_type=utf-8&output_type=hex&bits=2048
        // Value is smaller than p so there is no modulo operation needed
        let expected_hash = "94244120 ABA58B64 9FC1A66C FB5F6D51 106362AF 4C014AC3
            F1B0911F E5C16C23 81019FAD 1510B705 9455C9ED 120EEE8E
            47165355 F00ED9A1 6BA99419 B1806F2C 16E34F1E CFB1C397
            A200758D 138DBB34 604B18B1 80126DBF 3DBBB4D7 9061E28B
            B5548B22 00C13E4F 468FC1BE 429FA4BA 745FF847 EC9A0481
            9312F6BB 9610AA1A B12D3A2D 619BEA32 C2A1407F 4C54C487
            9D9C4A19 72DB21F7 266E0925 6E210F10 6FFF3F3C 48A934FE
            39546355 FB175CAD 87F13827 EF541C62 51BE7690 28CA6135
            331B618D 05BABF5F 9630B1C6 73581466 936DE30A B91F64CC
            BEDCB825 3CCAA3C2 94119FA5 B9E59894 85B2A0E1 8CDDE92A
            F1A3FE29 9D515F71 0A48D353 9CF678FC";

        let clean_exp_hash: String = expected_hash.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(hex_string, clean_exp_hash);
    }

    #[test]
    fn hash_p256() {
        // Testing the Hash function
        // Inputs have a small chance to fail, but 'testing' has a known point found on iteration 3
        let input = "testing";
        let group_hasher = HashP256::new(100_usize).unwrap();
        let _output = group_hasher.compute_hash(input).unwrap().to_affine().to_encoded_point(false);
    }
    
    #[test]
    #[should_panic]
    fn hash_p256_point_not_found() {
        // Testing the Hash function
        // 'testing' has a known point on the curve, but with 2 iterations it will not be found
        let input = "testing";
        let group_hasher = HashP256::new(2_usize).unwrap();
        let _output = group_hasher.compute_hash(input).unwrap().to_affine().to_encoded_point(false);
    }
}