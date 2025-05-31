#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Utilities - ElGamal
//!
//! This module implements the ElGamal encryption scheme in FFC and ECC.

// use std::str;
use std::io::Error;
use rand::rngs::OsRng;

use num_traits::{Num, One};
use num_bigint::{BigUint, RandBigInt};

use k256::{ProjectivePoint, NonZeroScalar};
use k256::elliptic_curve::{Group, AffineXCoordinate};
use sha2::{Digest, Sha256};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

/// Interface for using the ElGamal encryption scheme.
pub trait ElGamal {
    /// Public key type. In FFC: large integer in Z_p. In ECC: (x,y) coordinates of a point on the curve.
    type PublicKey;
    /// Private key type. In FFC: large integer in Z_p. In ECC: integer in Z_q.
    type SecretKey;
    /// Ciphertext type. Pair of values (c1, c2) with the same type as the public key.
    type Ciphertext;

    /// Generate key pair (sk, pk)
    fn keygen(&mut self) -> (Self::SecretKey, Self::PublicKey);

    /// Encrypt a message using the public key.
    fn encrypt(&mut self, pk: &Self::PublicKey, m: String) -> Self::Ciphertext;

    /// Decrypt a ciphertext using the private key.
    fn decrypt(&self, sk: &Self::SecretKey, ciphertext: Self::Ciphertext) -> Option<String>;

    /// Getter for the order of the group.
    fn order(&self) -> BigUint;
}

/// Structure implementing the ElGamal encryption scheme in the ffdhe2048 group.
pub struct ElGamalZp
{
    rng: OsRng,
    p: BigUint,
    q: BigUint,
    g: BigUint
}
impl ElGamalZp
{
    /// Create a new instance of the ElGamal encryption scheme in Z_p.
    pub fn new(p: BigUint, q: BigUint, g: BigUint) -> Result<Self, Error> {
        assert!(p>q, "The modulus must be greater than the order.");
        assert!(q>g, "The order must be greater than the generator.");
        assert!(g>BigUint::one(), "The generator must be greater than one.");

        let rng = OsRng; // Cryptographically secure random number generator
        Ok(Self {
            rng: rng,
            p: p,   // modulus
            q: q,   // order
            g: g    // generator
        })
    }
}
impl ElGamal for ElGamalZp
{
    type PublicKey = BigUint;
    type SecretKey = BigUint;
    type Ciphertext = (BigUint, BigUint);

    /// Key generation function.
    fn keygen(&mut self) -> (Self::SecretKey, Self::PublicKey) {
        let sk = self.rng.gen_biguint_range(&BigUint::from(2_u64), &self.q);
        let pk = self.g.modpow(&sk, &self.p);
        (sk.clone(), pk)
    }

    /// Encryption function.
    fn encrypt(&mut self, pk: &Self::PublicKey, m: String) -> Self::Ciphertext {
        let m_scalar = BigUint::from_bytes_be(m.as_bytes()) % &self.p;
        let r = self.rng.gen_biguint_range(&BigUint::one(), &self.q);
        let c1 = self.g.modpow(&r, &self.p);
        let c2 = (m_scalar * pk.modpow(&r, &self.p)) % &self.p;
        (c1, c2)
    }

    /// Decryption function.
    fn decrypt(&self, sk: &Self::SecretKey, c: Self::Ciphertext) -> Option<String> {
        let (c1, c2) = c;
        let s = c1.modpow(sk, &self.p);
        let s_inv = s.modinv(&self.p).unwrap();
        let m_scalar = (c2 * s_inv) % &self.p;

        // Try converting to a string
        String::from_utf8(m_scalar.to_bytes_be()).ok()
    }

    /// Getter for the order of the group.
    fn order(&self) -> BigUint {
        self.q.clone()
    }
}

/// Structure implementing the ElGamal encryption scheme in the ECC group secp256k1 (aka P256).
pub struct ElGamalP256 {
    rng: OsRng,
    // p: BigUint,
    q: BigUint,
    g: ProjectivePoint
}
impl ElGamalP256 {
    /// Create a new instance of ElGamal encryption scheme using ECC with curve P256.
    pub fn new() -> Result<Self, Error> {
        let rng = OsRng; // Cryptographically secure random number generator

        // let hex_modulus = "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        // let modulus = BigUint::from_str_radix(hex_modulus, 16).unwrap();

        let hex_order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
        let order = BigUint::from_str_radix(hex_order, 16).unwrap();

        Ok(Self {
            rng: rng,
            q: order,
            g: ProjectivePoint::GENERATOR
        })
    }

    /// Derive a symmetric key from a point on the curve.
    fn derive_symmetric_key(K: &ProjectivePoint) -> [u8; 32] {
        let x = K.to_affine().x();
        let x_bytes = x.as_slice();

        let mut hasher = Sha256::new();
        hasher.update(x_bytes);
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Encrypt a message using AES-GCM.
    fn AES_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from([0u8; 12]);
        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        ciphertext
    }

    /// Decrypt a message using AES-GCM.
    fn AES_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from([0u8; 12]);
        let plaintext = cipher.decrypt(&nonce, ciphertext);
        plaintext.ok() // If decryption fails, return None
    }
}
impl ElGamal for ElGamalP256 {
    type PublicKey = ProjectivePoint; // Represent the public key as coordinates (x, y)
    type SecretKey = NonZeroScalar; // The private key is a scalar
    type Ciphertext = (ProjectivePoint, ProjectivePoint, Vec<u8>); // Ciphertexts are pairs of curve points (c1, c2)

    /// Key generation function.
    fn keygen(&mut self) -> (Self::SecretKey, Self::PublicKey) {
        let sk = NonZeroScalar::random(&mut self.rng);
        let pk = self.g * *sk;
        (sk, pk)
    }

    /// Encryption function.
    fn encrypt(&mut self, pk: &Self::PublicKey, m: String) -> Self::Ciphertext {
        let r = NonZeroScalar::random(&mut self.rng);
        let K = ProjectivePoint::random(&mut self.rng);

        let symm_key = Self::derive_symmetric_key(&K);
        let c3 = Self::AES_encrypt(&symm_key, m.as_bytes());

        let c1 = self.g * *r;
        let c2 = K + *pk * *r;
        (c1, c2, c3)
    }

    /// Decryption function.
    fn decrypt(&self, sk: &Self::SecretKey, ciphertext: Self::Ciphertext) -> Option<String> {
        let (c1, c2, c3) = ciphertext;
        let s = c1 * **sk;
        let K = c2 - s;

        let symm_key = Self::derive_symmetric_key(&K);
        let m_bytes = Self::AES_decrypt(&symm_key, &c3);

        // Try converting to a string
        String::from_utf8(m_bytes?).ok() // If decryption fails, return None
    }

    /// Getter for the order of the curve.
    fn order(&self) -> BigUint {
        self.q.clone()
    }

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ffc_elgamal() {
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

        // Order of ffdhe2048
        let hex_order = "7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
            EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
            BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
            9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
            CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
            98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
            DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
            8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
            C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
            9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
            4435A11C 30942E4B FFFFFFFF FFFFFFFF";
        let clean_hex_order: String = hex_order.chars().filter(|c| !c.is_whitespace()).collect();
        let order = BigUint::from_str_radix(&clean_hex_order, 16).unwrap();

        // Generator of ffdhe2048
        let generator = BigUint::from(2_u64);
        
        // Setup
        let mut scheme = ElGamalZp::new(modulus, order, generator).unwrap();
        let (sk, pk) = scheme.keygen();
        // Encryption
        let message: String = "testing".to_string();
        let (c1, c2) = scheme.encrypt(&pk, message.clone());
        // Decryption
        let message_dec = scheme.decrypt(&sk, (c1, c2)).unwrap();
        assert_eq!(message, message_dec);
    }

    #[test]
    fn ecc_elgamal() {
        // Setup
        let mut scheme = ElGamalP256::new().unwrap();
        let (sk, pk) = scheme.keygen();

        // Encryption
        let message: String = "testing".to_string();
        let c = scheme.encrypt(&pk, message.clone());

        // Decryption
        let message_dec = scheme.decrypt(&sk, c).unwrap();
        assert_eq!(message, message_dec);
    }

    #[test]
    #[should_panic]
    fn ffc_elgamal_wrong_key_decrypt() {
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

        // Order of ffdhe2048
        let hex_order = "7FFFFFFF FFFFFFFF D6FC2A2C 515DA54D 57EE2B10 139E9E78
            EC5CE2C1 E7169B4A D4F09B20 8A3219FD E649CEE7 124D9F7C
            BE97F1B1 B1863AEC 7B40D901 576230BD 69EF8F6A EAFEB2B0
            9219FA8F AF833768 42B1B2AA 9EF68D79 DAAB89AF 3FABE49A
            CC278638 707345BB F15344ED 79F7F439 0EF8AC50 9B56F39A
            98566527 A41D3CBD 5E0558C1 59927DB0 E88454A5 D96471FD
            DCB56D5B B06BFA34 0EA7A151 EF1CA6FA 572B76F3 B1B95D8C
            8583D3E4 770536B8 4F017E70 E6FBF176 601A0266 941A17B0
            C8B97F4E 74C2C1FF C7278919 777940C1 E1FF1D8D A637D6B9
            9DDAFE5E 17611002 E2C778C1 BE8B41D9 6379A513 60D977FD
            4435A11C 30942E4B FFFFFFFF FFFFFFFF";
        let clean_hex_order: String = hex_order.chars().filter(|c| !c.is_whitespace()).collect();
        let order = BigUint::from_str_radix(&clean_hex_order, 16).unwrap();

        // Generator of ffdhe2048
        let generator = BigUint::from(2_u64);
        
        // Setup
        let mut scheme = ElGamalZp::new(modulus, order, generator).unwrap();
        let (_sk1, pk1) = scheme.keygen();
        let (sk2, _pk2) = scheme.keygen();

        // Encryption
        let message: String = "testing".to_string();
        let (c1, c2) = scheme.encrypt(&pk1, message.clone());

        // Decryption
        let _message_dec = scheme.decrypt(&sk2, (c1, c2)).unwrap();
    }

    #[test]
    #[should_panic]
    fn ecc_elgamal_wrong_key_decrypt() {
        // Setup
        let mut scheme = ElGamalP256::new().unwrap();
        let (_sk1, pk1) = scheme.keygen();
        let (sk2, _pk2) = scheme.keygen();

        // Encryption
        let message: String = "testing".to_string();
        let c = scheme.encrypt(&pk1, message.clone());

        // Decryption
        let _message_dec = scheme.decrypt(&sk2, c).unwrap();
    }
}