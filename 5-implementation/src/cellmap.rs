#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - CellMap
//!
//! Module implementing the map structure of the road pricing protocol.

use std::io::Error;

use num_traits::One;
use rand::{Rng, rngs::OsRng};
use num_bigint::{BigUint, RandBigInt};

use crate::utilities::group_hash::GroupHash;
use crate::utilities::elgamal::ElGamal;

/// Interface for using CellMap functions.
pub struct CellMap<G,H>
where
    G: ElGamal,
    H: GroupHash<HashOutput = G::PublicKey>, // Ensure the hash output matches the ElGamal's public key type.
{
    rng: OsRng,
    pkeys: Vec<G::PublicKey>,
    skeys: Vec<G::SecretKey>,
    fkeys: Vec<BigUint>,
    checklist: Vec<bool>,
    rates: Vec<f64>,
    scheme: G,
    hash: H,
}
impl<G,H> CellMap<G, H>
where
    G: ElGamal,
    H: GroupHash<HashOutput = G::PublicKey>,
    G::PublicKey: Clone,
    G::Ciphertext: Clone,
{
    /// Generate CellMap. 
    pub fn new(scheme: G, hash: H) -> Result<Self, Error> {
        Ok(Self {
            rng: OsRng,
            pkeys: Vec::new(),
            skeys: Vec::new(),
            fkeys: Vec::new(),
            checklist: Vec::new(),
            rates: Vec::new(),
            scheme: scheme,
            hash: hash
        })
    }

    /// Select k check cells from n cells.
    fn select_check_cells(n: usize, k: usize) -> Vec<bool> {
        assert!(k <= n);
        let mut rng = OsRng;
        let mut checklist = vec![false; n];
        for _ in 0..k {
            let mut i = rng.gen_range(0..n);
            while checklist[i] {
                i = rng.gen_range(0..n);
            }
            checklist[i] = true;
        }
        checklist
    }

    /// Setup the CellMap.
    pub fn setup(&mut self, n: usize, k: usize, checklist: Vec<bool>, rates: Vec<f64>) {
        assert_eq!(checklist.len(), n, "The length of the checklist does not match the expected value: {}", n);
        assert_eq!(rates.len(), n, "The length of the rates does not match the expected value: {}", n);
        let true_count = checklist.iter().filter(|&&x| x).count();
        assert_eq!(true_count, k, "The number of check cells does not match the expected value: {}", k);

        // Generate the public and secret keys.
        let (mut skeys, mut pkeys, mut fkeys) = (Vec::new(), Vec::new(), Vec::new());
        for i in 0..n {
            if checklist[i] {
                let (secret_key, public_key) = self.scheme.keygen();
                skeys.push(secret_key);
                pkeys.push(public_key);
            } else {
                let fake_key = self.rng.gen_biguint_range(&BigUint::one(), &self.scheme.order());
                let public_key = self.hash.compute_hash(&fake_key.to_bytes_be()).unwrap();
                fkeys.push(fake_key);
                pkeys.push(public_key);
            }
        }

        // Update the CellMap.
        self.pkeys = pkeys;
        self.skeys = skeys;
        self.fkeys = fkeys;
        self.rates = rates;
        self.checklist = checklist;
    }
    
    /// Setup the CellMap with randomly located check_cells, rates, and fake keys.
    pub fn setup_random(&mut self, n: usize, k: usize, checklist: Option<Vec<bool>>) {
        // Select the check cells.
        if checklist.is_none() {
            self.checklist = Self::select_check_cells(n, k);
        } else {
            assert_eq!(checklist.as_ref().unwrap().len(), n, 
                "The length of the checklist does not match the expected value: {}", n);
            self.checklist = checklist.unwrap();
        }

        // Generate the public and secret keys.
        let (mut skeys, mut pkeys, mut fkeys) = (Vec::new(), Vec::new(), Vec::new());
        for i in 0..n {
            if self.checklist[i] {
                let (secret_key, public_key) = self.scheme.keygen();
                skeys.push(secret_key);
                pkeys.push(public_key);
            } else {
                let fake_key = self.rng.gen_biguint_range(&BigUint::one(), &self.scheme.order());
                let public_key = self.hash.compute_hash(&fake_key.to_bytes_be()).unwrap();
                fkeys.push(fake_key);
                pkeys.push(public_key);
            }
        }

        // Generate random rates.
        let rates = (0..n).map(|_| self.rng.gen_range(0.0..1.0)).collect();

        // Update the CellMap.
        self.pkeys = pkeys;
        self.skeys = skeys;
        self.fkeys = fkeys;
        self.rates = rates;
    }

    /// Encrypt a message with a cell public key.
    pub fn encrypt(&mut self, cell_id: usize, message: String) -> G::Ciphertext {
        assert!(cell_id < self.pkeys.len(), "Cell ID out of bounds.");
        self.scheme.encrypt(&self.pkeys[cell_id], message)
    }

    /// Decrypt a ciphertext with a cell secret key.
    pub fn decrypt(&self, cell_id: usize, cipher: G::Ciphertext) -> Option<String> {
        assert!(cell_id < self.pkeys.len(), "Cell ID out of bounds.");
        self.scheme.decrypt(&self.skeys[cell_id], cipher)
    }

    /// Try to decrypt a ciphertext with all check cell secret keys.
    pub fn try_decrypt(&self, cipher: G::Ciphertext) -> Option<(String, usize)> {
        for sk_id in 0..self.skeys.len() {
            if let Some(message) = self.scheme.decrypt(&self.skeys[sk_id], cipher.clone()) {
                return Some((message, sk_id));
            }
        }
        return Option::None;
    }

    /// Hash a message with H.
    pub fn hash(&self, input: Vec<u8>) -> H::HashOutput {
        self.hash.compute_hash(input).unwrap()
    }

    /// Get the public key of a cell.
    pub fn get_cell_key(&self, cell_id: usize) -> G::PublicKey {
        self.pkeys[cell_id].clone()
    }

    /// Get the rate of a cell.
    pub fn get_cell_rate(&self, cell_id: usize) -> f64 {
        self.rates[cell_id]
    }

    /// Getter for the fake keys.
    pub fn get_fkeys(&self) -> Vec<BigUint> {
        self.fkeys.clone()
    }

    /// Getter for the checklist
    pub fn get_checklist(&self) -> Vec<bool> {
        self.checklist.clone()
    }

    /// Getter for the order of the scheme.
    pub fn get_order(&self) -> BigUint {
        self.scheme.order()
    }
}