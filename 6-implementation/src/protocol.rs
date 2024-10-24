#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Protocol
//!
//! Module implementing the road pricing protocol.

use std::io::Error;
use rand::rngs::OsRng;
use std::collections::HashMap;
use num_bigint::{BigUint, RandBigInt};

use crate::cellmap::CellMap;
use crate::utilities::elgamal::ElGamal;
use crate::utilities::group_hash::GroupHash;

use sha2::{Digest, Sha256};
type HashType = [u8; 32];

/// Interface for using the protocol.
pub struct Protocol<G,H>
where
    G: ElGamal,
    H: GroupHash<HashOutput = G::PublicKey>
{
    n: usize,
    k: usize,
    cellmap: CellMap<G,H>,
    log: Vec<(G::Ciphertext, f64, Option<HashType>)>,
    tickets: Vec<(usize, i64)>,
    tag_randomness: Option<BigUint>,
    known_tags: HashMap<HashType, usize>
}
impl<G,H> Protocol<G,H>
where
    G: ElGamal,
    H: GroupHash<HashOutput = G::PublicKey>,
    G::PublicKey: Clone,
    G::Ciphertext: Clone, 
{
    /// Create a new instance of the protocol.
    pub fn new(n: usize, k: usize, scheme: G, hash: H) -> Result<Self, Error> {
        Ok(Protocol {
            n: n,
            k: k,
            cellmap: CellMap::new(scheme, hash)?,
            log: Vec::new(),
            tickets: Vec::new(),
            tag_randomness: None,
            known_tags: HashMap::new()
        })
    }

    /// Setup the cell map.
    pub fn setup(&mut self) {
        self.cellmap.setup_random(self.n, self.k, None);
    }

    /// Setup the cell map with predefined checklist.
    pub fn setup_with_checklist(&mut self, checklist: Vec<bool>) {
        self.cellmap.setup_random(self.n, self.k, Some(checklist));
    }

    /// Initialize the tag.
    /// Tag_randomness is chosen by the user and static throughout a pricing period.
    /// For simplicity, we include the tag in the Protocol.
    pub fn initialize_tag(&mut self) {
        let mut rng = OsRng;
        let order = self.cellmap.get_order();
        let nonce: BigUint = rng.gen_biguint_below(&order);
        self.tag_randomness = Some(nonce);
    }

    /// Compute tag from cell id and random value: tag = SHA_256(cell_id|r)
    fn make_tag(cell_id: usize, r: BigUint) -> HashType {
        let mut tag_preimage = Vec::new();
        tag_preimage.extend_from_slice(&cell_id.to_be_bytes());
        tag_preimage.extend_from_slice(&r.to_bytes_be());
        
        let hash = Sha256::digest(tag_preimage);
        let mut candidate_bytes = [0u8; 32];
        candidate_bytes.copy_from_slice(&hash);
        candidate_bytes
    }

    /// Add travel data to user log (with optional tag).
    pub fn log_data(&mut self, cell_id: usize, t_in: i64, t_out: i64) {
        assert!(cell_id < self.n, "Cell ID out of bounds.");
        assert!(t_in < t_out, "Invalid time interval.");
        match &self.tag_randomness {
            Some(r) => {
                // Tag is SHA_256(cell_id|r)
                let tag = Self::make_tag(cell_id, r.clone());

                // Logging with tag (c,r,t)
                self.log.push((
                    self.cellmap.encrypt(cell_id, format!("{},{},{}", cell_id, t_in, t_out)), // encrypted data
                    self.cellmap.get_cell_rate(cell_id), // rate
                    Some(tag) // tag
                ));
            }
            None => {
                // Logging with no tag (c,r,_)
                self.log.push((
                    self.cellmap.encrypt(cell_id, format!("{},{},{}", cell_id, t_in, t_out)), // encrypted data
                    self.cellmap.get_cell_rate(cell_id), // rate
                    Option::None    // no tag
                ));
            }
        }
    }

    /// Add ticket information to log.
    pub fn log_ticket(&mut self, cell_id: usize, t: i64) {
        assert!(cell_id < self.n, "Cell ID out of bounds.");
        self.tickets.push((cell_id, t));
    }

    /// Recover values from a decrypted message.
    fn parse_message(&self, m: String) -> Option<(usize, i64, i64)> {
        let parts: Vec<&str> = m.split(",").collect();
        
        // Return None if there are not exactly 3 parts
        if parts.len() != 3 {
            return None;
        }

        // Parse the parts
        let c = parts[0].parse().ok()?;
        let t_in = parts[1].parse().ok()?;
        let t_out = parts[2].parse().ok()?;

        // Return the parsed values as Some tuple
        Some((c, t_in, t_out))
    }

    /// Decrypt the log.
    fn dec_log(&mut self) -> Vec<(usize, i64, i64, f64)> {
        let mut result = Vec::new();
        for (cipher, rate, tag) in self.log.iter() {

            if tag.is_some() {    // Tag is known
                
                let tag = tag.as_ref().unwrap();
                // Check if tag is known
                if let Some(sk_id) = self.known_tags.get(tag) {
                    // Decrypt message with known tag. If parsing works, add to result.
                    if let Some(message) = self.cellmap.decrypt(*sk_id, cipher.clone()) {
                        if let Some((cell_id, t_in, t_out)) = self.parse_message(message) {
                            result.push((cell_id, t_in, t_out, *rate));
                        }
                    }
                } else {
                    // If message can be decrypted, and parsed, add to result
                    if let Some((message, sk_id)) = self.cellmap.try_decrypt(cipher.clone()) {
                        if let Some((cell_id, t_in, t_out)) = self.parse_message(message) {
                            result.push((cell_id, t_in, t_out, *rate));
                            // Add tag to known tags
                            self.known_tags.insert(tag.clone(), sk_id);
                        }
                    }
                }

            } else { // No tag
                // If message can be decrypted, and parsed, add to result
                if let Some((message, _)) = self.cellmap.try_decrypt(cipher.clone()) {
                    if let Some((cell_id, t_in, t_out)) = self.parse_message(message) {
                        result.push((cell_id, t_in, t_out, *rate));
                    }
                }
            }

        }
        result
    }

    /// Verify tickets correspond with user log.
    pub fn check_log(&mut self) -> bool {
        let decrypted_log = self.dec_log();
        let checklist = self.cellmap.get_checklist();
        for (cell_id, t) in self.tickets.iter() {
            // Only check if cell is in checklist
            if checklist[*cell_id] {
                if !decrypted_log.iter().any(|(c, t_in, t_out, _)| c == cell_id && t_in <= t && t <= t_out) {
                    return false;
                }
            }
        }
        true
    }

    /// Return the fee to be paid by the user.
    pub fn get_fee(&self) -> f64 {
        let mut res = 0_f64;
        for (_,r,_) in self.log.iter() {res += r;}
        res
    }

    /// Reveal the fake cells location and the fake public keys.
    pub fn reveal_fake(&self) -> (Vec<BigUint>, Vec<bool>) {
        (self.cellmap.get_fkeys(), self.cellmap.get_checklist())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Num;
    use crate::utilities::elgamal::{ElGamalP256, ElGamalZp};
    use crate::utilities::group_hash::{HashP256, HashZp};

    #[test]
    fn ecc_protocol_no_tag() {
        // New ECC Protocol instance.
        let scheme = ElGamalP256::new().unwrap();
        let hash = HashP256::new(100).unwrap();
        let mut p = Protocol::new(100, 10, scheme, hash).unwrap();

        // Create a checklist.
        let mut checklist = vec![false; 100];
        checklist[1] = true;
        checklist[24] = true;

        // Setup the cell map.
        p.setup_with_checklist(checklist);

        // Log data.
        p.log_data(1, 100, 200);
        p.log_data(2, 200, 300);	
        p.log_data(12, 300, 400);
        p.log_data(13, 400, 500);
        p.log_data(14, 500, 600);
        p.log_data(24, 600, 700);
        p.log_data(25, 700, 800);

        // Log ticket.
        p.log_ticket(1, 150);
        p.log_ticket(24, 650);

        // Check log.
        assert!(p.check_log());
    }

    #[test]
    fn ecc_protocol_tag() {
        // New ECC Protocol instance.
        let scheme = ElGamalP256::new().unwrap();
        let hash = HashP256::new(100).unwrap();
        let mut p = Protocol::new(100, 10, scheme, hash).unwrap();

        // Create a checklist.
        let mut checklist = vec![false; 100];
        checklist[1] = true;
        checklist[24] = true;

        // Setup the cell map.
        p.setup_with_checklist(checklist);

        // Log data.
        p.initialize_tag();
        p.log_data(1, 100, 200);
        p.log_data(2, 200, 300);	
        p.log_data(12, 300, 400);
        p.log_data(13, 400, 500);
        p.log_data(14, 500, 600);
        p.log_data(24, 600, 700);
        p.log_data(25, 700, 800);

        // Log ticket.
        p.log_ticket(1, 150);
        p.log_ticket(24, 650);

        // Check log.
        assert!(p.check_log());
    }

    #[test]
    fn ffc_protocol_no_tag() {
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

        // Bit length of the prime
        let bit_length = 2048_u32;
        
        // New FFC Protocol instance.
        let scheme = ElGamalZp::new(modulus.clone(), order, generator).unwrap();
        let hash = HashZp::new(&modulus, bit_length).unwrap();
        let mut p = Protocol::new(100, 10, scheme, hash).unwrap();

        // Create a checklist.
        let mut checklist = vec![false; 100];
        checklist[1] = true;
        checklist[24] = true;

        // Setup the cell map.
        p.setup_with_checklist(checklist);

        // Log data.
        p.log_data(1, 100, 200);
        p.log_data(2, 200, 300);	
        p.log_data(12, 300, 400);
        p.log_data(13, 400, 500);
        p.log_data(14, 500, 600);
        p.log_data(24, 600, 700);
        p.log_data(25, 700, 800);

        // Log ticket.
        p.log_ticket(1, 150);
        p.log_ticket(24, 650);

        // Check log.
        assert!(p.check_log());
    }

    #[test]
    fn parse_message() {
        // New ECC Protocol instance.
        let p = Protocol::new(3, 2, ElGamalP256::new().unwrap(), HashP256::new(100_usize).unwrap()).unwrap();

        // Valid messages.
        assert_eq!(p.parse_message("1,2,3".to_string()), Some((1, 2, 3)));

        // Invalid messages.
        assert_eq!(p.parse_message("1,2".to_string()), None);
        assert_eq!(p.parse_message("1,2,3,4".to_string()), None);
        assert_eq!(p.parse_message("a,b,c".to_string()), None);

        assert_eq!(p.parse_message("1.1,2,3".to_string()), None);
        assert_eq!(p.parse_message("1,2.1,3".to_string()), None);
        assert_eq!(p.parse_message("1,2,3.1".to_string()), None);
    }
}