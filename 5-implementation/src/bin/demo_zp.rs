#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Demo for ElGamal encryption in Z_p
//!
//! Demonstration for using the ElGamal encryption scheme over Z_p

use std::io::Error;
use num_traits::Num;
use std::time::Instant;
use num_bigint::BigUint;
use rand::{Rng, rngs::OsRng};

use roadpricing::protocol::Protocol;
use roadpricing::utilities::elgamal::ElGamalZp;
use roadpricing::utilities::group_hash::HashZp;

/// Main function.
fn main() -> Result<(), Error>{
    println!("\n################\n# Road Pricing #\n################\n");
    let execution_start = Instant::now();
    println!("Protocol Demo - FFC variant (ffdhe2048)\n");

    // PRELIMINARIES
    let mut rng = OsRng;
    let (n,k): (usize, usize) = (10000, 100);

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

    // SETUP
    println!("Setting up the protocol with n = {} and k = {}...", n, k);

    // Generate ElGamal scheme
    let scheme = ElGamalZp::new(modulus.clone(), order, generator)?;

    // Generate Hash function
    // Parameter defines the number of iteration in try-and-increment
    let hash = HashZp::new(&modulus, bit_length)?;

    // Generate Protocol
    let mut protocol = Protocol::new(n, k, scheme, hash)?;

    // Check cells are selected randomly 
    // Rates are static and selected randomly
    protocol.setup();
    println!("\t-> Set up complete.");

    // LOGGING
    let n_data = 100; 
    println!("Logging {} travel entries and {} tickets...", n_data, n_data/3);

    // Log travel data
    // the cells are selected randomly 
    let mut cells_vec = Vec::new();
    let mut travel_time = 0;
    for _ in 0..n_data {
        let cell = rng.gen_range(0..n);
        protocol.log_data(cell, travel_time, travel_time+100);
        cells_vec.push((cell, travel_time + 50));
        travel_time += 100;
    }
    println!("\t-> Travel data logged.");

    // Log tickets
    for i in 0..n_data {
        if i % 3 == 0 {
            let (cell, time) = cells_vec[i];
            protocol.log_ticket(cell, time);
        }
    }
    println!("\t-> Tickets logged.");

    // VERIFICATION
    println!("Verifying the log...");
    if protocol.check_log() {
        println!("\t-> Log correct.");
    } else {
        println!("\t-> Log incorrect.");
    }

    // Execution time should be around 10 minutes for n=10000, k=100, n_data=100
    println!("\nTotal execution time: {:.2?}", execution_start.elapsed());
    Ok(())
}