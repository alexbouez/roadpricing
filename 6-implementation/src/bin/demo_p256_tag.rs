#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Demo for ElGamal encryption over P-256
//!
//! Demonstration for using ElGamal encryption scheme with the P-256 curve

use std::io::Error;
use std::time::Instant;
use rand::{Rng, rngs::OsRng};

use roadpricing::protocol::Protocol;
use roadpricing::utilities::group_hash::HashP256;
use roadpricing::utilities::elgamal::ElGamalP256;

/// Main function.
fn main() -> Result<(), Error>{
    println!("\n################\n# Road Pricing #\n################\n");
    let execution_start = Instant::now();
    println!("Protocol Demo - ECC variant (P256), with tags\n");

    // PRELIMINARIES
    let mut rng = OsRng;
    let n: usize = 10000;
    let (k, n_data, n_ticket) = (n/100, n/10, n/10);

    // SETUP
    println!("Setting up the protocol with n = {} and k = {}...", n, k);

    // Generate ElGamal scheme
    let scheme = ElGamalP256::new()?;

    // Generate Hash function
    // Parameter defines the number of iteration in try-and-increment
    let hash = HashP256::new(100_usize)?;

    // Generate Protocol
    let mut protocol = Protocol::new(n, k, scheme, hash)?;

    // Check cells are selected randomly 
    // Rates are static and selected randomly
    protocol.setup();
    println!("\t-> Set up complete.");

    // LOGGING
    println!("Logging {} travel entries and {} tickets...", n_data, n_ticket);

    // Log travel data
    // the cells are selected randomly
    let mut cells_vec = Vec::new();
    let mut travel_time = 0;
    protocol.initialize_tag();
    for _ in 0..n_data {
        let cell = rng.gen_range(0..n);
        protocol.log_data(cell, travel_time, travel_time+100);
        cells_vec.push((cell, travel_time + 50));
        travel_time += 100;
    }
    println!("\t-> Travel data logged.");

    // Log tickets
    for i in 0..n_ticket {
        let (cell, time) = cells_vec[i];
        protocol.log_ticket(cell, time);
    }
    println!("\t-> Tickets logged.");

    // VERIFICATION
    println!("Verifying the log...");
    if protocol.check_log() {
        println!("\t-> Log correct.");
    } else {
        println!("\t-> Log incorrect.");
    }

    // Execution time should be around 30-60 seconds for n=10000, k=100, n_data=1000, n_ticket=1000
    println!("\nTotal execution time: {:.2?}", execution_start.elapsed());
    Ok(())
}