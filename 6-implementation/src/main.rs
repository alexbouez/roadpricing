#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Main function
//!
//! The sandbox area of the main function allows for direct use of the road pricing functions.

use std::io::Error;
use std::time::Instant;

/// Main function of the crate.
/// Contains sandbox area, allows access to all tools.
fn main() -> Result<(), Error>{
    println!("\n################\n# Road Pricing #\n################\n");
    let execution_start = Instant::now();

    // Sandbox area
    // println!("Nothing to be done.");

    println!("\n-> Total execution time: {:.2?}", execution_start.elapsed());
    Ok(())
}
