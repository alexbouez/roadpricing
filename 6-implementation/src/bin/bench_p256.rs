#![warn(missing_docs)]
#![allow(non_snake_case)]

//! Road Pricing - Demo for ElGamal encryption over P-256
//!
//! Demonstration for using ElGamal encryption scheme with the P-256 curve

use std::io::Error;
use std::time::Instant;
use rand::{Rng, rngs::OsRng};

use csv::Writer;
use std::fs::{File, create_dir_all};
use std::sync::{Arc, Mutex};
use rayon::prelude::*;
use core_affinity;

use roadpricing::protocol::Protocol;
use roadpricing::utilities::elgamal::ElGamalP256;
use roadpricing::utilities::group_hash::HashP256;

#[derive(Debug, Clone)]
struct Task {
    rep: usize,
    set: usize,
    n: usize,
    k: usize,
    n_data: usize,
    n_ticket: usize,
    with_tag: bool,
}

fn roadpricing_p256(n: usize, k: usize, n_data: usize, n_ticket: usize, with_tag: bool) -> Result<(), Error> {
    // PRELIMINARIES
    let mut rng = OsRng;

    // SETUP
    let scheme = ElGamalP256::new()?;
    let hash = HashP256::new(100_usize)?;
    let mut protocol = Protocol::new(n, k, scheme, hash)?;
    protocol.setup();

    // LOGGING
    // Log travel data
    let mut cells_vec = Vec::new();
    let mut travel_time = 0;

    if with_tag {
        protocol.initialize_tag();
    }

    for _ in 0..n_data {
        let cell = rng.gen_range(0..n);
        protocol.log_data(cell, travel_time, travel_time+100);
        cells_vec.push((cell, travel_time + 50));
        travel_time += 100;
    }
    // Log tickets
    for i in 0..n_ticket {
        let (cell, time) = cells_vec[i];
        protocol.log_ticket(cell, time);
    }

    // VERIFICATION
    assert!(protocol.check_log());
    Ok(())
}

/// Main function.
fn main() -> Result<(), Error> {
    println!("\n################\n# Road Pricing #\n################\n");
    let execution_start = Instant::now();
    println!("Protocol Benchmark - ECC variant (P256)\n");

    // PARAMETERS
    let (reps, step, sets) = (10, 10000, 10);
    let mut n: usize = 10000;

    // CORE AFFINITY Setup
    let core_ids = core_affinity::get_core_ids().unwrap();
    let num_cores = core_ids.len();

    // CSV Setup
    create_dir_all("out")?;
    let wtr = Arc::new(Mutex::new(Writer::from_writer(File::create("out/benchmark_results_p256.csv")?)));
    wtr.lock().unwrap().write_record(&["function", "with_tag", "n", "k", "n_data", "n_ticket", "time"])?;

    // BENCHMARKING
    // Generate the list of tasks
    println!("\nStarting benchmarking...");
    let mut tasks: Vec<Task> = Vec::new();
    for set in 0..sets {
        let (k, n_data, n_ticket) = (n / 100, n / 10, n / 100);
        for rep in 0..reps {
            // We generate 10 iterations for each rep with varying numbers of log entries and tickets
            for j in 1..=10 {
                for with_tag in [true, false].iter() {
                    // Collect all necessary parameters into the task vector
                    tasks.push(Task {
                        rep,
                        set,
                        n,
                        k,
                        n_data: n_data * j,
                        n_ticket: n_ticket * j,
                        with_tag: *with_tag,
                    });
                }
            }
        }
        n += step; // Increment n for the next set
    }
    println!("\tGenerated {} tasks.", tasks.len());

    // Process tasks in batches of num_cores to avoid overloading the system
    tasks.chunks(num_cores).enumerate().for_each(|(batch_idx, task_batch)| {
        task_batch.into_par_iter().enumerate().for_each(|(i, task)| {
            // Pin the thread to a specific core
            let core = core_ids[i % num_cores];
            core_affinity::set_for_current(core);

            let task_index = batch_idx * num_cores + i;
            println!("\tRunning task {} (Set: {}, Rep: {}, core: {}, n: {}, k: {}, n_data: {}, n_ticket: {}, with_tag: {})",
                task_index, task.set, task.rep, i % num_cores, task.n, task.k, task.n_data, task.n_ticket, task.with_tag);

            let bench_start = Instant::now();
            roadpricing_p256(task.n, task.k, task.n_data, task.n_ticket, task.with_tag).ok();
            let bench_end = bench_start.elapsed();
            let time_taken = bench_end.as_secs_f64(); // Capture time in seconds as f64

            // Lock and write to the CSV (safe across threads)
            let mut writer = wtr.lock().unwrap();
            writer.write_record(&[
                "roadpricing_256",            // function name
                &task.with_tag.to_string(),   // with_tag value
                &task.n.to_string(),          // n value
                &task.k.to_string(),          // k value
                &task.n_data.to_string(),     // n_data value
                &task.n_ticket.to_string(),   // n_ticket value
                &time_taken.to_string(),      // elapsed time
            ]).unwrap();

            println!("\tTask {} completed in {:.2?}", task_index, bench_end);
        });
    });

    // Flush the CSV writer to ensure all data is written to the file
    wtr.lock().unwrap().flush()?;

    println!("\nTotal execution time: {:.2?}", execution_start.elapsed());
    Ok(())
}