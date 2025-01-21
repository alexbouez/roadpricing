# Roadpricing

Anonymized code and data for AsiaCCS 2025, submission #25:
'Mobile Cell-Based Road Pricing with Verifiable User Privacy'.

## Organization of the repository

This repository contains two directories, pertaining to different sections of the submission:
 - 6-implementation: contains the source code of the implementation and the benchmarking utilities.
 - 6.2-performance: contains the data and source code used to generate the benchmarking results graph.

## Running the source code

The protocol is implemented in Rust. Prerequisites for running it are up-to-date versions of Rust and Cargo. The full dependency list of the code can be found in the Cargo.toml file.
A Makefile is present, which gives access to the following commands:
 - 'make clean': delete all compilation products.
 - 'make build', 'make run': build or run the source code using 'src/main.rs' as starting point.
 - 'make demo_{name}': run the source code using a demo file as starting point. Available demo files: demo_zp, demo_p256_no_tag, demo_p256_tag.
 - 'make bench_p256': run the benchmarking process.

## Data and Visualization

The data files used to generate the graph presented in the article are available at '6.2-performance/data/'. The graphs are generated via the 'roadpricing.ipynb' notebook. This requires Jupyter Notebook and Python to run.