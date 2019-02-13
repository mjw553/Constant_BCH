# Constant-time BCH Implementation integrated into LAC cryptosystem.
## Introduction
These files contain various implementations of our constant-time BCH algorithm integrated with the LAC cryptosystem.

## Directory Structure
-- Reference<br>
---- Blinded Table Scan<br>
---- Full Table Scan<br>
-- Optimised<br>
---- Blinded Table Scan<br>
---- Full Table Scan<br>

## Compilation Instructions
To run cpucycle tests and output LAC results, in each base directory run:
* `make clean`
* `make`
* `./lac cpucycles`<br>
Output will be printed in `lac_results.csv`.
