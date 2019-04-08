# Constant-time BCH Implementation.
## Introduction
These files contain various implementations of our constant-time BCH algorithm.

## Directory Structure
-- Blinded Table Scan<br>
-- Full Table Scan<br>

## Parameters
The run behaviour of the tests can be altered. In each sub-directory alter the parameters `MAX_Err` to alter maximum number of errors added to a codeword and `REPEATS` to alter test repeats in `test_bch.h`. In test_bch.c alter `print_to_file` to determine test output behaviour. If printing to a file, `REPEATS` must be a minimum of 2000 to allow for initial cpu spikes.

## Compilation Instructions
To run cpucycle tests and output results, in each sub-directory run:
* `make clean`
* `make`
* `./bch`

If `print_to_file = 0`, output will be printed on the terminal.<br>
If `print_to_file = 1`, output will be printed to file `cycles.csv`.
