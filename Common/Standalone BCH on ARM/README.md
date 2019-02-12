# ARM Testing Component
## Introduction
These files provide the framework for testing the BCH implementation on ARM.
See README_ARM for specific details on the framework. 

## Important Files
-- benchmarks
---- crypto_kem
------ bch
-------- ref : Results from benchmarking tests are outputted here.
-- crypto_kem
---- speed.c : Main testing method for BCH implementation.
---- bch
------ ref : Stores main BCH implementation files.
-------- bch_implementations : Stores the three different implementations of BCH.
---------- bch_blinded.c : BCH with Blinded look-up table access.
---------- bch_full_table.c : BCH with Full table access.
---------- bch_no_table_countermeasures.c : BCH with no table security countermeasures.

## Compilation Instructions
### Pre-compilation
Choose an implementation from crypto_kem/bch/ref/bch_implementations
Copy chosen implementation to crypto_kem/bch/ref/
Rename copied file to bch.c in crypto_kem/bch/ref/

### Compilation
From the crypto_kem directory:
* make clean
* make

### Running the benchmarks
Run the command:
* sudo python3 benchmarks.py