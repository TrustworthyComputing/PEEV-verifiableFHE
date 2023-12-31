# PEEV
 Parse Encrypt Execute Verify -  A Verifiable FHE Framework.

This framework allows executing homomorphically encrypted programs based on the BGV scheme implementation in Micorsoft [SEAL](https://github.com/microsoft/SEAL) and verifying the computation using [Rinocchio](https://github.com/zkFHE/ringSNARK/tree/main) ZKP protocol.

### How to cite this work
The [PEEV article](https://github.com/TrustworthyComputing/PEEV-verifiableFHE/blob/main/PEEV-VerifiableFHE.pdf) that describes this work can be cited as follows:

```
@misc{ahmed2023verifiableFHE,
    author       = {Omar Ahmed and Charles Gouert and Nektarios Georgios Tsoutsos},
    title        = {{PEEV: Parse Encrypt Execute Verify - A Verifiable FHE Framework}},
    year         = {2023},
    note         = {\url{https://github.com/TrustworthyComputing/PEEV-verifiableFHE/blob/main/PEEV-VerifiableFHE.pdf}},
}
```

# Structure
* opl - a directory includes the OpL files that are used to create the arithmetic circuit executed in PEEV. The OpL is created by parsing [CirC](https://github.com/circify/circ) programs using [YAP](https://github.com/OmarAlmighty/YAP).
* Driver.cpp - for reading the `.opl` file and executing the arithmetic circuit. This used for executing most of the benchmarks provided with the following parameters' values:
    * BGV ploynomial modulus degree = $2^{14}$
    * ZKP plaintext bit size = $30$ bits
    * SEAL plaintext bit size = $30$ bits
* Driver_eq_check.cpp - has different parameters set for executing programs that involve equality check (e.g., hamming distance) and doesn't use batching. It has the following parameters' values:
    * BGV ploynomial modulus degree = $2^{15}$
    * ZKP plaintext bit size = $20$ bits
    * SEAL plaintext modulus value = $13$ bits. **Notice that this the value of the plaintext modulus, not its size**.
* Driver_larger_params.cpp - this has another parameters used for executing the factorial program. It has the following parameters' values:
    * BGV ploynomial modulus degree = $2^{15}$
    * ZKP plaintext bit size = $30$ bits
    * SEAL plaintext bit size = $30$ bits

# How to run
## Build
```
git clone https://github.com/OmarAlmighty/PEEV.git
cd PEEV
mkdir build && cd build && cmake ..
cd .. && cmake --build build --config RELEASE
```
## Run 
Navigate to binary path (on Windows, it is on the build/Release directory), opne the cmd, execute `<program.exe> -f <file.opl>`. For example,
`vppc.exe -f dot_product_v8.opl`. 

### Note
* vppc.exe is the executable of Driver.cpp
* vppc2.exe is the executable of Driver_eq_check.cpp
* vppc3.exe is the executable of Driver_larger_params.cpp

# Requirments
The project needs [Boost](https://www.boost.org/) library.

# Security
This a proof-of-concept implementation for research purposes. It is not ready for deployment in critical and production systems.


