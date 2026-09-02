# PEEV: Parse Encrypt Execute Verify - A Verifiable FHE Framework.

This framework allows executing homomorphically encrypted programs based on the BGV scheme implementation in Microsoft [SEAL](https://github.com/microsoft/SEAL) and verifying the computation using [Rinocchio](https://github.com/zkFHE/ringSNARK/tree/main) ZKP protocol.

**This codebase is directly built on top of Rinocchio's codebase**

### How to cite this work
The [PEEV article] (https://ieeexplore.ieee.org/document/10587231) that describes this work can be cited as follows:

```
@article{ahmed2023verifiableFHE,
    author       = {Ahmed, Omar and Gouert, Charles and Georgios Tsoutsos, Nektarios},
    journal      = {IEEE Access},
    title        = {PEEV: Parse Encrypt Execute Verify - A Verifiable FHE Framework},
    year         = {2024},
    volume       = {12},
    number       = {},
    pages        = {94673-94689},
    note         = {\url{https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10587231}}
}
```

# Structure
* `opl` - a directory includes the OpL files that are used to create the arithmetic circuit executed in PEEV. The OpL is created by parsing [CirC](https://github.com/circify/circ) programs using [YAP](https://github.com/TrustworthyComputing/YAParser.git).
* `src/peev.cpp` - for reading the `.opl` file and executing the arithmetic circuit. 

# How to run
## Build
```
git clone https://github.com/TrustworthyComputing/PEEV-verifiableFHE.git
cd PEEV-verifiableFHE
mkdir build && cd build && cmake ..
make
```
## Run
Navigate to binary path (in `build` directory), open the cmd, execute `<program.exe> -f <file.opl>`. For example,
`peev.exe -f ../opl/dot_product_v8.opl`.

# Requirments
The project needs [Boost](https://www.boost.org/) library.

# Security
This a proof-of-concept implementation for research purposes. It is not ready for deployment in critical and production systems.

## Acknowledgments
This work was supported by the National Science Foundation (Award #2239334).
