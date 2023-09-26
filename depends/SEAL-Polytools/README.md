# SEAL-POLYTOOLS

This repo defines a set of utilities for working with polynomials in SEAL.
By default, SEAL has poor support for operating on individual polynomials so we add functions to perform various operations over polynomials.
Originally based on [seal_utils.h](https://github.com/ucsd-crypto/CKKSKeyRecovery/blob/main/src/seal_utils.h)/[seal_utils.cpp](https://github.com/ucsd-crypto/CKKSKeyRecovery/blob/main/src/seal_utils.cpp) from Bayiu Li's implementation of their [CKKS key recovery attack](https://eprint.iacr.org/2020/1533),
these have been adapted by Alexander Viand to introduce proper abstractions and memory safety (these adaptations are also used in [AfSeal.h](https://github.com/ibarrond/Pyfhel/blob/dev/Pyfhel/Afhel/Afseal.h)/[AfSeal.cpp](https://github.com/ibarrond/Pyfhel/blob/dev/Pyfhel/Afhel/Afseal.cpp) in [Pyfhel](https://dl.acm.org/doi/10.1145/3474366.3486923).
In addition to adding arithmetic operations over individual polynomials, the toolset also defines a variety of utiliies for creating polynomials from ciphertexts and vice-versa, including the ability to generate trivial (insecure) encryptions where both the random mask and the random noise are zero.

In addition, this repo includes an example application that uses this toolset to output input/output pairs for a variety of polynomial and FHE operations.
Currently, this just uses SEAL's built-in serialization, the format of which is documented in [SEAL_serialization_format.pdf](SEAL_serialization_format.pdf).
Note that when SEAL is used in public encryption mode, ciphertexts are serialized fully. However, in private-key-only mode, some randmoness is replaced with the seeds used to generate it to save space.
In the future, this might be extended to a dictionary-based system (e.g., pandas, json or custom protobuf lang).