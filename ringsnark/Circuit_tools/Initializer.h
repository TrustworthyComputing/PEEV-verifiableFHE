#ifndef RINGSNARK_INITIALIZER_H
#define RINGSNARK_INITIALIZER_H

#include <iostream>

#include "depends/SEAL/native/src/seal/seal.h"
#include "ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp"

#include "depends/SEAL-Polytools/include/poly_arith.h"
#include "ringsnark/seal/seal_ring.hpp"
#include "ringsnark/gadgetlib/protoboard.hpp"
#include <sstream>
#include <vector>
#include <iomanip>
#include <sstream>

using namespace std;
using namespace seal;

class Initializer {
private:
    /// polynomial modulus degree for Rinocchio
    size_t zkp_poly_modulus_degree; // = pow(2, 11);
    /// polynomial modulus degree for SEAL
    size_t he_poly_modulus_degree; // = 8192;
    /// Plaintext bit size
    int plain_bit_size; //= 20;
    /// The secret key object for decryption
    SecretKey secretKey;
    /// The public key object for decryption
    PublicKey publicKey;
    /// The relinearization keys for relinearizing the ciphertext
    RelinKeys relinKeys;
    /// SEAL encryptor object
    Encryptor* encryptor;
    /// SEAL evaluator object
    Evaluator* evaluator;
    /// SEAL decryptor object
    Decryptor* decryptor;
    /// Number Theoretic Tables for multiplying high-degree polynomials for Rinocchio
    const util::NTTTables* tables; //= zkp_context.get_context_data(zkp_context.first_parms_id())->small_ntt_tables();


public:
    typedef ringsnark::seal::RingElem R;
    typedef ringsnark::seal::EncodingElem E;

    Initializer();
    ~Initializer();

    typedef ::ringsnark::rinocchio::keypair<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincKeys;

    RincKeys get_Rinocchio_keys(const ringsnark::protoboard<R>& pb);

    [[nodiscard]] SEALContext* getHEContext() const;
    BatchEncoder* getHEEncoder(SEALContext& he_context) const;

    [[nodiscard]] SEALContext* getZKPContext() const;
    BatchEncoder * getZKPEncoder(SEALContext& zkp_context) const;

    size_t getZkpPolyModulusDegree() const;

    size_t getHePolyModulusDegree() const;

    int getPlainBitSize() const;

    const SecretKey &getSecretKey() const;

    const PublicKey &getPublicKey() const;

    const RelinKeys &getRelinKeys() const;

    Encryptor *getEncryptor() const;

    Evaluator *getEvaluator() const;

    Decryptor *getDecryptor() const;

    const util::NTTTables *getTables() const;

};


#endif //RINGSNARK_INITIALIZER_H
