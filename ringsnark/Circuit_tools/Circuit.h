#ifndef RINGSNARK_CIRCUIT_H
#define RINGSNARK_CIRCUIT_H


#include <iostream>

#include "depends/SEAL/native/src/seal/seal.h"
#include "ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp"

#include "depends/SEAL-Polytools/include/poly_arith.h"
#include "Initializer.h"
#include "ringsnark/seal/seal_ring.hpp"
#include "ringsnark/gadgetlib/protoboard.hpp"
#include <sstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include "Initializer.h"
#include <map>

using namespace std;
using namespace seal;

class Circuit {
    typedef ringsnark::seal::RingElem R;
    typedef ringsnark::seal::EncodingElem E;
    typedef ringsnark::rinocchio::proof<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincProof;
    typedef ringsnark::rinocchio::proving_key<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincPb;
    typedef ringsnark::rinocchio::verification_key<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincVk;
private:
    bool verified = false;
    bool circuit_created = false;


    /// Total number of instructions (operations) executed by the circuit
    size_t n;

    int vars_count;


    /// A vector holding the ciphertext involved in the computations
    vector<Ciphertext> ciphers;
    /// A vector of RingElem objects that define the R1CS system
    ringsnark::pb_variable_array<R> vars;
    /// A vector of unsigned integers that are involved in the computations. Just normal values for debugging
    vector<int64_t> vs;
    /// A vector of SealPoly for running Rinocchio
    vector<::polytools::SealPoly> polys;
    /// A vector of RingElem objects for Rinocchio
    vector<ringsnark::seal::RingElem> values;
    vector<vector<int>> exec_lst;
    Encryptor* encryptor;
    Evaluator* evaluator;
    Decryptor* decryptor;
    SecretKey secretKey;
    PublicKey publicKey;
    RelinKeys relinKeys;

    BatchEncoder* zkp_encoder;
    SEALContext* zkp_context;
    BatchEncoder* he_encoder;
    SEALContext* he_context;

    const util::NTTTables* tables;
    ringsnark::protoboard<R> pb;
    /**
     * Multiply two values
     *
     * @param op1_indx the index of the first operand.
     * @param op2_indx the index of the second operand.
     * @param res_indx the index at which the result is saved
     * */
    void mul_(int op1_indx, int op2_indx, int res_indx);
    /**
     * Add two values
     *
     * @param op1_indx the index of the first operand.
     * @param op2_indx the index of the second operand.
     * @param res_indx the index at which the result is saved.
     * */
    void add_(int op1_indx, int op2_indx, int res_indx);

    /**
     * Defining a constant within the circuit
     *
     * @param const_val the value to be defined in the array.
     * @param indx the index at which the value is saved.
     * */
    void def_val_(int const_val, int indx);


    /**
     * Negate a value
     *
     * @param indx the index of the value to be negated.
     * @param res_indx the index at which the result is saved.
     * */
    void negate_(int indx, int res_indx);
public:
    Circuit(const Initializer& initializer);
    ~Circuit();
    ringsnark::protoboard<R> create_circuit(vector<vector<int>> exec_lst);
    void mul(int op1_indx, int op2_indx, int res_indx);
    void add(int op1_indx, int op2_indx, int one_indx, int res_indx);
    void def_val(int val, int indx);
    void def_var(char var, int indx);
    void negate(int indx, int one_indx, int res_indx);

    /**
     * Returns a 2D vector of the instructions to be executed by the list.
     * This mimics the actual circuit.
     * */
    vector<vector<int>> get_exec_list();

    /**
     * Print a textual representation of the instructions executed by the circuit.
     * */
    void print_circuit();

    /**
     * Execute the circuit giving the execution list.
     *
     * @param exec_list a 2D vector representing the execution list of the circuit.
     * */
    void execute(vector<vector<int>> exec_list, map<char, int> vars_vals);

    /**
     * Get the result of circuit execution.
     * */
    void get_results();


    RincProof prove(RincPb pk);

    void verify(RincVk vk, RincProof proof);
};


#endif //RINGSNARK_CIRCUIT_H
