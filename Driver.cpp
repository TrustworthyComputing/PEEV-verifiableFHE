#include <iostream>
#include "depends/SEAL/native/src/seal/seal.h"
#include "ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp"
#include "depends/SEAL-Polytools/include/poly_arith.h"
#include "ringsnark/seal/seal_ring.hpp"
#include "ringsnark/gadgetlib/protoboard.hpp"
#include <vector>
#include <map>
#include <boost/algorithm/string/trim.hpp>
#include <string>
#include <stack>
#include "./stdc++.h"
#include <ctype.h>
#include <regex>
#include <chrono>

using namespace std;
using namespace seal;


/// Type definitions for
// Ring element
typedef ringsnark::seal::RingElem R;
// Encoding element
typedef ringsnark::seal::EncodingElem E;
// Rinocchio proving and verification keys.
typedef ::ringsnark::rinocchio::keypair<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincKeys;
// Rinocchio proof
typedef ringsnark::rinocchio::proof<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincProof;
// Rinocchio proving key
typedef ringsnark::rinocchio::proving_key<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincPb;
// Rinocchio verification key
typedef ringsnark::rinocchio::verification_key<ringsnark::seal::RingElem, ringsnark::seal::EncodingElem> RincVk;

void pause_4_debug(string msg) {
    char x;
    cout << "\n"
         << msg << endl;
    cin >> x;
}

/// A class for initializing variables and elements used for Rinnichio and SEAL HE
class Initializer {

private:
    /// polynomial modulus degree for Rinocchio
    size_t zkp_poly_modulus_degree; // = pow(2, 11);
    /// polynomial modulus degree for SEAL
    size_t he_poly_modulus_degree; // = 8192;
    /// Plaintext bit size
    int zkp_plain_bit_size; //= 20;
    int he_plain_bit_size;
    /// The secret key object for decryption
    SecretKey secretKey;
    /// The public key object for decryption
    PublicKey publicKey;
    /// The relinearization keys for relinearizing the ciphertext
    RelinKeys relinKeys;
    /// SEAL encryptor object
    Encryptor *encryptor;
    /// SEAL evaluator object
    Evaluator *evaluator;
    /// SEAL decryptor object
    Decryptor *decryptor;
    /// Number Theoretic Tables for multiplying high-degree polynomials for Rinocchio
    const util::NTTTables *tables; //= zkp_context.get_context_data(zkp_context.first_parms_id())->small_ntt_tables();

public:
    Initializer() {
        /// Default polynomial modulus degree for ZKP. Changing it may cause errors or getting noise as a result.
        this->zkp_poly_modulus_degree = pow(2, 11);//pow(2, 11);
        /// Default polynomial modulus degree for HE
        this->he_poly_modulus_degree = pow(2, 14); //8192;
        /// Plaintext bit size
        this->zkp_plain_bit_size = 30;//20;
        this->he_plain_bit_size = 30;//20;
        /// Setup SEALContext object for HE.
        SEALContext *he_context = getHEContext();
        // BatchEncoder *he_encoder = getHEEncoder(*he_context);

        /// Setup a SEALContext object for ZKP.
        SEALContext *zkp_context = getZKPContext();
        // BatchEncoder *zkp_encoder = getZKPEncoder(*zkp_context);

        /// Initializing the Ring element and the Encoding element for ZKP.
        R::set_context(*zkp_context);
        E::set_context();

        /// Creating the secret, public, and relinearization keys for HE.
        KeyGenerator keygen(*he_context);
        secretKey = keygen.secret_key();
        keygen.create_public_key(publicKey);
        keygen.create_relin_keys(relinKeys); // Won't work with poly_mod_degree < 8192

        /// Creating the encryptor, evaluator, and decryptor for HE.
        encryptor = new Encryptor(*he_context, publicKey);
        evaluator = new Evaluator(*he_context);
        decryptor = new Decryptor(*he_context, secretKey);

        /// Number Theoretic Tables for multiplying high-degree polynomials for Rinocchio
        tables = zkp_context->get_context_data(zkp_context->first_parms_id())->small_ntt_tables();
    }

    /**Creates a SEALContext object comprising the parameters for HE.
     * @return context a SEALContext object.
     * */
    [[nodiscard]] SEALContext *getHEContext() const {
        // Define the scheme type = bgv
        EncryptionParameters params(scheme_type::bgv);
        params.set_poly_modulus_degree(he_poly_modulus_degree);
        // Initialize the coefficient modulus
        params.set_coeff_modulus(CoeffModulus::BFVDefault(he_poly_modulus_degree));
        // Initialize the plain modulus
        params.set_plain_modulus(PlainModulus::Batching(he_poly_modulus_degree, he_plain_bit_size));
        // wrap the parameters in a context object
        auto context = new SEALContext(params);
        return context;
    }

    /** Creates a BatchEncoder object for HE.
     * @param he_context a SEALContext object
     * @return batchEncoder a batchEncoder object.
     * */
    BatchEncoder *getHEEncoder(SEALContext &he_context) const {
        auto *batchEncoder = new BatchEncoder(he_context);
        return batchEncoder;
    }

    /**
     * Creates a SEALContext object for ZKP.
     * @return context a SEALContext object.
     * */
    [[nodiscard]] SEALContext *getZKPContext() const {
        // Define the scheme type = bgv
        EncryptionParameters params(scheme_type::bgv);
        // Define the polynomial modulus degree = 2^11
        params.set_poly_modulus_degree(this->zkp_poly_modulus_degree);
        // Initialize the coefficient modulus
        params.set_coeff_modulus(CoeffModulus::BFVDefault(this->zkp_poly_modulus_degree));
        // Initialize the plain modulus
        params.set_plain_modulus(PlainModulus::Batching(this->zkp_poly_modulus_degree,
                                                        this->zkp_plain_bit_size));
        // wrap the parameters in a context object
        auto context = new SEALContext(params);
        return context;
    }

    /**
     * Creates a BatchEncoder object for ZKP.
     * @return batchEncoder
     * */
    BatchEncoder *getZKPEncoder(SEALContext &zkp_context) const {
        auto *batchEncoder = new BatchEncoder(zkp_context);
        return batchEncoder;
    }

    /**
     * Creates Rinnochhio key pair object.
     * @param pb a protoboard object that holds the R1CS constraint.
     * @return keypair an object has the proving and verification keys.
     * */
    RincKeys get_Rinocchio_keys(const ringsnark::protoboard<R> &pb) {
        const auto keypair = ringsnark::rinocchio::generator<R, E>(pb.get_constraint_system());
        return keypair;
    }

    [[nodiscard]] size_t getZkpPolyModulusDegree() const {
        return zkp_poly_modulus_degree;
    }

    [[nodiscard]] size_t getHePolyModulusDegree() const {
        return he_poly_modulus_degree;
    }

    [[nodiscard]] int getPlainBitSize() const {
        return zkp_plain_bit_size;
    }

    [[nodiscard]] const SecretKey &getSecretKey() const {
        return secretKey;
    }

    [[nodiscard]] const PublicKey &getPublicKey() const {
        return publicKey;
    }

    [[nodiscard]] const RelinKeys &getRelinKeys() const {
        return relinKeys;
    }

    [[nodiscard]] Encryptor *getEncryptor() const {
        return encryptor;
    }

    [[nodiscard]] Evaluator *getEvaluator() const {
        return evaluator;
    }

    [[nodiscard]] Decryptor *getDecryptor() const {
        return decryptor;
    }

    [[nodiscard]] const util::NTTTables *getTables() const {
        return tables;
    }
};

class Circuit {
private:
    /// This variale used to track the size of the execution vector, which holds the instruction to be executed.
    size_t n;
    /// The last value computed and stored in the ciphers vector is the result. This variable is used to track the
    /// values computed and stored in the vector.
    int res_indx;
    /// A boolean variable to check if the computations has been verified or not.
    bool verified = false;
    /// A boolean variable to check if the circuit has been created before excution or not.
    bool circuit_created = false;
    /// The number of variables being used within the circuit.
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
    /// A 2D vector holding the instructions (operations) to be executed by the circuit.
    /// The first dimension holds vectors of operations.
    /// The second dimension is a vector that holds the operation code (opcode) and the its parameters.
    vector<vector<int>> exec_lst;
    /// Encryptor object for HE.
    Encryptor *encryptor;
    /// Evaluator object for HE.
    Evaluator *evaluator;
    /// Decryptor object for HE.
    Decryptor *decryptor;
    /// The secret key for HE decryption.
    SecretKey secretKey;
    /// The public key for HE encryption.
    PublicKey publicKey;
    /// The relinearization keys for bootstrapping HE operations.
    RelinKeys relinKeys;
    /// A BatchEncoder object for ZKP.
    BatchEncoder *zkp_encoder;
    /// A SEALContext object for ZKP.
    SEALContext *zkp_context;
    /// A BatchEncoder object for HE.
    BatchEncoder *he_encoder;
    /// A SEALContext object for HE.
    SEALContext *he_context;
    /// Number Theoretic Tables for ZKP.
    const util::NTTTables *tables;
    /// An object for defining the R1CS constraints.
    ringsnark::protoboard<R> pb;

    /**
     * Compute the multiplication between two ciphertexts.
     * @param op1_indx the index of the first ciphertext.
     * @param op2_indx the index of the second ciphertext.
     * @param res_indx the index at which to store the result.
     * */
    void mul_(int op1_indx, int op2_indx, int res_indx) {
        //        uint64_t op1 = vs[op1_indx];
        //        uint64_t op2 = vs[op2_indx];
        //        vs[res_indx] = op1 * op2;
        /// For HE
        evaluator->multiply(ciphers[op1_indx], ciphers[op2_indx], ciphers[res_indx]);
        evaluator->relinearize_inplace(ciphers[res_indx], relinKeys);
        //evaluator->mod_switch_to_next_inplace(ciphers[res_indx]);
        /// For ZKP
        auto poly = ::polytools::SealPoly(polys[op1_indx]);
        poly.multiply_inplace(polys[op2_indx]);
        polys[res_indx] = poly;
        values[res_indx] = ringsnark::seal::RingElem(poly);
        // cout << "mul:\t" << vs[res_indx] << endl;
    }

    /**
     * Compute the addition between two ciphertexts.
     * @param op1_indx the index of the first ciphertext.
     * @param op2_indx the index of the second ciphertext.
     * @param one_indx the index of the value 1 to be multiplied by the result of the addition operation.
     * @param res_indx the index at which to store the result.
     * */
    void add_(int op1_indx, int op2_indx, int one_indx, int res_indx) {
        // vs[res_indx] = vs[op1_indx] + vs[op2_indx];
        //  For HE
        evaluator->add(ciphers[op1_indx], ciphers[op2_indx], ciphers[res_indx]);
        /*Cancel relineraizing after additions*/
        //evaluator->relinearize_inplace(ciphers[res_indx], relinKeys);

        // For ZKP
        auto poly = ::polytools::SealPoly(polys[op1_indx]);
        poly.add_inplace(polys[op2_indx]);
        poly.multiply_inplace(polys[one_indx]);

        polys[res_indx] = poly;
        values[res_indx] = ringsnark::seal::RingElem(poly);
    }

    /**
     * Store a ciphertext in the ciphers vector.
     * @param cipher the ciphertext to be stored.
     * @param indx the index at which the ciphertext will be stored.*/
    void def_val_(Ciphertext cipher, int indx) {
        // vs[indx] = const_val;
        // vector<int64_t> pod_matrix(1, const_val);

        //        Plaintext pt;
        //        he_encoder->encode(pod_matrix, pt);

        //        encryptor->encrypt(pt, ciphers[indx]);
        Plaintext x;
        ciphers[indx] = cipher;
        zkp_encoder->encode(cipher, x);
        auto poly = polytools::SealPoly(*zkp_context, x, &(zkp_context->first_parms_id()));
        poly.ntt_inplace(tables);
        polys[indx] = poly;
        values[indx] = ringsnark::seal::RingElem(poly);
        // cout << "def:\t" << vs[indx] << endl;
    }

    /**
     * Negate a ciphertext.
     * @param indx the indx of the ciphertext to be negated.
     * @param neg_one_indx the index of -1 to be multiplied by the ciphertext.
     * @param res_indx the index at which the result will be stored.
     * */
    void negate_(int indx, int neg_one_indx, int res_indx) {
        // vs[res_indx] = vs[indx] * -1;
        evaluator->negate(ciphers[indx], ciphers[res_indx]);

        auto poly = ::polytools::SealPoly(polys[indx]);
        poly.multiply_inplace(polys[neg_one_indx]);
        polys[res_indx] = poly;
        values[res_indx] = ringsnark::seal::RingElem(poly);
    }

    /**
     * Compute the subtraction between two ciphertexts.
     * @param op1_indx the index of the first ciphertext.
     * @param op2_indx the index of the second ciphertext.
     * @param one_indx the index of the value 1 to be multiplied by the result of the addition operation.
     * @param res_indx the index at which to store the result.
     * */
    void subtract_(int op1_indx, int op2_indx, int one_indx, int res_indx) {
        evaluator->sub(ciphers[op1_indx], ciphers[op2_indx], ciphers[res_indx]);

        auto poly = ::polytools::SealPoly(polys[op1_indx]);
        poly.subtract_inplace(polys[op2_indx]);
        poly.multiply_inplace(polys[one_indx]);
        polys[res_indx] = poly;
        values[res_indx] = ringsnark::seal::RingElem(poly);
    }

    /**
    * Assigning the encrypted value of variable to another variable within the ciphers vector (e.g., r21 := r15).
    * @param lhs_indx the left-hand side index of the variable.
    * @param rhs_indx the right-hand side index of the variable.
    * */
    void assign_(int lhs_indx, int rhs_indx, int one_indx) {
        if (rhs_indx >= ciphers.size()) {
            cout << "The right-hand side >> r" << rhs_indx << " doesn't exist in ciphers vector!" << endl;
            exit(2);
        }
        if (lhs_indx >= ciphers.size()) {
            cout << "The left-hand side >> r" << lhs_indx << " doesn't exist in ciphers vector!" << endl;
            exit(2);
        }
        ciphers[lhs_indx] = ciphers[rhs_indx];
    }

    /**
     * Store the encrypted constants input by the user to the ciphers vector to be used within the circuit.
     * @param in_ciphers a vector of Ciphertext.
     * */
    void setInput_(vector<Ciphertext> in_ciphers) {
        Plaintext x;
        size_t size = in_ciphers.size();
        for (int i = 0; i < size; ++i) {
            auto c = in_ciphers[i];
            ciphers[i] = c;
            zkp_encoder->encode(c, x);
            auto poly = polytools::SealPoly(*zkp_context, x, &(zkp_context->first_parms_id()));
            poly.ntt_inplace(tables);
            polys[i] = poly;
            values[i] = ringsnark::seal::RingElem(poly);
        }
    }

public:
    /// The constructor takes an Initializer object to initialze local objects and variables.
    explicit Circuit(const Initializer &initializer) {
        this->n = 0;
        this->res_indx = 0;
        this->vars_count = 0;
        this->zkp_context = initializer.getZKPContext();
        this->zkp_encoder = initializer.getZKPEncoder(*this->zkp_context);
        this->he_context = initializer.getHEContext();
        this->he_encoder = initializer.getHEEncoder(*this->he_context);
        this->encryptor = initializer.getEncryptor();
        this->decryptor = initializer.getDecryptor();
        this->evaluator = initializer.getEvaluator();
        this->secretKey = initializer.getSecretKey();
        this->publicKey = initializer.getPublicKey();
        this->relinKeys = initializer.getRelinKeys();
        this->tables = initializer.getTables();
    }

    /**
     * Establish the circuit defined by the user.
     * @param exec_list a 2D vector includes the operations and their operands to be executed.
     * @param in_ciphers a vector of Ciphertext includes user's defined encrypted constants.
     * @return pb the R1CS constraints.
     * */
    ringsnark::protoboard<R> create_circuit(vector<vector<int>> exec_list, vector<Ciphertext> &in_ciphers) {
        /// the vectors size is the number of operations defined by exec_list + the constants defined by the user.
        this->n = exec_list.size() + in_ciphers.size();
        /// Setup vars vector for verifying the computations executed by the circuit.
        ringsnark::pb_variable_array<R> tmp_vars(n, ringsnark::pb_variable<R>());
        vars = tmp_vars;
        vars.allocate(pb, n, "x");
        /// Set the input size of the circuit.
        pb.set_input_sizes(n - 1); // vars[n-1] is private, all other values are public
        const size_t N = zkp_context->get_context_data(zkp_context->first_parms_id())->parms().poly_modulus_degree();

        /// A vector of plain values involved in the computation
        vector<int64_t> tmp_vs(N);
        vs = tmp_vs;

        /// A vector of Ciphertexts which includes all the values involved in the circuit.
        vector<Ciphertext> tmp(n);
        ciphers = tmp;

        /// A vector of SealPoly used in Rinocchio
        vector<::polytools::SealPoly> tmp_polys(n, ::polytools::SealPoly(*this->zkp_context));
        polys = tmp_polys;
        /// A vector of RingElem used in Rinocchio
        vector<ringsnark::seal::RingElem> tmp_values(n);
        values = tmp_values;

        /// Register user's defined constants within the ciphers vector.
        setInput_(in_ciphers);

        // Loop over the execution list.
        for (int i = 0; i < exec_list.size(); ++i) {
            vector<int> inst = exec_list[i]; // get an instruction
            int opcode = inst[0];            // the opcode is the first element in the instruction vector.
            if (opcode == 0) { // def_val -- do nothing.
                continue;
            } else if (opcode == 1) {                           // mul
                int op1_indx = inst[1]; // read the index of op1.
                int op2_indx = inst[2]; // read the index of op2.
                int res_indx = inst[3]; // read the index of the result.
                // Register the R1CS constraint.
                pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[op1_indx], vars[op2_indx],
                                                                     vars[res_indx]));
            } else if (opcode == 2) { // def_var -- do nothing.
                continue;
            } else if (opcode == 3) {                           // add
                int op1_indx = inst[1]; // read the index of op1.
                int op2_indx = inst[2]; // read the index of op2.
                int one_indx = inst[3]; // read the index of 1 value.
                int res_indx = inst[4]; // read the index of the result.
                // Register the R1CS constraint.
                pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[op1_indx] + vars[op2_indx],
                                                                     vars[one_indx], vars[res_indx]));
            } else if (opcode == 4) {                               // negate
                int indx = inst[1];         // read the index of the value to be negated.
                int neg_one_indx = inst[2]; // read the index of -1
                int res_indx = inst[3];     // read the index of the result
                // ringsnark::seal::RingElem::one().negate_inplace();
                //  Register the R1CS constraint.
                pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[indx], vars[neg_one_indx],
                                                                     vars[res_indx]));
            } else if (opcode == 5) {   //subtract
                int op1_indx = inst[1];
                int op2_indx = inst[2];
                int one_indx = inst[3];
                int res_indx = inst[4];
                pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[op1_indx] - vars[op2_indx], vars[one_indx],
                                                                     vars[res_indx]));
            } else if (opcode == 6) { // assignment
                continue;
            } else if (opcode == 7){
                int op1_indx = inst[1];
                int op2_indx = inst[2];
                int res_indx = inst[3];
            }
            else {
                cout << "Unrecognized opcode >> " << opcode << endl;
            }
        }
        circuit_created = true;

        return pb;
    }

    /**
     * Register the multiplication operation in the execution list to be executed by the circuit.
     * @param op1_indx the index of the first operand.
     * @param op2_indx the index of the second operand.
     * @param res_indx the index at which the result is stored.
     * */
    void mul(int op1_indx, int op2_indx, int res_indx) {
        // Encode the instruction into the execution list.
        vector<int> instruction{1, op1_indx, op2_indx, res_indx}; // 1 --> is the instruction code.
        exec_lst.push_back(instruction);
    }

    /**
     * Register the addition operation in the execution list to be executed by the circuit.
     * @param op1_indx the index of the first operand.
     * @param op2_indx the index of the second operand.
     * @param one_indx the index of the value 1.
     * @param res_indx the index at which the result is stored.
     * */
    void add(int op1_indx, int op2_indx, int one_indx, int res_indx) {
        // Encode the instruction into the execution list.
        vector<int> instruction{3, op1_indx, op2_indx, one_indx, res_indx}; // 3 --> is the instruction code.
        exec_lst.push_back(instruction);
    }

    [[deprecated]] void def_val(int val, int indx) {
        // operation, val, indx, -1
        vector<int> instruction{0, val, indx, -1};
        exec_lst.push_back(instruction);
    }

    /**
     * Define a variable withing circuit.
     * @param var a character represents a variable.
     * @param indx the index at which the variable will be stored.
     * */
    void def_var(char var, int indx) {
        this->vars_count++;
        vector<int> instruction{2, int(var), indx};
        exec_lst.push_back(instruction);
    }

    /**
     * Register a negation operation in the execution list to be executed by the circuit.
     * @param indx the index of the value to be negated.
     * @param neg_one_indx the index of the -1 value.
     * @param res_indx the index at which the result will be stored.
     * */
    void negate(int indx, int neg_one_indx, int res_indx) {
        // Encode the instruction into the execution list.
        vector<int> instruction{4, indx, neg_one_indx, res_indx}; // 4 --> is the instruction code.
        exec_lst.push_back(instruction);
    }

    /**
     * Register the subtraction operation in the execution list to be executed by the circuit.
     * @param op1_indx the index of the first operand.
     * @param op2_indx the index of the second operand.
     * @param one_indx the index of the value 1.
     * @param res_indx the index at which the result is stored.
     * */
    void subtract(int op1_indx, int op2_indx, int one_indx, int res_indx) {
        vector<int> instruction{5, op1_indx, op2_indx, one_indx, res_indx}; // 5 --> is the instruction code.
        exec_lst.push_back(instruction);
    }

    /**
    * Assigning the encrypted value of variable to another variable within the ctxt vector (e.g., r21 := r15).
    * @param lhs_indx the left-hand side index of the variable.
    * @param rhs_indx the right-hand side index of the variable.
    * */
    void assign(int lhs_indx, int rhs_indx, int one_indx) {
        vector<int> instruction{6, lhs_indx, rhs_indx, one_indx};  // 6 --> is the instruction code.
        exec_lst.push_back(instruction);
    }

    /**
     * Returns a 2D vector representing the execution list.
     * */
    vector<vector<int>> get_exec_list() {
        return exec_lst;
    }

    /**
     * Print a textual representation of the circuit.
     * */
    void print_circuit() {
        for (int i = 0; i < exec_lst.size(); ++i) {
            vector<int> inst = exec_lst[i];
            int opcode = inst[0];
            if (opcode == 0) { // def_val
                cout << "$" << inst[2] << " := " << inst[1] << endl;
            } else if (opcode == 1) { // mul
                cout << "$" << inst[3] << " := "
                     << "$" << inst[1] << " * "
                     << "$" << inst[2] << endl;
            } else if (opcode == 2) { // def_var
                cout << "$" << inst[2] << " := " << char(inst[1]) << endl;
            } else if (opcode == 3) { // add
                cout << "$" << inst[4] << " := "
                     << "$" << inst[1] << " + "
                     << "$" << inst[2] << endl;
            } else if (opcode == 4) { // negate
                cout << "$" << inst[3] << " := "
                     << "$(-)" << inst[1] << endl;
            } else if (opcode == 5) {
                cout << "$" << inst[4] << " := "
                     << "$" << inst[1] << " - "
                     << "$" << inst[2] << endl;
            } else if (opcode == 6) {
                cout << "$" << inst[1] << " := "
                     << "$" << inst[2] << endl;
            } else {
                cout << "Unrecognized opcode >> " << opcode << endl;
            }
        }
    }

    /**
     * Execute the current circuit.
     * @param exec_list a 2D vector representing the operations to be executed by the circuit.
     * @param vars_vals a map of char-Ciphertext pair representing the ciphertext value of a previously
     *          defined variable.
     * */
    void execute(const vector<vector<int>> &exec_list, map<char, Ciphertext> vars_vals) {
        if (circuit_created) {
            // Loop over each instruction in the list.
            for (auto inst: exec_list) {
                // get an instruction
                // get the instruction code
                int opcode = inst[0];
                // if it is 0, then it's a value definition operation.
                if (opcode == 0) { // def_val
                    // def_val_(inst[1], inst[2]);
                }
                    // if it is 1, then it is a multiplication operation
                else if (opcode == 1) { // mul
                    mul_(inst[1], inst[2], inst[3]);
                    res_indx = inst[3];
                }
                    // if it is 2, then it is a summation operation
                else if (opcode == 2) { // def_var
                    char var = char(inst[1]);
                    auto val = vars_vals[var];
                    int indx = inst[2];
                    def_val_(val, indx);
                }
                    // if it is 3, then it is an add operation
                else if (opcode == 3) { // add
                    add_(inst[1], inst[2], inst[3], inst[4]);
                    res_indx = inst[4];
                }
                    // if it is 4, then it is negation operation
                else if (opcode == 4) {
                    negate_(inst[1], inst[2], inst[3]);
                    res_indx = inst[3];
                } else if (opcode == 5) {
                    subtract_(inst[1], inst[2], inst[3], inst[4]);
                    res_indx = inst[4];
                } else if (opcode == 6) {
                    assign_(inst[1], inst[2], inst[3]);
                    res_indx = inst[1];
                } else if (opcode == 7){
//                    eq_(inst[1], inst[2], inst[3]);
//                    res_indx = inst[1];
                }
                else {
                    cout << "Unrecognized opcode >> " << opcode << endl;
                }
            }
            for (size_t i = 0; i < n; i++) {
                pb.val(vars[i]) = values[i];
            }
        } else {
            cout << "The circuit is not created!" << endl;
            exit(1);
        }
    }

    /**
     * Print the result of the execution. It works only when the circuit is created and the computations are verified.
     * */
    void get_results() {
        if (verified) {
            cout << "R1CS satisfied: " << std::boolalpha << pb.is_satisfied() << endl;
            // TODO
            Plaintext plain_res;
            auto ctxt = ciphers[res_indx];
            decryptor->decrypt(ctxt, plain_res);
            vector<int64_t> plain_res_decode;
            he_encoder->decode(plain_res, plain_res_decode);
            cout << "Noise Budget= " << decryptor->invariant_noise_budget(ctxt) << endl;
            cout << "Decrypted result= " << plain_res_decode[0] << endl;

            /////////////////////////
//            for (int i = 20; i <23 ; ++i) {
//                ctxt = ciphers[i];
//                decryptor->decrypt(ctxt, plain_res);
//                he_encoder->decode(plain_res, plain_res_decode);
//                cout << "Decrypted result= " << plain_res_decode[0] << endl;
//            }

            cout << endl;
        } else {
            cout << "The output is not verified!" << endl;
        }
    }

    /**
     * Generate a proof for the execution of the circuit.
     * @param pk the proving key for Rinocchio.
     * */
    RincProof prove(const RincPb &pk) {
        cout << "\n=== Generating Proof ===" << endl;
        auto proof = ringsnark::rinocchio::prover(pk,
                                                  pb.primary_input(),
                                                  pb.auxiliary_input());
        //cout << "Size of proof:\t" << proof.size_in_bits() << " bits" << endl;
        return proof;
    }

    /**
     * Verify the generated proof.
     * @param vk the verification key.
     * @param proof the generated proof.
     * */
    void verify(const RincVk &vk, const RincProof &proof) {
        cout << "\n=== Verifying ===" << endl;
        const bool verif = ringsnark::rinocchio::verifier(vk, pb.primary_input(), proof);
        cout << "Verification passed: " << std::boolalpha << verif << endl;
        verified = verif;
    }

    BatchEncoder *getHeEncoder() const {
        return he_encoder;
    }

//    void eq_(int op1_indx, int op2_indx, int res_indx, size_t ptxt_mod = 20) {
//        auto c1 = ciphers[op1_indx];
//        auto c2 = ciphers[op2_indx];
//        Ciphertext tmp;
//        evaluator->sub(c1, c2, tmp);
//        ///////
//        Plaintext plain_res;
//
//        decryptor->decrypt(tmp, plain_res);
//        vector<int64_t> plain_res_decode;
//        he_encoder->decode(plain_res, plain_res_decode);
//        cout << "Decrypted boolean= " << plain_res_decode[0] << endl;
//
//
//
//
//    }
//
//    void eq(int op1_indx, int op2_indx, int res_indx){
//        vector<int> instruction{7, op1_indx, op2_indx, res_indx};
//        exec_lst.push_back(instruction);
//    }
};

vector<string> split(string str, char separator) {
    vector<string> tokens;
    int startIndex = 0, endIndex = 0;
    for (int i = 0; i <= str.size(); i++) {
        // If we reached the end of the word or the end of the input.
        if (str[i] == separator || i == str.size()) {
            endIndex = i;
            string temp;
            temp.append(str, startIndex, endIndex - startIndex);
            tokens.push_back(temp);
            startIndex = endIndex + 1;
        }
    }
    return tokens;
}

bool is_number(const string &s) {
    string::const_iterator it = s.begin();
    while (it != s.end() && isdigit(*it))
        ++it;
    return !s.empty() && it == s.end();
}


/**
 * Define an encrypted constant within the circuit.
 * @param const_val the value (in plain) to be encrypted.
 * @param indx the index at which the value will be stored.
 * @param ctxt a vector of Ciphertext holding the encrypted constants.
 * @param he_encoder a BatchEncoder obejct for HE.
 * @param encryptor a SEAL encryptor object.
 * */
void def_const(int const_val, int indx, vector<Ciphertext> &ctxt, BatchEncoder &he_encoder, Encryptor &encryptor) {
    Ciphertext tmp;
    while (indx >= ctxt.size()) {
        ctxt.push_back(tmp);
    }

    vector<int64_t> pod_matrix(1, const_val);

    Plaintext pt;
    he_encoder.encode(pod_matrix, pt);
    encryptor.encrypt(pt, ctxt[indx]);
}


/**
 * Returns an encrypted object of a given value.
 * @param val the value (in plain) to be encrypted.
 * @param he_encoder a BatchEncoder object for HE.
 * @param encryptor a SEAL encryptor object.
 * @return a ciphertext of the given value.
 * */
Ciphertext encrypt(int val, BatchEncoder &he_encoder, Encryptor &encryptor) {
    vector<int64_t> pod_matrix(1, val);
    Plaintext pt;
    he_encoder.encode(pod_matrix, pt);
    Ciphertext res;
    encryptor.encrypt(pt, res);
    return res;
}

void print_header(string title) {
    if (!title.empty()) {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 * 10;
        string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
        string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

        cout << endl
             << banner_top << endl
             << banner_middle << endl
             << banner_top << endl;
    }
}

char *getCmdOption(char **begin, char **end, const std::string &option) {
    char **itr = std::find(begin, end, option);
    if (itr != end && ++itr != end) {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char **begin, char **end, const std::string &option) {
    return std::find(begin, end, option) != end;
}

int main(int argc, char *argv[]) {
    /**
     * todo
     * 1) remove relinearization after addition.
     * 2) profile the execution.
     * 3) track noise growth after each operation -- this might reduce the performance.
     * 4) try mod switch*/
    Initializer initializer;
    ifstream myfile;
    char* file;
    {
        Circuit circuit(initializer);
        string opl;
        map<char, Ciphertext> vars_vals;


        if (cmdOptionExists(argv, argv + argc, "-f")) {
            file = getCmdOption(argv, argv + argc, "-f");
            myfile.open(file);
            if (myfile.is_open()) {

            } else {
                cout << "Cannot open the file >> " << file << "!" << endl;
            }
        }
        if (cmdOptionExists(argv, argv + argc, "-v")) {
            auto vars = getCmdOption(argv, argv + argc, "-v");
            vector<string> v_vars = split(vars, ',');
            for (auto v: v_vars) {
                char variable_name = v[0];
                int variable_value = stoi(v.substr(v.find('=') + 1, v.size()));
                vars_vals[variable_name] = encrypt(variable_value, *circuit.getHeEncoder(),
                                                   *initializer.getEncryptor());
            }
        }
        if (cmdOptionExists(argv, argv + argc, "-h")) {
            cout
                    << "./[filename] -f [OpL file] -v variable_name1=value,variable_name2=value,variable_name3=value,...\n\n";
            cout
                    << "*** NOTE ***\n1)The variable name must be ONLY one char (e.g., x, y, z)\n2)There is NO space between the variable name, the equal sign, and the value (e.g., y=5)\n3)Variable names must be same as the ones in the parsed IR file\n";
            exit(0);
        }

        istringstream cir(opl);
        vector<Ciphertext> ctxt(1);
        int ONE_INDX = 0;
        int NEG_ONE_INDX = 1;
        def_const(1, 0, ctxt, *circuit.getHeEncoder(), *initializer.getEncryptor());
        def_const(-1, 1, ctxt, *circuit.getHeEncoder(), *initializer.getEncryptor());

        string inst;
        /// inst: result_indx := operand1 op operand2
        auto start_opl2circuit = std::chrono::system_clock::now();
        while (getline(myfile, inst)) {
            auto vec = split(inst, ' ');
            string res_indx = vec[0].substr(2);
            if (vec.size() == 5) {
                string op1_indx = vec[2].substr(1);;
                string op = vec[3];
                string op2_indx = vec[4].substr(1);;

                if (op == "*") {
                    circuit.mul(stoi(op1_indx), stoi(op2_indx), stoi(res_indx));
                } else if (op == "+") {
                    circuit.add(stoi(op1_indx), stoi(op2_indx),
                                ONE_INDX, stoi(res_indx));
                } else if (op == "-") {
                    circuit.subtract(stoi(op1_indx), stoi(op2_indx),
                                     ONE_INDX, stoi(res_indx));
                }
                 else {
                    cout << "Unknown operation!" << endl;
                }
            } else if (vec.size() == 3) { /// This is either a variable or a constant declaration
                string op1 = vec[2];
                if (is_number(op1)) { /// define a constant
                    def_const(stoi(op1), stoi(res_indx), ctxt,
                              *circuit.getHeEncoder(), *initializer.getEncryptor());
                } else if (op1[0] == 'r') {
                    //circuit.mul(stoi(op1.substr(1)), ONE_INDX, stoi(res_indx));
                    circuit.assign(stoi(res_indx), stoi(op1.substr(1)), ONE_INDX);
                } else {
                    circuit.def_var(op1[0], stoi(res_indx));
                }
            }
        }
        auto end_opl2circuit = std::chrono::system_clock::now();

        circuit.print_circuit();

        vector<vector<int>> exec_lst = circuit.get_exec_list();

        auto start_create_cir_r1cs = std::chrono::system_clock::now();
        ringsnark::protoboard<R> pb = circuit.create_circuit(exec_lst, ctxt);
        auto end_create_cir_r1cs = std::chrono::system_clock::now();

        auto start_rinc_keys = std::chrono::system_clock::now();
        const auto keypair = initializer.get_Rinocchio_keys(pb);
        auto end_rinc_keys = std::chrono::system_clock::now();

        auto start_circ_exec = std::chrono::system_clock::now();
        circuit.execute(exec_lst, vars_vals);
        auto end_circ_exec = std::chrono::system_clock::now();

        auto start_prove = std::chrono::system_clock::now();
        auto proof = circuit.prove(keypair.pk);
        auto end_prove = std::chrono::system_clock::now();

        auto start_verify = std::chrono::system_clock::now();
        circuit.verify(keypair.vk, proof);
        auto end_verify = std::chrono::system_clock::now();

        auto start_decrypt = std::chrono::system_clock::now();
        circuit.get_results();
        auto end_decrypt = std::chrono::system_clock::now();


        cout << "Program\tOpL2Circuit\tCircuit&R1CS\tGenerate Rino. Keys\tCircuit Execution\tProving\tVerifying\tDecryption\t\n";
        ofstream data("Running_times.csv", ios::app);
        if (!data.is_open()){
            cout << "Error writing to Running_times.csv" << endl;
            return 1;
        }
        data << file << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_opl2circuit - start_opl2circuit).count() << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_create_cir_r1cs - start_create_cir_r1cs).count() << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_rinc_keys - start_rinc_keys).count() << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_circ_exec - start_circ_exec).count() << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_prove - start_prove).count() << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_verify - start_verify).count() << ",";
        data << chrono::duration_cast<chrono::milliseconds>(end_decrypt - start_decrypt).count() << "";
        data << endl;

        data.close();
        cout << file << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_opl2circuit - start_opl2circuit).count() << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_create_cir_r1cs - start_create_cir_r1cs).count() << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_rinc_keys - start_rinc_keys).count() << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_circ_exec - start_circ_exec).count() << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_prove - start_prove).count() << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_verify - start_verify).count() << "\t";
        cout << chrono::duration_cast<chrono::milliseconds>(end_decrypt - start_decrypt).count() << "";
        cout << endl;

    }

    int x;
    cin >> x;

    return 0;
}
