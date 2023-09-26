#include <fstream>
#include <iostream>
#include "poly_arith.h"

/// This example demonstrates how to save (serialize) SEAL ciphertexts, keys and parameters
/// and then load them back into polytools and operate on them, before finally writing out the results again.

/// Class to persists the secret key and the input, to allow verifying things later
class Client
{
private:
    seal::EncryptionParameters parms;
    seal::SEALContext context = seal::SEALContext(parms); // Dummy context, since no default ctor

    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;

    std::unique_ptr<seal::Encryptor> encryptor;
    std::unique_ptr<seal::Evaluator> evaluator;
    std::unique_ptr<seal::Decryptor> decryptor;

    const uint64_t a = 7;
    const uint64_t b = 12;

    /// When this is set to true, transparent encryption is used.
    bool transparent = false;

public:
    Client()
    {
        int p = 524309;
        parms = seal::EncryptionParameters(seal::scheme_type::bgv);
        size_t n = 8192; // m=2^14, n=phi(m)=m/2=2^13
        // size_t n = 65536;
        parms.set_poly_modulus_degree(n);
        std::vector<int> bit_sizes = { 43, 43, 44, 44, 44 }; // BGVDefault(8192)
        parms.set_coeff_modulus(seal::CoeffModulus::Create(n, p, bit_sizes));
        parms.set_plain_modulus(p);

        // For 64k, it's currently necessary to set sec_level none,
        // because the lookup tables in SEAL don't extend to 64k yet
        if (n > 32768)
            context = seal::SEALContext(parms, true, seal::sec_level_type::none);
        else
            context = seal::SEALContext(parms);

        seal::KeyGenerator keygen(context);
        secret_key = keygen.secret_key();
        keygen.create_public_key(public_key);
        keygen.create_relin_keys(relin_keys);

        encryptor = std::make_unique<seal::Encryptor>(context, public_key);
        evaluator = std::make_unique<seal::Evaluator>(context);
        decryptor = std::make_unique<seal::Decryptor>(context, secret_key);
    }

    /// Encrypts two integers and saves the polys of their ctxts + associated parameters & keys to files
    void write_data_from_seal()
    {
        // Encrypt a
        seal::Plaintext a_plain(seal::util::uint_to_hex_string(&a, 1));
        seal::Ciphertext a_ctxt;
        if (transparent)
            a_ctxt = polytools::transparent_encryption(context, a_plain);
        else
            encryptor->encrypt(a_plain, a_ctxt);

        // Encrypt & serialize b
        seal::Plaintext b_plain(seal::util::uint_to_hex_string(&b, 1));
        seal::Ciphertext b_ctxt;
        if (transparent)
            b_ctxt = polytools::transparent_encryption(context, b_plain);
        else
            encryptor->encrypt(b_plain, b_ctxt);

        // Save Polynomials
        polytools::SealPoly a_0(context, a_ctxt, 0);
        polytools::SealPoly a_1(context, a_ctxt, 1);
        polytools::SealPoly b_0(context, b_ctxt, 0);
        polytools::SealPoly b_1(context, b_ctxt, 1);

        for (auto &p : std::vector<std::pair<polytools::SealPoly *, std::string>>(
                 { { &a_0, "a_0.poly" }, { &a_1, "a_1.poly" }, { &b_0, "b_0.poly" }, { &b_1, "b_1.poly" } }))
        {
            std::ofstream a_stream;
            a_stream.open(p.second);
            p.first->save(a_stream);
        }

        // Serialize parameters
        std::ofstream parms_stream;
        parms_stream.open("parms");
        parms.save(parms_stream);
    }

    /// Reads polynomials, converts it to ctxt and decrypts it
    void read_and_decrypt()
    {
        // Polynomials
        polytools::SealPoly r_0(context);
        polytools::SealPoly r_1(context);
        polytools::SealPoly r_2(context);

        // Load Polynomials
        for (auto &p : std::vector<std::pair<polytools::SealPoly *, std::string>>(
                 { { &r_0, "r_0.poly" }, { &r_1, "r_1.poly" }, { &r_2, "r_2.poly" } }))
        {
            try
            {
                std::ifstream file(p.second, std::ifstream::in);
                p.first->load(file);
            }
            catch (const std::exception &e)
            {
                std::cout << "Exception opening/reading " << p.second;
                return;
            }
        }

        // Turn polys back to ctxt
        seal::Ciphertext result = polytools::poly_to_ctxt(context, { r_0, r_1, r_2 });

        // Decrypt ctxt
        seal::Plaintext ptxt;
        decryptor->decrypt(result, ptxt);

        // Output ptxt
        std::cout << a << "*" << b << "=" << a * b << std::endl;
        std::cout << "Result (hex!): " << ptxt.to_string() << std::endl;
        for (size_t i = 0; i < ptxt.coeff_count(); ++i)
        {
            if (ptxt[i])
                std::cout << "ptxt[" << i << "]=" << ptxt[i] << std::endl;
        }
    }
};

/// Loads polys of two ctxts (and their keys/parms), then multiplies & relinearizes them before writing the result back
void polytools_computation()
{
    // Load parmeters
    seal::EncryptionParameters parms;
    try
    {
        std::ifstream file("parms", std::ifstream::in);
        parms.load(file);
    }
    catch (const std::exception &e)
    {
        std::cout << "Exception opening/reading parms";
        return;
    }

    // Build context
    seal::SEALContext context(parms);

    // Polynomials for a
    polytools::SealPoly a_0(context);
    polytools::SealPoly a_1(context);

    // Polynomials for b
    polytools::SealPoly b_0(context);
    polytools::SealPoly b_1(context);

    // Load Polynomials
    for (auto &p : std::vector<std::pair<polytools::SealPoly *, std::string>>(
             { { &a_0, "a_0.poly" }, { &a_1, "a_1.poly" }, { &b_0, "b_0.poly" }, { &b_1, "b_1.poly" } }))
    {
        try
        {
            std::ifstream file(p.second, std::ifstream::in);
            p.first->load(file);
        }
        catch (const std::exception &e)
        {
            std::cout << "Exception opening/reading " << p.second;
            return;
        }
    }

    // Polytools computation
    auto tables = context.get_context_data(a_0.get_parms_id())->small_ntt_tables();
    a_0.ntt_inplace(tables);
    a_1.ntt_inplace(tables);
    b_0.ntt_inplace(tables);
    b_1.ntt_inplace(tables);

    polytools::SealPoly r_0 = a_0;
    r_0.multiply_inplace(b_0);
    r_0.intt_inplace(tables);

    polytools::SealPoly r_1 = a_0;
    polytools::SealPoly r_1_t = a_1;
    r_1.multiply_inplace(b_1);
    r_1_t.multiply_inplace(b_0);
    r_1.add_inplace(r_1_t);
    r_1.intt_inplace(tables);

    polytools::SealPoly r_2 = a_1;
    r_2.multiply_inplace(b_1);
    r_2.intt_inplace(tables);

    // Save results
    for (auto &p : std::vector<std::pair<polytools::SealPoly *, std::string>>(
             { { &r_0, "r_0.poly" }, { &r_1, "r_1.poly" }, { &r_2, "r_2.poly" } }))
    {
        std::ofstream a_stream;
        a_stream.open(p.second);
        p.first->save(a_stream);
    }
}

int main()
{
    Client c;

    c.write_data_from_seal();

    polytools_computation();

    c.read_and_decrypt();

    return 0;
}