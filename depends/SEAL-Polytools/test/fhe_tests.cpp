#include <random>
#include "gtest/gtest.h"
#include "poly_arith.h"

// from SEAL examples.h
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

class FHETest : public ::testing::Test
{
protected:
    seal::EncryptionParameters parms;
    seal::SEALContext context = seal::SEALContext(parms); // Dummy context, since no default ctor
    bool using_batching;

    seal::SecretKey secret_key;
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;

    std::unique_ptr<seal::BatchEncoder> encoder;
    std::unique_ptr<seal::Encryptor> encryptor;
    std::unique_ptr<seal::Evaluator> evaluator;
    std::unique_ptr<seal::Decryptor> decryptor;

    void SetUp() override
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

        auto qualifiers = context.first_context_data()->qualifiers();
        using_batching = qualifiers.using_batching;

        if (using_batching)
        {
            encoder = std::make_unique<seal::BatchEncoder>(context);
        }
        else
        {
            encoder = nullptr;
        }
        encryptor = std::make_unique<seal::Encryptor>(context, public_key);
        evaluator = std::make_unique<seal::Evaluator>(context);
        decryptor = std::make_unique<seal::Decryptor>(context, secret_key);
    }

    void GetRandomPlaintext(seal::Plaintext *ptxt, unsigned int seed = 0)
    {
        std::mt19937_64 gen(seed);
        std::uniform_int_distribution<uint64_t> dis(0, parms.plain_modulus().value());

        if (using_batching)
        {
            std::vector<seal::Plaintext::pt_coeff_type> coeffs(parms.poly_modulus_degree());
            std::generate(coeffs.begin(), coeffs.end(), [&dis, &gen]() { return dis(gen); });
            encoder->encode(coeffs, *ptxt);
        }
        else
        {
            uint64_t p = dis(gen);
            auto *plain = new seal::Plaintext(uint64_to_hex_string(p));
            *ptxt = *plain;
        }
    }

    void GetRandomCiphertext(seal::Ciphertext *ctxt, unsigned int seed = 0)
    {
        seal::Plaintext ptxt;
        GetRandomPlaintext(&ptxt, seed);
        encryptor->encrypt(ptxt, *ctxt);
    }
};

TEST_F(FHETest, ScalarMultiplication)
{
    // Encrypt x
    seal::Ciphertext x_ctxt;
    GetRandomCiphertext(&x_ctxt, 0x5EED0);

    // Get Polynomials for x
    polytools::SealPoly x_0(context, x_ctxt, 0);
    polytools::SealPoly x_1(context, x_ctxt, 1);

    // Encrypt y
    uint64_t y = 7;
    seal::Plaintext y_plain(uint64_to_hex_string(y));

    // Get Polynomials for y (requires ntt form)
    polytools::SealPoly y_0(context, y_plain, &context.first_parms_id());

    // FHE operation
    seal::Ciphertext seal_sum;
    evaluator->multiply_plain(x_ctxt, y_plain, seal_sum);

    // Equivalent Polynomial Operations
    polytools::SealPoly s_0 = x_0;
    polytools::SealPoly s_1 = x_1;
    s_0.multiply_scalar_inplace(y);
    s_1.multiply_scalar_inplace(y);
    seal::Ciphertext polytools_sum = polytools::poly_to_ctxt(context, { s_0, s_1 });

    // Compare results
    seal::Plaintext seal_ptxt;
    decryptor->decrypt(seal_sum, seal_ptxt);
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(polytools_sum, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(seal_ptxt, polytools_ptxt);
}

TEST_F(FHETest, Addition)
{
    // Encrypt x
    seal::Ciphertext x_ctxt;
    GetRandomCiphertext(&x_ctxt, 0x5EED0);

    // Get Polynomials for x
    polytools::SealPoly x_0(context, x_ctxt, 0);
    polytools::SealPoly x_1(context, x_ctxt, 1);

    // Encrypt y
    seal::Ciphertext y_ctxt;
    GetRandomCiphertext(&y_ctxt, 0x5EED1);

    // Get Polynomials for y (requires ntt form)
    polytools::SealPoly y_0(context, y_ctxt, 0);
    polytools::SealPoly y_1(context, y_ctxt, 1);

    // FHE operation
    seal::Ciphertext seal_sum;
    evaluator->add(x_ctxt, y_ctxt, seal_sum);

    // Equivalent Polynomial Operations
    polytools::SealPoly s_0 = x_0;
    polytools::SealPoly s_1 = x_1;
    s_0.add_inplace(y_0);
    s_1.add_inplace(y_1);
    seal::Ciphertext polytools_sum = polytools::poly_to_ctxt(context, { s_0, s_1 });

    // Compare results
    seal::Plaintext seal_ptxt;
    decryptor->decrypt(seal_sum, seal_ptxt);
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(polytools_sum, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(seal_ptxt, polytools_ptxt);
}

TEST_F(FHETest, PlaintextAddition)
{
    // Encrypt x
    seal::Ciphertext x_ctxt;
    GetRandomCiphertext(&x_ctxt, 0x5EED0);

    // Get Polynomials for x (requires ntt form)
    polytools::SealPoly x_0(context, x_ctxt, 0);
    polytools::SealPoly x_1(context, x_ctxt, 1);

    // Encode y
    seal::Plaintext y_plain;
    GetRandomPlaintext(&y_plain, 0x5EED1);

    // Get Polynomials for y
    polytools::SealPoly y_0(context, y_plain, &context.first_parms_id());

    // FHE operation
    seal::Ciphertext seal_sum;
    evaluator->add_plain(x_ctxt, y_plain, seal_sum);

    // Equivalent Polynomial Operations
    polytools::SealPoly s_0 = x_0;
    s_0.add_inplace(y_0);
    seal::Ciphertext polytools_sum = polytools::poly_to_ctxt(context, { s_0, x_1 });

    // Compare results
    seal::Plaintext seal_ptxt;
    decryptor->decrypt(seal_sum, seal_ptxt);
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(polytools_sum, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(seal_ptxt, polytools_ptxt);
}

TEST_F(FHETest, Multiplication)
{
    // Encrypt x
    seal::Ciphertext x_ctxt;
    GetRandomCiphertext(&x_ctxt, 0x5EED0);

    // Get Polynomials for x
    polytools::SealPoly x_0(context, x_ctxt, 0);
    polytools::SealPoly x_1(context, x_ctxt, 1);

    // Encrypt y
    seal::Ciphertext y_ctxt;
    GetRandomCiphertext(&y_ctxt, 0x5EED1);

    // Get Polynomials for y
    polytools::SealPoly y_0(context, y_ctxt, 0);
    polytools::SealPoly y_1(context, y_ctxt, 1);

    // FHE operation
    seal::Ciphertext seal_product;
    evaluator->multiply(x_ctxt, y_ctxt, seal_product);

    // Equivalent Polynomial Operations
    auto tables = context.get_context_data(x_ctxt.parms_id())->small_ntt_tables();
    x_0.ntt_inplace(tables);
    x_1.ntt_inplace(tables);
    y_0.ntt_inplace(tables);
    y_1.ntt_inplace(tables);

    polytools::SealPoly r_0 = x_0;
    r_0.multiply_inplace(y_0);
    r_0.intt_inplace(tables);

    polytools::SealPoly r_1 = x_0;
    polytools::SealPoly r_1_t = x_1;
    r_1.multiply_inplace(y_1);
    r_1_t.multiply_inplace(y_0);
    r_1.add_inplace(r_1_t);
    r_1.intt_inplace(tables);

    polytools::SealPoly r_2 = x_1;
    r_2.multiply_inplace(y_1);
    r_2.intt_inplace(tables);

    seal::Ciphertext polytools_product = polytools::poly_to_ctxt(context, { r_0, r_1, r_2 });

    // Compare results
    seal::Plaintext seal_ptxt;
    decryptor->decrypt(seal_product, seal_ptxt);
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(polytools_product, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(seal_ptxt, polytools_ptxt);
}

TEST_F(FHETest, NTT)
{
    // Encrypt x
    seal::Ciphertext x_ctxt;
    GetRandomCiphertext(&x_ctxt, 0x5EED0);

    // Get Polynomials for x
    polytools::SealPoly x_0(context, x_ctxt, 0);
    polytools::SealPoly x_1(context, x_ctxt, 1);

    // FHE operation
    seal::Ciphertext seal_ntt;
    evaluator->transform_to_ntt(x_ctxt, seal_ntt);

    // Equivalent Polynomial Operations
    polytools::SealPoly n_0 = x_0;
    polytools::SealPoly n_1 = x_1;
    auto tables = context.get_context_data(x_0.get_parms_id())->small_ntt_tables();
    n_0.ntt_inplace(tables);
    n_1.ntt_inplace(tables);
    seal::Ciphertext polytools_ntt = polytools::poly_to_ctxt(context, { n_0, n_1 });

    // Since we cannot decrypt NTT-form ctxts in BGV SEAL, we need to convert back:
    seal::Ciphertext polytools;
    evaluator->transform_from_ntt(polytools_ntt, polytools);
    seal::Ciphertext seal;
    evaluator->transform_from_ntt(seal_ntt, seal);

    // Compare results
    seal::Plaintext seal_ptxt;
    decryptor->decrypt(seal, seal_ptxt);
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(polytools, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(seal_ptxt, polytools_ptxt);
}

TEST_F(FHETest, TransparentEncryption)
{
    seal::Plaintext y_ptxt;
    GetRandomPlaintext(&y_ptxt, 0x5EED0);
    seal::Ciphertext y_ctxt;
    encryptor->encrypt(y_ptxt, y_ctxt);

    // Transparent Encryption
    seal::Ciphertext transparent_enc = polytools::transparent_encryption(context, y_ptxt);

    seal::Plaintext seal_ptxt;
    decryptor->decrypt(y_ctxt, seal_ptxt);
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(transparent_enc, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(seal_ptxt, polytools_ptxt);
}

TEST_F(FHETest, Serialize)
{
    // Encrypt x
    seal::Plaintext x_plain;
    GetRandomPlaintext(&x_plain, 0x5EED0);
    seal::Ciphertext x_ctxt;
    encryptor->encrypt(x_plain, x_ctxt);

    // Get Polynomials for x
    polytools::SealPoly x_0(context, x_ctxt, 0);
    polytools::SealPoly x_1(context, x_ctxt, 1);

    // save them
    std::stringstream ss_0;
    x_0.save(ss_0);
    std::stringstream ss_1;
    x_1.save(ss_1);

    // load them again
    polytools::SealPoly xx_0(context);
    polytools::SealPoly xx_1(context);
    xx_0.load(ss_0);
    xx_1.load(ss_1);

    // combine to ctxt
    auto polytools_ctxt = polytools::poly_to_ctxt(context, { xx_0, xx_1 });

    // decrypt and compare
    seal::Plaintext polytools_ptxt;
    decryptor->decrypt(polytools_ctxt, polytools_ptxt);

    // This works because SEAL compares ptxt by content, not by address
    EXPECT_EQ(x_plain, polytools_ptxt);
}

TEST_F(FHETest, IsZero)
{
    seal::Plaintext x_ptxt;
    GetRandomPlaintext(&x_ptxt, 0x5EED0);

    polytools::SealPoly x(context, x_ptxt, &context.first_parms_id());
    polytools::SealPoly diff(context, x_ptxt, &context.first_parms_id());
    diff.subtract_inplace(x);

    bool zero = diff.is_zero();
    EXPECT_EQ(zero, true);

    zero = x.is_zero();
    EXPECT_EQ(zero, false);

    // Test in NTT form
    auto tables = context.get_context_data(x.get_parms_id())->small_ntt_tables();
    x.ntt_inplace(tables);
    diff.ntt_inplace(tables);

    zero = diff.is_zero();
    EXPECT_EQ(zero, true);

    zero = x.is_zero();
    EXPECT_EQ(zero, false);
}

TEST_F(FHETest, IsEqual)
{
    seal::Plaintext x_ptxt;
    GetRandomPlaintext(&x_ptxt, 0x5EED0);
    seal::Plaintext y_ptxt;
    GetRandomPlaintext(&y_ptxt, 0x5EED1);

    polytools::SealPoly x(context, x_ptxt, &context.first_parms_id());
    polytools::SealPoly y(context, y_ptxt, &context.first_parms_id());

    // lhs = x + y
    polytools::SealPoly lhs(context, x_ptxt, &context.first_parms_id());
    lhs.add_inplace(y);

    // rhs = y + x
    polytools::SealPoly rhs(context, y_ptxt, &context.first_parms_id());
    rhs.add_inplace(x);

    bool equal = lhs.is_equal(rhs);
    EXPECT_EQ(equal, true);

    equal = x.is_equal(y);
    EXPECT_EQ(equal, false);

    // Test in NTT form
    auto tables = context.get_context_data(lhs.get_parms_id())->small_ntt_tables();
    lhs.ntt_inplace(tables);
    rhs.ntt_inplace(tables);
    x.ntt_inplace(tables);
    y.ntt_inplace(tables);

    equal = lhs.is_equal(rhs);
    EXPECT_EQ(equal, true);

    equal = x.is_equal(y);
    EXPECT_EQ(equal, false);
}