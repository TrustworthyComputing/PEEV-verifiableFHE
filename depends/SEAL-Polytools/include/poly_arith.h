#ifndef POLYTOOLS_POLY_ARITH_H
#define POLYTOOLS_POLY_ARITH_H
#include "seal/seal.h"
#include <nlohmann/json.hpp>

namespace polytools
{
    /// Wrapper for underlying polynomials that make up plaintexts and ciphertexts in SEAL
    class SealPoly
    {
    private:
        /// Parameter id associated with this SealPoly
        seal::parms_id_type parms_id;

        /// Pointer to the SEAL MemoryPool in which the polynomial is allocated
        seal::MemoryPoolHandle mempool;

        /// The underlying data, either in standard coefficient form (coeff_repr) or in NTT form (eval_repr)
        seal::DynArray<std::uint64_t> data;

        /// True iff data is in NTT form
        bool is_ntt;

        /// Degree of the polynomial / number of coefficients
        size_t coeff_count;

        /// Vector of the different RNS coefficient moduli
        std::vector<seal::Modulus> coeff_modulus;

        friend void poly_to_ctxt(seal::Ciphertext &dest, std::vector<SealPoly> polys);

    public:
        /// Default Destructor
        virtual ~SealPoly() = default;

        /// Copy constructor
        SealPoly(const SealPoly &other) = default;

        /// Copy operator
        SealPoly &operator=(const SealPoly &other) = default;

        /// Initializes a zero polynomial with sizes based on the parameters of seal::SEALContext
        /// Specifically, this uses "first_parms_id" / "first_parms_data" from SEALContext
        /// \param context seal::SEALContext object, used to access the context
        explicit SealPoly(seal::SEALContext &context);

        /// Initializes a zero polynomial with sizes based on the parameters of the current ciphertext
        /// \param context seal::SEALContext object, used to access the context
        /// \param ref Ciphertext used as a reference to get get, e.g., coeff_modulus_count
        SealPoly(seal::SEALContext &context, const seal::Ciphertext &ref);

        /// Creates a copy of the index-th polynomial comprising the Ciphertext
        /// \param context seal::SEALContext object, used to access the context
        /// \param ctxt  Ciphertext from which the polynomial should be copied
        /// \param index Index (starting at 0) of the polynomial to be copied
        SealPoly(seal::SEALContext &context, const seal::Ciphertext &ctxt, size_t index);

        /// Creates a copy of polynomial in the Plaintext
        /// \param context seal::SEALContext object, used to access the context
        /// \param ptxt  Plaintext from which the polynomial should be copied
        SealPoly(
            seal::SEALContext &context, const seal::Plaintext &ptxt, const seal::parms_id_type *parms_id = nullptr);

        /// Creates a copy of polynomial with coefficients given by coeffs
        /// \param context seal::SEALContext object, used to access the context
        /// \param coeffs  Coefficients of the polynomial
        SealPoly(seal::SEALContext &context, const std::vector<uint64_t> &coeffs, const seal::parms_id_type *parms_id);

        /// Export polynomial to a vector of complex values
        /// \return vector of the (complex) coefficients of the polynomial
        std::vector<std::complex<double>> to_coeff_list(seal::SEALContext &context);

        /// get individual coefficient
        /// \param i index of the coefficient
        /// \return the i-th coefficient
        std::complex<double> get_coeff(seal::SEALContext &context, size_t i);

        /// get individual coefficient in RNS representation (expressed as a vector)
        /// \param i index of the coefficient
        /// \return the i-th coefficient
        std::vector<uint64_t> get_coefficient_rns(size_t i)
        {
            std::vector<uint64_t> res(get_coeff_modulus_count());
            for (size_t j = 0; j < get_coeff_modulus_count(); j++)
            {
                res[j] = data[j * get_coeff_count() + i];
            }
            return res;
        }

        /// get i-th RNS limb for all coefficients
        /// \param i index of the limb
        /// \return the i-th limb
        std::vector<uint64_t> get_limb(size_t i)
        {
            std::vector<uint64_t> res(get_coeff_count());
            for (size_t j = 0; j < get_coeff_count(); j++)
            {
                res[j] = data[i * get_coeff_count() + j];
            }
            return res;
        }

        /// set individual coefficient
        /// \param i index of the coefficient
        void set_coeff(seal::SEALContext &context, std::complex<double> &val, size_t i);

        /// Degree of the polynomial / number of coefficients
        [[nodiscard]] size_t get_coeff_count() const
        {
            return this->coeff_count;
        }

        /// The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
        [[nodiscard]] size_t get_coeff_modulus_count() const
        {
            return this->coeff_modulus.size();
        }

        [[nodiscard]] std::vector<seal::Modulus> get_coeff_modulus() const
        {
            return this->coeff_modulus;
        }

        /// Parameter id associated with this SealPoly
        seal::parms_id_type get_parms_id() const
        {
            return parms_id;
        }

        /// True iff data is in NTT form
        bool is_ntt_form() const
        {
            return is_ntt;
        }

        /// Serialize polynomial to json
        nlohmann::json to_json() const;

        /// Write json to file
        void save(std::ostream &ostream) const;

        /// Read json from file
        void load(std::istream &istream);

        // ----------- OPERATIONS -------------
        bool is_zero() const;
        bool is_equal(const SealPoly &other) const;

        // inplace ops -> result in first operand
        void multiply_scalar_inplace(uint64_t scalar);
        void add_scalar_inplace(uint64_t scalar);
        void add_inplace(const SealPoly &other);
        void add_inplace(const seal::Ciphertext &other, size_t index);
        void subtract_inplace(const SealPoly &other);
        void subtract_inplace(const seal::Ciphertext &other, size_t index);
        void subtract_scalar_inplace(uint64_t scalar);
        void multiply_inplace(const SealPoly &other);
        void multiply_inplace(const seal::Ciphertext &other, size_t index);
        void intt_inplace(const seal::util::NTTTables *small_ntt_tables);
        void ntt_inplace(const seal::util::NTTTables *small_ntt_tables);
        void negate_inplace();
        bool invert_inplace();

        friend seal::Ciphertext poly_to_ctxt(seal::SEALContext &context, std::vector<SealPoly> polys);
    };

    /// Overwrites dest with the coefficients from the polynomials
    /// \param context SEAL context to use for parameters/etc
    /// \param polys List of polynomials that should constitute the ctxt
    seal::Ciphertext poly_to_ctxt(seal::SEALContext &context, std::vector<SealPoly> polys);

    /// Encrypts the plaintext into a "transparent" ciphertext with zero noise and zero randomness
    /// \param context SEAL context to use for parameters/etc
    /// \param polys List of polynomials that should constitute the ctxt
    seal::Ciphertext transparent_encryption(seal::SEALContext &context, seal::Plaintext ptxt);

    // TODO: Add transparent_encryption with non-zero randomness, too

} // namespace polytools
#endif /* POLYTOOLS_POLY_ARITH_H */