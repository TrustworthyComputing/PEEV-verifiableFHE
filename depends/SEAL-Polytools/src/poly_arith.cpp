#include "seal/util/polyarithsmallmod.h"
#include "poly_arith.h"
#include <cassert>
#include <complex>
#include <stdexcept>
#include <vector>

using namespace polytools;

// =============================================================================
// ================================= SEALPOLY ==================================
// =============================================================================

/// Internally, seal stores the polynomials of a ctxt as DynArray<uint64_t>,
/// i.e., linear arrays of size ctxt.size * ctxt.poly_modulus_degree * ctxt.coeff_modulus_size

// ----------------------------- CLASS MANAGEMENT -----------------------------

SealPoly::SealPoly(seal::SEALContext &context)
    : parms_id(context.first_parms_id()), mempool(seal::MemoryManager::GetPool()),
      coeff_count(context.first_context_data()->parms().poly_modulus_degree()),
      coeff_modulus(context.first_context_data()->parms().coeff_modulus())
{
    data.resize(coeff_count * coeff_modulus.size(), true);
    is_ntt = true;
}

SealPoly::SealPoly(seal::SEALContext &context, const seal::Ciphertext &ref)
    : parms_id(ref.parms_id()), mempool(seal::MemoryManager::GetPool()), coeff_count(ref.poly_modulus_degree()),
      coeff_modulus(context.get_context_data(parms_id)->parms().coeff_modulus())
{
    data.resize(coeff_count * coeff_modulus.size(), true);
    is_ntt = true;
}

SealPoly::SealPoly(seal::SEALContext &context, const seal::Ciphertext &ctxt, size_t index)
    : parms_id(ctxt.parms_id()), mempool(seal::MemoryManager::GetPool()), coeff_count(ctxt.poly_modulus_degree()),
      coeff_modulus(context.get_context_data(parms_id)->parms().coeff_modulus())
{
    // Copy coefficients from ctxt polynomial
    data.resize(coeff_count * coeff_modulus.size());
    for (size_t i = 0; i < coeff_count * coeff_modulus.size(); ++i)
    {
        data[i] = *(ctxt.data(index) + i);
    }
    is_ntt = ctxt.is_ntt_form();
}

SealPoly::SealPoly(seal::SEALContext &context, const seal::Plaintext &ptxt, const seal::parms_id_type *parms_id_ptr)
    : parms_id(ptxt.parms_id()), mempool(seal::MemoryManager::GetPool())
{
    // If the polynomial is in non-ntt form (e.g., created from hex string), it'll have parms_id_zero
    if (ptxt.parms_id() == seal::parms_id_zero)
    {
        is_ntt = false;
        if (!parms_id_ptr)
            throw std::invalid_argument(
                "Plaintext must have valid parms_id or one must be provided in the function call.");

        parms_id = *parms_id_ptr;
    }

    // The size that this polynomial *should* end up as, based on the parameters
    auto parms = context.get_context_data(parms_id)->parms();
    coeff_modulus = parms.coeff_modulus();
    coeff_count = parms.poly_modulus_degree();

    // Initialize data array to the desired size (writes zeros)
    data.resize(coeff_count * coeff_modulus.size(), true);

    if (ptxt.parms_id() == seal::parms_id_zero)
    {
        // The size that it currently is (which might be smaller than desired size)
        auto ptxt_size = ptxt.dyn_array().size();
        auto ptxt_coeff_count = ptxt.coeff_count();
        auto ptxt_coeff_size = ptxt_coeff_count == 0 ? 1 : ptxt_size / ptxt_coeff_count;

        // TODO: not sure how to deal with multi-precision coefficients in non-RNS polynomials!
        assert(ptxt_coeff_size == 1);

        // copy over original values
        for (size_t i = 0; i < ptxt.dyn_array().size(); ++i)
        {
            data[i] = ptxt.dyn_array()[i];
        }

        // convert to RNS
        context.get_context_data(parms_id)->rns_tool()->base_q()->decompose_array(data.begin(), coeff_count, mempool);
    }
    else
    { // plain should be in NTT form already, which apparently implies RNS form?

        for (size_t i = 0; i < coeff_count * coeff_modulus.size(); ++i)
        {
            data[i] = ptxt.data()[i];
        }
    }
}

SealPoly::SealPoly(
    seal::SEALContext &context, const std::vector<uint64_t> &coeffs, const seal::parms_id_type *parms_id_ptr)
    : parms_id(*parms_id_ptr), mempool(seal::MemoryManager::GetPool())
{
    auto parms = context.get_context_data(parms_id)->parms();
    coeff_modulus = parms.coeff_modulus();
    coeff_count = parms.poly_modulus_degree();

    // If the polynomial is in non-ntt form (e.g., created from hex string), it'll have parms_id_zero
    if (parms_id == seal::parms_id_zero)
    {
        is_ntt = false;
    }
    else
    {
        is_ntt = true;
    }

    // Initialize data array to the desired size (writes zeros)
    data.resize(coeff_count * coeff_modulus.size(), true);

    for (size_t i = 0; i < coeff_modulus.size(); i++)
    {
        for (size_t j = 0; j < coeff_count; j++)
        {
            data[i * coeff_count + j] = coeffs[i * coeff_count + j];
        }
    }
}

// -------------------------------- COEFFICIENTS -------------------------------
std::vector<std::complex<double>> SealPoly::to_coeff_list(seal::SEALContext &context)
{
    throw std::runtime_error("Not yet implemented.");
}

std::complex<double> SealPoly::get_coeff(seal::SEALContext &context, size_t i)
{
    return to_coeff_list(context)[i];
}

void SealPoly::set_coeff(seal::SEALContext &context, std::complex<double> &val, size_t i)
{
    throw std::runtime_error("Not yet implemented.");
}

// -------------------------------- OPERATIONS ---------------------------------
bool SealPoly::is_zero() const
{
    auto mm = data.begin();
    size_t size = data.size();
    // Check if first item is zero, then use memcmp() to check remaining size-1 items
    return (*mm == 0) && !memcmp(mm, mm + 1, size - 1);
}

bool SealPoly::is_equal(const SealPoly &other) const
{
    if (data.size() != other.data.size())
    {
        return false;
    }
    return !memcmp(data.begin(), other.data.begin(), data.size());
}

void SealPoly::multiply_scalar_inplace(uint64_t scalar)
{
    if (scalar == 1)
    {
        return;
    }
    // No need for NTT check, since NTT is a no-op for the constant polynomial scalar.
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::multiply_poly_scalar_coeffmod(
            &data[j * coeff_count], coeff_count, scalar, coeff_modulus[j], &data[j * coeff_count]);
    }
}

void SealPoly::add_scalar_inplace(uint64_t scalar)
{
    if (scalar == 0)
    {
        return;
    }
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::add_poly_scalar_coeffmod(
            &data[j * coeff_count], coeff_count, scalar, coeff_modulus[j], &data[j * coeff_count]);
    }
}

void SealPoly::add_inplace(const SealPoly &other)
{
    assert(is_ntt == other.is_ntt);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::add_poly_coeffmod(
            &data[j * coeff_count], &other.data[j * coeff_count], coeff_count, coeff_modulus[j],
            &data[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
    }
}

void SealPoly::add_inplace(const seal::Ciphertext &other, size_t index)
{
    assert(is_ntt == other.is_ntt_form());
    auto other_data = other.data(index);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::add_poly_coeffmod(
            &data[j * coeff_count], &other_data[j * coeff_count], coeff_count, coeff_modulus[j],
            &data[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
    }
}

void SealPoly::subtract_inplace(const SealPoly &other)
{
    assert(is_ntt == other.is_ntt);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::sub_poly_coeffmod(
            &data[j * coeff_count], &other.data[j * coeff_count], coeff_count, coeff_modulus[j],
            &data[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
    }
}

void SealPoly::subtract_inplace(const seal::Ciphertext &other, size_t index)
{
    assert(is_ntt == other.is_ntt_form());
    auto other_data = other.data(index);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::sub_poly_coeffmod(
            &data[j * coeff_count], &other_data[j * coeff_count], coeff_count, coeff_modulus[j],
            &data[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
    }
}

void SealPoly::subtract_scalar_inplace(uint64_t scalar)
{
    if (scalar == 0)
    {
        return;
    }
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::sub_poly_scalar_coeffmod(
            &data[j * coeff_count], coeff_count, scalar, coeff_modulus[j], &data[j * coeff_count]);
    }
}

void SealPoly::multiply_inplace(const SealPoly &other)
{
    assert(is_ntt);
    assert(other.is_ntt);
    const SealPoly *o_p = dynamic_cast<const SealPoly *>(&other);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::dyadic_product_coeffmod(
            &data[j * coeff_count], &(*o_p).data[j * coeff_count], coeff_count, coeff_modulus[j],
            &data[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
    }
}

void SealPoly::multiply_inplace(const seal::Ciphertext &other, size_t index)
{
    assert(is_ntt);
    assert(other.is_ntt_form());
    auto other_data = other.data(index);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::dyadic_product_coeffmod(
            &data[j * coeff_count], &other_data[j * coeff_count], coeff_count, coeff_modulus[j],
            &data[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
    }
}

void SealPoly::ntt_inplace(const seal::util::NTTTables *small_ntt_tables)
{
    assert(!is_ntt && "Polynomial must not be in NTT form to allow NTT.");
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::ntt_negacyclic_harvey(data.begin() + (j * coeff_count), small_ntt_tables[j]);
    }
    is_ntt = true;
}

void SealPoly::intt_inplace(const seal::util::NTTTables *small_ntt_tables)
{
    assert(is_ntt && "Polynomial must be in NTT form to allow iNTT.");
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::inverse_ntt_negacyclic_harvey(data.begin() + (j * coeff_count), small_ntt_tables[j]);
    }
    is_ntt = false;
}

bool SealPoly::invert_inplace()
{
    // compute a^{-1}, where a is a double-CRT polynomial whose evaluation representation
    // is in a. The double-CRT representation in SEAL is stored as a flat array of
    // length coeff_count * modulus_count:
    //    [ 0 .. coeff_count-1 , coeff_count .. 2*coeff_count-1, ... ]
    //      ^--- a (mod p0)    , ^--- a (mod p1),              ,  ...
    // return if the inverse exists, and result is also in evaluation representation

    assert(is_ntt);
    bool *has_inv = new bool[coeff_modulus.size()];
    std::fill_n(has_inv, coeff_modulus.size(), true);
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        for (size_t i = 0; i < coeff_count && has_inv[j]; i++)
        {
            uint64_t inv = 0;
            if (seal::util::try_invert_uint_mod(data[i + (j * coeff_count)], coeff_modulus[j], inv))
            {
                data[i + (j * coeff_count)] = inv; // TODO: Check if this is safe (used to be result[...])
            }
            else
            {
                has_inv[j] = false;
            }
        }
    }
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        if (!has_inv[j])
            return false;
    }
    delete[] has_inv;

    return true;
}

void SealPoly::negate_inplace()
{
    for (size_t j = 0; j < coeff_modulus.size(); j++)
    {
        seal::util::negate_poly_coeffmod(&data[j * coeff_count], coeff_count, coeff_modulus[j], &data[j * coeff_count]);
    }
}

// =============================================================================
// =================================== MISC ====================================
// =============================================================================
nlohmann::json SealPoly::to_json() const
{
    // TODO: fix the extra commas from the loops!

    nlohmann::json j;

    // degree
    j["degree"] = coeff_count;

    // ntt
    j["ntt"] = is_ntt;

    // moduli
    std::vector<std::uint64_t> moduli;
    moduli.reserve(coeff_modulus.size());
    for (auto c : coeff_modulus)
    {
        moduli.push_back(c.value());
    }
    j["moduli"] = moduli;

    // coefficients
    std::vector<std::vector<uint64_t>> coefficients;
    coefficients.reserve(coeff_count);
    for (size_t i = 0; i < coeff_count; ++i)
    {
        coefficients.push_back(std::vector<uint64_t>(coeff_modulus.size()));
        for (size_t j = 0; j < coeff_modulus.size(); ++j)
        {
            coefficients[i][j] = data[j * coeff_count + i];
        }
    }
    j["coefficients"] = coefficients;

    return j;
}

void SealPoly::save(std::ostream &ostream) const
{
    ostream << this->to_json();
}

void SealPoly::load(std::istream &istream)
{
    nlohmann::json j;
    istream >> j;

    if (!j.contains("degree") || !j.contains("ntt") || !j.contains("moduli") || !j.contains("coefficients"))
        throw std::runtime_error("Cannot load polynomial since json does not contain the right fields.");

    coeff_count = j["degree"];
    is_ntt = j["ntt"];

    if (!j["moduli"].is_array() || !j["coefficients"].is_array())
        throw std::runtime_error("Cannot load polynomial since json does not contain correct moduli/coefficients.");

    std::vector<uint64_t> moduli = j["moduli"];
    coeff_modulus.clear();
    for (auto m : moduli)
        coeff_modulus.push_back(seal::Modulus(m));

    data.clear();
    data.resize(coeff_count * coeff_modulus.size());
    std::vector<std::vector<uint64_t>> coeffs = j["coefficients"];
    for (size_t i = 0; i < coeff_count; ++i)
    {
        for (size_t j = 0; j < coeff_modulus.size(); ++j)
        {
            data[j * coeff_count + i] = coeffs[i][j];
        }
    }
}

seal::Ciphertext polytools::poly_to_ctxt(seal::SEALContext &context, std::vector<SealPoly> polys)
{
    if (polys.empty())
        return seal::Ciphertext(context);

    seal::Ciphertext ctxt(context, polys[0].parms_id, polys.size());
    ctxt.resize(polys.size());
    ctxt.is_ntt_form() = polys[0].is_ntt;

    for (size_t i = 0; i < polys.size(); ++i)
    {
        for (size_t j = 0; j < polys[i].get_coeff_count() * polys[i].get_coeff_modulus_count(); ++j)
        {
            *(ctxt.data(i) + j) = polys[i].data[j];
        }
    }

    return ctxt;
}

seal::Ciphertext polytools::transparent_encryption(seal::SEALContext &context, seal::Plaintext ptxt)
{
    polytools::SealPoly t(context, ptxt, &context.first_parms_id());

    // This polynomial is in non-NTT, non-RNS form internally
    seal::Plaintext zero_ptxt("0");
    polytools::SealPoly zero(context, zero_ptxt, &context.first_parms_id());
    //(a*s+m+e, a) with a=s=e=0
    return polytools::poly_to_ctxt(context, { t, zero });
}
