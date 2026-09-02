// Updated version (2026.09)

#include <gmpxx.h>

#include <algorithm>
#include <cassert>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "depends/SEAL-Polytools/include/poly_arith.h"
#include "depends/SEAL/native/src/seal/seal.h"
#include "depends/SEAL/native/src/seal/util/uintarithsmallmod.h"
#include "ringsnark/gadgetlib/protoboard.hpp"
#include "ringsnark/seal/seal_ring.hpp"
#include "ringsnark/seal/seal_util.hpp"
#include "ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp"

using namespace std;
using namespace seal;
using namespace ringsnark;

typedef ringsnark::seal::RingElem R;
typedef ringsnark::seal::EncodingElem E;
typedef ringsnark::rinocchio::keypair<R, E> RincKeys;
typedef ringsnark::rinocchio::proof<R, E> RincProof;
typedef ringsnark::rinocchio::proving_key<R, E> RincPb;
typedef ringsnark::rinocchio::verification_key<R, E> RincVk;

bool cheating_flag = false;

vector<string> split(const string &str, char separator) {
  vector<string> tokens;
  size_t startIndex = 0, endIndex = 0;
  for (size_t i = 0; i <= str.size(); i++) {
    if (i == str.size() || str[i] == separator) {
      endIndex = i;
      tokens.push_back(str.substr(startIndex, endIndex - startIndex));
      startIndex = endIndex + 1;
    }
  }
  return tokens;
}

bool is_number(const string &s) {
  if (s.empty()) return false;
  size_t i = 0;
  if (s[0] == '-') i = 1;
  if (i == s.size()) return false;
  for (; i < s.size(); ++i)
    if (!isdigit(static_cast<unsigned char>(s[i]))) return false;
  return true;
}

char *getCmdOption(char **begin, char **end, const std::string &option) {
  char **itr = std::find(begin, end, option);
  if (itr != end && ++itr != end) return *itr;
  return nullptr;
}

bool cmdOptionExists(char **begin, char **end, const std::string &option) {
  return std::find(begin, end, option) != end;
}

void print_header(const string &title) {
  if (title.empty()) return;
  size_t banner_length = title.length() + 20;
  string banner_top = "+" + string(banner_length - 2, '-') + "+";
  string banner_middle = "|" + string(9, ' ') + title + string(9, ' ') + "|";
  cout << endl
       << banner_top << endl
       << banner_middle << endl
       << banner_top << endl;
}

void def_const(int const_val, int indx, vector<Ciphertext> &ctxt,
               BatchEncoder &encoder, Encryptor &encryptor) {
  Ciphertext tmp;
  while (indx >= (int)ctxt.size()) ctxt.push_back(tmp);
  vector<int64_t> pod_matrix(1, const_val);
  Plaintext pt;
  encoder.encode(pod_matrix, pt);
  encryptor.encrypt_symmetric(pt, ctxt[indx]);
}

Ciphertext encrypt(int val, BatchEncoder &encoder, Encryptor &encryptor) {
  vector<int64_t> pod_matrix(1, val);
  Plaintext pt;
  encoder.encode(pod_matrix, pt);
  Ciphertext res;
  encryptor.encrypt_symmetric(pt, res);
  return res;
}


void safe_transform_to_ntt(Ciphertext &ct, Evaluator &evaluator) {
  if (ct.is_ntt_form()) return;

  bool c1_is_zero = true;
  size_t poly_size = ct.poly_modulus_degree() * ct.coeff_modulus_size();
  if (ct.size() > 1) {
    for (size_t ptr = 0; ptr < poly_size; ++ptr) {
      if (ct.data(1)[ptr] != 0) { c1_is_zero = false; break; }
    }
    if (c1_is_zero) ct.data(1)[0] = 1;
  }

  evaluator.transform_to_ntt_inplace(ct);

  if (ct.size() > 1 && c1_is_zero) {
    std::fill_n(ct.data(1), poly_size, 0);
  }
}

void safe_transform_from_ntt(Ciphertext &ct, Evaluator &evaluator) {
  if (!ct.is_ntt_form()) return;
  bool c1_is_zero = true;
  size_t poly_size = ct.poly_modulus_degree() * ct.coeff_modulus_size();
  if (ct.size() > 1) {
    for (size_t ptr = 0; ptr < poly_size; ++ptr) {
      if (ct.data(1)[ptr] != 0) { c1_is_zero = false; break; }
    }
    if (c1_is_zero) ct.data(1)[0] = 1;
  }
  evaluator.transform_from_ntt_inplace(ct);
  if (ct.size() > 1 && c1_is_zero) {
    std::fill_n(ct.data(1), poly_size, 0);
  }
}


R get_scalar_ring_elem(SEALContext &context, mpz_class val) {
  auto &parms = context.first_context_data()->parms();
  size_t coeff_count = parms.poly_modulus_degree();
  auto &coeff_modulus = parms.coeff_modulus();
  Ciphertext dummy;
  dummy.resize(context, context.first_parms_id(), 2);
  dummy.is_ntt_form() = true;
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    mpz_class mod_mpz = val % coeff_modulus[j].value();
    uint64_t mod_val = std::stoull(mod_mpz.get_str());
    for (size_t k = 0; k < coeff_count; k++) {
      dummy.data(0)[j * coeff_count + k] = mod_val;
    }
  }
  return R(polytools::SealPoly(context, dummy, 0));
}


std::vector<Ciphertext> generate_custom_evk(const SecretKey &sk, int base_bits,
                                            int num_limbs, SEALContext &context,
                                            Encryptor &encryptor,
                                            Evaluator &evaluator,
                                            BatchEncoder &encoder) {
  auto context_data = context.first_context_data();
  auto &parms = context_data->parms();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_size = parms.coeff_modulus().size();
  auto &coeff_modulus = parms.coeff_modulus();

  std::vector<Ciphertext> custom_evk(num_limbs);
  const uint64_t *s_ptr = sk.data().data();

  std::vector<uint64_t> s_sq(coeff_count * coeff_mod_size);
  for (size_t j = 0; j < coeff_mod_size; j++) {
    for (size_t k = 0; k < coeff_count; k++) {
      size_t idx = j * coeff_count + k;
      s_sq[idx] =
          util::multiply_uint_mod(s_ptr[idx], s_ptr[idx], coeff_modulus[j]);
    }
  }

  uint64_t W = 1ULL << base_bits;
  mpz_class current_W_mpz = 1;

  for (int i = 0; i < num_limbs; i++) {
    vector<int64_t> pod_zero(coeff_count, 0);
    Plaintext pt_zero;
    encoder.encode(pod_zero, pt_zero);
    encryptor.encrypt_symmetric(pt_zero, custom_evk[i]);

    safe_transform_to_ntt(custom_evk[i], evaluator);

    uint64_t *c0_ptr = custom_evk[i].data(0);

    for (size_t j = 0; j < coeff_mod_size; j++) {
      uint64_t mod_val = coeff_modulus[j].value();
      mpz_class W_i_mpz = current_W_mpz % mod_val;
      uint64_t W_i_mod = std::stoull(W_i_mpz.get_str());

      for (size_t k = 0; k < coeff_count; k++) {
        size_t idx = j * coeff_count + k;
        uint64_t term =
            util::multiply_uint_mod(s_sq[idx], W_i_mod, coeff_modulus[j]);
        c0_ptr[idx] = util::add_uint_mod(c0_ptr[idx], term, coeff_modulus[j]);
      }
    }
    current_W_mpz *= W;
  }
  return custom_evk;
}


mpz_class coeff_val, rns_val, term, limb_val;
uint64_t limb_u64;
std::vector<Ciphertext> decompose_poly_gmp(const Ciphertext &c2_cipher,
                                           int base_bits, int num_limbs,
                                           SEALContext &context) {
  auto context_data = context.get_context_data(c2_cipher.parms_id());
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_size = coeff_modulus.size();

  mpz_class Q = 1;
  for (auto &mod : coeff_modulus) {
    Q *= mod.value();
  }

  std::vector<mpz_class> q_i_hat(coeff_mod_size);
  std::vector<mpz_class> q_i_hat_inv(coeff_mod_size);
  for (size_t i = 0; i < coeff_mod_size; i++) {
    q_i_hat[i] = Q / coeff_modulus[i].value();
    mpz_class mod_val = coeff_modulus[i].value();
    mpz_class inv;
    mpz_invert(inv.get_mpz_t(), q_i_hat[i].get_mpz_t(), mod_val.get_mpz_t());
    q_i_hat_inv[i] = inv;
  }

  std::vector<Ciphertext> limbs(num_limbs);
  for (int i = 0; i < num_limbs; i++) {
    limbs[i].resize(context, c2_cipher.parms_id(), 2);
    limbs[i].is_ntt_form() = false;
    std::fill_n(limbs[i].data(0), coeff_count * coeff_mod_size, 0);
    std::fill_n(limbs[i].data(1), coeff_count * coeff_mod_size, 0);
  }

  mpz_class W_mask = (mpz_class(1) << base_bits) - 1;
  const uint64_t *c2_ptr = c2_cipher.data(0);

  for (size_t k = 0; k < coeff_count; k++) {
    coeff_val = 0;
    for (size_t j = 0; j < coeff_mod_size; j++) {
      rns_val = c2_ptr[j * coeff_count + k];
      term = (rns_val * q_i_hat_inv[j]) % coeff_modulus[j].value();
      term = (term * q_i_hat[j]);
      coeff_val = (coeff_val + term) % Q;
    }

    for (int i = 0; i < num_limbs; i++) {
      limb_val = (coeff_val >> (i * base_bits)) & W_mask;
      limb_u64 = std::stoull(limb_val.get_str());

      for (size_t j = 0; j < coeff_mod_size; j++) {
        limbs[i].data(0)[j * coeff_count + k] =
            limb_u64 % coeff_modulus[j].value();
      }
    }
  }
  return limbs;
}

class Initializer {
 public:
  size_t poly_modulus_degree;
  size_t blowup_factor;
  size_t inner_poly_modulus_degree;
  int plain_bit_size;
  SecretKey secretKey;
  RelinKeys relinKeys;
  Encryptor *encryptor;
  Evaluator *evaluator;
  Decryptor *decryptor;
  BatchEncoder *encoder;
  SEALContext *context;
  const util::NTTTables *tables;

  int base_bits;
  int num_limbs;
  std::vector<Ciphertext> custom_evk;

  explicit Initializer(size_t poly_modulus_degree_ = 1 << 14,
                       size_t blowup_factor_ = 1, int plain_bit_size_ = 20) {
    poly_modulus_degree = poly_modulus_degree_;
    blowup_factor = blowup_factor_;
    inner_poly_modulus_degree = poly_modulus_degree * blowup_factor;
    plain_bit_size = plain_bit_size_;

    EncryptionParameters params(scheme_type::bgv);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(default_double_batching_modulus(
        poly_modulus_degree, inner_poly_modulus_degree));
    params.set_plain_modulus(
        PlainModulus::Batching(poly_modulus_degree, plain_bit_size));
    context = new SEALContext(params);

    try {
      R::set_context(*context);
      E::set_context(inner_poly_modulus_degree);
    } catch (std::invalid_argument &e) {
      cout << "Error establishing ringsnark context" << endl;
    }

    KeyGenerator keygen(*context);
    secretKey = keygen.secret_key();
    keygen.create_relin_keys(relinKeys);

    encryptor = new Encryptor(*context, secretKey);
    evaluator = new Evaluator(*context);
    decryptor = new Decryptor(*context, secretKey);
    encoder = new BatchEncoder(*context);
    tables = context->get_context_data(context->first_parms_id())
                 ->small_ntt_tables();


    base_bits = 60;
    int total_modulus_bits = 0;
    for (const auto &mod :
         context->first_context_data()->parms().coeff_modulus()) {
      total_modulus_bits += mod.bit_count();
    }
    num_limbs = (total_modulus_bits + base_bits - 1) / base_bits;
    custom_evk = generate_custom_evk(secretKey, base_bits, num_limbs, *context,
                                     *encryptor, *evaluator, *encoder);

    print_params(context->first_context_data()->parms());
  }

  [[nodiscard]] SEALContext *getContext() const { return context; }
  [[nodiscard]] BatchEncoder *getEncoder() const { return encoder; }
  [[nodiscard]] const SecretKey &getSecretKey() const { return secretKey; }
  [[nodiscard]] const RelinKeys &getRelinKeys() const { return relinKeys; }
  [[nodiscard]] Encryptor *getEncryptor() const { return encryptor; }
  [[nodiscard]] Evaluator *getEvaluator() const { return evaluator; }
  [[nodiscard]] Decryptor *getDecryptor() const { return decryptor; }
  [[nodiscard]] const util::NTTTables *getTables() const { return tables; }

  RincKeys get_Rinocchio_keys(const ringsnark::protoboard<R> &pb) const {
    return ringsnark::rinocchio::generator<R, E>(pb.get_constraint_system());
  }
};

class Circuit {
 private:
  struct MulGadget {
    int op1, op2, res;
    vector<vector<pb_variable<R>>> cross;
    vector<pb_variable<R>> c2_limbs_vars;
  };

  size_t n = 0;
  int res_indx = 0;
  int out_reg = -1;
  bool verified = false;
  bool circuit_created = false;
  vector<Ciphertext> ciphers;
  vector<int> reg_size;
  vector<pb_variable_array<R>> regs;
  vector<int> public_regs;
  vector<MulGadget> mul_gadgets;
  vector<vector<int>> exec_lst;

  Encryptor *encryptor;
  Evaluator *evaluator;
  Decryptor *decryptor;
  BatchEncoder *encoder;
  SEALContext *context;
  const util::NTTTables *tables;
  int base_bits;
  int num_limbs;
  std::vector<Ciphertext> custom_evk;

  protoboard<R> pb;
  pb_variable<R> one_var;

  void bind_(int r) {
    Ciphertext &c = ciphers[r];
    safe_transform_to_ntt(c, *evaluator);
    if ((int)c.size() != reg_size[r]) {
      cout << "bind_: register r" << r << " has " << c.size() << " components!"
           << endl;
      exit(5);
    }
    for (int k = 0; k < reg_size[r]; ++k)
      pb.val(regs[r][k]) = R(polytools::SealPoly(*context, c, k));
  }

  void add_(int op1_indx, int op2_indx, int /*one_indx*/, int res) {
    try {
      evaluator->add(ciphers[op1_indx], ciphers[op2_indx], ciphers[res]);
    } catch (const std::logic_error &e) {
      ciphers[res].resize(*context, ciphers[op1_indx].parms_id(), ciphers[op1_indx].size());
      size_t total = ciphers[res].poly_modulus_degree() * ciphers[res].coeff_modulus_size() * ciphers[res].size();
      std::fill_n(ciphers[res].data(), total, 0);
      ciphers[res].is_ntt_form() = ciphers[op1_indx].is_ntt_form();
    }
    bind_(res);
  }

  void subtract_(int op1_indx, int op2_indx, int /*one_indx*/, int res) {
    try {
      evaluator->sub(ciphers[op1_indx], ciphers[op2_indx], ciphers[res]);
    } catch (const std::logic_error &e) {
      ciphers[res].resize(*context, ciphers[op1_indx].parms_id(), ciphers[op1_indx].size());
      size_t total = ciphers[res].poly_modulus_degree() * ciphers[res].coeff_modulus_size() * ciphers[res].size();
      std::fill_n(ciphers[res].data(), total, 0);
      ciphers[res].is_ntt_form() = ciphers[op1_indx].is_ntt_form();
    }
    bind_(res);
  }

  void negate_(int indx, int /*neg_one_indx*/, int res) {
    try {
      evaluator->negate(ciphers[indx], ciphers[res]);
    } catch (const std::logic_error &e) {
      ciphers[res].resize(*context, ciphers[indx].parms_id(), ciphers[indx].size());
      size_t total = ciphers[res].poly_modulus_degree() * ciphers[res].coeff_modulus_size() * ciphers[res].size();
      std::fill_n(ciphers[res].data(), total, 0);
      ciphers[res].is_ntt_form() = ciphers[indx].is_ntt_form();
    }
    bind_(res);
  }

  void assign_(int lhs_indx, int rhs_indx, int /*one_indx*/) {
    ciphers[lhs_indx] = ciphers[rhs_indx];
    bind_(lhs_indx);
  }

  void def_val_(const Ciphertext &cipher, int indx) {
    ciphers[indx] = cipher;
    bind_(indx);
  }

  void setInput_(const vector<Ciphertext> &in_ciphers) {
    for (size_t i = 0; i < in_ciphers.size(); ++i) {
      ciphers[i] = in_ciphers[i];
      bind_((int)i);
    }
  }

 public:
  map<int, Ciphertext> published_;

  explicit Circuit(const Initializer &initializer) {
    context = initializer.getContext();
    encoder = initializer.getEncoder();
    encryptor = initializer.getEncryptor();
    decryptor = initializer.getDecryptor();
    evaluator = initializer.getEvaluator();
    tables = initializer.getTables();
    base_bits = initializer.base_bits;
    num_limbs = initializer.num_limbs;
    custom_evk = initializer.custom_evk;
  }

  BatchEncoder *getEncoder() const { return encoder; }
  int get_out_reg() const { return out_reg; }

  void mul(int op1_indx, int op2_indx, int res_indx) {
    exec_lst.push_back({1, op1_indx, op2_indx, res_indx});
  }
  void add(int op1_indx, int op2_indx, int one_indx, int res_indx) {
    exec_lst.push_back({3, op1_indx, op2_indx, one_indx, res_indx});
  }
  void def_val(int val_indx, int indx, int one_indx) {
    exec_lst.push_back({0, val_indx, indx, one_indx});
  }
  void def_var(int var_indx, int one_indx, int res_indx) {
    exec_lst.push_back({2, var_indx, one_indx, res_indx});
  }
  void negate(int indx, int neg_one_indx, int res_indx) {
    exec_lst.push_back({4, indx, neg_one_indx, res_indx});
  }
  void subtract(int op1_indx, int op2_indx, int one_indx, int res_indx) {
    exec_lst.push_back({5, op1_indx, op2_indx, one_indx, res_indx});
  }
  void assign(int lhs_indx, int rhs_indx, int one_indx) {
    exec_lst.push_back({6, lhs_indx, rhs_indx, one_indx});
  }

  vector<vector<int>> get_exec_list() { return exec_lst; }

  void print_circuit() {
    for (auto &inst : exec_lst) {
      int op = inst[0];
      if (op == 0)
        cout << "$" << inst[2] << " := " << inst[1] << endl;
      else if (op == 1)
        cout << "$" << inst[3] << " := $" << inst[1] << " * $" << inst[2]
             << endl;
      else if (op == 2)
        cout << "$" << inst[3] << " := " << char(inst[1]) << endl;
      else if (op == 3)
        cout << "$" << inst[4] << " := $" << inst[1] << " + $" << inst[2]
             << endl;
      else if (op == 4)
        cout << "$" << inst[3] << " := $(-)" << inst[1] << endl;
      else if (op == 5)
        cout << "$" << inst[4] << " := $" << inst[1] << " - $" << inst[2]
             << endl;
      else if (op == 6)
        cout << "$" << inst[1] << " := $" << inst[2] << endl;
    }
  }

  protoboard<R> create_circuit(const vector<vector<int>> &exec_list,
                               vector<Ciphertext> &in_ciphers) {
    int max_reg = (int)in_ciphers.size() - 1;
    for (auto &inst : exec_list) {
      switch (inst[0]) {
        case 0:
          max_reg = max({max_reg, inst[1], inst[2]});
          break;
        case 1:
          max_reg = max({max_reg, inst[1], inst[2], inst[3]});
          break;
        case 2:
          max_reg = max(max_reg, inst[3]);
          break;
        case 3:
          max_reg = max({max_reg, inst[1], inst[2], inst[4]});
          break;
        case 4:
          max_reg = max({max_reg, inst[1], inst[3]});
          break;
        case 5:
          max_reg = max({max_reg, inst[1], inst[2], inst[4]});
          break;
        case 6:
          max_reg = max({max_reg, inst[1], inst[2]});
          break;
      }
    }
    n = (size_t)(max_reg + 1);

    reg_size.assign(n, 2);

    out_reg = -1;
    set<int> bound;
    for (size_t i = 0; i < in_ciphers.size(); ++i) bound.insert((int)i);
    for (auto &inst : exec_list) {
      switch (inst[0]) {
        case 0:
          out_reg = inst[2];
          break;
        case 1:
          out_reg = inst[3];
          break;
        case 2:
          bound.insert(inst[3]);
          out_reg = inst[3];
          break;
        case 3:
          out_reg = inst[4];
          break;
        case 4:
          out_reg = inst[3];
          break;
        case 5:
          out_reg = inst[4];
          break;
        case 6:
          out_reg = inst[1];
          break;
      }
    }

    bound.insert(out_reg);
    public_regs.assign(bound.begin(), bound.end());

    vector<int> alloc_order;
    for (int r : public_regs) alloc_order.push_back(r);
    for (size_t r = 0; r < n; ++r)
      if (!binary_search(public_regs.begin(), public_regs.end(), (int)r))
        alloc_order.push_back((int)r);

    one_var.allocate(pb, "1");
    regs.resize(n);
    for (int r : alloc_order)
      regs[r].allocate(pb, reg_size[r], "r" + to_string(r));

    size_t total_public = 0;
    for (int r : public_regs) total_public += reg_size[r];
    pb.set_input_sizes(1 + total_public);

    ciphers.assign(n, Ciphertext());
    mul_gadgets.clear();

    auto comp = [&](int r, int k) -> linear_combination<R> {
      if (k < reg_size[r]) return linear_combination<R>(regs[r][k]);
      return linear_combination<R>();
    };

    for (auto &inst : exec_list) {
      int opcode = inst[0];
      if (opcode == 0) {
        int val_indx = inst[1], res = inst[2];
        for (int k = 0; k < reg_size[res]; ++k)
          pb.add_r1cs_constraint(
              r1cs_constraint<R>(one_var, comp(val_indx, k), regs[res][k]));

      } else if (opcode == 1) {
        int op1 = inst[1], op2 = inst[2], res = inst[3];
        MulGadget g;
        g.op1 = op1;
        g.op2 = op2;
        g.res = res;
        g.cross.assign(2, vector<pb_variable<R>>(2));

        for (int i = 0; i < 2; ++i) {
          for (int j = 0; j < 2; ++j) {
            pb_variable<R> p;
            p.allocate(pb);
            pb.add_r1cs_constraint(
                r1cs_constraint<R>(regs[op1][i], regs[op2][j], p));
            g.cross[i][j] = p;
          }
        }

        linear_combination<R> acc_c0 = g.cross[0][0];
        linear_combination<R> acc_c1 = g.cross[0][1] + g.cross[1][0];
        linear_combination<R> acc_c2 = g.cross[1][1];


        g.c2_limbs_vars.resize(num_limbs);
        linear_combination<R> recon_c2;
        mpz_class current_W = 1;

        for (int i = 0; i < num_limbs; ++i) {
          g.c2_limbs_vars[i].allocate(pb);
          R W_i = get_scalar_ring_elem(*context, current_W);
          recon_c2 = recon_c2 + g.c2_limbs_vars[i] * W_i;
          current_W *= uint64_t(1ULL << base_bits);
        }
        pb.add_r1cs_constraint(r1cs_constraint<R>(one_var, recon_c2, acc_c2));


        linear_combination<R> relin_c0 = acc_c0;
        linear_combination<R> relin_c1 = acc_c1;
        for (int i = 0; i < num_limbs; ++i) {
          R evk0 = R(polytools::SealPoly(*context, custom_evk[i], 0));
          R evk1 = R(polytools::SealPoly(*context, custom_evk[i], 1));
          relin_c0 = relin_c0 + g.c2_limbs_vars[i] * evk0;
          relin_c1 = relin_c1 + g.c2_limbs_vars[i] * evk1;
        }

        pb.add_r1cs_constraint(
            r1cs_constraint<R>(one_var, relin_c0, regs[res][0]));
        pb.add_r1cs_constraint(
            r1cs_constraint<R>(one_var, relin_c1, regs[res][1]));

        mul_gadgets.push_back(g);

      } else if (opcode == 2) {
        continue;
      } else if (opcode == 3) {
        int op1 = inst[1], op2 = inst[2], res = inst[4];
        for (int k = 0; k < reg_size[res]; ++k)
          pb.add_r1cs_constraint(r1cs_constraint<R>(
              one_var, comp(op1, k) + comp(op2, k), regs[res][k]));

      } else if (opcode == 4) {
        int indx = inst[1], res = inst[3];
        for (int k = 0; k < reg_size[res]; ++k)
          pb.add_r1cs_constraint(
              r1cs_constraint<R>(one_var, (-1) * comp(indx, k), regs[res][k]));

      } else if (opcode == 5) {
        int op1 = inst[1], op2 = inst[2], res = inst[4];
        for (int k = 0; k < reg_size[res]; ++k)
          pb.add_r1cs_constraint(r1cs_constraint<R>(
              one_var, comp(op1, k) - comp(op2, k), regs[res][k]));

      } else if (opcode == 6) {
        int rhs = inst[2], lhs = inst[1];
        for (int k = 0; k < reg_size[lhs]; ++k)
          pb.add_r1cs_constraint(
              r1cs_constraint<R>(one_var, comp(rhs, k), regs[lhs][k]));
      }
    }

    setInput_(in_ciphers);
    circuit_created = true;
    return pb;
  }

  void execute(const vector<vector<int>> &exec_list,
               map<char, Ciphertext> vars_vals) {
    pb.val(one_var) = R::one();
    size_t mul_idx = 0;

    for (auto &inst : exec_list) {
      int opcode = inst[0];
      if (opcode == 0) {
        def_val_(ciphers[inst[1]], inst[2]);
        res_indx = inst[2];

      } else if (opcode == 1) {
        auto &g = mul_gadgets[mul_idx++];


        for (int i = 0; i < 2; ++i)
          for (int j = 0; j < 2; ++j)
            pb.val(g.cross[i][j]) =
                pb.val(regs[g.op1][i]) * pb.val(regs[g.op2][j]);


        Ciphertext prod;
        try {
          evaluator->multiply(ciphers[inst[1]], ciphers[inst[2]], prod);
        } catch (const std::logic_error &e) {

          prod.resize(*context, ciphers[inst[1]].parms_id(), 3);
          size_t total = prod.poly_modulus_degree() * prod.coeff_modulus_size() * 3;
          std::fill_n(prod.data(), total, 0);
          prod.is_ntt_form() = false;
        }


        size_t poly_size =
            prod.poly_modulus_degree() * prod.coeff_modulus_size();
        Ciphertext c2_cipher;
        c2_cipher.resize(*context, prod.parms_id(), 2);
        std::copy_n(prod.data(2), poly_size, c2_cipher.data(0));
        std::fill_n(c2_cipher.data(1), poly_size, 0);


        c2_cipher.is_ntt_form() = prod.is_ntt_form();
        safe_transform_from_ntt(c2_cipher, *evaluator);


        std::vector<Ciphertext> c2_limbs =
            decompose_poly_gmp(c2_cipher, base_bits, num_limbs, *context);


        for (int i = 0; i < num_limbs; i++) {
          Ciphertext &limb_ct = c2_limbs[i];
          safe_transform_to_ntt(limb_ct, *evaluator);

          pb.val(g.c2_limbs_vars[i]) =
              R(polytools::SealPoly(*context, limb_ct, 0));
        }


        Ciphertext relin_out;
        relin_out.resize(*context, prod.parms_id(), 2);
        std::copy_n(prod.data(0), poly_size, relin_out.data(0));
        std::copy_n(prod.data(1), poly_size, relin_out.data(1));
        relin_out.is_ntt_form() = prod.is_ntt_form();

        safe_transform_to_ntt(relin_out, *evaluator);

        auto &coeff_modulus =
            context->get_context_data(prod.parms_id())->parms().coeff_modulus();
        for (size_t i = 0; i < num_limbs; i++) {
          uint64_t *limb_ptr = c2_limbs[i].data(0);
          for (size_t j = 0; j < coeff_modulus.size(); j++) {
            for (size_t k = 0; k < prod.poly_modulus_degree(); k++) {
              size_t idx = j * prod.poly_modulus_degree() + k;
              auto mod = coeff_modulus[j];
              uint64_t t0 = util::multiply_uint_mod(
                  limb_ptr[idx], custom_evk[i].data(0)[idx], mod);
              relin_out.data(0)[idx] =
                  util::add_uint_mod(relin_out.data(0)[idx], t0, mod);
              uint64_t t1 = util::multiply_uint_mod(
                  limb_ptr[idx], custom_evk[i].data(1)[idx], mod);
              relin_out.data(1)[idx] =
                  util::add_uint_mod(relin_out.data(1)[idx], t1, mod);
            }
          }
        }

        ciphers[inst[3]] = relin_out;
        res_indx = inst[3];
        bind_(res_indx);

      } else if (opcode == 2) {
        char var = char(inst[1]);
        auto it = vars_vals.find(var);
        def_val_(it->second, inst[3]);
        res_indx = inst[3];
      } else if (opcode == 3) {
        add_(inst[1], inst[2], inst[3], inst[4]);
        res_indx = inst[4];
      } else if (opcode == 4) {
        negate_(inst[1], inst[2], inst[3]);
        res_indx = inst[3];
      } else if (opcode == 5) {
        subtract_(inst[1], inst[2], inst[3], inst[4]);
        res_indx = inst[4];
      } else if (opcode == 6) {
        assign_(inst[1], inst[2], inst[3]);
        res_indx = inst[1];
      }
    }
    published_[out_reg] = ciphers[out_reg];
  }

  void get_results() {
    if (!verified) return;
    const Ciphertext &ctxt = published_.at(out_reg);
    Plaintext plain_res;
    decryptor->decrypt(ctxt, plain_res);
    vector<int64_t> plain_res_decode;
    encoder->decode(plain_res, plain_res_decode);
    cout << "Decrypted result= " << plain_res_decode[0] << endl << endl;
  }

  RincProof prove(const RincPb &pk) {
    return ringsnark::rinocchio::prover(pk, pb.primary_input(),
                                        pb.auxiliary_input());
  }

  bool verify(const RincVk &vk, const RincProof &proof,
              const map<int, Ciphertext> &published) {
    ringsnark::r1cs_primary_input<R> primary;
    primary.push_back(R::one());
    for (int r : public_regs) {
      const Ciphertext &c = published.at(r);
      for (int k = 0; k < reg_size[r]; ++k)
        primary.push_back(R(polytools::SealPoly(*context, c, k)));
    }
    verified = ringsnark::rinocchio::verifier(vk, primary, proof);

    cout << "Verified = " << verified << endl;

    return verified;
  }
};

int main(int argc, char *argv[]) {
  if (cmdOptionExists(argv, argv + argc, "-h") ||
      !cmdOptionExists(argv, argv + argc, "-f"))
    return 0;

  Initializer initializer(1 << 14, 1, 20);

  Circuit circuit(initializer);
  map<char, Ciphertext> vars_vals;

  cout << "Circuit is initialized..." << endl;
  char *file = getCmdOption(argv, argv + argc, "-f");
  ifstream myfile(file);

  if (cmdOptionExists(argv, argv + argc, "-v")) {
    string vars = getCmdOption(argv, argv + argc, "-v");
    for (auto &v : split(vars, ',')) {
      if (v.empty()) continue;
      char variable_name = v[0];
      int variable_value = stoi(v.substr(v.find('=') + 1));
      vars_vals[variable_name] = encrypt(variable_value, *circuit.getEncoder(),
                                         *initializer.getEncryptor());
    }
  }

  vector<Ciphertext> ctxt(1);
  const int ONE_INDX = 0;
  const int NEG_ONE_INDX = 1;
  def_const(1, ONE_INDX, ctxt, *circuit.getEncoder(),
            *initializer.getEncryptor());
  def_const(-1, NEG_ONE_INDX, ctxt, *circuit.getEncoder(),
            *initializer.getEncryptor());

  string inst;
  auto start_opl2circuit = std::chrono::system_clock::now();
  while (getline(myfile, inst)) {
    if (inst.empty()) continue;
    auto vec = split(inst, ' ');
    if (vec.empty() || vec[0].size() < 3) continue;
    string res_indx = vec[0].substr(2);

    if (vec.size() == 5) {
      string op = vec[3];
      if (op == "*")
        circuit.mul(stoi(vec[2].substr(1)), stoi(vec[4].substr(1)),
                    stoi(res_indx));
      else if (op == "+")
        circuit.add(stoi(vec[2].substr(1)), stoi(vec[4].substr(1)), ONE_INDX,
                    stoi(res_indx));
      else if (op == "-")
        circuit.subtract(stoi(vec[2].substr(1)), stoi(vec[4].substr(1)),
                         ONE_INDX, stoi(res_indx));
    } else if (vec.size() == 3) {
      string op1 = vec[2];
      if (is_number(op1))
        def_const(stoi(op1), stoi(res_indx), ctxt, *circuit.getEncoder(),
                  *initializer.getEncryptor());
      else if (op1[0] == 'r')
        circuit.assign(stoi(res_indx), stoi(op1.substr(1)), ONE_INDX);
      else
        circuit.def_var(op1[0], ONE_INDX, stoi(res_indx));
    }
  }


  vector<vector<int>> exec_lst = circuit.get_exec_list();
  auto end_opl2circuit = std::chrono::system_clock::now();

  auto start_create_cir_r1cs = std::chrono::system_clock::now();
  protoboard<R> pb = circuit.create_circuit(exec_lst, ctxt);
  auto end_create_cir_r1cs = std::chrono::system_clock::now();
  cout << "Circuit is created..." << endl;

  auto start_rinc_keys = std::chrono::system_clock::now();
  const auto keypair = initializer.get_Rinocchio_keys(pb);
  auto end_rinc_keys = std::chrono::system_clock::now();

  cout << "Circuit is executing..." << endl;
  auto start_circ_exec = std::chrono::system_clock::now();
  circuit.execute(exec_lst, vars_vals);
  auto end_circ_exec = std::chrono::system_clock::now();

  cout << "Proving..." << endl;
  auto start_prove = std::chrono::system_clock::now();
  auto proof = circuit.prove(keypair.pk);
  auto end_prove = std::chrono::system_clock::now();

  map<int, Ciphertext> server_published = circuit.published_;
  map<int, Ciphertext> client_view;

  for (size_t i = 0; i < ctxt.size(); ++i) {
    Ciphertext c = ctxt[i];
    safe_transform_to_ntt(c, *initializer.getEvaluator());
    client_view[(int)i] = c;
  }


  for (auto &inst_map : exec_lst) {
    if (inst_map[0] == 2) {
      char var = char(inst_map[1]);
      int target_reg = inst_map[3];
      Ciphertext c = vars_vals[var];
      safe_transform_to_ntt(c, *initializer.getEvaluator());
      client_view[target_reg] = c;
    }
  }
  client_view[circuit.get_out_reg()] =
      server_published.at(circuit.get_out_reg());

  cout << "Verifying..." << endl;
  auto start_verify = std::chrono::system_clock::now();
  circuit.verify(keypair.vk, proof, client_view);
  auto end_verify = std::chrono::system_clock::now();

  cout << "Decrypting..." << endl;
  auto start_decrypt = std::chrono::system_clock::now();
  circuit.get_results();
  auto end_decrypt = std::chrono::system_clock::now();

  const int w_prog = 20;
  const int w_opl = 14;
  const int w_r1cs = 15;
  const int w_keys = 22;
  const int w_exec = 20;
  const int w_prv = 10;
  const int w_ver = 12;
  const int w_dec = 12;

  cout << left << setw(w_prog) << "Program" << setw(w_opl) << "OpL2Circuit"
       << setw(w_r1cs) << "Circuit&R1CS" << setw(w_keys)
       << "Generate Rino. Keys" << setw(w_exec) << "Circuit Execution"
       << setw(w_prv) << "Proving" << setw(w_ver) << "Verifying" << setw(w_dec)
       << "Decryption" << "\n";

  ofstream data("Running_times.csv", ios::app);
  if (!data.is_open()) {
    cout << "Error writing to Running_times.csv" << endl;
    return 1;
  }

  string filename = filesystem::path(file).stem().string();

  data << filename << ","
       << chrono::duration_cast<chrono::milliseconds>(end_opl2circuit -
                                                      start_opl2circuit)
              .count()
       << ","
       << chrono::duration_cast<chrono::milliseconds>(end_create_cir_r1cs -
                                                      start_create_cir_r1cs)
              .count()
       << ","
       << chrono::duration_cast<chrono::milliseconds>(end_rinc_keys -
                                                      start_rinc_keys)
              .count()
       << ","
       << chrono::duration_cast<chrono::milliseconds>(end_circ_exec -
                                                      start_circ_exec)
              .count()
       << ","
       << chrono::duration_cast<chrono::milliseconds>(end_prove - start_prove)
              .count()
       << ","
       << chrono::duration_cast<chrono::milliseconds>(end_verify - start_verify)
              .count()
       << ","
       << chrono::duration_cast<chrono::milliseconds>(end_decrypt -
                                                      start_decrypt)
              .count()
       << "\n";

  data.close();

  cout << left << setw(w_prog) << filename << setw(w_opl)
       << chrono::duration_cast<chrono::milliseconds>(end_opl2circuit -
                                                      start_opl2circuit)
              .count()
       << setw(w_r1cs)
       << chrono::duration_cast<chrono::milliseconds>(end_create_cir_r1cs -
                                                      start_create_cir_r1cs)
              .count()
       << setw(w_keys)
       << chrono::duration_cast<chrono::milliseconds>(end_rinc_keys -
                                                      start_rinc_keys)
              .count()
       << setw(w_exec)
       << chrono::duration_cast<chrono::milliseconds>(end_circ_exec -
                                                      start_circ_exec)
              .count()
       << setw(w_prv)
       << chrono::duration_cast<chrono::milliseconds>(end_prove - start_prove)
              .count()
       << setw(w_ver)
       << chrono::duration_cast<chrono::milliseconds>(end_verify - start_verify)
              .count()
       << setw(w_dec)
       << chrono::duration_cast<chrono::milliseconds>(end_decrypt -
                                                      start_decrypt)
              .count()
       << "\n";

  return 0;
}
