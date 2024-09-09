#ifndef IP
#define IP

#include "global.h"
#include "hash.h"
#include "print.h"
#include "routines.h"

using namespace std;

// define the structure of InnerProduct Proof
struct InnerProduct_PP
{
	size_t VECTOR_LEN;      // denotes the size of witness (witness is upto l = 2^VECTOR_LEN)
	size_t LOG_VECTOR_LEN;  // LOG_VECTOR_LEN = log(VECTOR_LEN) 

	// size of the vector = VECTOR_LEN
	vector<EC_POINT *> vec_g;
	vector<EC_POINT *> vec_h;
};

//P = vec_g^vec_a vec_h^vec_b u^<vec_a, vec_b>
struct InnerProduct_Instance
{
	EC_POINT *u;
	EC_POINT *P;
};

struct InnerProduct_Witness
{
	// size of the vector = VECTOR_LEN
	vector<BIGNUM *> vec_a;
	vector<BIGNUM *> vec_b;
};

struct InnerProduct_Proof
{
	// size of the vector = LOG_VECTOR_LEN
	vector<EC_POINT *> vec_L;
	vector<EC_POINT *> vec_R;
	BIGNUM *a;
	BIGNUM *b;
};

void InnerProduct_Proof_serialize(InnerProduct_Proof &proof, ofstream &fout);

void InnerProduct_Proof_deserialize(InnerProduct_Proof &proof, ifstream &fin);

void InnerProduct_PP_print(InnerProduct_PP &pp);

void InnerProduct_Witness_print(InnerProduct_Witness &witness);

void InnerProduct_Instance_print(InnerProduct_Instance &instance);

void InnerProduct_Proof_print(InnerProduct_Proof &proof);

void InnerProduct_PP_new(InnerProduct_PP &pp, size_t VECTOR_LEN);

void InnerProduct_PP_free(InnerProduct_PP &pp);

void InnerProduct_Instance_new(InnerProduct_Instance &instance);

void InnerProduct_Instance_free(InnerProduct_Instance &instance);

void InnerProduct_Witness_new(InnerProduct_Witness &witness, uint64_t VECTOR_LEN);

void InnerProduct_Witness_free(InnerProduct_Witness &witness);

void InnerProduct_Proof_new(InnerProduct_Proof &proof);

void InnerProduct_Proof_free(InnerProduct_Proof &proof);

/* compute the jth bit of a big integer i (count from little endian to big endian) */
inline uint64_t BN_parse_binary(BIGNUM *BN_i, uint64_t j)
{
	BIGNUM *BN_bit = BN_new();
	BN_copy(BN_bit, BN_i);

	BN_rshift(BN_bit, BN_bit, j);
	BN_mod(BN_bit, BN_bit, BN_2, bn_ctx);

	uint64_t bit;
	if (BN_is_one(BN_bit)) bit = 1;
	else bit = 0;
	BN_free(BN_bit);
	return bit;
}


/* compute the jth bit of a small integer num \in [0, 2^{m-1}] (count from big endian to little endian) */
inline uint64_t int_parse_binary(size_t num, size_t j, size_t m)
{
	size_t cursor = 1 << (m - 1); // set cursor = 2^{m-1} = 1||0...0---(m-1)

	for (auto i = 0; i < j; i++)
	{
		cursor = cursor >> 1;
	}
	if ((num & cursor) != 0) return 1;
	else return 0;
}

/* generate a^n = (a^0, a^1, a^2, ..., a^{n-1}) */
inline void BN_vec_gen_power(vector<BIGNUM *> &result, BIGNUM *&a)
{
	BN_one(result[0]); // set result[0] = 1
	for (auto i = 1; i < result.size(); i++)
	{
		BN_mod_mul(result[i], a, result[i - 1], order, bn_ctx); // result[i] = result[i-1]*a % order
	}
}

/* assign left or right part of a Zn vector */
inline void BN_vec_assign(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, string selector)
{
	size_t start_index;
	if (selector == "left") start_index = 0;
	if (selector == "right") start_index = vec_a.size() / 2;

	for (auto i = 0; i < result.size(); i++)
	{
		BN_copy(result[i], vec_a[start_index + i]);
	}
}

// assign left or right part of an ECn vector
inline void ECP_vec_assign(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_g, string selector)
{
	size_t start_index;
	if (selector == "left") start_index = 0;
	if (selector == "right") start_index = vec_g.size() / 2;

	for (auto i = 0; i < result.size(); i++)
	{
		EC_POINT_copy(result[i], vec_g[start_index + i]);
	}
}

/* sum_i^n a[i]*b[i] */
inline void BN_vec_inner_product(BIGNUM *&result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
	BN_zero(result); // set result = 0

	BIGNUM *product = BN_new();

	if (vec_a.size() != vec_b.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}
	for (auto i = 0; i < vec_a.size(); i++)
	{
		BN_mul(product, vec_a[i], vec_b[i], bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
		BN_add(result, result, product);     // result = (result+product) mod order
	}
	BN_mod(result, result, order, bn_ctx);
}

/* g[i] = g[i]+h[i] */
inline void ECP_vec_add(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, vector<EC_POINT *> &vec_B)
{
	if (vec_A.size() != vec_B.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}
	for (auto i = 0; i < vec_A.size(); i++)
	{
		EC_POINT_add(group, result[i], vec_A[i], vec_B[i], bn_ctx);
	}
}

/* a[i] = (a[i]+b[i]) mod order */
inline void BN_vec_add(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
	if (vec_a.size() != vec_b.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}
	for (auto i = 0; i < vec_a.size(); i++)
	{
		BN_mod_add(result[i], vec_a[i], vec_b[i], order, bn_ctx);
	}
}

/* a[i] = (a[i]-b[i]) mod order */
inline void BN_vec_sub(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
	if (vec_a.size() != vec_b.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}
	for (auto i = 0; i < vec_a.size(); i++)
	{
		BN_mod_sub(result[i], vec_a[i], vec_b[i], order, bn_ctx);
	}
}

/* c[i] = a[i]*b[i] mod order */
inline void BN_vec_product(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
	if (vec_a.size() != vec_b.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}

	for (auto i = 0; i < vec_a.size(); i++)
	{
		BN_mod_mul(result[i], vec_a[i], vec_b[i], order, bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
	}
}

/* compute the inverse of a[i] */
inline void BN_vec_inverse(vector<BIGNUM *> &vec_a_inverse, vector<BIGNUM *> &vec_a)
{
	for (auto i = 0; i < vec_a.size(); i++)
	{
		BN_mod_inverse(vec_a_inverse[i], vec_a[i], order, bn_ctx);
	}
}

/* vec_g = c * vec_g */
inline void ECP_vec_scalar(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, BIGNUM *&c)
{
	for (auto i = 0; i < vec_A.size(); i++)
	{
		EC_POINT_mul(group, result[i], NULL, vec_A[i], c, bn_ctx); // result[i] = vec_g[i]^c
	}
}

/* result[i] = c * a[i] */
inline void BN_vec_scalar(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, BIGNUM *&c)
{
	for (auto i = 0; i < vec_a.size(); i++)
	{
		BN_mod_mul(result[i], vec_a[i], c, order, bn_ctx);
	}
}

/* result[i] = -result[i] */
inline void BN_vec_negative(vector<BIGNUM *> &result)
{
	for (auto i = 0; i < result.size(); i++)
	{
		BN_mod_negative(result[i]);
	}
}

/* result[i] = A[i]*a[i] */
inline void ECP_vec_product(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, vector<BIGNUM *> &vec_a)
{
	if (vec_A.size() != vec_a.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}
	for (auto i = 0; i < vec_A.size(); i++)
	{
		EC_POINT_mul(group, result[i], NULL, vec_A[i], vec_a[i], bn_ctx);
	}
}

/* result = sum_{i=1^n} a[i]*A[i] */
inline void ECP_vec_mul(EC_POINT *&result, vector<EC_POINT *> &vec_A, vector<BIGNUM *> &vec_a)
{
	if (vec_A.size() != vec_a.size())
	{
		cout << "vector size does not match!" << endl;
		exit(EXIT_FAILURE);
	}
	EC_POINTs_mul(group, result, NULL, vec_A.size(),
		(const EC_POINT **)vec_A.data(), (const BIGNUM **)vec_a.data(), bn_ctx);
}

void compute_vec_ss(vector<BIGNUM *> &vec_s, vector<BIGNUM *> &vec_x, vector<BIGNUM *> &vec_x_inverse);

void InnerProduct_Setup(InnerProduct_PP &pp, size_t VECTOR_LEN, bool INITIAL_FLAG);

void InnerProduct_Prove(InnerProduct_PP pp,
	InnerProduct_Instance instance,
	InnerProduct_Witness witness,
	string &transcript_str,
	InnerProduct_Proof &proof);

bool InnerProduct_Verify(InnerProduct_PP &pp,
	InnerProduct_Instance &instance,
	string &transcript_str,
	InnerProduct_Proof &proof);

#endif

