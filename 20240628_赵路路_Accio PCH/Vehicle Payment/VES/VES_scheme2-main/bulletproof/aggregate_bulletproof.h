#ifndef BULLET_H
#define BULLET_H

#include "innerproduct_proof.h"

// define the structure of Bulletproofs
struct Bullet_PP
{
	size_t RANGE_LEN;
	size_t LOG_RANGE_LEN;
	size_t AGG_NUM; // number of sub-argument (for now, we require m to be the power of 2)

	EC_POINT *g, *h;
	EC_POINT *u; // used for inside innerproduct statement
	vector<EC_POINT *> vec_g;
	vector<EC_POINT *> vec_h; // the pp of innerproduct part    
};

struct Bullet_Instance
{
	vector<EC_POINT *> C;  // Ci = g^ri h^vi
};

struct Bullet_Witness
{
	vector<BIGNUM *> r; // r = twisted elgamal encryption's random value beta
	vector<BIGNUM *> v; // v = signature.s
};

struct Bullet_Proof
{
	EC_POINT *A, *S, *T1, *T2;
	BIGNUM *taux, *mu, *tx;
	InnerProduct_Proof ip_proof;
};

void Bullet_Proof_print(Bullet_Proof &proof);

void Bullet_Proof_serialize(Bullet_Proof &proof, ofstream &fout);

void Bullet_Proof_deserialize(Bullet_Proof &proof, ifstream &fin);

void Bullet_PP_new(Bullet_PP &pp, size_t &RANGE_LEN, size_t &AGG_NUM);

void Bullet_PP_free(Bullet_PP &pp);

void Bullet_Witness_new(Bullet_PP &pp, Bullet_Witness &witness);

void Bullet_Witness_free(Bullet_Witness &witness);

void Bullet_Instance_new(Bullet_PP &pp, Bullet_Instance &instance);

void Bullet_Instance_free(Bullet_Instance &instance);

void Bullet_Proof_new(Bullet_Proof &proof);

void Bullet_Proof_free(Bullet_Proof &proof);

void Bullet_Setup(Bullet_PP &pp, size_t &RANGE_LEN, size_t &AGG_NUM);

void Bullet_Setup(Bullet_PP &pp, size_t &RANGE_LEN, size_t &AGG_NUM, uint8_t *hx, uint8_t hy);

void Bullet_Prove(Bullet_PP &pp, Bullet_Instance &instance, Bullet_Witness &witness,
	string &transcript_str, Bullet_Proof &proof);

bool Bullet_Verify(Bullet_PP &pp, Bullet_Instance &instance, string &transcript_str, Bullet_Proof &proof);

#endif