#include <stdio.h>
#include <string.h>
#include <x86intrin.h>
#include "api.h"
#include "rand.h"
#include "ecc.h"
#include "bin-lwe.h"

#define NTESTS 10000
#define EXTRA_TESTS 2000
#define cpucycles() _rdtsc()
unsigned long long sum,average;

unsigned long long kem_result = 0, kem_fo_result = 0, ke_result = 0, ake_result = 0;

static void print_uint64(unsigned long long num)
{
	if(num>=10)
		print_uint64(num/10);
	printf("%d",(int)(num%10));
}

static void print_uint64_file(FILE *fp, unsigned long long num)
{
	if(num>=10)
		print_uint64_file(fp,num/10);
	fprintf(fp,"%d",(int)(num%10));
}

void print_results()
{
	FILE *fp0;
	if((fp0=fopen("lac_results.csv", "a"))==NULL) {
		printf("Cannot open file.\n");
		exit(1);
	}
	print_uint64_file(fp0,kem_result);
	fprintf(fp0,",");
	print_uint64_file(fp0,kem_fo_result);
	fprintf(fp0,",");
	print_uint64_file(fp0,ke_result);
	fprintf(fp0,",");
	print_uint64_file(fp0,ake_result);
	fprintf(fp0,"\n");
	fclose(fp0);
}

int calc_equiv(unsigned long long num)
{
	if(num >= 10)
		calc_equiv(num/10);
	return (int)(num % 10);
}

int print_cpucycles(unsigned long long *t)
{
	int i;
	sum=0;
	for(i=0;i<NTESTS-1;i++)
	{
		t[i]=t[i+1]-t[i];
		sum+=t[i];
	}
	average=sum/(NTESTS-1);
	printf(": ");
	print_uint64(average);
    printf(" cpucycles\n");
	
	return 0;
}

int calc_average(unsigned long long *t)
{
	int i;
	sum=0;
	for(i=0;i<NTESTS-1;i++)
	{
		t[i]=t[i+1]-t[i];
		sum+=t[i];
	}
	average=sum/(NTESTS-1);
	return average;
}

//test pke
int test_pke_cpucycles()
{
	unsigned long long t[NTESTS];
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char k1[CRYPTO_BYTES],k2[CRYPTO_BYTES],c[CRYPTO_CIPHERTEXTBYTES];
	int i;
	unsigned long long mlen=CRYPTO_BYTES,clen=CRYPTO_CIPHERTEXTBYTES;

	crypto_encrypt_keypair(pk,sk);
	
	crypto_encrypt_keypair(pk,sk);
	random_bytes(k1,CRYPTO_BYTES);

	crypto_encrypt(c,&clen,k1,mlen,pk);
	
	crypto_encrypt_keypair(pk,sk);
	random_bytes(k1,CRYPTO_BYTES);
	crypto_encrypt(c,&clen,k1,mlen,pk);
	
    for(i=0;i<NTESTS + EXTRA_TESTS;i++)
	{
		if(i >= EXTRA_TESTS) t[i - EXTRA_TESTS] = cpucycles();
		crypto_encrypt_open(k2,&mlen,c,clen,sk);
	}
	
    kem_result = calc_average(t);
	
	return 0;
}

//test kem fo
int test_kem_fo_cpucycles()
{
	unsigned long long t[NTESTS];
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char k1[CRYPTO_BYTES],k2[CRYPTO_BYTES],c[CRYPTO_CIPHERTEXTBYTES];
	int i;
	
	crypto_kem_keypair(pk,sk);
	
	crypto_kem_keypair(pk,sk);
	random_bytes(k1,CRYPTO_BYTES);
	
	crypto_kem_enc(c,k1,pk);
	
	crypto_kem_keypair(pk,sk);
	crypto_kem_enc(c,k1,pk);
	
	for(i=0;i<NTESTS+EXTRA_TESTS;i++)
	{
		if(i >= EXTRA_TESTS) t[i - EXTRA_TESTS] = cpucycles();
		crypto_kem_dec(k2,c,sk);
	}
	
    kem_fo_result = calc_average(t);
	
	return 0;
}

// test ke
int test_ke_cpucycles()
{
	unsigned long long t[NTESTS];
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char k1[CRYPTO_BYTES],k2[CRYPTO_BYTES],c[CRYPTO_CIPHERTEXTBYTES];
	int i;
	
	crypto_ke_alice_send(pk,sk);
	
	crypto_ke_bob_receive(pk,c,k1);

	//test alilce send
    for(i=0;i<NTESTS+EXTRA_TESTS;i++)
	{
		if(i >= EXTRA_TESTS) t[i - EXTRA_TESTS] = cpucycles();
		crypto_ke_alice_receive(pk,sk,c,k2);
	}
	
    ke_result = calc_average(t);
	
	return 0;
}

// test ake
int test_ake_cpucycles()
{
	unsigned long long t[NTESTS];
	unsigned char pk_a[CRYPTO_PUBLICKEYBYTES],pk_b[CRYPTO_PUBLICKEYBYTES],pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES],sk_a[CRYPTO_SECRETKEYBYTES],sk_b[CRYPTO_SECRETKEYBYTES];
	unsigned char k_a[CRYPTO_BYTES],k_b[CRYPTO_BYTES],c_a[CRYPTO_CIPHERTEXTBYTES],c_b[2*CRYPTO_CIPHERTEXTBYTES],k1[CRYPTO_BYTES];
	int i;
	
	crypto_encrypt_keypair(pk_a,sk_a);
	crypto_encrypt_keypair(pk_b,sk_b);
	
	//test alilce send
	crypto_ake_alice_send(pk,sk,pk_b,sk_a,c_a,k1);

	crypto_ake_bob_receive(pk_b,sk_b,pk_a,pk,c_a,c_b,k_b);
	
	
	//test alilce send
    for(i=0;i<NTESTS+EXTRA_TESTS;i++)
	{
		if(i >= EXTRA_TESTS) t[i - EXTRA_TESTS] = cpucycles();
		crypto_ake_alice_receive(pk_a,sk_a,pk_b,pk,sk,c_a,c_b,k1,k_a);
	}
	
    ake_result = calc_average(t);

	return 0;
}

// test  hash
int test_hash_cpucycles()
{
	int i,len=1024,loop=100000;
	unsigned char buf[len],seed[SEED_LEN],out[MESSAGE_LEN];
	uint64_t t0,t1;
	random_bytes(seed,SEED_LEN);
	pseudo_random_bytes(buf,len,seed);
	t0=__rdtsc();
	for(i=0;i<loop;i++)
	{
		hash(buf,len,out);
	}
	t1=__rdtsc();
	printf("test hash speed:\n");
//	printf("time: %f us\n",(t1-t0)/(2800.0*loop));
	printf("cpucycles: %f \n",(t1-t0)/((double)loop));
	printf("CPB: %f \n",(t1-t0)/((double)loop*len));
	printf("\n");
	
	return 0;
}

// test aes
int test_aes_cpucycles()
{
	int i,len=512,loop=100000;
	unsigned char buf[len],seed[SEED_LEN];
	uint64_t t0,t1;
	random_bytes(seed,SEED_LEN);
	t0=__rdtsc();
	for(i=0;i<loop;i++)
	{
		pseudo_random_bytes(buf,len,seed);
	}
	t1=__rdtsc();
	printf("test aes speed:\n");
//	printf("time: %f us\n",(t1-t0)/(2800.0*loop));
	printf("cpucycles: %f \n",(t1-t0)/((double)loop));
	printf("CPB: %f \n",(t1-t0)/((double)loop*len));
	printf("\n");
	
	return 0;
}

//test gen_psi
int test_gen_psi_cpucycles()
{
	int i,loop=100000;
	unsigned char seed[SEED_LEN];
	char e[DIM_N];
	uint64_t t0,t1;
	random_bytes(seed,SEED_LEN);
	t0=__rdtsc();
	for(i=0;i<loop;i++)
	{
		gen_psi(e,DIM_N,seed);
	}
	t1=__rdtsc();
	printf("test gen_psi speed:\n");
//	printf("time: %f us\n",(t1-t0)/(2800.0*loop));
	printf("cpucycles: %f \n",(t1-t0)/((double)loop));
	printf("\n");
	
	return 0;
}

//test gen_a
int test_gen_a_cpucycles()
{
	int i,loop=100000;
	unsigned char seed[SEED_LEN];
	unsigned char a[DIM_N];
	uint64_t t0,t1,sum;
	random_bytes(seed,SEED_LEN);
	sum=0;
	for(i=0;i<loop;i++)
	{
		t0=__rdtsc();
		gen_a(a,seed);
		t1=__rdtsc();
		sum+=(t1-t0);
	}
	
	printf("test gen_a speed:\n");
//	printf("time: %f us\n",(sum)/(2800.0*loop));
	printf("cpucycles: %f \n",(sum)/((double)loop));
	printf("\n");
	
	return 0;
}

//test polymul
int test_poly_mul_cpucycles()
{
	int i,loop=100000;
	unsigned char a[DIM_N],pk[DIM_N],seed[SEED_LEN];
	char sk[DIM_N];
	uint64_t t0,t1,sum;
	
	random_bytes(a,DIM_N);
	random_bytes(seed,SEED_LEN);
	gen_psi(sk,DIM_N,seed);
	sum=0;
	for(i=0;i<loop;i++)
	{
		t0=__rdtsc();
		poly_mul(a,sk,pk,DIM_N);
		t1=__rdtsc();
		sum+=(t1-t0);
	}
	
	printf("test poly_nul speed:\n");
//	printf("time: %f us\n",(sum)/(2800.0*loop));
	printf("cpucycles: %f \n",(sum)/((double)loop));
	printf("\n");
	
	return 0;
}
