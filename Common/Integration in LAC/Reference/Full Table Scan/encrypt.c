#include <string.h>
#include "api.h"
#include "rand.h"
#include "bch.h"
#include "ecc.h"
#include "bin-lwe.h"

#define RATIO 125

//key generation
int crypto_encrypt_keypair( unsigned char *pk, unsigned char *sk)
{
	//check parameter
	if(pk==NULL || sk==NULL)
	{
		return -1;
	}
	kg(pk,(char *)sk);
	
	return 0;
}

//encryption
int crypto_encrypt( unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *pk)
{
	//check parameter
	if(c==NULL || m==NULL || pk==NULL)
	{
		return -1;
	}
	if(mlen>MESSAGE_LEN)
	{
		return -1;
	}
	
	//call pke encryption function
	pke_enc(pk,m, mlen,c);
	//set ciphertext length
	*clen=CRYPTO_CIPHERTEXTBYTES;

	return 0;
}
//decryption
int crypto_encrypt_open(unsigned char *m, unsigned long long *mlen,const unsigned char *c, unsigned long long clen,const unsigned char *sk)
{
	//check parameter
	if(sk==NULL || m==NULL || c==NULL || mlen==NULL || clen!=CIPHER_LEN)
	{
		return -1;
	}
	if(clen<CIPHER_LEN)
	{
		return -1;
	}
	unsigned char mlen_byte;
	//call pke decryption function
	pke_dec((const char *)sk,c,m,&mlen_byte);
	//set plaintext length
	*mlen=mlen_byte;

	return 0;
}

//key generation with seed
int kg_seed(unsigned char *pk, char *sk, unsigned char *seed)
{
	unsigned char seeds[3*SEED_LEN];
	unsigned char a[DIM_N];
	char e[DIM_N];
	//check pointer
	if(pk==NULL || sk==NULL)
	{
		return -1;
	}
	//generate three seeds for a,sk,e
	pseudo_random_bytes(seeds,3*SEED_LEN,seed);	
	//copy the seed of a to pk
	memcpy(pk,seeds,SEED_LEN);
	//generate a
	gen_a(a,pk);
	//generate  sk,e
	gen_psi(sk,DIM_N,seeds+SEED_LEN);
	gen_psi(e,DIM_N,seeds+2*SEED_LEN);
	//compute pk=a*sk+e
	poly_aff(a,sk,e,pk+SEED_LEN,DIM_N);
	//copy pk=as+e to the second part of sk, now sk=s|pk
	memcpy(sk+DIM_N,pk,PK_LEN);
	return 0;
}

//key generation
int kg(unsigned char *pk, char *sk)
{
	unsigned char seed[SEED_LEN];
	
	//generate seed
	random_bytes(seed,SEED_LEN);		
	//key generation with seed 
	kg_seed(pk,sk,seed);	
	
	return 0;
}
// encryption
int pke_enc(const unsigned char *pk, const unsigned char *m, unsigned char mlen, unsigned char *c)
{
	unsigned char seed[SEED_LEN];
	
	//generate seed
	random_bytes(seed,SEED_LEN);
	//encrypt with seed 
	pke_enc_seed(pk,m,mlen,c,seed);	

	return 0;
}
// decrypt
int pke_dec(const char *sk, const unsigned char *c,unsigned char *m, unsigned char *mlen)
{
	unsigned char out[DIM_N];
	unsigned char code[CODE_LEN];
	unsigned char c2[C2_VEC_NUM];
	int i;
	unsigned char m_buf[MESSAGE_LEN+1];
	
	//check parameter
	if(sk==NULL || m==NULL || c==NULL)
	{
		return -1;
	}
	
	//c2 decompress
	poly_decompress(c+DIM_N,c2,C2_VEC_NUM);
	//c1*sk
	poly_mul(c,sk,out,DIM_N);
	
	//compute c2-c1*sk and recover data from m*q/2+e
	#ifdef LAC256 //D2 decoding
	memset(code,0,CODE_LEN);
	int vec_bound=C2_VEC_NUM/2;
	int temp1,temp2;
	int center_point=Q/2;
	int d2_bound=Q/2;
	
	for(i=0;i<vec_bound;i++)
	{
		//D2 decoding:compute m*q/2+e1 + m*q/2+e2 in [0,2*Q]
		temp1=(c2[i]-out[i]+Q)%Q;
		temp2=(c2[i+vec_bound]-out[i+vec_bound]+Q)%Q;
		
		//shift
		if(temp1<center_point)
		{
			temp1=center_point-temp1+center_point;//mirror around Q/2
		}
		if(temp2<center_point)
		{
			temp2=center_point-temp2+center_point;//mirror around Q/2
		}
		//merge erors
		temp1+=temp2-Q;

		//recover m from m*q/2+e1 + m*q/2+e2, RATIO=q/2
		if(temp1<d2_bound)
		{
			code[i/8]=code[i/8]^(1<<(i%8));
		}
	}
	#else
	int temp;
	int low=Q/4;
	int high=Q*3/4;
	memset(code,0,CODE_LEN);
	
	for(i=0;i<C2_VEC_NUM;i++)
	{
		//compute m*q/2+e in [0,Q]
		temp=(c2[i]-out[i]+Q)%Q;
		
		//recover m from m*q/2+e, RATIO=q/2
		if(temp>=low && temp<high)
		{
			code[i/8]=code[i/8]^(1<<(i%8));
		}
	}
	#endif
	//bch decode to recover m
	ecc_dec(m_buf,code);
	//get mlen
	memcpy(mlen,m_buf,1);
	//check message len
	if(*mlen>MESSAGE_LEN)
	{
		return -1;
	}
	//get plaintext
	memcpy(m,m_buf+1,*mlen);
	
	return 0;
}

// encryption with seed
int pke_enc_seed(const unsigned char *pk, const unsigned char *m, unsigned char mlen, unsigned char *c, unsigned char *seed)
{
	unsigned char code[CODE_LEN],seeds[3*SEED_LEN];
	char r[DIM_N];
	char e1[DIM_N],e2[C2_VEC_NUM];
	unsigned char c2[C2_VEC_NUM];
	unsigned char a[DIM_N];
	unsigned char m_buf[MESSAGE_LEN+1];
	int i;
	
	//check parameter
	if(pk==NULL || m==NULL || c==NULL )
	{
		return -1;
	}
	if(mlen>MESSAGE_LEN)
	{
		return -1;
	}
	
	//generate  a from seed in the first part of pk
	gen_a(a,pk);
	//package m_buf
	memset(m_buf,0,MESSAGE_LEN+1);
	memcpy(m_buf,&mlen,1);
	memcpy(m_buf+1,m,mlen);
	//encode m with ecc code
	ecc_enc(m_buf,code);
	//generate three seeds for r,e1,e2
	pseudo_random_bytes(seeds,3*SEED_LEN,seed);
	//generate random vector r
	gen_psi(r,DIM_N,seeds);
	//generate error vector e1
	gen_psi(e1,DIM_N,seeds+SEED_LEN);
	//compute c1=a*r+e1
	poly_aff(a,r,e1,c,DIM_N);
	
	//generate error vector e2
	gen_psi(e2,C2_VEC_NUM,seeds+2*SEED_LEN);
	//D2 encoding
	#ifdef LAC256
	int vec_bound=C2_VEC_NUM/2;
	char message;
	//compute  code*q/2+e2, 
	for(i=0;i<vec_bound;i++)
	{
		//RATIO=q/2. add code*q/2 to e2
		message=RATIO*((code[i/8]>>(i%8))&1);
		e2[i]=e2[i]+message;
		//D2 encode, repeat at i+vec_bound
		e2[i+vec_bound]=e2[i+vec_bound]+message;
	}

	#else
	//compute  code*q/2+e2, 
	for(i=0;i<C2_VEC_NUM;i++)
	{
		//RATIO=q/2. add code*q/2 to e2
		e2[i]=e2[i]+RATIO*((code[i/8]>>(i%8))&1);
	}
	#endif
	//c2=b*r+e2+m*[q/2]
	poly_aff(pk+SEED_LEN,r,e2,c2,C2_VEC_NUM);
	//compress c2
	poly_compress(c2,c+DIM_N,C2_VEC_NUM);

	return 0;
}

