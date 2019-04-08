/*
 * Based on original BCH library by Ivan Djelic. 
 *
*/
# define _BSD_SOURCE
# include <stdint.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include "bch.h"
# include "ecc.h"
# define MODULE_LICENSE(s)
# define MODULE_AUTHOR(s)
# define MODULE_DESCRIPTION(s)
# define EXPORT_SYMBOL_GPL(x)
# define GFP_KERNEL
# define kmalloc(size, flags) malloc(size)
# define kzalloc(size, flags) memset(malloc(size), 0, size)
# define kfree(ptr) free(ptr)
# define DIV_ROUND_UP(a, b) ((a + b - 1) / b)
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))
# define cpu_to_be32(x) htobe32(x)
# define fls(x) ({ \
	unsigned int __tmp = x; \
	unsigned int __count = 0; \
	while (__tmp >>= 1) \
		__count++; \
	__count + 1; \
})

#define EINVAL  100
#define EBADMSG 74
#if defined(CONFIG_BCH_CONST_PARAMS)
#define GF_M(_p)               (CONFIG_BCH_CONST_M)
#define GF_T(_p)               (CONFIG_BCH_CONST_T)
#define GF_N(_p)               ((1 << (CONFIG_BCH_CONST_M))-1)
#else
#define GF_M(_p)               ((_p)->m)
#define GF_T(_p)               ((_p)->t)
#define GF_N(_p)               ((_p)->n)
#endif

#define BCH_ECC_WORDS(_p)      DIV_ROUND_UP(GF_M(_p)*GF_T(_p), 32)
#define BCH_ECC_BYTES(_p)      DIV_ROUND_UP(GF_M(_p)*GF_T(_p), 8)

#ifndef dbg
#define dbg(_fmt, args...)     do {} while (0)
#endif

#include <x86intrin.h>
#include <inttypes.h>

#if defined(LAC128)
//bch(511,385,29)
#include "bch128.h"
#endif

#if defined(LAC192)
//bch(511,457,13)
#include "bch192.h"
#endif

#if defined(LAC256)
//D2+bch(511,376,31)
#include "bch256.h"
#endif

unsigned int mod_val;

/*
 * same as encode_bch(), but process input data one byte at a time
 */
static void encode_bch_unaligned_constant(
				 const unsigned char *data, unsigned int len,
				 uint32_t *ecc)
{
	int i, max_len = 3, lenFlag;
	const uint32_t *p;
	const int l = (MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32 -1;
	unsigned int mask = 0x80000000;

	while (max_len--) {
		lenFlag = (int)(((max_len - len) & mask) >> 31); // if max_len < len, execute.
		
		p = mod8_tab + (l+1)*(((ecc[0] >> 24)^(*data)) & 0xff);
		data += (1 * lenFlag);
		
		for (i = 0; i < l; i++) {
			ecc[i] = (((ecc[i] << 8)|(ecc[i+1] >> 24))^(*p++)) * lenFlag + ecc[i] * !lenFlag;
			p -= (1 * !lenFlag);
		}

		ecc[l] = ((ecc[l] << 8)^(*p)) * lenFlag + ecc[l] * !lenFlag;
	}
}

/*
* Constant-time copy of arrays with 8-bit elements.
*/
void cmov_8(uint8_t *r, const uint8_t *x, size_t len, unsigned char executeFlag)
{
	size_t i;
  	executeFlag = -executeFlag;
  
  	for(i=0; i < len; i++) {
  		*(r+i) ^= executeFlag & (x[i] ^ *(r+i));
  }
}

/*
* Constant-time copy of arrays with 32-bit elements.
*/
void cmov_32(uint32_t *r, uint32_t *x, size_t len, unsigned char executeFlag)
{
	size_t i;
  	executeFlag = -executeFlag;
  
  	for(i=0; i < len; i++) {
  		*(r+i) ^= executeFlag & (x[i] ^ *(r+i));
  }
}

/*
 * convert ecc bytes to aligned, zero-padded 32-bit ecc words
 */
static void load_ecc8(uint32_t *dst,
		      const uint8_t *src)
{
	uint8_t pad[4] = {0, 0, 0, 0};
	unsigned int i, nwords = (MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32 -1, nbytes = (MAX_ERROR * LOG_CODE_LEN + 8 - 1) / 8;

	for (i = 0; i < nwords; i++, src += 4)
		dst[i] = (src[0] << 24)|(src[1] << 16)|(src[2] << 8)|src[3];

	cmov_8(pad,src,(nbytes-4*nwords),1);
	dst[nwords] = (pad[0] << 24)|(pad[1] << 16)|(pad[2] << 8)|pad[3];
}

/*
 * convert 32-bit ecc words to ecc bytes
 */
static void store_ecc8(uint8_t *dst,
		       const uint32_t *src)
{
	uint8_t pad[4];
	unsigned int i, nwords = (MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32 -1, nbytes = (MAX_ERROR * LOG_CODE_LEN + 8 - 1) / 8;

	for (i = 0; i < nwords; i++) {
		*dst++ = (src[i] >> 24);
		*dst++ = (src[i] >> 16) & 0xff;
		*dst++ = (src[i] >>  8) & 0xff;
		*dst++ = (src[i] >>  0) & 0xff;
	}
	pad[0] = (src[nwords] >> 24);
	pad[1] = (src[nwords] >> 16) & 0xff;
	pad[2] = (src[nwords] >>  8) & 0xff;
	pad[3] = (src[nwords] >>  0) & 0xff;
	cmov_8(dst,pad,nbytes-4*nwords,1);
}

/*
* Encode BCH data to calculate error-correcting parity.
*/
void encode_bch(uint32_t *ecc_buf, const uint8_t *data,
		unsigned int len, uint8_t *ecc)
{
	const unsigned int  l = (MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32 -1;
	unsigned int i, mlen;
	unsigned long m;
	uint32_t w, r[l+1];
	const uint32_t * const tab0 = mod8_tab;
	const uint32_t * const tab1 = tab0 + 256*(l+1);
	const uint32_t * const tab2 = tab1 + 256*(l+1);
	const uint32_t * const tab3 = tab2 + 256*(l+1);
	const uint32_t *pdata, *p0, *p1, *p2, *p3;

	unsigned int mask = 0x80000000, max_len;
	int mFlag, mlenFlag, maxlenFlag, flag;
	
	memset(ecc_buf, 0, sizeof(r));

	/* process first unaligned data bytes */
	m = ((unsigned long)data) & 3;
	mFlag = (int)(((0 - m) & mask) >> 31); // if m > 0
	mlenFlag = (int)(((len - (4-m)) & mask) >> 31); // if len < (4-m)
	mlen = len * mlenFlag + (4-m) * mlenFlag; 
	encode_bch_unaligned_constant(data, mlen * mFlag, ecc_buf);
	data += (mlen * mFlag);
	len  -= (mlen * mFlag);

	/* process 32-bit aligned data words */
	pdata = (uint32_t *)data;
	mlen  = len/4;
	max_len = DATA_LEN / 4;
	data += 4*mlen;
	len  -= 4*mlen;

	for(i = 0; i < l+1; i++)
		r[i] ^= (r[i] ^ ecc_buf[i]);
	
	/*
	 * split each 32-bit word into 4 polynomials of weight 8 as follows:
	 *
	 * 31 ...24  23 ...16  15 ... 8  7 ... 0
	 * xxxxxxxx  yyyyyyyy  zzzzzzzz  tttttttt
	 *                               tttttttt  mod g = r0 (precomputed)
	 *                     zzzzzzzz  00000000  mod g = r1 (precomputed)
	 *           yyyyyyyy  00000000  00000000  mod g = r2 (precomputed)
	 * xxxxxxxx  00000000  00000000  00000000  mod g = r3 (precomputed)
	 * xxxxxxxx  yyyyyyyy  zzzzzzzz  tttttttt  mod g = r0^r1^r2^r3
	 */
	while (max_len--) {
		maxlenFlag = (int)(((max_len - mlen) & mask) >> 31); // if max_len < mlen, execute.
		/* input data is read in big-endian format */
		w = r[0]^cpu_to_be32(*pdata);
		pdata += (1 * maxlenFlag);
		p0 = tab0 + (l+1)*((w >>  0) & 0xff);
		p1 = tab1 + (l+1)*((w >>  8) & 0xff);
		p2 = tab2 + (l+1)*((w >> 16) & 0xff);
		p3 = tab3 + (l+1)*((w >> 24) & 0xff);

		for (i = 0; i < l; i++)
			r[i] = (r[i+1]^p0[i]^p1[i]^p2[i]^p3[i]) * maxlenFlag + r[i] * !maxlenFlag;

		r[l] = (p0[l]^p1[l]^p2[l]^p3[l]) * maxlenFlag + r[l] * !maxlenFlag; 
	}

	for(i =0; i < l+1; i++)
		ecc_buf[i] ^= (r[i] ^ ecc_buf[i]);
		
	/* process last unaligned bytes */
	flag = (int)(((0 - len) & mask) >> 31); // if len > 0
	encode_bch_unaligned_constant(data, len * flag, ecc_buf);

	/* store ecc parity bytes into original parity buffer */
	if (ecc)
		store_ecc8(ecc, ecc_buf);
}

/*
* Full Table Scan read for elp
*/
unsigned int elp_read(unsigned int * arr, size_t size, int index) {
	int i;
	unsigned int a;
	/* Read entire array into cache */
	for(i = 0; i < size; i++) {
		a = arr[i];
	}
	a = arr[index]; // Read from intended value
	return a;
}

/*
* Full Table Scan read for data
*/
uint8_t data_read(uint8_t * arr, size_t size, int index) {
	int i;
	uint8_t a;
	for(i = 0; i < size; i++) {
		a = arr[i];
	}
	a = arr[index];
	return a;
}

/*
* Full Table Scan read for a_pow_tab
*/
uint16_t a_pow_full_table_access(unsigned int index) {
	int i;
	uint16_t a;
	for(i = 0; i < 512; i++) {
		a = a_pow_tab[i];
	}
	a = a_pow_tab[index];
	return a;
}

/*
* Full Table Scan read for a_log_tab
*/
uint16_t a_log_full_table_access(unsigned int index) {
	int i;
	uint16_t a;
	for(i = 0; i < 512; i++) {
		a = a_log_tab[i];
	}
	a = a_log_tab[index];
	return a;
}

/*
* Full Table Scan write for elp
*/
unsigned int elp_write(unsigned int * arr, size_t size, int index, unsigned int val) {
	unsigned int sum = 0;

	int i;
	unsigned int a;
	for(i = 0; i < size; i++) {
		a = arr[i];
	}
	a = index;
	arr[a] = val;
	return(sum);
}

/*
* Full Table Scan write for data
*/
uint8_t data_write(uint8_t * arr, size_t size, int index, uint8_t val) {
	uint8_t sum = 0;

	int i;
	uint8_t a;
	for(i = 0; i < size; i++) {
		a = arr[i];
	}
	a = index;
	arr[a] = val;

	return(sum);
}

/*
* BCH decode part 1 - Syndrome Generation
*/
static void compute_syndromes(uint32_t *ecc, unsigned int *syn)
{
	int i, j, s;
	unsigned int m, bit;
	uint32_t poly;
	const int t = MAX_ERROR;
	int mFlag; 
	unsigned int mask = 0x80000000;
	const unsigned int n = (1 << LOG_CODE_LEN)-1;
	unsigned int synVal;
	unsigned int powVal;
	s = ECC_BITS;

	/* make sure extra bits in last ecc word are cleared */
	m = ((unsigned int)s) & 31;
	mFlag = (int)(((0 - m) & mask) >> 31); // if m > 0
	ecc[s/32] = ecc[s/32] & (~((1u << (32-m))-1) * mFlag + ecc[s/32] * !mFlag);
	memset(syn, 0, 2*t*sizeof(*syn));

	/* compute v(a^j) for j=1 .. 2t-1 */
	do {
		poly = *ecc++;
		s -= 32;
		for(bit = 0; bit < 32; bit++) {
			i = (poly & (1 << bit)) >> bit;
			for (j = 0; j < 2*t; j += 2) {
				syn[j] ^= a_pow_tab[((j+1)*(bit+s) - n * (((j+1)*(bit+s)) / n))] * i;
			}
		}
	} while (s > 0);

	/* v(a^(2j)) = v(a^j)^2 */
	for (j = 0; j < t; j++) {
		synVal = syn[j];
		powVal = 2* a_log_full_table_access(synVal);
		mFlag = (int)(((0 - synVal) & mask) >> 31); // if synVal > 0
		syn[2*j+1] = a_pow_full_table_access(powVal - n * (powVal / n)) * mFlag;
	}
	
}

/*
* BCH decode part 2 - Error-location polynomial calculation
*/
static int compute_error_locator_polynomial(unsigned int *syn2,unsigned int * elp_c, unsigned int *deg)
{
	unsigned int i, j, l, d, read_write_val;
	unsigned int tmp = 0, pd = 1, it = 0, ELP_SIZE = MAX_ERROR + 1, evalVal = 0, mask = 0x80000000, synVal = 0,elpVal = 0, elpDeg = 0, pelpVal = 0, pelpDeg = 0;
	unsigned int pelp_c[2*MAX_ERROR + 1] = {0}, elp_copy_c[2*MAX_ERROR + 1] = {0};
	const unsigned int n = (1 << LOG_CODE_LEN)-1;
	const unsigned int t = MAX_ERROR;
	int k, pp = -1, modu = 0, boundsFlag = 0, dFlag = 0;
	
	/* Flags */
	int v = 0; 
	int x = 0; 
	int a = 0;
	int b = 0;
	int y = 0;

	d = syn2[0];

    pelp_c[0] = 1;
    elp_c[0] = 1;

	elpDeg = 0;
	pelpDeg = 1;

	/* Main SiBMA algorithm */
	for (i = 0; (i < t); i++) {
		b = (int)(((elpDeg - (t + 1)) & mask) >> 31); // b = 1 if elp->deg <= t, setting to 0 means no effect saved, so can make a_pow and a_log 0.
		dFlag = (int)(((0 - d) & mask) >> 31) * b; // is d > 0?
		k = ((2*i) - pp) * dFlag;
		
		/* Copy elp_c to elp_copy_c */
		for(it = 0; it <= t; it++) {
			boundsFlag = (int)(((it - (elpDeg+1)) & mask) >> 31); // boundsFlag = 1 if it < elpDeg+1
		    read_write_val = elp_copy_c[it];
			elp_copy_c[it] = read_write_val ^ (-dFlag & -boundsFlag & (read_write_val ^ elp_c[it]));
		}
		
		/* e[i+1](X) = e[i](X)+di*dp^-1*X^2(i-p)*e[p](X) */
		tmp = (a_log_full_table_access(d) + n - a_log_full_table_access(pd)) * dFlag + tmp * !dFlag ;
		
		for (j = 0; j <= t; j++) {
			x = (int)(((j - (pelpDeg+1)) & mask) >> 31) * dFlag; // x = 1 if j <= pelp->deg
			a = j;
			pelpVal = pelp_c[a];
			v = (((0 - pelpVal) & mask) >> 31) * x; // v = 1 if pelp->c[a] > 0
	
			l = a_log_full_table_access(pelpVal) * v;
			
			modu = (tmp+l) - n * ((tmp+l) / n);
			
			read_write_val = elp_read(elp_c,ELP_SIZE,a+k) ^ (a_pow_full_table_access(modu) * v);
			elp_write(elp_c,ELP_SIZE,a+k,read_write_val);
		}
		
		/* compute l[i+1] = max(l[i]->c[l[p]+2*(i-p)]) */
		tmp = (pelpDeg - 1 + k) * dFlag;
		v = (int)(((elpDeg - tmp) & mask) >> 31) * dFlag; // v = 1 if tmp > elp->deg
		pelpDeg = (elpDeg + 1) * v + pelpDeg * !v;
		
		/* Copy elp_copy_c to pelp_c */
		for(it = 0; it <= t; it++) {
			boundsFlag = (int)(((it - (elpDeg+1)) & mask) >> 31); // boundsFlag = 1 if it < elpDeg+1
			read_write_val = pelp_c[it];
			pelp_c[it] = read_write_val ^ (-v & -boundsFlag & (read_write_val ^ elp_copy_c[it]));
		}
		elpDeg = tmp * v + elpDeg * !v;
		pd = d * v + pd * !v;
		pp = 2*i*v + pp*!v;	
		
		/* d[i+1] = S(2i+3)+elp[i+1].1*S(2i+2)+...+elp[i+1].lS(2i+3-l) */
		a = (int)(((i - (t-1)) & mask) >> 31) * b; // a = 1 if t-1 > i
		// S(2i+3)
		synVal = syn2[2*i+2];
		d = synVal * a + d * !a;
		elpDeg = elpDeg + 1;
		// +elp[i+1}.S(2i+2)+..
		for (j = 1; j <= t; j++) {
			x = (int)(((j - (elpDeg)) & mask) >> 31) * a; // x = 1 if j <= elp->deg
			synVal = elp_read(syn2,2*t,2*i+2-(j*x + 1*!x));
			elpVal = elp_c[j];
			v = (int)(((0 - elpVal) & mask) >> 31); // if(elpVal)
			v = (int)(((0 - synVal) & mask) >> 31) * v; // if(elpVal && synVal)
			v = v * x; // if(elpVal && synVal && j <= elp->deg)
			
			synVal = elp_read(syn2,2*t,2*i+2-(j*x + 1*!x));
			evalVal = a_log_full_table_access(elpVal) + a_log_full_table_access(synVal);
			
			y = (int)(((evalVal - n) & mask) >> 31); // y = 1 if evalVal < GF_N(bch)
			
			d = d ^ a_pow_full_table_access( evalVal - (n * !y ) ) * v;
		}
		elpDeg = elpDeg - 1;
	}
	*deg = elpDeg;
	y = (int)(((t - elpDeg) & mask) >> 31); // y = 1 if elpDeg > t
	return (-1 * y + (int)elpDeg * !y);
}

/*
* BCH decode part 3 - Chien Search
*/
static int chien_search(unsigned int len, unsigned int *p, unsigned int *roots, int d)
{
	int m;
	unsigned int i, j, syn, syn0, count = 0;
	const unsigned int k = 8*len+ECC_BITS;
	const unsigned int n = (1 << LOG_CODE_LEN)-1;
	const unsigned int t = MAX_ERROR;
	int x,v,a,val,z = 0;
	unsigned int pi;
	unsigned int mask = 0x80000000;
	int bch_cache[2*t];

	unsigned int p0 = p[0];
	unsigned int pd = elp_read(p,t+1,d);

	unsigned int log_pd_val = a_log_full_table_access(pd);
	int logVal = a_log_full_table_access(p0) + n - log_pd_val;

	x = (int)(((logVal - n) & mask) >> 31); // x = 1 if val < n
	v = (int)(((0 - p0) & mask) >> 31); // v = 1 if p0 > 0

	syn0 = a_pow_full_table_access(logVal - (n*!x)) * v;
	
	int l = n - log_pd_val;

	/* use a log-based representation of polynomial */
	for (i = 0; i <= t; i++) {
		x = (int)(((i - d) & mask) >> 31); // x = 1 if i < d
		pi = p[i];
		v = (int)(((0 - pi) & mask) >> 31) * x; // v = 1 if p->c[i*x] > 0

        val = a_log_full_table_access(pi)+l;

		val = val - n * (val / n);
		bch_cache[i] = (val * v + -1 * !v) * x + 0 * !x;
	}

	/* Main Algorithm */
	for (i = 1; i <= n; i++) {
		a = (int)(((i - n-k) & mask) >> 31); // if i > n - k

		/* Test each potential a^i */
		for (j = 1, syn = syn0; j <= t; j++) {
			x = (int)(((j - (d + 1)) & mask) >> 31) * !z * a; // x = 1 if j <= d
			m = bch_cache[j];
			v = (int)(((0 - (m+1)) & mask) >> 31) * x; // v = 1 if m >= 0

			val = ((m + j * i)*v) - n * (((m + j * i)*v) / n);
			syn ^= a_pow_full_table_access(val) * v;
		}
		/* Store found roots */
		v = !(int)(((0 - syn) & mask) >> 31) * !z * a; // v = 1 if syn == 0
		elp_write(roots,t,count,n-i);
		count = count + (1 * v);
		z = !((int)((0 - (d - count)) & mask) >> 31) * v;
	}
	z = !((int)((0 - (d - count)) & mask) >> 31);
	return (count * (int)z);
}

/*
* Main BCH Decode Process
*/
int decode_bch_const(uint8_t *data, uint32_t *ecc_buff, unsigned int len)
{	
	// Prep
	unsigned int nbits, mask = 0x80000000, errlocVal, deg = 0;
	int i, err, nroots, flag, flag2, flag3 = 1, t = MAX_ERROR;
	unsigned int elp_c[MAX_ERROR + 1] = {0};
	
	// 1. Compute Syndromes
	unsigned int syn2[2*MAX_ERROR] = {0};

	compute_syndromes(ecc_buff, syn2);

	// 2. Compute Error Location Polynomial
	err = compute_error_locator_polynomial(syn2,elp_c,&deg);

	// 3. Error correction.
	unsigned int errloc[t];
	
    nroots = chien_search(1,elp_c,errloc,deg);
    
	flag = ((int)((0 - (nroots-err)) & mask) >> 31); // 0 if err == nroots, 1 otherwise.
	err = -1 * flag + err * !flag;

	/* post-process raw error locations for easier correction */
	nbits = (len*8)+ECC_BITS;
	for (i = 0; i < t; i++) {
		flag = (int)(((i - err) & mask) >> 31) * flag3;	// 1 if i < err and dont break.
		errlocVal = errloc[i];
		flag2 = (int)(((nbits - (errlocVal+1)) & mask) >> 31) * flag; // 1 if errloc[i] >= nbits
		err = -1 * flag2 + err * !flag2;
		flag3 = flag3 * !flag2; // 1 if errloc[i] < nbits (dont break), 0 otherwise

		flag = flag * flag3; // if i < err and !break (flag3)

		errlocVal = (nbits-1-errlocVal) * flag + errlocVal * !flag;
		errlocVal = ((errlocVal & ~7)|(7-(errlocVal & 7))) * flag + errlocVal * !flag;
		errloc[i] = errlocVal;
	}

	uint8_t dataVal;
	unsigned int modVal;
	for (i=0;i<t;i++)
	{
		flag = (int)(((i - err) & mask) >> 31);	// 1 if i < err
		errlocVal = errloc[i];
		flag2 = (int)(((errlocVal - (DATA_LEN*8)) & mask) >> 31) * flag; // 1 if errloc[i] < DATA_LEN*8
		dataVal = data_read(data,MAX_ERROR+1,(errlocVal*flag2 + 1*!flag2)/8);
		modVal = (errlocVal) - 8 * (errlocVal / 8);
		dataVal = dataVal ^ ((1 << modVal) * flag2);
		data_write(data,MAX_ERROR+1,(errlocVal*flag2 + 1*!flag2)/8,dataVal);
	}

	// Return
	flag = (int)(((0 - (err+1)) & mask) >> 31); // 1 if err >= 0
	return err * flag + (-EBADMSG) * !flag;
}

void prepare_ecc_buff(uint32_t *ecc_buff, const uint8_t *recv_ecc)
{
	const unsigned int ecc_words = (MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32;
	uint32_t sum;
	int i;
	uint32_t ecc_buff_2[ecc_words];	
	uint32_t eccVal;
	
	// Prep
	load_ecc8(ecc_buff_2, recv_ecc);
	/* XOR received and calculated ecc */
	for (i = 0, sum = 0; i < (int)ecc_words; i++) {
		eccVal = ecc_buff[i] ^ ecc_buff_2[i];
		ecc_buff[i] = eccVal;
		sum |= eccVal;
	}
}
