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
# define cpu_to_be32(x) (x)
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

//#include <x86intrin.h>
#include <inttypes.h>
//#define cpucycles() _rdtsc()

#if defined(LAC128)
//bch(511,256,61)
#include "bch128.h"
#endif

#if defined(LAC192)
//bch(511,384,29)
#include "bch192.h"
#endif

#if defined(LAC256)
//bch(1023,512,115)
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
	int i;
	const uint32_t *p;
	const int l = (MAX_ERROR * LOG_CODE_LEN + 32 - 1) / 32 -1;
	
	int max_len = 3, lenFlag;
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
* Replace htobe32() function
*/
uint32_t swap(uint32_t data) {
	return (((data>>24)&0xff)|((data<<8)&0xff0000)|((data>>8)&0xff00)|((data<<24)&0xff000000));
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

	for(unsigned int i = 0; i < l+1; i++)
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
		w = r[0]^swap(*pdata);
		pdata += (1 * maxlenFlag);
		p0 = tab0 + (l+1)*((w >>  0) & 0xff);
		p1 = tab1 + (l+1)*((w >>  8) & 0xff);
		p2 = tab2 + (l+1)*((w >> 16) & 0xff);
		p3 = tab3 + (l+1)*((w >> 24) & 0xff);

		for (i = 0; i < l; i++)
			r[i] = (r[i+1]^p0[i]^p1[i]^p2[i]^p3[i]) * maxlenFlag + r[i] * !maxlenFlag;

		r[l] = (p0[l]^p1[l]^p2[l]^p3[l]) * maxlenFlag + r[l] * !maxlenFlag; 
	}

	for(unsigned int i =0; i < l+1; i++)
		ecc_buf[i] ^= (r[i] ^ ecc_buf[i]);
		
	/* process last unaligned bytes */
	flag = (int)(((0 - len) & mask) >> 31); // if len > 0
	encode_bch_unaligned_constant(data, len * flag, ecc_buf);

	/* store ecc parity bytes into original parity buffer */
	if (ecc)
		store_ecc8(ecc, ecc_buf);
}

// one entry contains 7 consecutive entries of a_pow_tab.
uint32_t a_pow_tab_packed[] =
{1049601,8396808,67174464,17843217,12984456,102860898,9971457,79769676,118604913,22955929,44480686,94989138,68621509,28339227,96952536,125291763,41848747,57203518,59700148,78592966,74521671,43033641,67699528,22041621,46571688,111782754,81344325,131200125,123717625,54452159,19815326,19290262,23480466,57067698,65989554,128973814,79642567,82918479,110208105,85542745,26637469,82258122,103910499,1574665,12595212,100761696,26765073,75968716,87116883,14034057,111257706,77145921,97612893,131589369,125816827,37658543,23616286,50778292,15608706,123852918,48146337,107584366,47757093,105485164,64550709,101684204,33062679,126349564,100626387,112704751,70848331,13644813,109158504,93939537,93811933,100101339,116894955,104435563,5773069,46182444,109683552,98137941,127399165,92229595,45530287,86592346,1447045,10496010,83968080,22430865,48670890,128576370,77543365,99712095,114795753,121229179,1972109,14694414,117555312,31352721,111655150,79245123,80819277,127001721,90130393,62323903,91179994,37133479,19417882,17191060,6686850,52480050,30303120,103258342,12070659,96563292,123192561,58642363,53402558,28212118,86464726,7736451,60876858,97477584,121101559,8261515,65075262,131064816,130023415,71245775,15744015,125952120,98527185,129498367,75435979,49331247,118080376,27162517,78067918,70323267,9446409,75571272,85017681,30827673,115845354,112832355,72947533,64025661,105874408,66649911,118477820,29261719,94861534,74910915,45132843,84493144,18240661,15083658,119654514,14559105,115456110,110733153,89741149,60224701,74386378,40934439,50905912,9319300,73472070,34636833,264,1};
 

// one entry contains 7 consecutive entries of a_log_tab.
uint32_t a_log_tab_packed[] =
{262144,68158594,935043,61737892,76393092,2361734,68691877,90036293,56268933,95832103,1504135,131864059,5409702,16650223,62364742,106344617,87301254,39169675,77053480,46325209,99316616,86248647,3097596,15987158,85508007,80226908,69263344,37781930,121510471,25811997,90535594,73346204,4187783,32152702,56834700,94186610,125855785,6442439,96380378,78472111,116026249,21427905,2064584,95327299,109708797,38541523,132607959,43809603,25302952,122850970,5922909,20866989,29422065,122294834,17100203,84222720,70795336,66822631,62781470,57722442,49300651,71480502,106817693,82719209,131160712,9445835,87937151,93386430,108621965,63287897,39831667,114479180,13945386,58442465,77513672,14693273,89118683,74113310,46778800,54417725,81443210,72054317,99805378,27305119,117828809,4723087,86944836,98752550,67961854,61556513,3607252,125380746,115433432,131855558,16506180,105992653,70328233,48808476,86125723,15707040,80000606,88354414,80893358,117219520,31783922,93905820,69962803,79668889,31235500,94929969,38380801,43681206,8762953,63839925,122058216,84016757,66571295,126738683,26437195,92388064,9409708,93158119,91009207,97395244,64278174,14627214,73808874,54163683,45857417,129493701,4663244,98323285,61227136,78029188,32734399,118934427,48510606,15417109,57203290,82175156,127303284,79245562,94658637,43477713,26928171,74476941,126458594,92127154,92917193,116805719,7047578,28341012,129075676,98216338,96929567,53622668,60210609,81880662,79033150,43098159,91592587,65171029,116475438,28190659,97985219,100334466,21954208,100717217,64792778,28017826,400,385};
 
/*
* Efficient packed implementation of blinded array access.
*/
uint32_t a_log_tab_blind_access_parallel7x(uint32_t index)
{
    uint32_t xorVal, setZero, locIndex, allIndex, anyOnes, res;
    uint32_t one7x = 262657;
    uint32_t seven7x = 787971;
    uint32_t one = 1;
    uint32_t nine_ones = 511;           

    uint32_t j;
    uint32_t sum = 0;

	// pack index
    uint32_t index_packed = index + (index<<(9*1)) + (index<<(9*2));
    
    // pack iterator
	uint32_t j_packed;
    j = 0;
    j_packed = j + ((j+1)<<(9*1))+ ((j+2)<<(9*2));

	// Index 0 to 509
    for(j=0; j<510; j=j+3)
	{
        xorVal = j_packed ^ index_packed;
        setZero = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
        locIndex = (setZero&one7x) ^ one7x;
        allIndex = locIndex * nine_ones;
        sum = sum + (allIndex & a_log_tab_packed[j/3]); 
        j_packed = j_packed + seven7x;
	}
   
   	// Index 510
	xorVal = 510 ^ index;
	anyOnes = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
	allIndex = (anyOnes&one) - one;
	sum = sum + (allIndex & a_log_tab_packed[170]);  

   	// Index 511
	xorVal = 511 ^ index;
	anyOnes = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
	allIndex = (anyOnes&one) - one;
	sum = sum + (allIndex & a_log_tab_packed[171]);  

    // unpacking
    res = (sum & 511);
    sum = sum >> 9;
    res = res + (sum & 511);
    sum = sum >> 9;
    res = res + (sum & 511);

    return(res);
}
 

uint32_t a_pow_tab_blind_access_parallel7x(uint32_t index)
{
    uint32_t xorVal, setZero, locIndex, allIndex, anyOnes, res;
    uint32_t one7x = 262657;
    uint32_t seven7x = 787971;
    uint32_t one = 1;
    uint32_t nine_ones = 511;           

    uint32_t j;
    uint32_t sum = 0;

	// pack index
    uint32_t index_packed = index + (index<<(9*1)) + (index<<(9*2));
    
    // pack iterator
	uint32_t j_packed;
    j = 0;
    j_packed = j + ((j+1)<<(9*1))+ ((j+2)<<(9*2));

	// Index 0 to 509
    for(j=0; j<510; j=j+3)
	{
        xorVal = j_packed ^ index_packed;
        setZero = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
        locIndex = (setZero&one7x) ^ one7x;
        allIndex = locIndex * nine_ones;
        sum = sum + (allIndex & a_pow_tab_packed[j/3]); 
        j_packed = j_packed + seven7x;
	}
   
   	// Index 510
	xorVal = 510 ^ index;
	anyOnes = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
	allIndex = (anyOnes&one) - one;
	sum = sum + (allIndex & a_pow_tab_packed[170]);  

   	// Index 511
	xorVal = 511 ^ index;
	anyOnes = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
	allIndex = (anyOnes&one) - one;
	sum = sum + (allIndex & a_pow_tab_packed[171]);  

    // unpacking
    res = (sum & 511);
    sum = sum >> 9;
    res = res + (sum & 511);
    sum = sum >> 9;
    res = res + (sum & 511);

    return(res);
}

/*
* Blinded read for elp
*/
unsigned int elp_read(unsigned int * arr, size_t size, int index) {
	unsigned int temp1, temp2;
	unsigned int one = 1;

	unsigned int j;
	unsigned int sum = 0;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;	// XOR potential index with required index
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1); // {0} if j = index, {1} otherwise
		temp1 = (temp2&1) - one; // [1] if temp2 = {0}, [0] otherwise
		sum = sum + (temp1 & arr[j]); // temp1 = [0] except if j = index
  	}

	return(sum);
}

/*
* Blinded read for data
*/
uint8_t data_read(uint8_t * arr, size_t size, int index) {
	uint8_t temp1, temp2;
	uint8_t one = 1;

	uint8_t j;
	uint8_t sum = 0;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1);
		temp1 = (temp2&1) - one;
		sum = sum + (temp1 & arr[j]);
  	}
	return(sum);
}

/*
* Blinded read for ecc_buff
*/
uint32_t ecc_buff_read(uint32_t * arr, size_t size, int index) {
	uint32_t temp1, temp2;
	uint32_t one = 1;

	uint32_t j;
	uint32_t sum = 0;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1);
		temp1 = (temp2&1) - one;
		sum = sum + (temp1 & arr[j]);
  	}
	return(sum);
}

/*
* Blinded write for elp
*/
unsigned int elp_write_flag(unsigned int * arr, size_t size, int index, unsigned int val, int writeFlag) {
	unsigned int temp1, temp2;
	unsigned int one = 1;

	unsigned int j;
	unsigned int sum = 0;
	unsigned int arrVal;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1);
		temp1 = (temp2&1) - one;
        arrVal = arr[j];
		arr[j] = ((~temp1) & arrVal) + (temp1 & (val * writeFlag + arrVal * !writeFlag));
  	}
	return(sum);
}

/*
* Blinded write for data
*/
uint8_t data_write(uint8_t * arr, size_t size, int index, uint8_t val) {
	uint8_t temp1, temp2;
	uint8_t one = 1;

	uint8_t j;
	uint8_t sum = 0;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1);
		temp1 = (temp2&1) - one;
		arr[j] = ((~temp1) & arr[j]) + (temp1 & val);
  	}
	return(sum);
}

/*
* Blinded write for bch cache
*/
int bch_write(int * arr, size_t size, int index, unsigned int val) {
	int temp1, temp2;
	int one = 1;

	size_t j;
	int sum = 0;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1);
		temp1 = (temp2&1) - one;
		arr[j] = ((~temp1) & arr[j]) + (temp1 & val);
  	}
	return(sum);
}

/*
* Blinded read for bch cache
*/
int bch_read(int * arr, size_t size, int index) {
	int temp1, temp2;
	int one = 1;

	size_t j;
	int sum = 0;

	for(j=0; j < size; j++)
	{
		temp1 = j ^ index;
		temp2 = (temp1>>8)|(temp1>>7)|(temp1>>6)|(temp1>>5)|(temp1>>4)|(temp1>>3)|(temp1>>2)|(temp1>>1)|(temp1);
		temp1 = (temp2&1) - one;
		sum = sum + (temp1 & arr[j]);
  	}
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
		powVal = 2* a_log_tab_blind_access_parallel7x(synVal);
		mFlag = (int)(((0 - synVal) & mask) >> 31); // if synVal > 0
		syn[2*j+1] = a_pow_tab_blind_access_parallel7x(powVal - n * (powVal / n)) * mFlag;
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

	for (i = 0; (i < t); i++) {
		b = (int)(((elpDeg - (t + 1)) & mask) >> 31); // b = 1 if elp->deg <= t, setting to 0 means no effect saved, so can make a_pow and a_log 0.
		dFlag = (int)(((0 - d) & mask) >> 31) * b; // is d > 0?
		k = ((2*i) - pp) * dFlag;
		for(it = 0; it <= t; it++) {
			boundsFlag = (int)(((it - (elpDeg+1)) & mask) >> 31); // boundsFlag = 1 if it < elpDeg+1
			read_write_val = elp_copy_c[it];
			elp_copy_c[it] = read_write_val ^ (-dFlag & -boundsFlag & (read_write_val ^ elp_c[it]));		
		}
		
		/* e[i+1](X) = e[i](X)+di*dp^-1*X^2(i-p)*e[p](X) */
		tmp = (a_log_tab_blind_access_parallel7x(d) + n - a_log_tab_blind_access_parallel7x(pd)) * dFlag + tmp * !dFlag ;
		
		for (j = 0; j <= t; j++) {
			x = (int)(((j - (pelpDeg+1)) & mask) >> 31) * dFlag; // x = 1 if j <= pelp->deg
			a = j;
			pelpVal = pelp_c[a];			
			v = (((0 - pelpVal) & mask) >> 31) * x; // v = 1 if pelp->c[a] > 0
	
			l = a_log_tab_blind_access_parallel7x(pelpVal) * v;
			
			modu = (tmp+l) - n * ((tmp+l) / n);
			
			read_write_val = elp_read(elp_c,ELP_SIZE,a+k) ^ (a_pow_tab_blind_access_parallel7x(modu) * v);
			elp_write_flag(elp_c,ELP_SIZE,a+k,read_write_val,1);
		}
		
		/* compute l[i+1] = max(l[i]->c[l[p]+2*(i-p)]) */
		tmp = (pelpDeg - 1 + k) * dFlag;
		v = (int)(((elpDeg - tmp) & mask) >> 31) * dFlag; // v = 1 if tmp > elp->deg
		pelpDeg = (elpDeg + 1) * v + pelpDeg * !v;
		for(it = 0; it <= t; it++) {
			boundsFlag = (int)(((it - (elpDeg+1)) & mask) >> 31); // boundsFlag = 1 if it < elpDeg+1
			read_write_val = pelp_c[it];
			pelp_c[it] = read_write_val ^ (-dFlag & -boundsFlag & (read_write_val ^ elp_copy_c[it]));
		}
		elpDeg = tmp * v + elpDeg * !v;
		pd = d * v + pd * !v;
		pp = 2*i*v + pp*!v;	
		
		/* d[i+1] = S(2i+3)+elp[i+1].1*S(2i+2)+...+elp[i+1].lS(2i+3-l) */
		a = (int)(((i - (t-1)) & mask) >> 31) * b; // a = 1 if t-1 > i
		synVal = syn2[2*i+2];
		d = synVal * a + d * !a;
		elpDeg = elpDeg + 1;
		for (j = 1; j <= t; j++) {
			x = (int)(((j - (elpDeg)) & mask) >> 31) * a; // x = 1 if j <= elp->deg
			synVal = elp_read(syn2,2*t,2*i+2-(j*x));
			elpVal = elp_c[j];
			v = (int)(((0 - elpVal) & mask) >> 31);
			v = (int)(((0 - synVal) & mask) >> 31) * v;
			v = v * x;
			
			synVal = elp_read(syn2,2*t,2*i+2-(j*x));
			evalVal = a_log_tab_blind_access_parallel7x(elpVal) + a_log_tab_blind_access_parallel7x(synVal);
			
			y = (int)(((evalVal - n) & mask) >> 31); // y = 1 if evalVal < GF_N(bch)
			
			d = d ^ a_pow_tab_blind_access_parallel7x( evalVal - (n * !y ) ) * v;
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

	unsigned int log_pd_val = a_log_tab_blind_access_parallel7x(pd);
	int logVal = a_log_tab_blind_access_parallel7x(p0) + n - log_pd_val;

	x = (int)(((logVal - n) & mask) >> 31); // x = 1 if val < n
	v = (int)(((0 - p0) & mask) >> 31); // v = 1 if p0 > 0

	syn0 = a_pow_tab_blind_access_parallel7x(logVal - (n*!x)) * v;

	int l = n - log_pd_val;

	for (i = 0; i <= t; i++) {
		x = (int)(((i - d) & mask) >> 31); // x = 1 if i < d
		pi = p[i];
		v = (int)(((0 - pi) & mask) >> 31) * x; // v = 1 if p->c[i*x] > 0

		val = a_log_tab_blind_access_parallel7x(pi)+l;

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
			syn ^= a_pow_tab_blind_access_parallel7x(val) * v;
		}
		/* Store found roots */
		v = !(int)(((0 - syn) & mask) >> 31) * !z * a; // v = 1 if syn == 0
		val = (n - i) * v + elp_read(roots,t,count) * !v;
		elp_write_flag(roots,t,count,val,1);
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
	unsigned int syn2[2*t];
	
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
