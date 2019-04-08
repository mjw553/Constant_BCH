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
#define cpucycles() _rdtsc()

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
	int i,max_len = 3, lenFlag;
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

// one entry contains 7 consecutive entries of a_pow_tab.
uint64_t a_pow_tab_packed[] =
{1154048505100108801, 4904706146675589248, 685233360000304177, 7383807872410398796, 3272510108327259939, 1947456885676936042, 7708964539412734168, 6806783619864543047, 5121090276851944675, 387388845576987689, 3849534358727731242, 9016003979346086826, 7465269428114933753, 5265346339920189229, 4534767650140677209, 1433826926772878326, 2948514455809849502, 5652735114764434246, 216384130176355427, 928366071637893144, 5986626653527316582, 5797554678079562889, 8979956955006520467, 2587875434018371573, 6960373171667622686, 6121585445174802197, 3281842496475684023, 8871747916273390444, 9088131977728427977, 7745011565901883361, 1875328820856819531, 7970164513108869328, 8032960191930152805, 793408382726410091, 3380719145040568408, 6337969573201574774, 2407537229748944047, 2885121262750272266, 3344638104560018240, 1721775552801139570, 4174691025730074814, 1009792442031872974, 4291634936353505392, 2776947340744807388, 6193713509994918708, 3020642522779548863, 5337474336157145934, 3606401578502784065, 4679588314046423952, 8691444828731366423, 3669795872148781013, 2371491303846214550, 7816576061757995782, 567727049850613619, 9078833672158771262, 540978397518487551, 6770736661958553660, 856801575785987327, 5688816155244984414, 4832578150576790631, 1469309283707397129, 8438979726796032162, 5012916354712258489, 5616688159008027709, 5760944222214683775, 5147838929184078959, 2695485855777205291, 4111297832670497578, 7934083472628319176, 3416766171529717601, 1406514774193851258, 640417445609631900, 4760450083607091270,1};

// one entry contains 7 consecutive entries of a_log_tab.
uint64_t a_log_tab_packed[] = 
{2369034296372756480, 3841727403853350690, 4720469844662881571, 710113830304077893, 197982856044010276, 1144194614867480055, 2428202733211720774, 8630314529020877326, 6824985906428752677, 8467183051840163015, 381561746342312440, 2596354495139012914, 3065912174325930567, 8993953973730980539, 3905650860909722639, 8213443399426845810, 3203738266086420774, 1472514478554157867, 9182123454816551112, 7924902888345650434, 1738805643746641913, 7728971920079752858, 4775582536435015475, 5787741256437946322, 549400737067057224, 618521208541535996, 7340456005704707260, 8286213008702452201, 2222479099559692304, 4349111221176310628, 771969872880978035, 6375142067861219941, 6124189270684414759, 5716842871834468638, 7981983186293464876, 1876393540994565394, 1225613020768890057, 2341827324877117270, 247888501411824387, 3582344117981096074, 3042643272122232314, 3354092967009670036, 1695461623199837339, 5383443197403488859, 2184174548474233140, 2765593220507820956, 1190682524057231315, 3001749639168394090, 8799594922325161545, 8756110415631983418, 1816750271657801469, 4162589005411629792, 4919502762978231997, 1005174525095918963, 2475242322345212906, 7276021356478946781, 4207496798305430033, 7408311324136350084, 7485734169268161381, 5647033750307255354, 1397744844643139188, 6666851773929935408, 8690168446582463078, 1579723804953657266, 1036533449217506088, 6749375420372858988, 7807431667370886943, 4496795323709639518, 6294194673602813741, 8140126796497710677, 6877092685976229651, 6921234461786718590, 7209519892806805706, 385};

/*
* Efficient packed implementation of blinded array access.
*/
uint64_t a_log_tab_blind_access_parallel7x(uint64_t index)
{
	uint64_t xorVal, setZero, locIndex, allIndex, anyOnes, res;
	uint64_t one7x = 18049651735527937; //1+2^9+2^(9*2)+2^(9*3)+2^(9*4)+2^(9*5)+2^(9*6)
	uint64_t seven7x = 126347562148695559; //7+7*2^9+7*2^(9*2)+7*2^(9*3)+7*2^(9*4)+7*2^(9*5)+7*2^(9*6)
	uint64_t one = 1;
	uint64_t nine_ones = 511;	

	uint64_t j;
	uint64_t sum = 0;

    // pack index
	uint64_t index_packed = index + (index<<(9*1)) + (index<<(9*2)) + (index<<(9*3)) + (index<<(9*4)) + (index<<(9*5)) + (index<<(9*6));
    // pack iterator
	uint64_t j_packed;
	j = 0;
	j_packed = j + ((j+1)<<(9*1))+ ((j+2)<<(9*2))+ ((j+3)<<(9*3))+ ((j+4)<<(9*4))+ ((j+5)<<(9*5))+ ((j+6)<<(9*6));

	for(j=0; j<511; j=j+7)
	{
		xorVal = j_packed ^ index_packed; // XOR 7 indexed with 7* required index
		setZero = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal); // if required index, set first bit to 0, 1 otherwise
		locIndex = (setZero&one7x) ^ one7x;	 // 9-bit chunks of 0s, set first bit of required index to 1
		allIndex = locIndex * nine_ones;  // set all bits of requred chunk to 1
		sum = sum + (allIndex & a_log_tab_packed[j/7]);	// allIndex is 0 in all cases except j=index
		j_packed = j_packed + seven7x;		// increment j by 7 in all positions	
 	}
	
	/* Account for the 64th bit containing index 511 */
	xorVal = nine_ones ^ index;			// for j=511
	// check if any of the 9 bits is non-zero; anyOnes will be either 0 or 1
	anyOnes = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
	allIndex = (anyOnes&one) - one;	// allIndex = {0} if anyOnes=1 otherwise allIndex = {1}
	sum = sum + (allIndex & a_log_tab_packed[73]);	// allIndex is 0 in all cases except j=index

	// unpacking
	res = (sum & 134217727) | (sum>>27);
	res = (res & 262143) | (res>>18);
	res = (res & 511) | (res>>9);

	return(res);
}

uint64_t a_pow_tab_blind_access_parallel7x(uint64_t index)
{
	uint64_t xorVal, setZero, locIndex, allIndex, anyOnes, res;
	uint64_t one7x = 18049651735527937; //1+2^9+2^(9*2)+2^(9*3)+2^(9*4)+2^(9*5)+2^(9*6)
	uint64_t seven7x = 126347562148695559; //7+7*2^9+7*2^(9*2)+7*2^(9*3)+7*2^(9*4)+7*2^(9*5)+7*2^(9*6)
	uint64_t one = 1;
	uint64_t nine_ones = 511;	

	uint64_t j;
	uint64_t sum = 0;

    // pack index
	uint64_t index_packed = index + (index<<(9*1)) + (index<<(9*2)) + (index<<(9*3)) + (index<<(9*4)) + (index<<(9*5)) + (index<<(9*6));
    // pack iterator
	uint64_t j_packed;
	j = 0;
	j_packed = j + ((j+1)<<(9*1))+ ((j+2)<<(9*2))+ ((j+3)<<(9*3))+ ((j+4)<<(9*4))+ ((j+5)<<(9*5))+ ((j+6)<<(9*6));

	for(j=0; j<511; j=j+7)
	{
		xorVal = j_packed ^ index_packed; // XOR 7 indexed with 7* required index
		setZero = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal); // if required index, set first bit to 0, 1 otherwise
		locIndex = (setZero&one7x) ^ one7x;	 // 9-bit chunks of 0s, set first bit of required index to 1
		allIndex = locIndex * nine_ones;  // set all bits of requred chunk to 1
		sum = sum + (allIndex & a_pow_tab_packed[j/7]);	// allIndex is 0 in all cases except j=index
		j_packed = j_packed + seven7x;		// increment j by 7 in all positions	
 	}
	
	/* Account for the 64th bit containing index 511 */
	xorVal = nine_ones ^ index;			// for j=511
	// check if any of the 9 bits is non-zero; anyOnes will be either 0 or 1
	anyOnes = (xorVal>>8)|(xorVal>>7)|(xorVal>>6)|(xorVal>>5)|(xorVal>>4)|(xorVal>>3)|(xorVal>>2)|(xorVal>>1)|(xorVal);
	allIndex = (anyOnes&one) - one;	// allIndex = {0} if anyOnes=1 otherwise allIndex = {1}
	sum = sum + (allIndex & a_pow_tab_packed[73]);	// allIndex is 0 in all cases except j=index

	// unpacking
	res = (sum & 134217727) | (sum>>27);
	res = (res & 262143) | (res>>18);
	res = (res & 511) | (res>>9);

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
		temp1 = j ^ index;			// temp1 becomes 0 only if j=index
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
	
	// Define flags
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

	/* Main SiBMA algorithm  */
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
			synVal = elp_read(syn2,2*t,2*i+2-j);
			elpVal = elp_c[j];
			v = (int)(((0 - elpVal) & mask) >> 31); // if(elpVal)
			v = (int)(((0 - synVal) & mask) >> 31) * v; // if(elpVal && synVal)
			v = v * x; // if(elpVal && synVal && j <= elp->deg)
			
			synVal = elp_read(syn2,2*t,2*i+2-j);
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

	/* use a log-based representation of polynomial */
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
		elp_write_flag(roots,t,count,n-i,v);
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
