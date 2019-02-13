#include "api.h"
#include "stm32wrapper.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "ecc.h"
#include "bch.h"
#include "makeRandomInput.h"

static unsigned long long overflowcnt = 0;

void sys_tick_handler(void)
{
  ++overflowcnt;
}

static void printcycles(const char *s, unsigned long long c)
{
  char outs[32];
  send_USART_str(s);
  snprintf(outs,sizeof(outs),"%llu\n",c);
  send_USART_str(outs);
}


int main(void)
{
  	unsigned int t0, t1;
  	int count;

	// Variables for BCH
	unsigned char mlen = MESSAGE_LEN;
	unsigned char mlenP;
	unsigned char buf[MESSAGE_LEN+CIPHER_LEN]; 
	unsigned char buf_store[MESSAGE_LEN+CIPHER_LEN]; 
	unsigned char buf2[MESSAGE_LEN+CIPHER_LEN];
	unsigned char m_buf[MESSAGE_LEN+1];
	unsigned char code1[CODE_LEN];

  	clock_setup(CLOCK_BENCHMARK);
  	gpio_setup();
  	usart_setup(115200);
  	systick_setup();
  	rng_enable();

	int pos_arr[29] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28};

	// Controls how many errors get tested. 1 -> number specified. 
	int fixed_errors_up_to = 29; 
	int repeats_per_error = 100;

	//seed_rng();

	for(int k = 0; k <= fixed_errors_up_to; k++) {
		send_USART_str(">>>=======================");
		for(count=0; count<repeats_per_error; count++)
		{
			// Shuffle Random Err Pos Array
			for(int i = 0; i < 29; i++) {
				int temp = pos_arr[i];
				int randomIndex = rand() % 29;
				pos_arr[i] = pos_arr[randomIndex];
				pos_arr[randomIndex] = temp;
			}

			// Prep Message data.
			unsigned char * mlenP2 = &mlenP;
			memset(buf,0,MESSAGE_LEN+CIPHER_LEN);
			memset(buf2,0,MESSAGE_LEN+CIPHER_LEN);
			generate_input(buf, MESSAGE_LEN);

			memcpy(buf_store,buf,MESSAGE_LEN);
			
			memset(m_buf,0,MESSAGE_LEN+1);
			memcpy(m_buf,&mlen,1);
			memcpy(m_buf+1,buf,mlen);

			// Encoding:
			ecc_enc(m_buf,code1);

			// Add error:
			uint8_t *code2 = (uint8_t *)code1;
			for(int i = 0; i < k; i++)
				code2[pos_arr[i]] = code2[pos_arr[i]] ^ (1 << (i & 7));
			
			t0 = systick_get_value();
			overflowcnt = 0;
			ecc_dec(m_buf,code1);
			t1 = systick_get_value();
			printcycles("", (t0+overflowcnt*2400000llu)-t1);

			memcpy(mlenP2,m_buf,1);
			memcpy(buf2,m_buf+1,*mlenP2);
		}
	}
  	send_USART_str("#");
  	while(1);
  return 0;
}
