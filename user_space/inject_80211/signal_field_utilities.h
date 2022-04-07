// Author:		Thomas Schuddinck
// Year:		2022

#include <stdio.h>

typedef unsigned char u8;

u8 reverse_byte(u8 b){
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return b;
} 

unsigned long int switch_bit_order_signal_field(unsigned long int signal_field){
	int i;
	unsigned long int result = 0;
	u8 byte;
	for (i = 0; i < 3; i++)
	{
		byte = signal_field & 0xff;
		signal_field = signal_field >> 8;
		byte = reverse_byte(byte);
		result = result | (byte << (i*8)); 
	}
	return result;
} 