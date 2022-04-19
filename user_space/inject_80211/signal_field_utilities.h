// Author:		Thomas Schuddinck
// Year:		2022

#include <stdio.h>

typedef unsigned char u8;

static const long int MAX_VALUE_SIGNAL_FIELD = 0xffffff;

static const long int OFFSET_TMSTMP = 0x8;

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

bool check_parity(unsigned long int signal_field){
    u8 parity_count = 0;
    // remove tail bits
    signal_field = signal_field >> 6;
	while(signal_field != 0){
	    if(signal_field & 0x01){
	        parity_count++;
	    }
	    signal_field = signal_field>> 1;
	}	
    return parity_count %2 == 0;
} 

unsigned long int correct_parity(unsigned long int signal_field, bool bits_reverse_order){
	if(bits_reverse_order)
        signal_field = switch_bit_order_signal_field(signal_field);
    
    if(!check_parity(signal_field))
        signal_field = signal_field ^ 0x40;

	if(bits_reverse_order)
        signal_field = switch_bit_order_signal_field(signal_field);

	return signal_field;
}

char * to_hex_string(unsigned long int signal_field, bool bits_reverse_order){
    if(bits_reverse_order)
        signal_field = switch_bit_order_signal_field(signal_field);
    char * ret = (char *) malloc(9); 
    sprintf(ret, "0x%02x%02x%02x", (u8) (signal_field >> 16) , (u8) (signal_field >> 8) & 0xff, (u8) signal_field & 0xff);
    return ret; 
} 

unsigned long int to_unsigned_long_int(u8 * signal_field, bool bits_reverse_order){
    int i;
    unsigned long int result = 0;
    for (i = 0; i < 3; i++)
        result = result << 8 | signal_field[i]; 

    if(bits_reverse_order)
        result = switch_bit_order_signal_field(result);

    return result; 
} 

void to_u8_array(unsigned long int signal_field, u8 * array,  bool bits_reverse_order){
    int i;
    if(bits_reverse_order)
        signal_field = switch_bit_order_signal_field(signal_field);
    for (i = 2; i >=0; i--){
        array[i] = signal_field & 0xff; 
        signal_field = signal_field >> 8;
    } 
} 


void inject_signal_field(u8 *buffer, u8 *signal_field)
{
	int i;
	for (i = 0; i < 8; i++)
	{
		if (i < 3)
			buffer[OFFSET_TMSTMP + i] = reverse_byte(signal_field[i]);
		else
			buffer[OFFSET_TMSTMP + i] = 0xaa;
	}
}