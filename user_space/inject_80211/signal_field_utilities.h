// Author:		Thomas Schuddinck
// Year:		2022

#include <stdio.h>

typedef unsigned char u8;

static const long int MAX_VALUE_LEGACY_SIGNAL_FIELD = 0xffffff;

static const long long int MAX_VALUE_HT_SIGNAL_FIELD = 0xffffffffffff;


static const int OFFSET_TMSTMP = 0x8;

static const int OFFSET_MAC = 28;

/**
 * @brief reverse the bit order in a singel byte
 * 
 * @param b the provided byte
 * @return the byte with reverse bit order
 */
u8 reverse_byte(u8 b){
	b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
	b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
	b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
	return b;
} 
/**
 * @brief switch the bit order for each byte
 * 
 * @param field the starting field
 * @param size the number of bytes in the field
 * @return the field with the bit order per byte reversed
 */
unsigned long long int switch_bit_order(unsigned long long int field, u8 size){
	int i;
	unsigned long int result = 0;
	u8 byte;
	for (i = 0; i < size ; i++)
	{
		byte = field & 0xff;
		field = field >> 8;
		byte = reverse_byte(byte);
		result = result | (byte << (i*8)); 
	}
	return result;
} 

/**
 * @brief check the parity of the provided signal field
 * 
 * @param signal_field 
 * @param is_legacy_signal_field whether or not this is a legacy signal field or not
 * @return true if the parity bit is set correctly
 * @return false if the parity bit is NOT set correctly
 */
bool check_parity(unsigned long long int signal_field, bool is_legacy_signal_field){
	if(!is_legacy_signal_field){
		printf("HT MODE is not supported yet");
		exit(1);
	} 
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

/**
 * @brief Correct the parity bit of a provided signal field
 * 
 * @param signal_field 
 * @param bits_reverse_order whether the bytes are in reverse bit order
 * @param is_legacy_signal_field whether or not this is a legacy signal field or not
 * @return the signal field with a correct parity bit (if the parity bit was already set correctly, nothing changes)
 */
unsigned long long int correct_parity(unsigned long long int signal_field, bool bits_reverse_order, bool is_legacy_signal_field){
	if(!is_legacy_signal_field){
		printf("HT MODE is not supported yet");
		exit(1);
	} 
	if(bits_reverse_order)
        signal_field = switch_bit_order(signal_field, is_legacy_signal_field);
    
    if(!check_parity(signal_field, is_legacy_signal_field))
        signal_field = signal_field ^ 0x40;

	if(bits_reverse_order)
        signal_field = switch_bit_order(signal_field, is_legacy_signal_field);

	return signal_field;
}

/**
 * @brief translate a signal field to a hex string
 * 
 * @param field 
 * @param bits_reverse_order  whether the bytes are in reverse bit order
 * @param size the number of bytes in the field
 * @return the field in hex string
 */
char * to_hex_string(unsigned long long int field, bool bits_reverse_order, u8 size){
	if(size < 1)
		return "0x00";
    if(bits_reverse_order)
        field = switch_bit_order(field, size);
    char * ret;
	ret = (char *) malloc((size)*2+3); 
	ret[0] = '0';
	ret[1] = 'x';
	sprintf(&ret[2], "%02llx",field);
	ret[(size)*2+3] = '\0';   	
    return ret; 
} 

/**
 * @brief translate a field from a u8 array to a long long int
 * 
 * @param field 
 * @param bits_reverse_order 
 * @param size the size of the array
 * @return the long long int representation of the field
 */
unsigned long long int to_unsigned_long_int(u8 * field, bool bits_reverse_order, u8 size){
    int i;
    unsigned long long int result = 0;
    for (i = 0; i < size; i++)
        result = result << 8 | field[i]; 

    if(bits_reverse_order)
        result = switch_bit_order(result, size);

    return result; 
} 

/**
 * @brief translate a long long int to a u8 array
 * 
 * @param field 
 * @param array the array to translate to
 * @param bits_reverse_order whether the bytes are in reverse bit order
 * @param size the number of bytes in the field
 */
void to_u8_array(unsigned long long int signal_field, u8 * array, bool bits_reverse_order, u8 size){
    int i;
    if(bits_reverse_order)
        signal_field = switch_bit_order(signal_field, size);
    for (i = size - 1; i >=0; i--){
        array[i] = signal_field & 0xff; 
        signal_field = signal_field >> 8;
    } 
} 

void inject_signal_field(u8 *buffer, u8 *signal_field, bool is_legacy_signal_field){
 	int i, guard = (is_legacy_signal_field ? 3 : 6 );
	u8 fill = (is_legacy_signal_field ? 0xaa : 0xbb );
	for (i = 0; i < 8; i++)
	{
		if (i < guard)
			buffer[OFFSET_TMSTMP + i] = reverse_byte(signal_field[i]);
		else
			buffer[OFFSET_TMSTMP + i] = fill;
	}
}


void log_injected_mac(long long int mac_field){
	printf("MAC HDR (HR): %s\n", to_hex_string(mac_field, false, 4));
	printf("MAC HDR (SEND OUT): %s\n", to_hex_string(mac_field, true, 4));
} 

void inject_mac(u8 *buffer, unsigned long long int mac_field){
	log_injected_mac(mac_field);
	u8 mac_field_arr[4];
	to_u8_array(mac_field, mac_field_arr, false, 4); 
 	int i;
	for (i = 0; i < 4; i++)
	{
		buffer[OFFSET_MAC + i] = mac_field_arr[i];
	}
}
