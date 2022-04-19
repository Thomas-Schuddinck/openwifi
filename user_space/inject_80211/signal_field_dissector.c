// Author:		Thomas Schuddinck
// Year:		2022

#include "signal_field_dissector.h"
#include "signal_field_utilities.h"


/**
 * @brief Check if the provided signal field is valid 
 * @param sf the provided signal field
 * @param is_reverse_bit_order whether the field is in reverse bitorder or not 
 * @return whether the signal field is valid or not
 */

bool is_valid_signal_field(unsigned long int signal_field, bool is_reverse_bit_order){
        
    int length;
	u8 tail, parity, reserved, rate, rate_value;
	bool is_valid = true;
	bool is_parity_correct = check_parity(signal_field);

	// reverse the bit order if necessary
	if(is_reverse_bit_order){
		signal_field = switch_bit_order_signal_field(signal_field);
	} 

	// extract tail
	tail = signal_field & 0x3f;
	signal_field = signal_field>>6;
	
	// extract parity
	parity = signal_field & 0x01;
	signal_field = signal_field>>1;
	
	// extract length
	length = signal_field & 0x0fff;
	signal_field = signal_field>>12;
	
	// extract reserved
	reserved = signal_field & 0x01;
	signal_field = signal_field>>1;
	
	// extract rate
	rate = signal_field & 0x0f;
	
	// get rate value
	rate_value = bits_to_rates[rate];	
	
	printf("name:\t\tdec\thex\t\tdescription\n");
	printf("----------------------------------------------------\n");

	if(rate_value){
	    printf("rate:\t\t%d\t0x%02x\t\t%d Mbps\n", rate, rate, rate_value);
	}else{
	    printf("rate:\t\t%d\t0x%02x\t\t%s\n", rate, rate, "illegal (least significant bit is always 1)");
		is_valid = false;
	}

	if(reserved == 0){
		printf("reserved:\t%d\t0x%02x\t\t%s\n", reserved, reserved, "legal");
	} else {
		printf("reserved:\t%d\t0x%02x\t\t%s\n", reserved, reserved, "illegal (must be zero bit)");
		is_valid = false;
	} 	

	printf("length:\t\t%d\t0x%04x\t\tpacket is %d bytes long\n", length, length, length);

	if(is_parity_correct){
		printf("parity:\t\t%d\t0x%02x\t\t%s\n", parity, parity, "legal");
	} else {
		printf("parity:\t\t%d\t0x%02x\t\t%s\n", parity, parity, "illegal (first 18 bit contain uneven '1' bits)");
		is_valid = false;
	} 

	if(tail == 0){
		printf("tail:\t\t%d\t0x%02x\t\t%s\n", tail, tail, "legal");
	} else {
		printf("tail:\t\t%d\t0x%02x\t\t%s\n", tail, tail, "illegal (must be all zero bits)");
		is_valid = false;
	} 	

	return is_valid;
	
} 


void usage(void)
{
	printf(
	    "(c)2022 Thomas Schuddinck <thomas.schuddinck@gmail.com> \n"
	    "Usage: signal_field_dissector [options]\n\nOptions"
		"\n-f/--signal_field <hexadecimal representation of signal field for PHY fuzzing> (hex value. example:\n"
		"     0xff2345\n"
		"     WARNING: the signal field is 24 bits, or 3 bytes long, so the value can't be longer than that.\n"
		"     if the value contains less than six hexadecimal values, they will be supplemented with zeros at the front."
	    "\n-r/--the bit order (per byte) is reversed\n"

	    "Example:\n"
	    "  signal_field_dissector -f Ox8b0a00 -r \n"
	    "\n");
	exit(1);
}   


int main(int argc, char *argv[])
{
	unsigned long int signal_field;
	bool is_reverse_bit_order = false;
	bool field_parsed = false;

	while (1)
	{
		int nOptionIndex;
		static const struct option options[] =
		{			
			{ "signal_field", required_argument, NULL, 'f' },
			{ "is_reverse_bit_order", no_argument, NULL, 'r' },
			{ 0, 0, 0, 0 }
		};
		int c = getopt_long(argc, argv, "f:r", options, &nOptionIndex);
 
		if (c == -1)
			break;
		switch (c)
		{
			case 'f':
				signal_field = strtol(optarg, NULL, 0);
				if(signal_field > 16777215){
					usage();
				} 
				field_parsed = true;
				break;
			case 'r':
				is_reverse_bit_order = true;
				break;

			default:
				printf("unknown switch %c\n", c);
				usage();
				break;
		}
	}

	if(!field_parsed){
		usage();
	} 

	
	printf("\n--------------------------------------\nThe provided signal field is %svalid\n--------------------------------------\n",
	is_valid_signal_field(signal_field, is_reverse_bit_order) ? "" : "NOT ");	
	return (0);
}