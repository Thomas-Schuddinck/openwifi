#include <stdio.h>
#include <stdlib.h>
typedef unsigned char u8;
struct map_entry
{
    u8 key;
    u8 value;
};

u8 find_in_rate_map(struct map_entry * map, int size, u8 key){
    int i;
    for (i = 0; i < size; i++) {
        if(key == map[i].key){
            return map[i].value;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if(argc != 2){
        printf("Dissector program expects exactly one parameter!\n");
        exit (-1);
    }
        
    int length, parity_checker;
	u8 tail, parity, reserved, rate, rate_value, parity_count;
	unsigned long int signal_field;
    
    // init rate map
    struct map_entry *map = malloc(sizeof(struct map_entry) * 8);
    
    map[0].key = 13; // 0011
    map[0].value = 6;
    
    map[1].key = 15; // 1111
    map[1].value = 9;
    
    map[2].key = 5; // 0101
    map[2].value = 12;
    
    map[3].key = 7; // 0111
    map[3].value = 18;
    
    map[4].key = 9;  // 0011
    map[4].value = 24;
    
    map[5].key = 11; // 1011
    map[5].value = 36;
    
    map[6].key = 1; // 0001
    map[6].value = 48;
    
    map[7].key = 3; // 0011
    map[7].value = 54;
	
	signal_field = strtol(argv[1], NULL, 0);
	if(signal_field > 16777215){
		printf("Illegal length for input (max 0xffffff or 16777215!\n");
	} 
	
	printf("SIGNAL FIELD:\t%02lu \n\n", signal_field);
	// extract tail
	tail = signal_field & 0x3f;
	signal_field = signal_field>>6;
	
	// extract parity
	parity = signal_field & 0x01;
	signal_field = signal_field>>1;
	parity_checker = signal_field;
	
	// extract length
	length = signal_field & 0x0fff;
	signal_field = signal_field>>12;
	
	// extract reserved
	reserved = signal_field & 0x01;
	signal_field = signal_field>>1;
	
	// extract rate
	rate = signal_field & 0x0f;
	
	// get rate value
	rate_value = find_in_rate_map(map, 8, rate);
	
	// check parity
	parity_count = 0;
	while(parity_checker != 0){
	    if(parity_checker & 0x01){
	        parity_count++;
	    }
	    parity_checker = parity_checker >> 1;
	}
	
	
	printf("name:\t\tdec\thex\t\tdescription\n");
	printf("----------------------------------------------------\n");
	if(rate_value){
	    printf("rate:\t\t%d\t0x%02x\t\t%d Mbps\n", rate, rate, rate_value);
	}else{
	    printf("rate:\t\t%d\t0x%02x\t\t%s\n", rate, rate, "illegal (least significant bit is always 1)");
	}
	printf("reserved:\t%d\t0x%02x\t\t%s\n", reserved, reserved, (reserved == 0 ? "legal" : "illegal (must be zero bit)"));
	printf("length:\t\t%d\t0x%04x\t\tpacket is %d bytes long\n", length, length, length);
	printf("parity:\t\t%d\t0x%02x\t\t%s\n", parity, parity, ((parity + parity_count) % 2 == 0 ? "legal" : "illegal (first 18 bit contain uneven '1' bits)"));
	printf("tail:\t\t%d\t0x%02x\t\t%s\n", tail, tail, (tail == 0 ? "legal" : "illegal (must be all zero bits)"));
	

	return (0);
}