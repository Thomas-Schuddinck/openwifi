// Author:		Thomas Schuddinck
// Year:		2022

#include "signal_field_fuzzer.h"
#include "signal_field_utilities.h"


int perform_single_fuzz(unsigned long int signal_field, char * iterations_as_string, char *packet_type_ptr, bool is_reverse_bit_order){
    int result;
    pid_t pid;
    if ((pid=fork())<0){
        perror("ERROR OCCURED DURING FORK");
        exit(1);
    }
    if (pid==0){
        printf("Value of fuzzed field: %s\n", to_hex_string(signal_field, is_reverse_bit_order));
        result = execl("/root/openwifi/inject_80211/inject_80211", "inject_80211", "-m", "n", "-r", "0", "-n", iterations_as_string, "-t", packet_type_ptr, "-s", "64", "-c", to_hex_string(signal_field, is_reverse_bit_order), "sdr0", (char *)NULL);
        
        if(result<0){
            perror("FUZZING FAILED");
            exit(1);
        }	
        exit(0);
    }
    waitpid(pid,NULL,0);
    return 0;
}

void usage(void)
{
    printf(
        "(c)2022 Thomas Schuddinck <thomas.schuddinck@gmail.com> \n"
        "Usage: signal_field_fuzzer [options]\n\nOptions"
        "\n-i/--signal_field <hexadecimal representation of start value of the signal field for PHY fuzzing> [default=0] (hex value. example:\n"
        "     0xff2345\n"
        "     WARNING: the signal field is 24 bits, or 3 bytes long, so the value can't be longer than that.\n"
        "     if the value contains less than six hexadecimal values, they will be supplemented with zeros at the front."
        "-j/--the value to increment the singal field with <increment value [default=1]\n"
        "     Must be greater than 0\n"
        "-n/--number_of_injections <number of injections that have to be performed> [default=100]\n"
        "     Must be greater than 0\n"
        "-m/--number_of_repetitions <number of times a single injection is repeated> [default=1] \n"
        "     Must be greater than 0\n"
        "-f/--fuzzing_type (i/r for incremental/random) [default='i']\n"
        "-t/--packet_type (m/c/d/r for management/control/data/reserved) [default='d']\n"
        "-s/--sleep_time <number of seconds to sleep between each injection> [default=1]"
        "     Must be greater or equal than 0\n"
        "-r/--the bit order (per byte) is reversed [default=false]\n"
        "-p/--whether or not the parity bit needs to be fixed [default=false]\n"

        "Example:\n"
        "  signal_field_fuzzer -i Ox8b0a00 -n 20 -t d -r \n"
        "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    // char pointers to pass to execl
    char iterations_as_string[20];
    char *packet_type_ptr;

    int number_of_injections                = 100;
    int number_of_repetitions               = 1;
    char fuzzing_type                       = 'i';
    char packet_type                        = 'd';
    unsigned long int signal_field          = 0;
    unsigned long int increment_value       = 1;
    int i                                   = 0;
    int sleep_time                               = 1;
    bool is_reverse_bit_order               = false;
    bool fix_parity_bit                     = false;

    while (1)
    {
        int nOptionIndex;
        static const struct option optiona[] =
            {
                {"signal_field", required_argument, NULL, 'i'},
                {"number_of_injections", required_argument, NULL, 'n'},
                {"number_of_repetitions", required_argument, NULL, 'm'},
                {"fuzzing_type", required_argument, NULL, 'f'},
                {"packet_type", required_argument, NULL, 't'},
                {"sleep", required_argument, NULL, 's'},
                {"is_reverse_bit_order", no_argument, NULL, 'r'},
                {"fix_parity_bit ", no_argument, NULL, 'p'},
                {0, 0, 0, 0}};
        int c = getopt_long(argc, argv, "i:n:m:f:t:s:rp", optiona, &nOptionIndex);

        if (c == -1)
            break;
        switch (c)
        {
        case 0: // long option
            break;

        case 'i':
            signal_field = strtol(optarg, NULL, 0);
            if (signal_field > MAX_VALUE_SIGNAL_FIELD)
            {
                usage();
            }

            break;

        case 'j':
            increment_value = strtol(optarg, NULL, 0);
            if (increment_value < 1)
                usage();
            break;

        case 'n':
            number_of_injections = atoi(optarg);
            if (number_of_injections < 1)
                usage();
            break;

        case 'm':
            number_of_repetitions = atoi(optarg);
            if (number_of_repetitions < 1)
                usage();
            break;

        case 'r':
            is_reverse_bit_order = true;
            break;

        case 'p':
            fix_parity_bit = true;
            break;

        case 'f':
            fuzzing_type = optarg[0];
            break;

        case 't':
            packet_type = optarg[0];
            break;

        case 's':
            sleep_time = atoi(optarg);
            if (sleep_time < 0)
                usage();
            break;

        default:
            printf("unknown switch %c\n", c);
            usage();
            break;
        }
    }

    // reverse the bit order in case the bits are flipped (LSB on the left)
    if (is_reverse_bit_order)
    {
        signal_field = switch_bit_order(signal_field);
    }

    // convert non-char pointer values to char pointers
    sprintf(iterations_as_string, "%d", number_of_repetitions);
    packet_type_ptr = &packet_type;

    printf("PARAMETERS USED:\n");
    printf("start value: %s\nfuzzing type: %s\nnumber of injections: %d\nnumber of repetitions: %d\nsleep time: %d seconds\nfix parity bit: %s\n", to_hex_string(signal_field, is_reverse_bit_order), fuzzing_type == 'i' ? "incremental" : "random", number_of_injections, number_of_repetitions, sleep_time, fix_parity_bit ? "yes" : "no");
    printf("-----------------------------------------------------------\n");
    printf("			STARTING INJECTION\n");
    printf("-----------------------------------------------------------\n");
    if (fuzzing_type == 'i')
    {
        while (i < number_of_injections)
        {


            if (fix_parity_bit)
                signal_field = correct_parity(signal_field, is_reverse_bit_order);

            sleep(sleep_time);

            perform_single_fuzz(signal_field, iterations_as_string, packet_type_ptr, is_reverse_bit_order);

            if (signal_field > MAX_VALUE_SIGNAL_FIELD - increment_value)
            {
                printf("signal field reached the maximum value. Exiting..\n.");
                return (0);
            }
            signal_field = signal_field + increment_value;
            i++;
        }
    }
    else
    {
        srand(time(NULL));
        while (i < number_of_injections)
        {
            sleep(sleep_time);
            signal_field = (rand() % (MAX_VALUE_SIGNAL_FIELD + 1));
            if (fix_parity_bit)
                signal_field = correct_parity(signal_field, false);
            perform_single_fuzz(signal_field, iterations_as_string, packet_type_ptr, is_reverse_bit_order);
            signal_field++;
            signal_field++;
            i++;
        }
    }

    return (0);
}