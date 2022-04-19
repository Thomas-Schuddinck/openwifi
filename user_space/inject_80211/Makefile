
all: inject_80211 analyze_80211 signal_field_dissector phy_fuzzer

inject_80211: inject_80211.c
	gcc  -Wall -Werror inject_80211.c -o inject_80211 -lpcap

analyze_80211: analyze_80211.c
	gcc  -Wall -Werror radiotap.c analyze_80211.c -o analyze_80211 -lpcap

signal_field_dissector: signal_field_dissector.c
	gcc  -Wall -Werror signal_field_dissector.c -o signal_field_dissector -lpcap

phy_fuzzer: phy_fuzzer.c
	gcc  -Wall -Werror phy_fuzzer.c -o phy_fuzzer -lpcap

clean:
	rm -f inject_80211 analyze_80211

