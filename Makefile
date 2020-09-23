all : pcap-test

pcap-test : pcap-test.cpp
	g++ -o pcap-test pcap-test.cpp -lpcap

clean:
	rm -f pcap-test *.o