
OPTS=-Wall -Werror

run: ss
	./ss

ss: main.cpp snmp.a asn1.a
	g++ -std=c++11 ${OPTS} -o $@ $^

%.a: %.c
	gcc -c ${OPTS} -o $@ $^
