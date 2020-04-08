
OPTS=-Wall -Werror -pedantic -g


ss: main.cpp snmp.a asn1.a easysnmp.hpp
	g++ -std=c++11 ${OPTS} -o $@ $< snmp.a asn1.a

%.a: %.c
	gcc -c ${OPTS} -o $@ $^

run: ss
	./ss

valgrind: ss
	valgrind --leak-check=full --track-origins=yes ./ss

valgrind_all: ss
	valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all ./ss

gdb: ss
	gdb -ex r ./ss

clean:
	rm -f *.a ss

.PHONY: run clean
