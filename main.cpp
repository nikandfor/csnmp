#include <exception>
#include <iostream>
#include <string>

#include "easysnmp.hpp"

using namespace snmp;

class A : public String {
    string operator()() const {
        return "string value";
    }
};

class B : public Int {
    int operator()() const {
        return 5;
    }
};

int main(int argc, const char *argv[]) {
    const char *addr = "5000";

    if (argc >= 2) {
        addr = argv[1];
    }

    A a;
    B b;

    int working = 3;

    EasySNMP s;

    s.listen(addr);

    cerr << "listening " << addr << endl;

    s.add(vector<int>{1, 2, 3, 4}, &a);
    s.add(vector<int>{1, 2, 3, 5}, &b);

    while (working) {
        try {
            s.serve();
        } catch (const exception &e) {
            cerr << "snmp.serve " << e.what() << endl;
        } catch (...) {
            cerr << "snmp.serve "
                 << "something happend" << endl;
        }
    }

    s.close();

    return 0;
}
