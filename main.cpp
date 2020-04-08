#include <exception>
#include <iostream>
#include <string>

#include "easysnmp.hpp"

using namespace snmp;

int v = 0;
long long start = time(NULL);

class A : public String {
    string operator()() const {
        return "string value";
    }
};

class B : public Int {
    int type() const {
        return SNMP_TP_COUNTER;
    }

    int operator()() const {
        return ++v;
    }
};

class C : public String {
    string operator()() const {
        return "Русский язык велик и могуч!";
    }
};

class D : public String {
    string operator()() const {
        return "ロシア語は素晴らしく、強力です！";
    }
};

class E : public Int {
    int operator()() const {
        return rand() % 10000;
    }
};

class F : public Int64 {
    long long operator()() const {
        return rand() << 20;
    }
};

class Contact : public String {
    string operator()() const {
        return "nikandfor@gmail.com";  // 255 bytes max
    }
};

class Description : public String {
    string operator()() const {
        return "Test snmp device";  // 255 bytes max
    }
};

class Location : public String {
    string operator()() const {
        return "My own local host I suppose";  // 255 bytes max
    }
};

class Name : public String {
    string operator()() const {
        return "Device name";  // 255 bytes max
    }
};

class Uptime : public Int64 {
    int type() const {
        return SNMP_TP_TIMETICKS;
    }

    long long operator()() const {
        return (long long)time(NULL) - start;
    }
};

class DevOID : public ObjectID {
    vector<int> operator()() const {
        return vector<int>{1, 3, 6, 1, 4, 1, 121212};  // 1,3,6,1,4,1, than some random but not allocated already http://oid-info.com/get/1.3.6.1.4.1
    }
};

int main(int argc, const char *argv[]) {
    const char *addr = "5000";

    if (argc >= 2) {
        addr = argv[1];
    }

    A a;
    B b;
    C c;
    D d;
    E e;
    F f;

    Description descr;
    Contact contact;
    Name name;
    Location loc;
    DevOID oid;
    Uptime uptime;

    int working = 3;

    EasySNMP s;

    s.listen(addr);

    cerr << "listening " << addr << endl;

    s.add({{1, 3, 6, 1, 4, 1, 121212, 1, 1}}, &b);
    s.add({{1, 3, 6, 1, 4, 1, 121212, 1, 2}}, &e);
    //    s.add({{1, 3, 6, 1, 4, 1, 121212, 1, 3}}, &f); // int64
    s.add({{1, 3, 6, 1, 4, 1, 121212, 2, 1}}, &a);
    s.add({{1, 3, 6, 1, 4, 1, 121212, 2, 2}}, &c);
    s.add({{1, 3, 6, 1, 4, 1, 121212, 2, 3}}, &d);

    s.add({{1, 3, 6, 1, 2, 1, 1, 1, 0}}, &descr);
    s.add({{1, 3, 6, 1, 2, 1, 1, 2, 0}}, &oid);
    s.add({{1, 3, 6, 1, 2, 1, 1, 3, 0}}, &uptime);
    s.add({{1, 3, 6, 1, 2, 1, 1, 4, 0}}, &contact);
    s.add({{1, 3, 6, 1, 2, 1, 1, 5, 0}}, &name);
    s.add({{1, 3, 6, 1, 2, 1, 1, 6, 0}}, &loc);

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
