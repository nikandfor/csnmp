#pragma once

#include <map>
#include <string>
#include <vector>

extern "C" {
#include <errno.h>

#include "snmp.h"
}

using namespace std;

namespace snmp {

class Var {
   public:
    virtual int type() const {
        return 0;
    };
    virtual void *val() const = 0;
};

class String : public Var {
   public:
    virtual string operator()() const = 0;

    int type() const {
        return ASN1_OCT_STR;
    }

    void *val() const {
        string v = this->operator()();
        return asn1_new_str(v.c_str(), 0);
    }
};

class Int : public Var {
   public:
    virtual int operator()() const = 0;

    int type() const {
        return ASN1_INT;
    }

    void *val() const {
        int v = this->operator()();
        return snmp_new_int(v);
    }
};

class Int64 : public Var {
   public:
    virtual long long operator()() const = 0;

    int type() const {
        return SNMP_TP_INT64;  // not supported by some implementations
    }

    void *val() const {
        long long v = this->operator()();
        return snmp_new_long(v);
    }
};

class ObjectID : public Var {
   public:
    virtual vector<int> operator()() const = 0;

    int type() const {
        return ASN1_OID;
    }

    void *val() const {
        vector<int> v = this->operator()();
        return asn1_new_oid(v.data(), v.size());
    }
};

class OID {
    asn1_oid_t oid;

   public:
    OID(const OID &b) {
        oid = asn1_crt_oid(b.oid.b, b.oid.len);
    }

    OID(const vector<int> v) {
        oid = asn1_crt_oid(v.data(), v.size());
    }

    OID(asn1_oid_t v) {
        oid = asn1_crt_oid(v.b, v.len);
    }

    ~OID() {
        asn1_free_oid(&oid);
    }

    bool operator<(const OID b) const {
        return asn1_cmp_oids(oid, b.oid) < 0;
    }

    bool operator==(const OID b) const {
        return asn1_cmp_oids(oid, b.oid) == 0;
    }

    operator asn1_oid_t() const {
        return asn1_crt_oid(oid.b, oid.len);
    }
};

class EasySNMP {
    int fd = -1;
    map<OID, Var *> oids;

   public:
    void listen(string addr) {
        fd = snmp_bind_addr(addr.c_str());
        if (fd < 0) {
            throw logic_error("can't bind");
        }
    }

    void resp_get(snmp_pdu_t *p) {
        if (p->vars_len == 0) {
            snmp_add_error(p, SNMP_ERR_NO_SUCH_NAME, "empty request");
            return;
        }

        for (int j = 0; j < p->vars_len; j++) {
            snmp_var_t *v = &p->vars[j];

            snmp_free_var_value(v);

            auto it = oids.find(v->oid);
            if (it == oids.end()) {
                v->type = SNMP_TP_NULL;
                //  snmp_add_error(p, SNMP_ERR_NO_SUCH_NAME, "no such variable");
                continue;
            }

            const Var *var = it->second;

            v->type = var->type();
            v->value = var->val();
        }
    }

    void resp_get_next(snmp_pdu_t *p) {
        if (p->vars_len == 0) {
            snmp_add_error(p, SNMP_ERR_NO_SUCH_NAME, "empty request");
            return;
        }

        asn1_oid_t first = p->vars[0].oid;

        auto it = oids.upper_bound(first);
        if (it == oids.end()) {
            snmp_add_error(p, SNMP_ERR_END_OF_MIB_VIEW, "no more vars");
            return;
        }

        snmp_free_pdu_vars(p);

        asn1_oid_t oid = it->first;
        int type = it->second->type();
        void *val = it->second->val();

        if (type == 0) {
            throw logic_error("bad var");
        }

        snmp_add_var(p, oid, type, val);
    }

    void resp_get_bulk(snmp_pdu_t *p) {
        if (p->vars_len == 0) {
            snmp_add_error(p, SNMP_ERR_NO_SUCH_NAME, "empty request");
            return;
        }

        asn1_oid_t first = p->vars[0].oid;
        first = asn1_crt_oid(first.b, first.len);

        auto it = oids.lower_bound(first);
        if (it == oids.end()) {
            snmp_add_error(p, SNMP_ERR_END_OF_MIB_VIEW, "no more vars");
            goto error;
        }

        snmp_free_pdu_vars(p);

        try {
            for (; it != oids.end(); it++) {
                asn1_oid_t oid = it->first;

                int type = it->second->type();
                void *val = it->second->val();

                if (type == 0) {
                    asn1_free_oid(&oid);
                    throw logic_error("bad var");
                }

                snmp_add_var(p, oid, type, val);

                if (p->vars_len >= p->max_repetitions) {
                    break;
                }
            }
        } catch (...) {
            asn1_free_oid(&first);

            throw;
        }

    error:
        asn1_free_oid(&first);
    }

    void serve() {
        snmp_pdu_t p = {};

        try {
            int r = snmp_recv_pdu(fd, &p);
            if (r < 0) {
                if (p.error.code == 0) {
                    perror("recv pdu error, errno:");
                    throw logic_error("read error");
                } else {
                    cerr << "recv pdu: " << p.error.message << endl;
                }

                snmp_free_pdu_vars(&p);
                snmp_add_error(&p, p.error.code, p.error.message);

                goto respond;
            }

            snmp_dump_pdu("got ", &p);

            switch (p.command) {
            case SNMP_CMD_GET:
                resp_get(&p);
                break;
            case SNMP_CMD_GET_NEXT:
                resp_get_next(&p);
                break;
            case SNMP_CMD_GET_BULK:
                resp_get_bulk(&p);
                break;
            default:
                snmp_free_pdu_vars(&p);
                snmp_add_error(&p, SNMP_ERR_GENERAL, "unsupported command");
                break;
            }

        respond:
            p.command = SNMP_CMD_RESPONSE;

            r = snmp_send_pdu(fd, &p);
            snmp_dump_pdu("send", &p);
            if (r < 0) {
                if (p.error.code == 0) {
                    perror("send pdu error, errno:");
                    snmp_dump_pdu(NULL, &p);
                    throw logic_error("send response");
                } else {
                    cerr << "send pdu: " << p.error.message << endl;
                    snmp_dump_pdu(NULL, &p);
                }
            }
        } catch (...) {
            snmp_free_pdu(&p);

            throw;
        }

        snmp_free_pdu(&p);
    }

    void close() {
        snmp_close(fd);
    }

    void add(const OID &oid, Var *cb) {
        oids[oid] = cb;
    }
};
}  // namespace snmp
