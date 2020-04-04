#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "snmp.h"

int working = 3;

int main(int argc, char *arv[]) {
    int ret = 1;

    int fd = snmp_bind(0, 5000);
    if (fd < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        goto error;
    }

    fprintf(stderr, "binded\n");

    snmp_pdu_t p = {};

    while (working--) {
        int r = snmp_recv_pdu(fd, &p);
        snmp_dump_pdu(&p, "got packet ");

        if (r < 0) {
            if (p.error.code) {
                snmp_free_pdu_vars(&p);
                p.command = SNMP_CMD_RESPONSE;
                snmp_add_error(&p, p.error.code, p.error.message);
            } else {
                fprintf(stderr, "read packet: %s", strerror(errno));
                continue;
            }
        } else {
            p.command = SNMP_CMD_RESPONSE;
            for (int j = 0; j < p.vars_len; j++) {
                snmp_var_t *v = &p.vars[j];
                snmp_free_var_value(v);
                v->type = SNMP_TP_OCT_STR;
                v->value = asn1_new_str("some value", 0);
            }

            snmp_add_var(&p,                                     //
                         asn1_crt_oid((int[4]){1, 2, 3, 4}, 4),  //
                         ASN1_INT, snmp_new_int(5));
        }

        r = snmp_send_pdu(fd, &p);
        if (r < 0) {
            fprintf(stderr, "send packet: %s\n", strerror(errno));
        } else {
            fprintf(stderr, "sent %d bytes\n", r);
            snmp_dump_pdu(&p, "packet sent");
        }
    }

    ret = 0;

error:
    snmp_free_pdu(&p);

    if (fd >= 0) {
        snmp_close(fd);
    }

    return ret;
}
