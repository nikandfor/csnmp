#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "snmp.h"

int working = 3;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <listen_addr>\n", argv[0]);
        return 1;
    }

    int ret = 1;

    snmp_pdu_t p = {0};

    int fd = snmp_bind_addr(argv[1]);
    if (fd < 0) {
        fprintf(stderr, "bind error (errno %s)\n", strerror(errno));
        goto error;
    }

    fprintf(stderr, "binded\n");

    while (working--) {
        int r = snmp_recv_pdu(fd, &p);
        snmp_dump_pdu("got packet ", &p);

        if (r < 0) {
            if (p.error.code) {
                snmp_free_pdu_vars(&p);
                p.command = SNMP_CMD_RESPONSE;
                snmp_add_error(&p, p.error.code, p.error.message);
                fprintf(stderr, "read packet, error: %s (pos %d)", p.error.message, p.error.pos);
            } else {
                fprintf(stderr, "read packet, errno: %s", strerror(errno));
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
            if (p.error.code) {
                fprintf(stderr, "read packet, error: %s (pos %d)", p.error.message, p.error.pos);
            } else {
                fprintf(stderr, "send packet, errno: %s\n", strerror(errno));
            }
        } else {
            fprintf(stderr, "sent %d bytes\n", r);
            snmp_dump_pdu("packet sent", &p);
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
