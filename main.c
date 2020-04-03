#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "snmp.h"

int main(int argc, char *arv[]) {
    int ret = 1;

    int fd = snmp_bind(0, 5000);
    if (fd < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        goto error;
    }

    fprintf(stderr, "binded\n");

    snmp_pdu_t p = {};

    int r = snmp_recv_pdu(fd, &p);
    if (r < 0) {
        if (p.error.code) {
            fprintf(stderr, "recv packet (%x): %s [%d]\n", p.error.pos, p.error.message, p.error.code);
        } else {
            fprintf(stderr, "recv packet: %s\n", strerror(errno));
        }
        goto error;
    }

    snmp_dump_pdu(&p, "got packet ");

    p.command = SNMP_CMD_RESPONSE;

    r = snmp_send_pdu(fd, &p);
    if (r < 0) {
        fprintf(stderr, "send packet: %s\n", strerror(errno));
        goto error;
    }

    fprintf(stderr, "sent %d bytes\n", r);

    snmp_dump_pdu(&p, "packet sent");

    ret = 0;

error:
    snmp_free_pdu(&p);

    if (fd >= 0) {
        snmp_close(fd);
    }

    return ret;
}
