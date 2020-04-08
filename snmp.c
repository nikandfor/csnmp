#define _POSIX_C_SOURCE 200112L

#include "snmp.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int snmp_bind(uint32_t addr, int port) {
    int fd = 0;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        goto error;
    }

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));

    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = addr;
    serv.sin_port = htons(port);

    int r = bind(fd, (const struct sockaddr *)&serv, sizeof(serv));
    if (r == -1) {
        goto error;
    }

error:
    return fd;
}

int snmp_bind_addr(const char *addr) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    int ret = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    s = getaddrinfo(NULL, addr, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        if (s > 0)
            s = -s;
        return s;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        int r = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (r == 0) {
            goto ok;
        }

        close(sfd);
    }

    if (rp == NULL) {
        goto error;
    }

ok:
    ret = sfd;

error:
    freeaddrinfo(result);

    return ret;
}

int snmp_close(int fd) {
    return close(fd);
}

void snmp_free_var_value(snmp_var_t *v) {
    switch (v->type) {
    case SNMP_TP_BOOL:
    case SNMP_TP_INT:
    case SNMP_TP_COUNTER:
    case SNMP_TP_GAUGE:
    case SNMP_TP_COUNTER64:
    case SNMP_TP_INT64:
    case SNMP_TP_UINT64:
    case SNMP_TP_TIMETICKS:
        free(v->value);
        break;
    case SNMP_TP_BIT_STR:
    case SNMP_TP_OCT_STR:
    case SNMP_TP_IP_ADDR:
    default:
        asn1_free_str((asn1_str_t *)v->value);
        free(v->value);
        break;
    case SNMP_TP_OID:
        asn1_free_oid((asn1_oid_t *)v->value);
        free(v->value);
        break;
    case 0:
    case SNMP_TP_NULL:
    case SNMP_TP_NO_SUCH_OBJ:
    case SNMP_TP_NO_SUCH_INSTANCE:
    case SNMP_TP_END_OF_MIB_VIEW:
        break;
    }

    v->type = 0;
    v->value = NULL;
}

void snmp_free_var(snmp_var_t *v) {
    asn1_free_oid(&v->oid);

    snmp_free_var_value(v);
}

void snmp_free_pdu_vars(snmp_pdu_t *p) {
    for (int i = 0; i < p->vars_len; i++) {
        snmp_free_var(&p->vars[i]);
    }

    p->vars_len = 0;
    p->vars_cap = 0;

    if (p->vars) {
        free(p->vars);
        p->vars = NULL;
    }
}

void snmp_free_pdu(snmp_pdu_t *p) {
    asn1_free_str(&p->community);

    snmp_free_pdu_vars(p);
}

static void _hex_dump(const char *b, int pos, int l) {
    for (ssize_t i = 0; i < l; i++) {
        if (i % 16 == 0) {
            fprintf(stderr, "%06lx  ", pos + i);
        }
        if (i % 8 == 0) {
            fprintf(stderr, " ");
        }

        fprintf(stderr, " %02x", (unsigned char)b[pos + i]);

        if (i % 16 == 15) {
            fprintf(stderr, "\n");
        }
    }

    if (l % 16 != 15) {
        fprintf(stderr, "\n");
    }
}

static int _append_var(snmp_pdu_t *p, snmp_var_t v) {
    if (p->vars_len == p->vars_cap) {
        if (p->vars_cap == 0) {
            p->vars_cap = 4;
        } else if (p->vars_cap < 100) {
            p->vars_cap *= 2;
        } else {
            p->vars_cap += p->vars_cap / 4;
        }

        p->vars = realloc(p->vars, p->vars_cap * sizeof(snmp_var_t));
        if (p->vars == NULL) {
            return -1;
        }
    }

    p->vars[p->vars_len++] = v;

    return 0;
}

int snmp_add_error(snmp_pdu_t *p, int code, const char *msg) {
    if (p->error_status) {
        return -1;
    }

    if (msg == NULL) {
        msg = "internal error";
    }

    p->error_status = code;
    p->error_index = p->vars_len;

    snmp_var_t v = {0};

    // v.oid.id = malloc();

    v.type = ASN1_OCT_STR;

    asn1_str_t *str = malloc(sizeof(asn1_str_t));
    str->len = strlen(msg);
    str->b = malloc(str->len + 1);  // +1 for null byte
    memcpy(str->b, msg, str->len + 1);
    v.value = str;

    int r = _append_var(p, v);
    if (r < 0) {
        snmp_free_var(&v);
        return -1;
    }

    return 0;
}

int snmp_set_error_index(snmp_pdu_t *p, int code, int index) {
    if (p->error_status) {
        return -1;
    }

    p->error_status = code;
    p->error_index = index;

    return 0;
}

int snmp_add_var(snmp_pdu_t *p, asn1_oid_t oid, int tp, void *val) {
    snmp_var_t v = {
        .oid = oid,
        .type = tp,
        .value = val,
    };

    return _append_var(p, v);
}

static int _dec_var(const char *b, int *i, int l, int tp, void *v_) {
    snmp_var_t *v = (snmp_var_t *)v_;

    if (b[(*i)++] != ASN1_OID) {
        asn1_set_error(&v->error, *i, "expected oid");
        return -1;
    }

    int r = asn1_dec_oid(b, i, l, &v->oid);
    if (r) {
        asn1_set_error(&v->error, *i, "bad oid");
        return -1;
    }

    v->type = b[(*i)++];

    switch (v->type) {
    case SNMP_TP_BOOL:
    case SNMP_TP_INT:
    case SNMP_TP_COUNTER:
    case SNMP_TP_GAUGE:
        v->value = malloc(sizeof(int));
        r = asn1_dec_int(b, i, l, (int *)v->value);
        break;
    case SNMP_TP_COUNTER64:
    case SNMP_TP_INT64:
    case SNMP_TP_UINT64:
    case SNMP_TP_TIMETICKS:
        v->value = malloc(sizeof(long long));
        r = asn1_dec_long(b, i, l, (long long *)v->value);
        break;
    case SNMP_TP_BIT_STR:
    case SNMP_TP_OCT_STR:
    case SNMP_TP_IP_ADDR:
    default:
        v->value = calloc(1, sizeof(asn1_str_t));
        r = asn1_dec_string(b, i, l, (asn1_str_t *)v->value);
        break;
    case SNMP_TP_OID:
        v->value = calloc(1, sizeof(asn1_oid_t));
        r = asn1_dec_oid(b, i, l, (asn1_oid_t *)v->value);
        break;
    case SNMP_TP_NULL:
    case SNMP_TP_NO_SUCH_OBJ:
    case SNMP_TP_NO_SUCH_INSTANCE:
    case SNMP_TP_END_OF_MIB_VIEW:
        r = asn1_dec_string(b, i, l, NULL);
        break;
    }
    if (r) {
        asn1_set_error(&v->error, *i, "bad var value");
        return -1;
    }

    return 0;
}

static int _dec_pdu3(const char *b, int *i, int l, int tp, void *p_) {
    snmp_pdu_t *p = (snmp_pdu_t *)p_;

    snmp_free_pdu_vars(p);

    while (*i < l) {
        snmp_var_t v = {0};
        int r = asn1_dec_sequence(b, i, l, _dec_var, &v);
        if (r < 0) {
            p->error = v.error;
            snmp_free_var(&v);
            return -1;
        }

        r = _append_var(p, v);
        if (r) {
            asn1_set_error(&p->error, *i, "alloc vars array");
            snmp_free_var(&v);
            return -1;
        }
    }

    if (*i != l) {
        asn1_set_error(&p->error, *i, "unexpected end of stream");
        return -1;
    }

    return 0;
}

static int _dec_pdu2(const char *b, int *i, int l, int tp, void *p_) {
    snmp_pdu_t *p = (snmp_pdu_t *)p_;

    p->command = tp;

    if (b[(*i)++] != ASN1_INT) {
        asn1_set_error(&p->error, *i, "request id expected");
        return -1;
    }

    int r = asn1_dec_int(b, i, l, &p->req_id);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "bad request id");
        return -1;
    }

    if (tp == SNMP_CMD_GET_BULK) {
        if (b[(*i)++] != ASN1_INT) {
            asn1_set_error(&p->error, *i, "max repeaters expected");
            return -1;
        }

        r = asn1_dec_int(b, i, l, &p->max_repeaters);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "bad max repeaters");
            return -1;
        }

        if (b[(*i)++] != ASN1_INT) {
            asn1_set_error(&p->error, *i, "max repetitions expected");
            return -1;
        }

        r = asn1_dec_int(b, i, l, &p->max_repetitions);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "bad max repetitions");
            return -1;
        }
    } else {
        if (b[(*i)++] != ASN1_INT) {
            asn1_set_error(&p->error, *i, "error status expected");
            return -1;
        }

        r = asn1_dec_int(b, i, l, &p->error_status);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "bad error status");
            return -1;
        }

        if (b[(*i)++] != ASN1_INT) {
            asn1_set_error(&p->error, *i, "error index expected");
            return -1;
        }

        r = asn1_dec_int(b, i, l, &p->error_index);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "bad error index");
            return -1;
        }
    }

    r = asn1_dec_sequence(b, i, l, _dec_pdu3, p);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "pdu2 seq");
        return -1;
    }

    return 0;
}

static int _dec_pdu(const char *b, int *i, int l, int tp, void *p_) {
    snmp_pdu_t *p = (snmp_pdu_t *)p_;

    if (*i >= l) {
        asn1_set_error(&p->error, *i, "empty stream");
        return -1;
    }

    if (b[(*i)++] != ASN1_INT) {
        asn1_set_error(&p->error, *i, "version expected");
        return -1;
    }

    int r = asn1_dec_int(b, i, l, &p->version);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "unsupported version");
        return -1;
    }

    if (*i >= l) {
        asn1_set_error(&p->error, *i, "unexpected end of stream");
        return -1;
    }

    if (b[(*i)++] != ASN1_OCT_STR) {
        asn1_set_error(&p->error, *i, "community expected");
        return -1;
    }

    r = asn1_dec_string(b, i, l, &p->community);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "bad community");
        return -1;
    }

    r = asn1_dec_sequence(b, i, l, _dec_pdu2, p);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "pdu1 seq");
        return -1;
    }

    return 0;
}

int snmp_dec_pdu(const char *buf, int buf_len, snmp_pdu_t *p) {
    // fprintf(stderr, "pdu:\n");
    // _hex_dump(buf, 0, buf_len);

    int i = 0;
    int r = asn1_dec_sequence(buf, &i, buf_len, _dec_pdu, p);
    if (r < 0) {
        asn1_set_error(&p->error, i, "pdu seq");
        return r;
    }

    if (i < buf_len) {
        asn1_set_error(&p->error, i, "unused data at the end of pdu");
        return -1;
    }
    if (i > buf_len) {
        asn1_set_error(&p->error, i, "unexpected end of stream");
        return -1;
    }

    return 0;
}

static int _enc_var(char **b, int *i, int *l, void *v_) {
    snmp_var_t *v = (snmp_var_t *)v_;

    int r = asn1_enc_oid(b, i, l, ASN1_OID, v->oid);
    if (r) {
        asn1_set_error(&v->error, *i, "encode var oid");
        return -1;
    }

    switch (v->type) {
    case 0:
    default:
        asn1_set_error(&v->error, *i, "undefined var type");
        return -1;
    case SNMP_TP_BOOL:
    case SNMP_TP_INT:
    case SNMP_TP_COUNTER:
    case SNMP_TP_GAUGE:
        r = asn1_enc_int(b, i, l, v->type, *(int *)v->value);
        break;
    case SNMP_TP_COUNTER64:
    case SNMP_TP_INT64:
    case SNMP_TP_UINT64:
    case SNMP_TP_TIMETICKS:
        r = asn1_enc_long(b, i, l, v->type, *(long long *)v->value);
        break;
    case SNMP_TP_BIT_STR:
    case SNMP_TP_OCT_STR:
    case SNMP_TP_IP_ADDR:
        r = asn1_enc_string(b, i, l, v->type, *(asn1_str_t *)v->value);
        break;
    case SNMP_TP_OID:
        r = asn1_enc_oid(b, i, l, v->type, *(asn1_oid_t *)v->value);
        break;
    case SNMP_TP_NULL:
    case SNMP_TP_NO_SUCH_OBJ:
    case SNMP_TP_NO_SUCH_INSTANCE:
    case SNMP_TP_END_OF_MIB_VIEW:
        r = asn1_enc_null(b, i, l, v->type);
        break;
    }

    if (r) {
        asn1_set_error(&v->error, *i, "encode var value");
        return -1;
    }

    return 0;
}

static int _enc_pdu3(char **b, int *i, int *l, void *p_) {
    snmp_pdu_t *p = (snmp_pdu_t *)p_;

    for (int j = 0; j < p->vars_len; j++) {
        p->vars[j].error = (asn1_error_t){0};

        int r = asn1_enc_sequence(b, i, l, ASN1_CONSTRUCTOR | ASN1_SEQ, _enc_var, &p->vars[j]);
        if (r) {
            p->error = p->vars[j].error;
            asn1_set_error(&p->error, *i, "encode var sequence");
            return -1;
        }
    }

    return 0;
}

static int _enc_pdu2(char **b, int *i, int *l, void *p_) {
    snmp_pdu_t *p = (snmp_pdu_t *)p_;

    int r = asn1_enc_int(b, i, l, ASN1_INT, p->req_id);
    if (r) {
        asn1_set_error(&p->error, *i, "encode req id");
        return -1;
    }

    if (p->command == SNMP_CMD_GET_BULK) {
        r = asn1_enc_int(b, i, l, ASN1_INT, p->max_repeaters);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "encode max repeaters");
            return -1;
        }

        r = asn1_enc_int(b, i, l, ASN1_INT, p->max_repetitions);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "encode max repetitions");
            return -1;
        }
    } else {
        r = asn1_enc_int(b, i, l, ASN1_INT, p->error_status);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "encode error status");
            return -1;
        }

        r = asn1_enc_int(b, i, l, ASN1_INT, p->error_index);
        if (r < 0) {
            asn1_set_error(&p->error, *i, "encode error index");
            return -1;
        }
    }

    r = asn1_enc_sequence(b, i, l, ASN1_CONSTRUCTOR | ASN1_SEQ, _enc_pdu3, p);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "pdu2 seq");
        return -1;
    }

    return 0;
}

static int _enc_pdu(char **b, int *i, int *l, void *p_) {
    snmp_pdu_t *p = (snmp_pdu_t *)p_;

    int r = asn1_enc_int(b, i, l, ASN1_INT, p->version);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "encode version");
        return -1;
    }

    r = asn1_enc_string(b, i, l, ASN1_OCT_STR, p->community);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "encode community");
        return -1;
    }

    r = asn1_enc_sequence(b, i, l, p->command, _enc_pdu2, p);
    if (r < 0) {
        asn1_set_error(&p->error, *i, "pdu1 seq");
        return -1;
    }

    return 0;
}

int snmp_enc_pdu(char **buf, int *i, int *buf_len, snmp_pdu_t *p) {
    int r = asn1_enc_sequence(buf, i, buf_len, ASN1_CONSTRUCTOR | ASN1_SEQ, _enc_pdu, p);
    if (r) {
        asn1_set_error(&p->error, *i, "pdu seq");
        return -1;
    }

    return 0;
}

int snmp_recv_pdu(int fd, snmp_pdu_t *p) {
    int ret = -1;

    p->error = (asn1_error_t){0};

    int buf_len = 20 * (1 << 10);
    char *buf = malloc(buf_len);
    if (!buf) {
        asn1_set_error(&p->error, -1, "alloc read buffer");
        goto error;
    }

    p->addr_len = sizeof(p->addr);
    memset(&p->addr, 0, p->addr_len);

    ssize_t n = recvfrom(fd, (void *)buf, buf_len, 0, (struct sockaddr *)&p->addr, &p->addr_len);
    if (n < 0) {
        asn1_set_error(&p->error, -1, "recvfrom");
        ret = n;
        goto error;
    }

    int r = snmp_dec_pdu(buf, n, p);
    if (r < 0) {
        goto error;
    }

    ret = n;

error:
    if (buf) {
        free(buf);
    }

    return ret;
}

int snmp_send_pdu(int fd, snmp_pdu_t *p) {
    int ret = -1;

    p->error = (asn1_error_t){0};

    int buf_len = 20 * (1 << 10);
    char *buf = malloc(buf_len);
    if (!buf) {
        asn1_set_error(&p->error, -1, "alloc encode buffer");
        goto error;
    }

    int m = 0;
    int r = snmp_enc_pdu(&buf, &m, &buf_len, p);
    if (r) {
        goto error;
    }

    // fprintf(stderr, "sending:\n");
    // _hex_dump(buf, 0, m);

    ssize_t n = sendto(fd, buf, m, 0, (struct sockaddr *)&p->addr, p->addr_len);
    if (n < 0) {
        asn1_set_error(&p->error, -1, "sendto");
        ret = n;
        goto error;
    }

    ret = n;

error:
    if (buf) {
        free(buf);
    }

    return ret;
}

int snmp_dump_packet(int fd) {
    int ret = -1;

    size_t buf_len = 20 * (1 << 10);
    char *buf = malloc(buf_len);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&addr, 0, addr_len);

    ssize_t n = recvfrom(fd, (void *)buf, buf_len, 0, (struct sockaddr *)&addr, &addr_len);
    if (n < 0) {
        goto error;
    }

    _hex_dump(buf, 0, n);

    ssize_t n1 = sendto(fd, (void *)buf, n, 0, (struct sockaddr *)&addr, addr_len);
    if (n1 < 0 || n1 != n) {
        goto error;
    }

    ret = 0;

error:
    if (buf) {
        free(buf);
    }

    return ret;
}

void snmp_dump_var(snmp_var_t *v) {
    asn1_dump_oid(v->oid);

    fprintf(stderr, ": (tp %x) ", v->type);

    switch (v->type) {
    case SNMP_TP_BOOL:
    case SNMP_TP_INT:
    case SNMP_TP_COUNTER:
    case SNMP_TP_GAUGE:
        fprintf(stderr, "%d", *(int *)v->value);
        break;
    case SNMP_TP_COUNTER64:
    case SNMP_TP_INT64:
    case SNMP_TP_UINT64:
    case SNMP_TP_TIMETICKS:
        fprintf(stderr, "%lld", *(long long *)v->value);
        break;
    case SNMP_TP_BIT_STR:
    case SNMP_TP_OCT_STR:
        fprintf(stderr, "%s", ((asn1_str_t *)v->value)->b);
        break;
    case SNMP_TP_IP_ADDR: {
        asn1_str_t *str = (asn1_str_t *)v->value;
        for (int j = 0; j < str->len; j++) {
            if (j != 0) {
                fprintf(stderr, ".");
            }
            fprintf(stderr, "%d", str->b[j]);
        }
        break;
    }
    case SNMP_TP_OID:
        asn1_dump_oid(*(asn1_oid_t *)v->value);
        break;
    case SNMP_TP_NULL:
    case SNMP_TP_NO_SUCH_OBJ:
    case SNMP_TP_NO_SUCH_INSTANCE:
    case SNMP_TP_END_OF_MIB_VIEW:
    default: {
        asn1_str_t *str = (asn1_str_t *)v->value;
        if (str) {
            fprintf(stderr, "null [%x] (%d)", v->type, str->len);
        } else {
            fprintf(stderr, "null [%x]", v->type);
        }
        break;
    }
    }
}

void snmp_dump_pdu(const char *msg, snmp_pdu_t *p) {
    fprintf(stderr, "%s: ver %c community %s command %-9s (%x) (%d vars) reqid %x %s %d,%d\n",  //
            (msg == NULL ? "pdu" : msg), '0' + p->version,                                      //
            p->community.b, snmp_command_str(p->command), p->command, p->vars_len, p->req_id,   //
            p->command == SNMP_CMD_GET_BULK ? "max" : "err",                                    //
            p->command == SNMP_CMD_GET_BULK ? p->max_repeaters : p->error_status,               //
            p->command == SNMP_CMD_GET_BULK ? p->max_repetitions : p->error_index);

    for (int i = 0; i < p->vars_len; i++) {
        fprintf(stderr, "    var[%2d]: ", i);
        snmp_dump_var(&p->vars[i]);
        fprintf(stderr, "\n");
    }
}

const char *snmp_command_str(int c) {
    int q = c & 0xf;
    if (q < 0 || q > SNMP_CMD_GET_BULK) {
        return "undefined";
    }

    const char *a[] = {"GET", "GETNEXT", "RESPONSE", "SET", "TRAP", "GETBULK"};

    return a[q];
}

int *snmp_new_int(int v) {
    int *r = malloc(sizeof(v));
    *r = v;
    return r;
}

long long *snmp_new_long(long long v) {
    long long *r = malloc(sizeof(v));
    *r = v;
    return r;
}
