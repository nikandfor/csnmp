#include "asn1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int asn1_cmp_oids(asn1_oid_t a, asn1_oid_t b) {
    for (int j = 0; j < a.len && j < b.len; j++) {
        if (a.b[j] < b.b[j]) {
            return -1;
        }

        if (a.b[j] > b.b[j]) {
            return 1;
        }
    }

    if (a.len == b.len) {
        return 0;
    }

    if (a.len < b.len) {
        return -1;
    }

    return 1;
}

int asn1_oid_has_prefix(asn1_oid_t a, asn1_oid_t b) {
    for (int j = 0; j < a.len && j < b.len; j++) {
        if (a.b[j] != b.b[j]) {
            return 0;
        }
    }

    if (a.len < b.len) {
        return 0;
    }

    return 1;
}

void asn1_set_error(asn1_error_t *s, int p, const char *m) {
    if (s->code) {
        return;
    }

    s->code = -1;
    s->pos = p;
    s->message = m;
}

void asn1_free_oid(asn1_oid_t *id) {
    if (id->b) {
        free(id->b);
        id->b = NULL;
    }
    id->len = 0;
}

void asn1_free_str(asn1_str_t *s) {
    if (s->b) {
        free(s->b);
        s->b = NULL;
    }
    s->len = 0;
}

asn1_oid_t asn1_crt_oid(const int *id, int l) {
    asn1_oid_t v;

    v.len = l;
    v.b = malloc(l * sizeof(int));
    memcpy(v.b, id, l * sizeof(int));

    return v;
}

asn1_oid_t *asn1_new_oid(const int *id, int l) {
    asn1_oid_t *v = malloc(sizeof(*v));

    v->len = l;
    v->b = malloc(l * sizeof(int));
    memcpy(v->b, id, l * sizeof(int));

    return v;
}

inline asn1_str_t *asn1_new_str(const char *msg, int l) {
    if (l == 0) {
        l = strlen(msg);
    }

    asn1_str_t *v = malloc(sizeof(*v));

    v->len = l;
    v->b = malloc(l + 1);
    memcpy(v->b, msg, l + 1);

    return v;
}

int asn1_dec_length(const char *b, int *i, int l) {
    int res = 0;

    if (*i >= l) {
        return -1;
    }

    int n = b[(*i)++];

    if ((n & ASN1_LONGLEN) != ASN1_LONGLEN) {
        return n;
    }

    n &= 0xf;

    if (*i + n > l) {
        return -1;
    }

    for (int j = 0; j < n; j++) {
        res = res << 8 | b[(*i)++];
    }

    return res;
}

int asn1_dec_int(const char *b, int *i, int l, int *val) {
    if (*i >= l) {
        return -1;
    }

    int n = b[(*i)++];

    if (*i + n > l) {
        return -1;
    }

    int res = 0;

    for (int j = 0; j < n; j++) {
        res = res << 8 | ((int)b[(*i)++] & 0xff);
    }

    if (val) {
        *val = res;
    }

    return 0;
}

int asn1_dec_long(const char *b, int *i, int l, long long *val) {
    if (*i >= l) {
        return -1;
    }

    int n = b[(*i)++];

    if (*i + n > l) {
        return -1;
    }

    long long res = 0;

    for (int j = 0; j < n; j++) {
        res = res << 8 | b[(*i)++];
    }

    if (val) {
        *val = res;
    }

    return 0;
}

int asn1_dec_string(const char *b, int *i, int l, asn1_str_t *val) {
    int n = asn1_dec_length(b, i, l);
    if (n < 0) {
        return -1;
    }
    if (*i + n > l) {
        return -1;
    }

    if (val) {
        val->len = n;

        val->b = realloc(val->b, n + 1);
        memcpy(val->b, b + *i, n);
        val->b[n] = '\0';
    }

    *i += n;

    return 0;
}

int asn1_dec_oid(const char *b, int *i, int l, asn1_oid_t *id) {
    int n = asn1_dec_length(b, i, l);
    if (n < 0) {
        return -1;
    }
    if (*i + n > l) {
        return -1;
    }
    if (n == 0) {
        return 0;
    }

    id->b = realloc(id->b, (n + 1) * sizeof(int));
    id->len = 2;

    id->b[0] = b[*i] / 40;
    id->b[1] = b[(*i)++] % 40;

    int buf = 0;
    for (int j = 1; j < n; j++) {
        int q = b[(*i)++];

        buf = buf << 7 | (q & 0x7f);

        if ((q & 0x80) == 0) {
            id->b[id->len++] = buf;
            buf = 0;
        }
    }

    return 0;
}

int asn1_dec_sequence(const char *b, int *i, int l, int (*c)(const char *b, int *i, int l, int tp, void *arg), void *arg) {
    if (*i >= l) {
        return -1;
    }

    int tp = (int)b[(*i)++] & 0xff;

    int rl = asn1_dec_length(b, i, l);
    if (rl < 0) {
        return -1;
    }

    return c(b, i, *i + rl, tp, arg);
}

int _grow(char **buf, int *i, int *l, int s) {
    if (*i + s <= *l) {
        return 0;
    }

    if (*l == 0) {
        *l = 20;
    } else if (*l < 1000) {
        *l *= 2;
    } else {
        *l += *l / 4;
    }

    *buf = realloc(*buf, *l);
    if (*buf == NULL) {
        return -1;
    }

    return 0;
}

static int _len_size(int l) {
    if (l < 0x80) {
        return 1;
    }

    int s = 2;

    for (unsigned q = l >> 8; q != 0; q >>= 8) {
        s++;
    }

    return s;
}

static void _enc_len(char *buf, int *i, int len) {
    if (len < 0x80) {
        buf[(*i)++] = len;
        return;
    }

    int n = 1;
    for (unsigned q = len >> 8; q != 0; q >>= 8) {
        n++;
    }

    buf[(*i)++] = n | ASN1_LONGLEN;

    for (int j = n - 1; j >= 0; j--) {
        buf[(*i)++] = len >> (8 * j);
    }
}

int asn1_enc_null(char **buf, int *i, int *l, int tp) {
    int r = _grow(buf, i, l, 2);
    if (r) {
        return -1;
    }

    (*buf)[(*i)++] = tp;
    (*buf)[(*i)++] = 0;

    return 0;
}

int asn1_enc_int(char **buf, int *i, int *l, int tp, int val) {
    int n = 1;
    for (unsigned q = val >> 8; q != 0; q >>= 8) {
        n++;
    }

    int r = _grow(buf, i, l, 2 + n);
    if (r) {
        return -1;
    }

    (*buf)[(*i)++] = tp;
    (*buf)[(*i)++] = n;

    for (int j = n - 1; j >= 0; j--) {
        (*buf)[(*i)++] = val >> (8 * j);
    }

    return 0;
}

int asn1_enc_long(char **buf, int *i, int *l, int tp, long long val) {
    int n = 1;
    for (unsigned long long q = val >> 8; q != 0; q >>= 8) {
        n++;
    }

    int r = _grow(buf, i, l, 2 + n);
    if (r) {
        return -1;
    }

    (*buf)[(*i)++] = tp;
    (*buf)[(*i)++] = n;

    for (int j = n - 1; j >= 0; j--) {
        (*buf)[(*i)++] = val >> (8 * j);
    }

    return 0;
}

int asn1_enc_string(char **buf, int *i, int *l, int tp, asn1_str_t val) {
    int r = _grow(buf, i, l, 1 + _len_size(val.len) + val.len);
    if (r) {
        return -1;
    }

    (*buf)[(*i)++] = tp;
    _enc_len(*buf, i, val.len);
    memcpy(*buf + *i, val.b, val.len);

    *i += val.len;

    return 0;
}

int asn1_enc_oid(char **buf, int *i, int *l, int tp, asn1_oid_t val) {
    int len = 1;
    for (int j = 2; j < val.len; j++) {
        int q = val.b[j];

        if (q < 0x80) {
            len++;
        } else if (q < 0x4000) {
            len += 2;
        } else if (q < 0x200000) {
            len += 3;
        } else if (q < 0x10000000) {
            len += 4;
        } else {
            len += 5;
        }
    }

    int r = _grow(buf, i, l, 1 + _len_size(len) + len);
    if (r) {
        return -1;
    }

    (*buf)[(*i)++] = tp;
    _enc_len(*buf, i, len);

    if (val.len == 0) {
        (*buf)[(*i)++] = 0;
    } else if (val.b[0] > 2) {
        return -1;
    } else if (val.len == 1) {
        (*buf)[(*i)++] = val.b[0] * 40;
    } else if (val.b[1] >= 40) {
        return -1;
    } else {
        (*buf)[(*i)++] = val.b[0] * 40 + val.b[1];
    }

    for (int j = 2; j < val.len; j++) {
        int q = val.b[j];

        if (q < 0x80) {
            (*buf)[(*i)++] = q;
        } else if (q < 0x4000) {
            (*buf)[(*i)++] = (q >> 7) | 0x80;
            (*buf)[(*i)++] = q & 0x7f;
        } else if (q < 0x200000) {
            (*buf)[(*i)++] = (q >> 14) | 0x80;
            (*buf)[(*i)++] = (q >> 7) | 0x80;
            (*buf)[(*i)++] = q & 0x7f;
        } else if (q < 0x10000000) {
            (*buf)[(*i)++] = (q >> 21) | 0x80;
            (*buf)[(*i)++] = (q >> 14) | 0x80;
            (*buf)[(*i)++] = (q >> 7) | 0x80;
            (*buf)[(*i)++] = q & 0x7f;
        } else {
            (*buf)[(*i)++] = (q >> 28) | 0x80;
            (*buf)[(*i)++] = (q >> 21) | 0x80;
            (*buf)[(*i)++] = (q >> 14) | 0x80;
            (*buf)[(*i)++] = (q >> 7) | 0x80;
            (*buf)[(*i)++] = q & 0x7f;
        }
    }

    return 0;
}

int asn1_enc_sequence(char **buf, int *i, int *l, int tp, int (*c)(char **buf, int *i, int *l, void *arg), void *arg) {
    int st = *i;

    int r = c(buf, i, l, arg);
    if (r) {
        return -1;
    }

    int len = *i - st;
    int ll = _len_size(len);

    r = _grow(buf, &st, l, 1 + ll + len);
    if (r) {
        return -1;
    }

    memmove(*buf + st + 1 + ll, *buf + st, len);

    (*buf)[st++] = tp;
    _enc_len(*buf, &st, len);

    *i += 1 + ll;

    return 0;
}

void asn1_dump_oid(asn1_oid_t d) {
    for (int j = 0; j < d.len; j++) {
        if (j != 0) {
            fprintf(stderr, ".");
        }
        fprintf(stderr, "%d", d.b[j]);
    }
}
