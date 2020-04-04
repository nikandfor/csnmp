#pragma once

// types
#define ASN1_BOOL    0x1
#define ASN1_INT     0x2
#define ASN1_BIT_STR 0x3
#define ASN1_OCT_STR 0x4
#define ASN1_NULL    0x5
#define ASN1_OID     0x6
#define ASN1_SEQ     0x10
#define ASN1_SET     0x11

#define ASN1_UNIVERSAL   0x0
#define ASN1_APPLICATION 0x40
#define ASN1_CONTEXT     0x80
#define ASN1_PRIVATE     0xc0

#define ASN1_PRIMITIVE   0x0
#define ASN1_CONSTRUCTOR 0x20

#define ASN1_LONGLEN 0x80

typedef struct {
    char *b;
    int len;
} asn1_str_t;

typedef struct {
    int *b;
    int len;
} asn1_oid_t;

typedef struct {
    int code;
    int pos;
    const char *message;
} asn1_error_t;

void asn1_set_error(asn1_error_t *s, int p, const char *m);

void asn1_free_oid(asn1_oid_t *id);
void asn1_free_str(asn1_str_t *s);

int asn1_dec_length(const char *b, int *i, int l);

int asn1_dec_int(const char *b, int *i, int l, int *val);
int asn1_dec_long(const char *b, int *i, int l, long long *val);
int asn1_dec_oid(const char *b, int *i, int l, asn1_oid_t *val);
int asn1_dec_string(const char *b, int *i, int l, asn1_str_t *val);

int asn1_dec_sequence(const char *b, int *i, int l, int (*c)(const char *b, int *i, int l, int tp, void *arg), void *arg);

int asn1_enc_null(char **b, int *i, int *l, int tp);
int asn1_enc_int(char **b, int *i, int *l, int tp, int val);
int asn1_enc_long(char **b, int *i, int *l, int tp, long long val);
int asn1_enc_oid(char **b, int *i, int *l, int tp, asn1_oid_t val);
int asn1_enc_string(char **b, int *i, int *l, int tp, asn1_str_t val);

int asn1_enc_sequence(char **b, int *i, int *l, int tp, int (*c)(char **b, int *i, int *l, void *arg), void *arg);

void asn1_dump_oid(asn1_oid_t d);
