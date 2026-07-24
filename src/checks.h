#ifndef CHECKS_H
#define CHECKS_H

#include <stddef.h>
#include <time.h>


#define MAX_NAME 64
#define MAX_PATH 256
#define MAX_CVE 8
#define MAX_CVE_STR 32
#define MAX_CHECKS 64
#define MAX_LINE 4096
#define MAX_DESC 192

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define BOLD  "\x1B[1m"
#define RESET "\x1B[0m"

typedef enum {
    PASS = 0,
    WARN,
    VULN,
    SKIP,
    ERROR_RESULT
} result_t;

typedef enum {
    CAT_MEMORY = 0,
    CAT_KERNEL,
    CAT_NETWORK,
    CAT_FILESYSTEM,
    CAT_CPU,
    CAT_CRYPTO,
    CAT_EXEC
} category_t;

typedef enum {
    OP_EQ = 0,
    OP_GE,
    OP_LE,
    OP_NE,
    OP_CONTAINS,
    OP_ALWAYS
} op_t;

typedef enum {
    TYPE_INT = 0,
    TYPE_STR
} check_type_t;

typedef struct {
    int id;
    char name[MAX_NAME];
    char path[MAX_PATH];
    char desc[MAX_DESC];
    int expected_val;
    op_t op;
    category_t category;
    check_type_t type;
    int remediable;
    int remediate_val;
    char cves[MAX_CVE][MAX_CVE_STR];
    int cve_count;
    result_t (*custom_fn)(int *val, char *str, size_t str_size);
    result_t fail_result;
} check_def_t;

typedef struct {
    int id;
    result_t result;
    int current_val;
    char current_str[MAX_DESC];
} check_result_t;

typedef struct {
    char name[64];
    char desc[256];
    char version[16];
    int override_count;
    int override_ids[MAX_CHECKS];
    int override_vals[MAX_CHECKS];
    op_t override_ops[MAX_CHECKS];
} profile_t;

int run_all_checks(check_result_t *results, int max_results, const char *profile_path);
void print_results(const check_result_t *results, int count);
void print_summary(const check_result_t *results, int count);
int apply_remediation(const check_result_t *results, int count, int force);
int export_json(const check_result_t *results, int count, const char *outdir);
int export_csv(const check_result_t *results, int count, const char *outdir);
int export_html(const check_result_t *results, int count, const char *outdir);
int load_profile(const char *path, profile_t *profile);
int run_watch(int interval, const char *profile_path, int json, int csv, int html, const char *outdir);
int send_webhook(const char *url, const char *outdir);

#endif
