#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include "checks.h"

static result_t check_entropy_fn(int *val, char *str, size_t sz);
static result_t check_spectre_fn(int *val, char *str, size_t sz);
static result_t check_meltdown_fn(int *val, char *str, size_t sz);
static result_t check_l1tf_fn(int *val, char *str, size_t sz);
static result_t check_mds_fn(int *val, char *str, size_t sz);
static result_t check_core_pattern_fn(int *val, char *str, size_t sz);

static const char *category_names[] = {
    "memory", "kernel", "network", "filesystem", "cpu", "crypto", "exec"
};

static const check_def_t check_table[] = {
    {
        1, "aslr",
        "/proc/sys/kernel/randomize_va_space",
        "ASLR Full Randomization",
        2, OP_EQ, CAT_MEMORY, TYPE_INT,
        1, 2,
        {{""}}, 0,
        NULL, VULN
    },
    {
        2, "kptr_restrict",
        "/proc/sys/kernel/kptr_restrict",
        "Kernel Pointer Restriction",
        2, OP_GE, CAT_KERNEL, TYPE_INT,
        1, 2,
        {{"CVE-2015-1333"}}, 1,
        NULL, VULN
    },
    {
        3, "ptrace_scope",
        "/proc/sys/kernel/yama/ptrace_scope",
        "Yama Ptrace Scope",
        1, OP_GE, CAT_KERNEL, TYPE_INT,
        1, 1,
        {{"CVE-2019-13272"}}, 1,
        NULL, WARN
    },
    {
        4, "dmesg_restrict",
        "/proc/sys/kernel/dmesg_restrict",
        "Dmesg Restriction",
        1, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 1,
        {{"CVE-2018-10124"}}, 1,
        NULL, VULN
    },
    {
        5, "bpf_jit_harden",
        "/proc/sys/net/core/bpf_jit_harden",
        "BPF JIT Hardening",
        2, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 2,
        {{"CVE-2016-4557"}}, 1,
        NULL, WARN
    },
    {
        6, "tcp_syncookies",
        "/proc/sys/net/ipv4/tcp_syncookies",
        "TCP SYN Cookie Protection",
        1, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, WARN
    },
    {
        7, "userns_clone",
        "/proc/sys/kernel/unprivileged_userns_clone",
        "Unprivileged User Namespaces",
        0, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 0,
        {{"CVE-2021-22555"}, {"CVE-2022-0185"}}, 2,
        NULL, WARN
    },
    {
        8, "ip_forward",
        "/proc/sys/net/ipv4/ip_forward",
        "IPv4 Forwarding Disabled",
        0, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 0,
        {{""}}, 0,
        NULL, VULN
    },
    {
        9, "protected_symlinks",
        "/proc/sys/fs/protected_symlinks",
        "Protected Symlinks",
        1, OP_EQ, CAT_FILESYSTEM, TYPE_INT,
        1, 1,
        {{"CVE-2018-1000001"}}, 1,
        NULL, VULN
    },
    {
        10, "protected_hardlinks",
        "/proc/sys/fs/protected_hardlinks",
        "Protected Hardlinks",
        1, OP_EQ, CAT_FILESYSTEM, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, VULN
    },
    {
        11, "kexec_disabled",
        "/proc/sys/kernel/kexec_load_disabled",
        "Kexec Loading Disabled",
        1, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, WARN
    },
    {
        12, "perf_event_paranoid",
        "/proc/sys/kernel/perf_event_paranoid",
        "Perf Event Restrictions",
        2, OP_GE, CAT_KERNEL, TYPE_INT,
        1, 3,
        {{"CVE-2013-2094"}}, 1,
        NULL, VULN
    },
    {
        13, "rp_filter_all",
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "Reverse Path Filter (all)",
        1, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, VULN
    },
    {
        14, "rp_filter_default",
        "/proc/sys/net/ipv4/conf/default/rp_filter",
        "Reverse Path Filter (default)",
        1, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, VULN
    },
    {
        15, "tcp_rfc1337",
        "/proc/sys/net/ipv4/tcp_rfc1337",
        "TCP TIME-WAIT Assassination",
        1, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, WARN
    },
    {
        16, "icmp_ignore_bogus",
        "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses",
        "ICMP Bogus Error Protection",
        1, OP_EQ, CAT_NETWORK, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, WARN
    },
    {
        17, "arp_ignore",
        "/proc/sys/net/ipv4/conf/all/arp_ignore",
        "ARP Ignore Mode",
        1, OP_GE, CAT_NETWORK, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, WARN
    },
    {
        18, "arp_announce",
        "/proc/sys/net/ipv4/conf/all/arp_announce",
        "ARP Announce Mode",
        2, OP_GE, CAT_NETWORK, TYPE_INT,
        1, 2,
        {{""}}, 0,
        NULL, WARN
    },
    {
        19, "unpriv_bpf",
        "/proc/sys/kernel/unprivileged_bpf_disabled",
        "Unprivileged BPF Disabled",
        1, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 1,
        {{"CVE-2020-8835"}}, 1,
        NULL, VULN
    },
    {
        20, "ftrace_enabled",
        "/proc/sys/kernel/ftrace_enabled",
        "Ftrace Disabled",
        0, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 0,
        {{""}}, 0,
        NULL, WARN
    },
    {
        21, "core_uses_pid",
        "/proc/sys/kernel/core_uses_pid",
        "Core Dump PID Naming",
        1, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 1,
        {{""}}, 0,
        NULL, WARN
    },
    {
        22, "sysrq",
        "/proc/sys/kernel/sysrq",
        "SysRq Restricted",
        0, OP_EQ, CAT_KERNEL, TYPE_INT,
        1, 0,
        {{""}}, 0,
        NULL, WARN
    },
    {
        23, "mmap_min_addr",
        "/proc/sys/vm/mmap_min_addr",
        "MMAP Minimum Address",
        65536, OP_GE, CAT_MEMORY, TYPE_INT,
        1, 65536,
        {{"CVE-2012-0056"}}, 1,
        NULL, VULN
    },
    {
        24, "entropy_avail",
        "/proc/sys/kernel/random/entropy_avail",
        "System Entropy",
        200, OP_GE, CAT_CRYPTO, TYPE_INT,
        0, 0,
        {{""}}, 0,
        check_entropy_fn, WARN
    },
    {
        25, "spectre_v2",
        "/sys/devices/system/cpu/vulnerabilities/spectre_v2",
        "Spectre V2 Mitigation",
        0, OP_CONTAINS, CAT_CPU, TYPE_STR,
        0, 0,
        {{"CVE-2017-5715"}}, 1,
        check_spectre_fn, VULN
    },
    {
        26, "meltdown",
        "/sys/devices/system/cpu/vulnerabilities/meltdown",
        "Meltdown Mitigation",
        0, OP_CONTAINS, CAT_CPU, TYPE_STR,
        0, 0,
        {{"CVE-2017-5754"}}, 1,
        check_meltdown_fn, VULN
    },
    {
        27, "l1tf",
        "/sys/devices/system/cpu/vulnerabilities/l1tf",
        "L1TF Mitigation",
        0, OP_CONTAINS, CAT_CPU, TYPE_STR,
        0, 0,
        {{"CVE-2018-3620"}, {"CVE-2018-3646"}}, 2,
        check_l1tf_fn, VULN
    },
    {
        28, "mds",
        "/sys/devices/system/cpu/vulnerabilities/mds",
        "MDS Mitigation",
        0, OP_CONTAINS, CAT_CPU, TYPE_STR,
        0, 0,
        {{"CVE-2018-12126"}, {"CVE-2018-12130"}, {"CVE-2018-12127"}, {"CVE-2019-11091"}}, 4,
        check_mds_fn, VULN
    },
    {
        29, "core_pattern",
        "/proc/sys/kernel/core_pattern",
        "Core Dump Handler Safety",
        0, OP_ALWAYS, CAT_EXEC, TYPE_STR,
        0, 0,
        {{""}}, 0,
        check_core_pattern_fn, VULN
    }
};

static const int check_count = (int)(sizeof(check_table) / sizeof(check_table[0]));

static int read_int(const char *path, int *val)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int r = fscanf(f, "%d", val);
    fclose(f);
    return (r == 1) ? 0 : -1;
}

static int read_str(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)size, f)) {
        fclose(f);
        return -1;
    }
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
        buf[len-1] = '\0';
        len--;
    }
    fclose(f);
    return 0;
}

static result_t check_entropy_fn(int *val, char *str, size_t sz)
{
    (void)str;
    (void)sz;
    if (read_int("/proc/sys/kernel/random/entropy_avail", val) != 0) return ERROR_RESULT;
    return (*val >= 200) ? PASS : WARN;
}

static result_t check_spectre_fn(int *val, char *str, size_t sz)
{
    if (read_str("/sys/devices/system/cpu/vulnerabilities/spectre_v2", str, sz) != 0)
        return SKIP;
    *val = 0;
    if (strstr(str, "Mitigation") || strstr(str, "Not affected")) {
        *val = 1;
        return PASS;
    }
    return VULN;
}

static result_t check_meltdown_fn(int *val, char *str, size_t sz)
{
    if (read_str("/sys/devices/system/cpu/vulnerabilities/meltdown", str, sz) != 0)
        return SKIP;
    *val = 0;
    if (strstr(str, "Mitigation") || strstr(str, "Not affected")) {
        *val = 1;
        return PASS;
    }
    return VULN;
}

static result_t check_l1tf_fn(int *val, char *str, size_t sz)
{
    if (read_str("/sys/devices/system/cpu/vulnerabilities/l1tf", str, sz) != 0)
        return SKIP;
    *val = 0;
    if (strstr(str, "Mitigation") || strstr(str, "Not affected")) {
        *val = 1;
        return PASS;
    }
    return VULN;
}

static result_t check_mds_fn(int *val, char *str, size_t sz)
{
    if (read_str("/sys/devices/system/cpu/vulnerabilities/mds", str, sz) != 0)
        return SKIP;
    *val = 0;
    if (strstr(str, "Mitigation") || strstr(str, "Not affected")) {
        *val = 1;
        return PASS;
    }
    return VULN;
}

static result_t check_core_pattern_fn(int *val, char *str, size_t sz)
{
    if (read_str("/proc/sys/kernel/core_pattern", str, sz) != 0) return ERROR_RESULT;
    *val = 0;
    if (str[0] == '|') {
        return WARN;
    }
    if (strcmp(str, "core") == 0 || strcmp(str, "/var/crash/core") == 0) {
        *val = 1;
        return PASS;
    }
    *val = 1;
    return PASS;
}

int run_all_checks(check_result_t *results, int max_results, const char *profile_path)
{
    int count = 0;
    profile_t profile;
    int use_profile = 0;

    if (profile_path) {
        if (load_profile(profile_path, &profile) == 0) {
            use_profile = 1;
        } else {
            fprintf(stderr, "    " YEL "[!] Warning: Failed to load profile '%s', using defaults\n" RESET, profile_path);
        }
    }

    for (int i = 0; i < check_count && count < max_results; i++) {
        const check_def_t *def = &check_table[i];
        check_result_t *r = &results[count];
        int val = 0;
        char str[MAX_DESC];
        str[0] = '\0';

        int expected = def->expected_val;
        op_t op = def->op;

        if (use_profile) {
            for (int j = 0; j < profile.override_count; j++) {
                if (profile.override_ids[j] == def->id) {
                    expected = profile.override_vals[j];
                    op = profile.override_ops[j];
                    break;
                }
            }
        }

        r->id = def->id;
        r->current_val = 0;
        r->current_str[0] = '\0';

        if (def->custom_fn) {
            r->result = def->custom_fn(&val, str, sizeof(str));
            r->current_val = val;
            if (str[0]) {
                size_t slen = strlen(str);
                if (slen >= sizeof(r->current_str)) slen = sizeof(r->current_str) - 1;
                memcpy(r->current_str, str, slen);
                r->current_str[slen] = '\0';
            }
            if (use_profile && op != def->op) {
                switch (op) {
                    case OP_EQ:
                        r->result = (val == expected) ? PASS : def->fail_result;
                        break;
                    case OP_GE:
                        r->result = (val >= expected) ? PASS : def->fail_result;
                        break;
                    case OP_LE:
                        r->result = (val <= expected) ? PASS : def->fail_result;
                        break;
                    case OP_NE:
                        r->result = (val != expected) ? PASS : def->fail_result;
                        break;
                    default:
                        break;
                }
            }
        } else if (def->type == TYPE_INT) {
            if (read_int(def->path, &val) != 0) {
                r->result = SKIP;
            } else {
                r->current_val = val;
                switch (op) {
                    case OP_EQ:
                        r->result = (val == expected) ? PASS : def->fail_result;
                        break;
                    case OP_GE:
                        r->result = (val >= expected) ? PASS : def->fail_result;
                        break;
                    case OP_LE:
                        r->result = (val <= expected) ? PASS : def->fail_result;
                        break;
                    case OP_NE:
                        r->result = (val != expected) ? PASS : def->fail_result;
                        break;
                    default:
                        r->result = ERROR_RESULT;
                        break;
                }
            }
        } else {
            if (read_str(def->path, str, sizeof(str)) != 0) {
                r->result = SKIP;
            } else {
                size_t slen = strlen(str);
                if (slen >= sizeof(r->current_str)) slen = sizeof(r->current_str) - 1;
                memcpy(r->current_str, str, slen);
                r->current_str[slen] = '\0';
                if (op == OP_CONTAINS) {
                    r->result = (strstr(str, "Mitigation") || strstr(str, "Not affected"))
                        ? PASS : def->fail_result;
                } else if (op == OP_ALWAYS) {
                    r->result = PASS;
                } else {
                    r->result = ERROR_RESULT;
                }
            }
        }

        count++;
    }

    return count;
}

void print_results(const check_result_t *results, int count)
{
    static const char *cat_names[] = {
        "MEMORY", "KERNEL", "NETWORK", "FS", "CPU", "CRYPTO", "EXEC"
    };

    for (int i = 0; i < count; i++) {
        const check_result_t *r = &results[i];
        const check_def_t *def = NULL;
        for (int j = 0; j < check_count; j++) {
            if (check_table[j].id == r->id) {
                def = &check_table[j];
                break;
            }
        }
        if (!def) continue;

        const char *color = GRN;
        const char *symbol = "[+]";
        const char *status_str = "PASS";
        const char *cat = (def->category < 7) ? cat_names[def->category] : "?";

        if (r->result == VULN) {
            color = RED;
            symbol = "[-]";
            status_str = "VULN";
        } else if (r->result == WARN) {
            color = YEL;
            symbol = "[!]";
            status_str = "WARN";
        } else if (r->result == SKIP) {
            color = BLU;
            symbol = "[~]";
            status_str = "SKIP";
        } else if (r->result == ERROR_RESULT) {
            color = RED;
            symbol = "[E]";
            status_str = "ERR";
        }

        printf("    [ %02d ]  %-7s >  %-35s %s%s%s [  %-5s%s ]\n",
               r->id, cat, def->desc, color, symbol, RESET, status_str, RESET);

        if (r->current_str[0] && r->result != PASS) {
            printf("             >  %-35s   (%s)\n", "", r->current_str);
        }
    }
}

void print_summary(const check_result_t *results, int count)
{
    int p = 0, w = 0, v = 0, s = 0, e = 0;
    for (int i = 0; i < count; i++) {
        switch (results[i].result) {
            case PASS: p++; break;
            case WARN: w++; break;
            case VULN: v++; break;
            case SKIP: s++; break;
            default: e++; break;
        }
    }

    printf(BOLD "\n+---Summary---------------------------------------------------------------------+\n" RESET);
    printf("  " GRN "PASS: %02d" RESET " | " YEL "WARN: %02d" RESET " | " RED "VULN: %02d" RESET " | " BLU "SKIP: %02d" RESET "\n",
           p, w, v, s);
    if (e > 0) {
        printf("  " RED "ERROR: %02d" RESET "\n", e);
    }
    printf("  \033[1;33m[!]\033[0m Audit finished. Reports generated in reports/\n");
    printf(BOLD "+-------------------------------------------------------------------------------+\n" RESET);
}

static int write_sysctl(const char *path, int val)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    int r = fprintf(f, "%d\n", val);
    fclose(f);
    return (r > 0) ? 0 : -1;
}

int apply_remediation(const check_result_t *results, int count, int force)
{
    if (geteuid() != 0) {
        printf("    " RED "Remediation requires root privileges.\n" RESET);
        return -1;
    }

    int applied = 0;
    int skipped = 0;

    for (int i = 0; i < count; i++) {
        const check_result_t *r = &results[i];
        if (r->result == PASS || r->result == SKIP) continue;

        const check_def_t *def = NULL;
        for (int j = 0; j < check_count; j++) {
            if (check_table[j].id == r->id) {
                def = &check_table[j];
                break;
            }
        }
        if (!def || !def->remediable) {
            skipped++;
            continue;
        }

        if (!force) {
            printf("    " YEL "[?] Fix %s (set %s to %d)? [y/N]: " RESET,
                   def->name, def->path, def->remediate_val);
            int c = getchar();
            int answer = c;
            while (c != '\n' && c != EOF) c = getchar();
            if (answer != 'y' && answer != 'Y') {
                printf("    " YEL "     Skipped.\n" RESET);
                skipped++;
                continue;
            }
        }

        int backup = 0;
        read_int(def->path, &backup);

        if (write_sysctl(def->path, def->remediate_val) != 0) {
            printf("    " RED "[!] Failed to remediate %s\n" RESET, def->name);
            skipped++;
            continue;
        }

        int verify = 0;
        read_int(def->path, &verify);

        if (verify == def->remediate_val) {
            printf("    " GRN "[+] Remediated: %s (%d -> %d)\n" RESET,
                   def->name, backup, verify);
            applied++;
        } else {
            printf("    " RED "[!] Verification failed for %s (got %d, expected %d)\n" RESET,
                   def->name, verify, def->remediate_val);
            skipped++;
        }
    }

    printf("\n    " GRN "Remediation complete: %d applied, %d skipped\n" RESET, applied, skipped);
    return applied;
}

static int is_safe_path(const char *path)
{
    if (!path) return 1;
    if (path[0] == '/') return 0;
    if (strstr(path, "..") != NULL) return 0;
    return 1;
}

static void fprint_json_string(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *cp = (const unsigned char *)s; *cp; cp++) {
        switch (*cp) {
            case '"': fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (*cp < 0x20) {
                    fprintf(f, "\\u%04x", *cp);
                } else {
                    fputc(*cp, f);
                }
                break;
        }
    }
    fputc('"', f);
}

int export_json(const check_result_t *results, int count, const char *outdir)
{
    char path[MAX_PATH];
    if (outdir) {
        if (!is_safe_path(outdir)) return -1;
        snprintf(path, sizeof(path), "%s/report.json", outdir);
    } else {
        snprintf(path, sizeof(path), "reports/report.json");
    }

    struct stat st;
    char dir[MAX_PATH];
    size_t dlen = strlen(path);
    memcpy(dir, path, dlen + 1);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (stat(dir, &st) != 0) {
            if (mkdir(dir, 0750) != 0 && errno != EEXIST) {
                return -1;
            }
        }
        *slash = '/';
    }

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    time_t now = time(NULL);
    if (now == (time_t)-1) now = 0;

    char hostname[256] = "unknown";
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }
    struct utsname uts;
    const char *kernel_str = "";
    const char *os_str = "";
    if (uname(&uts) == 0) {
        os_str = uts.sysname;
        kernel_str = uts.release;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"LinSpec\",\n");
    
    fprintf(f, "  \"timestamp\": %ld,\n", (long)now);
    fprintf(f, "  \"hostname\": ");
    fprint_json_string(f, hostname);
    fprintf(f, ",\n  \"kernel\": ");
    fprint_json_string(f, kernel_str);
    fprintf(f, ",\n  \"os\": ");
    fprint_json_string(f, os_str);
    fprintf(f, ",\n  \"checks\": [\n");

    int first = 1;
    int p = 0, w = 0, v = 0, s = 0, e = 0;
    for (int i = 0; i < count; i++) {
        const check_result_t *r = &results[i];
        const check_def_t *def = NULL;
        for (int j = 0; j < check_count; j++) {
            if (check_table[j].id == r->id) {
                def = &check_table[j];
                break;
            }
        }
        if (!def) def = &check_table[0];

        switch (r->result) { case PASS: p++; break; case WARN: w++; break; case VULN: v++; break; case SKIP: s++; break; default: e++; break; }

        if (!first) fprintf(f, ",\n");
        first = 0;

        const char *rs = "error";
        const char *rs_upper = "ERROR";
        if (r->result == PASS) { rs = "pass"; rs_upper = "PASS"; }
        else if (r->result == WARN) { rs = "warn"; rs_upper = "WARN"; }
        else if (r->result == VULN) { rs = "vuln"; rs_upper = "VULN"; }
        else if (r->result == SKIP) { rs = "skip"; rs_upper = "SKIP"; }

        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %d,\n", r->id);
        fprintf(f, "      \"name\": \"%s\",\n", def->name);
        fprintf(f, "      \"result\": \"%s\",\n", rs);
        fprintf(f, "      \"status\": \"%s\",\n", rs_upper);
        fprintf(f, "      \"category\": \"%s\",\n", category_names[def->category]);
        fprintf(f, "      \"current\": %d,\n", r->current_val);
        fprintf(f, "      \"expected\": %d", def->expected_val);
        if (r->current_str[0]) {
            fprintf(f, ",\n      \"message\": ");
            fprint_json_string(f, r->current_str);
        } else {
            fprintf(f, ",\n      \"message\": \"\"");
        }
        if (def->cve_count > 0 && def->cves[0][0]) {
            fprintf(f, ",\n      \"cves\": [");
            for (int k = 0; k < def->cve_count; k++) {
                if (k > 0) fprintf(f, ",");
                fprintf(f, "\"%s\"", def->cves[k]);
            }
            fprintf(f, "]");
        }
        if (def->remediable) {
            fprintf(f, ",\n      \"remediable\": true,\n      \"remediate_val\": %d", def->remediate_val);
        }
        fprintf(f, "\n    }");
    }

    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total\": %d,\n", count);
    fprintf(f, "    \"pass\": %d,\n", p);
    fprintf(f, "    \"warn\": %d,\n", w);
    fprintf(f, "    \"vuln\": %d,\n", v);
    fprintf(f, "    \"skip\": %d,\n", s);
    fprintf(f, "    \"error\": %d\n", e);
    fprintf(f, "  }\n");
    fprintf(f, "}\n");

    fclose(f);
    return 0;
}

int export_csv(const check_result_t *results, int count, const char *outdir)
{
    char path[MAX_PATH];
    if (outdir) {
        if (!is_safe_path(outdir)) return -1;
        snprintf(path, sizeof(path), "%s/report.csv", outdir);
    } else {
        snprintf(path, sizeof(path), "reports/report.csv");
    }

    struct stat st;
    char dir[MAX_PATH];
    size_t dlen = strlen(path);
    memcpy(dir, path, dlen + 1);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (stat(dir, &st) != 0) {
            if (mkdir(dir, 0750) != 0 && errno != EEXIST) return -1;
        }
        *slash = '/';
    }

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "id,name,result,status,category,current,expected,detail\n");
    for (int i = 0; i < count; i++) {
        const check_result_t *r = &results[i];
        const check_def_t *def = NULL;
        for (int j = 0; j < check_count; j++) {
            if (check_table[j].id == r->id) {
                def = &check_table[j];
                break;
            }
        }
        if (!def) continue;

        const char *rs = "error";
        const char *rs_upper = "ERROR";
        if (r->result == PASS) { rs = "pass"; rs_upper = "PASS"; }
        else if (r->result == WARN) { rs = "warn"; rs_upper = "WARN"; }
        else if (r->result == VULN) { rs = "vuln"; rs_upper = "VULN"; }
        else if (r->result == SKIP) { rs = "skip"; rs_upper = "SKIP"; }

        fprintf(f, "%d,%s,%s,%s,%s,%d,%d,\"%s\"\n",
                r->id, def->name, rs, rs_upper, category_names[def->category],
                r->current_val, def->expected_val, r->current_str);
    }

    fclose(f);
    return 0;
}

int export_html(const check_result_t *results, int count, const char *outdir)
{
    char path[MAX_PATH];
    if (outdir) {
        if (!is_safe_path(outdir)) return -1;
        snprintf(path, sizeof(path), "%s/report.html", outdir);
    } else {
        snprintf(path, sizeof(path), "reports/report.html");
    }

    struct stat st;
    char dir[MAX_PATH];
    size_t dlen = strlen(path);
    memcpy(dir, path, dlen + 1);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (stat(dir, &st) != 0) {
            if (mkdir(dir, 0750) != 0 && errno != EEXIST) return -1;
        }
        *slash = '/';
    }

    FILE *f = fopen(path, "w");
    if (!f) return -1;

    int p = 0, w = 0, v = 0, s = 0, e = 0;
    for (int i = 0; i < count; i++) {
        switch (results[i].result) {
            case PASS: p++; break; case WARN: w++; break; case VULN: v++; break;
            case SKIP: s++; break; default: e++; break;
        }
    }

    time_t now = time(NULL);
    char timebuf[64];
    struct tm *tm_local = localtime(&now);
    if (tm_local) {
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_local);
    } else {
        snprintf(timebuf, sizeof(timebuf), "%ld", (long)now);
    }

    fprintf(f, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
    fprintf(f, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">");
    fprintf(f, "<title>LinSpec Audit Report</title>");
    fprintf(f, "<style>");
    fprintf(f, "*{margin:0;padding:0;box-sizing:border-box;}");
    fprintf(f, "body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:20px;}");
    fprintf(f, "h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px;}");
    fprintf(f, "h2{margin-top:20px;color:#8b949e;}");
    fprintf(f, ".summary{display:flex;gap:10px;margin:20px 0;flex-wrap:wrap;}");
    fprintf(f, ".badge{padding:8px 16px;border-radius:6px;font-weight:700;font-size:14px;}");
    fprintf(f, ".badge-pass{background:#1b3a1b;color:#3fb950;border:1px solid #3fb950;}");
    fprintf(f, ".badge-warn{background:#3a2f1b;color:#d29922;border:1px solid #d29922;}");
    fprintf(f, ".badge-vuln{background:#3a1b1b;color:#f85149;border:1px solid #f85149;}");
    fprintf(f, ".badge-skip{background:#1b2a3a;color:#58a6ff;border:1px solid #58a6ff;}");
    fprintf(f, "table{width:100%%;border-collapse:collapse;margin-top:10px;}");
    fprintf(f, "th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #21262d;}");
    fprintf(f, "th{background:#161b22;color:#8b949e;font-size:12px;text-transform:uppercase;}");
    fprintf(f, "tr:hover{background:#161b22;}");
    fprintf(f, ".status-pass{color:#3fb950;font-weight:700;}");
    fprintf(f, ".status-warn{color:#d29922;font-weight:700;}");
    fprintf(f, ".status-vuln{color:#f85149;font-weight:700;}");
    fprintf(f, ".status-skip{color:#58a6ff;font-weight:700;}");
    fprintf(f, ".cve{color:#f0883e;font-size:12px;}");
    fprintf(f, ".meta{color:#8b949e;font-size:12px;margin-top:4px;}");
    fprintf(f, ".detail{color:#8b949e;font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}");
    fprintf(f, "</style></head><body>");
    fprintf(f, "<h1>LinSpec</h1>");
    fprintf(f, "<div class=\"meta\">%s</div>", timebuf);
    fprintf(f, "<div class=\"summary\">");
    fprintf(f, "<span class=\"badge badge-pass\">PASS: %d</span>", p);
    fprintf(f, "<span class=\"badge badge-warn\">WARN: %d</span>", w);
    fprintf(f, "<span class=\"badge badge-vuln\">VULN: %d</span>", v);
    fprintf(f, "<span class=\"badge badge-skip\">SKIP: %d</span>", s);
    if (e > 0) fprintf(f, "<span class=\"badge badge-vuln\">ERROR: %d</span>", e);
    fprintf(f, "</div>");
    fprintf(f, "<table><thead><tr>");
    fprintf(f, "<th>ID</th><th>Check</th><th>Category</th><th>Status</th><th>Current</th><th>Expected</th><th>Detail</th><th>CVEs</th>");
    fprintf(f, "</tr></thead><tbody>");

    static const char *cat_names[] = {
        "Memory", "Kernel", "Network", "FS", "CPU", "Crypto", "Exec"
    };

    for (int i = 0; i < count; i++) {
        const check_result_t *r = &results[i];
        const check_def_t *def = NULL;
        for (int j = 0; j < check_count; j++) {
            if (check_table[j].id == r->id) { def = &check_table[j]; break; }
        }
        if (!def) continue;

        const char *status_class = "status-pass";
        const char *status_str = "PASS";
        if (r->result == VULN) { status_class = "status-vuln"; status_str = "VULN"; }
        else if (r->result == WARN) { status_class = "status-warn"; status_str = "WARN"; }
        else if (r->result == SKIP) { status_class = "status-skip"; status_str = "SKIP"; }
        else if (r->result == ERROR_RESULT) { status_class = "status-vuln"; status_str = "ERR"; }

        const char *cat = (def->category < 7) ? cat_names[def->category] : "?";

        fprintf(f, "<tr>");
        fprintf(f, "<td>%d</td>", r->id);
        fprintf(f, "<td>%s</td>", def->name);
        fprintf(f, "<td>%s</td>", cat);
        fprintf(f, "<td class=\"%s\">%s</td>", status_class, status_str);
        if (def->type == TYPE_INT) {
            fprintf(f, "<td>%d</td><td>%d</td>", r->current_val, def->expected_val);
            fprintf(f, "<td class=\"detail\">%s</td>", r->current_str[0] ? r->current_str : "-");
        } else {
            fprintf(f, "<td colspan=\"3\">%s</td>", r->current_str[0] ? r->current_str : "-");
        }
        fprintf(f, "<td class=\"cve\">");
        int cve_first = 1;
        for (int k = 0; k < def->cve_count; k++) {
            if (def->cves[k][0]) {
                if (!cve_first) fprintf(f, ", ");
                fprintf(f, "%s", def->cves[k]);
                cve_first = 0;
            }
        }
        if (cve_first) fprintf(f, "-");
        fprintf(f, "</td></tr>\n");
    }

    fprintf(f, "</tbody></table>");
    fprintf(f, "<div class=\"meta\">Generated by LinSpec</div>");
    fprintf(f, "</body></html>\n");

    fclose(f);
    return 0;
}

int load_profile(const char *path, profile_t *profile)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[8192];
    size_t total = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (total <= 0) return -1;
    buf[total] = '\0';

    memset(profile, 0, sizeof(*profile));
    profile->override_count = 0;

    char *p = buf;

    while (*p && *p != '{') p++;
    if (!*p) return -1;

    char *end = strrchr(p, '}');
    if (!end) return -1;
    *end = '\0';

    char *name_start = strstr(p, "\"name\"");
    if (name_start) {
        char *colon = strchr(name_start, ':');
        if (colon) {
            char *q = colon + 1;
            while (*q && (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r')) q++;
            if (*q == '"') {
                q++;
                int idx = 0;
                while (*q && *q != '"' && idx < 63) profile->name[idx++] = *q++;
                profile->name[idx] = '\0';
            }
        }
    }

    char *checks_section = strstr(p, "\"checks\"");
    if (!checks_section) return -1;

    char *cb = strchr(checks_section, '{');
    if (!cb) return -1;
    cb++;

    char *iter = cb;
    while (iter && *iter && iter < end) {
        while (*iter && (*iter == ' ' || *iter == '\t' || *iter == '\n' || *iter == '\r' || *iter == ',')) iter++;
        if (!*iter || *iter == '}') break;

        if (*iter == '"') {
            char check_name[64];
            int idx = 0;
            iter++;
            while (*iter && *iter != '"' && idx < 63) check_name[idx++] = *iter++;
            check_name[idx] = '\0';
            if (*iter == '"') iter++;

            while (*iter && (*iter == ' ' || *iter == '\t' || *iter == '\n' || *iter == '\r' || *iter == ':')) iter++;
            if (*iter == '{') iter++;

            int ov_val = 0;
            char ov_op[16] = "eq";

            while (iter && *iter && *iter != '}') {
                while (*iter && (*iter == ' ' || *iter == '\t' || *iter == '\n' || *iter == '\r' || *iter == ',')) iter++;
                if (!*iter || *iter == '}') break;

                if (*iter == '"') {
                    char key[32];
                    int ki = 0;
                    iter++;
                    while (*iter && *iter != '"' && ki < 31) key[ki++] = *iter++;
                    key[ki] = '\0';
                    if (*iter == '"') iter++;

                    while (*iter && (*iter == ' ' || *iter == '\t' || *iter == '\n' || *iter == '\r' || *iter == ':')) iter++;

                    if (strcmp(key, "expected") == 0) {
                        ov_val = 0;
                        while (*iter >= '0' && *iter <= '9') { ov_val = ov_val * 10 + (*iter - '0'); iter++; }
                    } else if (strcmp(key, "op") == 0) {
                        while (*iter && (*iter == ' ' || *iter == '\t' || *iter == '\n' || *iter == '\r')) iter++;
                        if (*iter == '"') {
                            int oi = 0;
                            iter++;
                            while (*iter && *iter != '"' && oi < 15) ov_op[oi++] = *iter++;
                            ov_op[oi] = '\0';
                            if (*iter == '"') iter++;
                        }
                    } else {
                        while (*iter && *iter != ',' && *iter != '}') iter++;
                    }
                }
            }
            if (*iter == '}') iter++;

            for (int ci = 0; ci < check_count && profile->override_count < MAX_CHECKS; ci++) {
                if (strcmp(check_table[ci].name, check_name) == 0) {
                    profile->override_ids[profile->override_count] = check_table[ci].id;
                    profile->override_vals[profile->override_count] = ov_val;
                    if (strcmp(ov_op, "ge") == 0) profile->override_ops[profile->override_count] = OP_GE;
                    else if (strcmp(ov_op, "le") == 0) profile->override_ops[profile->override_count] = OP_LE;
                    else if (strcmp(ov_op, "ne") == 0) profile->override_ops[profile->override_count] = OP_NE;
                    else profile->override_ops[profile->override_count] = OP_EQ;
                    profile->override_count++;
                    break;
                }
            }
        }
    }

    return 0;
}

int run_watch(int interval, const char *profile_path, int json, int csv, int html, const char *outdir)
{
    if (interval <= 0) interval = 60;

    printf(BOLD "\n+---LinSpec Watch Mode--------------------------------------------------------+\n" RESET);
    printf("  Interval: %d seconds | Output: %s%s%s%s\n",
           interval,
           json ? "json " : "",
           csv ? "csv " : "",
           html ? "html " : "",
           (!json && !csv && !html) ? "terminal" : "");
    printf(BOLD "+-------------------------------------------------------------------------------+\n" RESET);

    int iteration = 0;
    while (1) {
        printf("\n" BOLD "=== Iteration %d ===%s\n", ++iteration, RESET);

        check_result_t results[MAX_CHECKS];
        int count = run_all_checks(results, MAX_CHECKS, profile_path);

        if (!json && !csv && !html) {
            print_results(results, count);
            print_summary(results, count);
        }

        if (json) export_json(results, count, outdir);
        if (csv) export_csv(results, count, outdir);
        if (html) export_html(results, count, outdir);

        if (json || csv || html) {
            printf("    " GRN "o" RESET " Reports updated in %s\n", outdir ? outdir : "reports/");
        }

        sleep((unsigned int)interval);
    }

    return 0;
}

int send_webhook(const char *url, const char *outdir)
{
    char path[MAX_PATH];
    if (outdir) {
        if (!is_safe_path(outdir)) return -1;
        snprintf(path, sizeof(path), "%s/report.json", outdir);
    } else {
        snprintf(path, sizeof(path), "reports/report.json");
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        printf("    " RED "x" RESET " Webhook failed: report.json not found at %s\n", path);
        return -1;
    }
    fclose(f);

    const char *api_key = getenv("LINSPEC_API_KEY");
    if (!api_key || api_key[0] == '\0') { printf("    " YEL "x" RESET " Webhook: LINSPEC_API_KEY not set\n"); return -1; }

    pid_t pid = fork();
    if (pid == -1) {
        printf("    " YEL "x" RESET " Webhook failed: fork error\n");
        return -1;
    }

    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd != -1) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }

        char api_header[512];
        snprintf(api_header, sizeof(api_header), "X-API-Key: %s", api_key);

        char data_opt[544];
        snprintf(data_opt, sizeof(data_opt), "--data-binary@%s", path);

        execlp("curl", "curl", "-s", "-X", "POST",
               "-H", "Content-Type: application/json",
               "-H", api_header,
               data_opt,
               url,
               (char *)NULL);

        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("    " GRN "o" RESET " Report sent to %s\n", url);
        return 0;
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        printf("    " YEL "x" RESET " Webhook failed: curl not available\n");
    } else {
        printf("    " YEL "x" RESET " Webhook failed: curl exit %d\n",
               WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    }
    return -1;
}
