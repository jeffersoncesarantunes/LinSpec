#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "remediator.h"

static const char* check_to_sysctl(const char *name) {
    if (strcmp(name, "aslr") == 0) return "kernel.randomize_va_space";
    if (strcmp(name, "kptr_restrict") == 0) return "kernel.kptr_restrict";
    if (strcmp(name, "ptrace_scope") == 0) return "kernel.yama.ptrace_scope";
    if (strcmp(name, "dmesg_restrict") == 0) return "kernel.dmesg_restrict";
    if (strcmp(name, "bpf_jit_harden") == 0) return "net.core.bpf_jit_harden";
    if (strcmp(name, "tcp_syncookies") == 0) return "net.ipv4.tcp_syncookies";
    if (strcmp(name, "userns_clone") == 0) return "kernel.unprivileged_userns_clone";
    if (strcmp(name, "ip_forward") == 0) return "net.ipv4.ip_forward";
    if (strcmp(name, "protected_symlinks") == 0) return "fs.protected_symlinks";
    if (strcmp(name, "protected_hardlinks") == 0) return "fs.protected_hardlinks";
    if (strcmp(name, "kexec_disabled") == 0) return "kernel.kexec_load_disabled";
    if (strcmp(name, "perf_event_paranoid") == 0) return "kernel.perf_event_paranoid";
    if (strcmp(name, "rp_filter_all") == 0) return "net.ipv4.conf.all.rp_filter";
    if (strcmp(name, "rp_filter_default") == 0) return "net.ipv4.conf.default.rp_filter";
    if (strcmp(name, "tcp_rfc1337") == 0) return "net.ipv4.tcp_rfc1337";
    if (strcmp(name, "icmp_ignore_bogus") == 0) return "net.ipv4.icmp_ignore_bogus_error_responses";
    if (strcmp(name, "arp_ignore") == 0) return "net.ipv4.conf.all.arp_ignore";
    if (strcmp(name, "arp_announce") == 0) return "net.ipv4.conf.all.arp_announce";
    if (strcmp(name, "unpriv_bpf") == 0) return "kernel.unprivileged_bpf_disabled";
    if (strcmp(name, "ftrace_enabled") == 0) return "kernel.ftrace_enabled";
    if (strcmp(name, "core_uses_pid") == 0) return "kernel.core_uses_pid";
    if (strcmp(name, "sysrq") == 0) return "kernel.sysrq";
    if (strcmp(name, "mmap_min_addr") == 0) return "vm.mmap_min_addr";
    return NULL;
}

static int read_file(const char *path, char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return -1; }
    fseek(f, 0, SEEK_SET);
    *out = malloc((size_t)sz + 1);
    if (!*out) { fclose(f); return -1; }
    size_t n = fread(*out, 1, (size_t)sz, f);
    fclose(f);
    (*out)[n] = '\0';
    *out_len = n;
    return 0;
}

static int extract_int(const char *obj, const char *key, int *val) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(obj, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    *val = 0;
    int sign = 1;
    if (*p == '-') { sign = -1; p++; }
    if (*p < '0' || *p > '9') return -1;
    while (*p >= '0' && *p <= '9') {
        *val = *val * 10 + (*p - '0');
        p++;
    }
    *val *= sign;
    return 0;
}

static int extract_string(const char *obj, const char *key, char *out, size_t out_size) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(obj, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_size - 1) {
        if (*p == '\\' && *(p + 1)) p++;
        out[i++] = *p;
        p++;
    }
    out[i] = '\0';
    return 0;
}

static int extract_bool(const char *obj, const char *key, int *val) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(obj, search);
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (strncmp(p, "true", 4) == 0) { *val = 1; return 0; }
    if (strncmp(p, "false", 5) == 0) { *val = 0; return 0; }
    return -1;
}

int parse_linspec_report(const char *report_path, remediation_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));

    char *buf = NULL;
    size_t len = 0;
    if (read_file(report_path, &buf, &len) != 0) return -1;

    char *checks_start = strstr(buf, "\"checks\"");
    if (!checks_start) { free(buf); return -1; }

    checks_start = strchr(checks_start, '[');
    if (!checks_start) { free(buf); return -1; }
    checks_start++;

    int depth = 1;
    char *p = checks_start;
    while (*p && depth > 0) {
        if (*p == '[') depth++;
        else if (*p == ']') depth--;
        p++;
    }
    if (depth != 0) { free(buf); return -1; }

    char *obj_start = checks_start;
    int count = 0;

    while (obj_start < p && count < MAX_REMEDIATIONS) {
        while (*obj_start && (*obj_start == ' ' || *obj_start == '\n' || *obj_start == '\t' || *obj_start == '\r' || *obj_start == ',')) obj_start++;
        if (*obj_start != '{') break;

        depth = 1;
        char *obj_end = obj_start + 1;
        while (*obj_end && depth > 0) {
            if (*obj_end == '{') depth++;
            else if (*obj_end == '}') depth--;
            obj_end++;
        }

        size_t obj_len = (size_t)(obj_end - obj_start);
        char *obj_copy = malloc(obj_len + 1);
        if (!obj_copy) { obj_start = obj_end; continue; }
        memcpy(obj_copy, obj_start, obj_len);
        obj_copy[obj_len] = '\0';

        remediation_t *r = &plan->items[count];
        memset(r, 0, sizeof(remediation_t));

        int remediable = 0;
        char result[16] = "";

        if (extract_int(obj_copy, "id", &r->id) != 0) { free(obj_copy); obj_start = obj_end; continue; }
        extract_string(obj_copy, "name", r->name, sizeof(r->name));
        extract_string(obj_copy, "result", result, sizeof(result));
        extract_int(obj_copy, "current", &r->current_val);
        extract_int(obj_copy, "expected", &r->recommended_val);
        extract_bool(obj_copy, "remediable", &remediable);

        if (remediable && (strcmp(result, "vuln") == 0 || strcmp(result, "warn") == 0)) {
            const char *sysctl_name = check_to_sysctl(r->name);
            if (sysctl_name) {
                int rem_val = r->recommended_val;
                extract_int(obj_copy, "remediate_val", &rem_val);
                r->recommended_val = rem_val;

                snprintf(r->sysctl_param, sizeof(r->sysctl_param), "%s", sysctl_name);
                snprintf(r->command, sizeof(r->command), "sysctl -w %s=%d", sysctl_name, rem_val);
                snprintf(r->persistent_line, sizeof(r->persistent_line), "%s = %d", sysctl_name, rem_val);

                if (strcmp(result, "vuln") == 0) {
                    snprintf(r->severity, sizeof(r->severity), "critical");
                    plan->critical++;
                } else {
                    snprintf(r->severity, sizeof(r->severity), "warning");
                    plan->warning++;
                }

                r->automated = 1;
                count++;
            }
        }

        free(obj_copy);
        obj_start = obj_end;
    }

    plan->total = count;

    size_t p_off = 0;
    p_off += (size_t)snprintf(plan->persistent_block + p_off, sizeof(plan->persistent_block) - p_off,
        "# SYNTROPY Remediation Plan\n# Generated by LinSpec Remediation v" REMEDIATOR_VERSION "\n# Add to /etc/sysctl.d/99-syntropy-hardening.conf\n#\n");
    for (int i = 0; i < count; i++) {
        p_off += (size_t)snprintf(plan->persistent_block + p_off, sizeof(plan->persistent_block) - p_off,
            "%s\n", plan->items[i].persistent_line);
    }

    free(buf);
    return 0;
}

int generate_remediation_json(const remediation_plan_t *plan, const char *outpath) {
    FILE *f = stdout;
    int close_f = 0;

    if (outpath) {
        struct stat st;
        char dir[MAX_PATH];
        size_t dlen = strlen(outpath);
        memcpy(dir, outpath, dlen + 1);
        char *slash = strrchr(dir, '/');
        if (slash) {
            *slash = '\0';
            if (stat(dir, &st) != 0) {
                if (mkdir(dir, 0750) != 0 && errno != EEXIST) return -1;
            }
            *slash = '/';
        }
        f = fopen(outpath, "w");
        if (!f) return -1;
        close_f = 1;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) now = 0;

    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"LinSpec Remediation\",\n");
    fprintf(f, "  \"version\": \"" REMEDIATOR_VERSION "\",\n");
    fprintf(f, "  \"generated_at\": %ld,\n", (long)now);
    fprintf(f, "  \"source\": \"linspec\",\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total\": %d,\n", plan->total);
    fprintf(f, "    \"critical\": %d,\n", plan->critical);
    fprintf(f, "    \"warning\": %d\n", plan->warning);
    fprintf(f, "  },\n");
    fprintf(f, "  \"remediations\": [\n");

    for (int i = 0; i < plan->total; i++) {
        if (i > 0) fprintf(f, ",\n");
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %d,\n", plan->items[i].id);
        fprintf(f, "      \"check\": \"%s\",\n", plan->items[i].name);
        fprintf(f, "      \"severity\": \"%s\",\n", plan->items[i].severity);
        fprintf(f, "      \"current\": %d,\n", plan->items[i].current_val);
        fprintf(f, "      \"recommended\": %d,\n", plan->items[i].recommended_val);
        fprintf(f, "      \"sysctl\": \"%s\",\n", plan->items[i].sysctl_param);
        fprintf(f, "      \"command\": \"%s\",\n", plan->items[i].command);
        fprintf(f, "      \"persistent\": \"%s\",\n", plan->items[i].persistent_line);
        fprintf(f, "      \"automated\": %s\n", plan->items[i].automated ? "true" : "false");
        fprintf(f, "    }");
    }

    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"persistent_block\": \"");
    fflush(f);
    for (const char *cp = plan->persistent_block; *cp; cp++) {
        if (*cp == '"' || *cp == '\\') fputc('\\', f);
        if (*cp == '\n') { fputc('\\', f); fputc('n', f); }
        else fputc(*cp, f);
    }

    fprintf(f, "\"\n");
    fprintf(f, "}\n");

    if (close_f) fclose(f);
    return 0;
}

static void sysctl_name_to_path(const char *sysctl_name, char *path, size_t path_size) {
    snprintf(path, path_size, "/proc/sys/%s", sysctl_name);
    for (char *p = path + 10; *p; p++) {
        if (*p == '.') *p = '/';
    }
}

static int write_sysctl_file(const char *path, int val) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    int r = fprintf(f, "%d\n", val);
    fclose(f);
    return (r > 0) ? 0 : -1;
}

int apply_remediation_plan(const remediation_plan_t *plan, int force) {
    if (geteuid() != 0) {
        printf("\033[31m[!] Remediation requires root privileges.\033[0m\n");
        return -1;
    }

    int applied = 0;
    int skipped = 0;

    for (int i = 0; i < plan->total; i++) {
        const remediation_t *r = &plan->items[i];
        if (!r->automated) { skipped++; continue; }

        if (!force) {
            printf("\033[33m[?] Fix %s (set %s to %d)? [y/N/a]: \033[0m",
                   r->name, r->sysctl_param, r->recommended_val);
            int c = getchar();
            int answer = c;
            while (c != '\n' && c != EOF) c = getchar();
            if (answer == 'a' || answer == 'A') { force = 1; }
            else if (answer != 'y' && answer != 'Y') {
                printf("\033[33m     Skipped.\033[0m\n");
                skipped++;
                continue;
            }
        }

        char proc_path[MAX_PATH];
        sysctl_name_to_path(r->sysctl_param, proc_path, sizeof(proc_path));

        int cur = 0;
        FILE *sysctl_f = fopen(proc_path, "r");
        if (sysctl_f) {
            if (fscanf(sysctl_f, "%d", &cur) != 1) cur = -1;
            fclose(sysctl_f);
        }

        if (write_sysctl_file(proc_path, r->recommended_val) != 0) {
            printf("\033[31m[!] Failed to remediate %s\033[0m\n", r->name);
            skipped++;
            continue;
        }

        int verify = 0;
        sysctl_f = fopen(proc_path, "r");
        if (sysctl_f) {
            if (fscanf(sysctl_f, "%d", &verify) != 1) verify = -1;
            fclose(sysctl_f);
        }

        if (verify == r->recommended_val) {
            printf("\033[32m[+] Remediated: %s (%d -> %d)\033[0m\n",
                   r->name, cur, verify);
            applied++;
        } else {
            printf("\033[31m[!] Verification failed for %s (got %d, expected %d)\033[0m\n",
                   r->name, verify, r->recommended_val);
            skipped++;
        }
    }

    printf("\n\033[32mRemediation complete: %d applied, %d skipped\033[0m\n", applied, skipped);
    return applied;
}

static void print_usage(void) {
    printf("LinSpec Remediation v" REMEDIATOR_VERSION "\n");
    printf("Usage: remediator [options]\n\n");
    printf("Options:\n");
    printf("  -i, --input FILE     Input LinSpec report.json (default: reports/report.json)\n");
    printf("  -o, --output FILE    Output remediation plan JSON (default: stdout)\n");
    printf("  -a, --apply          Apply remediations interactively\n");
    printf("  -f, --force          Skip confirmation prompt for --apply\n");
    printf("  -h, --help           Show this help\n");
}

int main(int argc, char **argv) {
    const char *input_path = "reports/report.json";
    const char *output_path = NULL;
    int flag_apply = 0;
    int flag_force = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) {
            if (i + 1 < argc) input_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output_path = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--apply") == 0) {
            flag_apply = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            flag_force = 1;
        } else {
            print_usage();
            return 1;
        }
    }

    remediation_plan_t plan;
    if (parse_linspec_report(input_path, &plan) != 0) {
        fprintf(stderr, "Error: could not parse %s\n", input_path);
        return 1;
    }

    if (plan.total == 0) {
        printf("No remediations needed.\n");
        return 0;
    }

    if (flag_apply) {
        return apply_remediation_plan(&plan, flag_force) < 0 ? 1 : 0;
    }

    if (generate_remediation_json(&plan, output_path) != 0) {
        fprintf(stderr, "Error: could not generate remediation output\n");
        return 1;
    }

    return 0;
}
