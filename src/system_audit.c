#include <stdio.h>
#include <string.h>
#include <time.h>
#include "checks.h"

void print_result(int id, const char *cat, const char *desc, const char *symbol, const char *color, const char *status) {
    printf("    [ %02d ]  %-7s >  %-35s %s%s%s [  %-5s%s ]\n", 
           id, cat, desc, color, symbol, RESET, status, RESET);
}

void check_kptr_restrict(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/kptr_restrict", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val >= 1) { 
        print_result(2, "KERNEL", "Kernel Pointer Restriction", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(2, "KERNEL", "Kernel Pointer Restriction", "[-]", BOLD RED, "VULN");
        (*v)++; 
    }
}

void check_ptrace_scope(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val >= 1) { 
        print_result(3, "SYSTEM", "Yama Ptrace Scope Protection", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(3, "SYSTEM", "Yama Ptrace Scope Protection", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_dmesg_restrict(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/dmesg_restrict", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 1) { 
        print_result(4, "KERNEL", "Kernel Log Dmesg Restriction", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(4, "KERNEL", "Kernel Log Dmesg Restriction", "[-]", BOLD RED, "VULN");
        (*v)++; 
    }
}

void check_bpf_jit(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/net/core/bpf_jit_harden", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 2) { 
        print_result(5, "NETWORK", "BPF JIT Compiler Hardening", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(5, "NETWORK", "BPF JIT Compiler Hardening", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_tcp_syncookies(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/net/ipv4/tcp_syncookies", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 1) { 
        print_result(6, "NETWORK", "TCP SYN Flood Protection (Cookies)", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(6, "NETWORK", "TCP SYN Flood Protection (Cookies)", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_unprivileged_userns(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 0) { 
        print_result(7, "SYSTEM", "Unprivileged User Namespaces", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(7, "SYSTEM", "Unprivileged User Namespaces", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_ip_forwarding(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 0) { 
        print_result(8, "NETWORK", "IPv4 Packet Forwarding (Routing)", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(8, "NETWORK", "IPv4 Packet Forwarding (Routing)", "[-]", BOLD RED, "VULN");
        (*v)++; 
    }
}

void check_protected_symlinks(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/fs/protected_symlinks", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 1) { 
        print_result(9, "FS", "Protected Symlinks Restriction", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(9, "FS", "Protected Symlinks Restriction", "[-]", BOLD RED, "VULN");
        (*v)++; 
    }
}

void check_protected_hardlinks(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/fs/protected_hardlinks", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 1) { 
        print_result(10, "FS", "Protected Hardlinks Restriction", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(10, "FS", "Protected Hardlinks Restriction", "[-]", BOLD RED, "VULN");
        (*v)++; 
    }
}

void check_kexec_load(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/kexec_load_disabled", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val == 1) { 
        print_result(11, "KERNEL", "Kexec Kernel Image Loading", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(11, "KERNEL", "Kexec Kernel Image Loading", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_entropy(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    if (val > 200) { 
        print_result(13, "CRYPTO", "System Entropy Availability", "[+]", BOLD GRN, "PASS");
        (*p)++; 
    } else { 
        print_result(13, "CRYPTO", "System Entropy Availability", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_spectre_v2(int *p, int *v, int *w) {
    FILE *fp = fopen("/sys/devices/system/cpu/vulnerabilities/spectre_v2", "r");
    char buf[256];
    if (fp && fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "Mitigation") || strstr(buf, "Not affected")) { 
            print_result(14, "CPU", "Spectre V2 Mitigation Status", "[+]", BOLD GRN, "PASS");
            (*p)++; 
        } else { 
            print_result(14, "CPU", "Spectre V2 Mitigation Status", "[-]", BOLD RED, "VULN");
            (*v)++; 
        }
        fclose(fp);
    } else { 
        print_result(14, "CPU", "Spectre V2 Mitigation Status", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void check_meltdown(int *p, int *v, int *w) {
    FILE *fp = fopen("/sys/devices/system/cpu/vulnerabilities/meltdown", "r");
    char buf[256];
    if (fp && fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "Mitigation") || strstr(buf, "Not affected")) { 
            print_result(15, "CPU", "Meltdown Mitigation Status", "[+]", BOLD GRN, "PASS");
            (*p)++; 
        } else { 
            print_result(15, "CPU", "Meltdown Mitigation Status", "[-]", BOLD RED, "VULN");
            (*v)++; 
        }
        fclose(fp);
    } else { 
        print_result(15, "CPU", "Meltdown Mitigation Status", "[!]", BOLD YEL, "WARN");
        (*w)++; 
    }
}

void export_reports(int p, int w, int v) {
    FILE *csv = fopen("report.csv", "w");
    if (csv) {
        fprintf(csv, "Category,Status_Count\n");
        fprintf(csv, "PASS,%d\n", p);
        fprintf(csv, "WARN,%d\n", w);
        fprintf(csv, "VULN,%d\n", v);
        fclose(csv);
        printf("\n    " GRN "●" RESET " CSV report generated: report.csv\n");
    }
    FILE *json = fopen("report.json", "w");
    if (json) {
        time_t now; time(&now);
        fprintf(json, "{\n  \"audit_info\": {\n    \"tool\": \"LinSpec\",\n    \"timestamp\": %ld\n  },\n", (long)now);
        fprintf(json, "  \"summary\": {\n    \"pass\": %d,\n    \"warn\": %d,\n    \"vuln\": %d\n  }\n}\n", p, w, v);
        fclose(json);
        printf("    " GRN "●" RESET " JSON report generated: report.json\n\n");
    }
}
