#include <stdio.h>
#include <string.h>
#include "checks.h"

void check_kptr_restrict(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/kptr_restrict", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 02 ]  %-7s >  %-37s ", "KERNEL", "Kernel Pointer Restriction");
    if (val >= 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
}

void check_ptrace_scope(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 03 ]  %-7s >  %-37s ", "SYSTEM", "Yama Ptrace Scope Protection");
    if (val >= 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_dmesg_restrict(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/dmesg_restrict", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 04 ]  %-7s >  %-37s ", "KERNEL", "Kernel Log Dmesg Restriction");
    if (val == 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
}

void check_bpf_jit(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/net/core/bpf_jit_harden", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 05 ]  %-7s >  %-37s ", "NETWORK", "BPF JIT Compiler Hardening");
    if (val == 2) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_tcp_syncookies(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/net/ipv4/tcp_syncookies", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 06 ]  %-7s >  %-37s ", "NETWORK", "TCP SYN Flood Protection (Cookies)");
    if (val == 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_unprivileged_userns(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/unprivileged_userns_clone", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 07 ]  %-7s >  %-37s ", "SYSTEM", "Unprivileged User Namespaces");
    if (val == 0) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_ip_forwarding(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 08 ]  %-7s >  %-37s ", "NETWORK", "IPv4 Packet Forwarding (Routing)");
    if (val == 0) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
}

void check_protected_symlinks(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/fs/protected_symlinks", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 09 ]  %-7s >  %-37s ", "FS", "Protected Symlinks Restriction");
    if (val == 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
}

void check_protected_hardlinks(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/fs/protected_hardlinks", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 10 ]  %-7s >  %-37s ", "FS", "Protected Hardlinks Restriction");
    if (val == 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
}

void check_kexec_load(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/kexec_load_disabled", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 11 ]  %-7s >  %-37s ", "KERNEL", "Kexec Kernel Image Loading");
    if (val == 1) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_entropy(int *p, int *w) {
    FILE *fp = fopen("/proc/sys/kernel/random/entropy_avail", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 13 ]  %-7s >  %-37s ", "CRYPTO", "System Entropy Availability");
    if (val > 200) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_spectre_v2(int *p, int *v, int *w) {
    FILE *fp = fopen("/sys/devices/system/cpu/vulnerabilities/spectre_v2", "r");
    char buf[256];
    printf("    [ 14 ]  %-7s >  %-37s ", "CPU", "Spectre V2 Mitigation Status");
    if (fp && fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "Mitigation") || strstr(buf, "Not affected")) { 
            printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; 
        }
        else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
        fclose(fp);
    } else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}

void check_meltdown(int *p, int *v, int *w) {
    FILE *fp = fopen("/sys/devices/system/cpu/vulnerabilities/meltdown", "r");
    char buf[256];
    printf("    [ 15 ]  %-7s >  %-37s ", "CPU", "Meltdown Mitigation Status");
    if (fp && fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "Mitigation") || strstr(buf, "Not affected")) { 
            printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; 
        }
        else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
        fclose(fp);
    } else { printf(BOLD YEL "[!] " RESET "[ " BOLD YEL "  WARN  " RESET " ]\n"); (*w)++; }
}
