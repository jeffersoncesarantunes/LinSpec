#include <stdio.h>
#include "checks.h"

void check_aslr(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/randomize_va_space", "r");
    int val = 0;
    if (fp) { fscanf(fp, "%d", &val); fclose(fp); }
    printf("    [ 01 ]  %-7s >  %-37s ", "MEMORY", "Address Space Layout Randomization");
    if (val == 2) { printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++; }
    else { printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++; }
}

void check_dev_mem_restrict(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/devmem_restrict", "r");
    printf("    [ 12 ]  %-7s >  %-37s ", "MEMORY", "Direct Memory Access Restriction");
    if (fp) {
        printf(BOLD RED "[-] " RESET "[ " BOLD RED "  VULN  " RESET " ]\n"); (*v)++;
        fclose(fp);
    } else {
        printf(BOLD GRN "[+] " RESET "[ " BOLD GRN "  PASS  " RESET " ]\n"); (*p)++;
    }
}
