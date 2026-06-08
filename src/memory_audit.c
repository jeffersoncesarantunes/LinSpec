#include <stdio.h>
#include "checks.h"

void check_aslr(int *p, int *v) {
    FILE *fp = fopen("/proc/sys/kernel/randomize_va_space", "r");
    int val = 0;
    if (fp) {
        if (fscanf(fp, "%d", &val) != 1) val = 0;
        fclose(fp);
    }
    if (val == 2) {
        print_result(1, "MEMORY", "Address Space Layout Randomization", "[+]", BOLD GRN, "PASS");
        (*p)++;
    } else {
        print_result(1, "MEMORY", "Address Space Layout Randomization", "[-]", BOLD RED, "VULN");
        (*v)++;
    }
}
