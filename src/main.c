#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "checks.h"

static void print_usage(void)
{
    printf(BOLD "LinSpec - Kernel Hardening Audit Tool\n" RESET);
    printf("Usage: linspec [options]\n\n");
    printf("Options:\n");
    printf("  -j, --json            Export JSON report\n");
    printf("  -c, --csv             Export CSV report\n");
    printf("  -H, --html            Export HTML report\n");
    printf("  -o, --output-dir DIR  Output directory (default: reports/)\n");
    printf("  -p, --profile FILE    Load custom audit profile\n");
    printf("  -a, --apply           Apply remediation for VULN/WARN checks\n");
    printf("  -f, --force           Skip confirmation prompt for --apply\n");
    printf("  -w, --watch SEC       Watch mode with interval in seconds\n");
    printf("  -V, --version         Show version\n");
    printf("  -W, --webhook URL     POST JSON report to URL via curl\n");
    printf("  -h, --help            Show this help\n");
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    int flag_json = 0;
    int flag_csv = 0;
    int flag_html = 0;
    int flag_apply = 0;
    int flag_force = 0;
    int flag_watch = 0;
    int watch_interval = 0;
    int flag_webhook = 0;
    const char *output_dir = NULL;
    const char *profile_path = NULL;
    const char *webhook_url = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            flag_json = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--csv") == 0) {
            flag_csv = 1;
        } else if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--html") == 0) {
            flag_html = 1;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--apply") == 0) {
            flag_apply = 1;
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0) {
            flag_force = 1;
        } else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("LinSpec\n");
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output-dir") == 0) {
            if (i + 1 < argc) output_dir = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--profile") == 0) {
            if (i + 1 < argc) profile_path = argv[++i];
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--watch") == 0) {
            if (i + 1 < argc) {
                watch_interval = atoi(argv[++i]);
                if (watch_interval > 0) flag_watch = 1;
            }
        } else if (strcmp(argv[i], "-W") == 0 || strcmp(argv[i], "--webhook") == 0) {
            if (i + 1 < argc) {
                webhook_url = argv[++i];
                flag_webhook = 1;
            }
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage();
            return 1;
        }
    }

    if (!flag_json && !flag_csv && !flag_html && !flag_apply && !flag_watch) {
        flag_json = 1;
        flag_csv = 1;
    }

    if (flag_watch) {
        return run_watch(watch_interval, profile_path,
                         flag_json, flag_csv, flag_html, output_dir);
    }

    printf(BOLD "+---LinSpec"          "---------------------------------------------------------------------+\n" RESET);
    printf("  Forensic Kernel Hardening Audit\n");
    printf(BOLD "+-------------------------------------------------------------------------------+\n\n" RESET);

    check_result_t results[MAX_CHECKS];
    int count = run_all_checks(results, MAX_CHECKS, profile_path);

    print_results(results, count);
    print_summary(results, count);

    if ((flag_webhook || flag_json) && export_json(results, count, output_dir) == 0) {
        printf("    " GRN "o" RESET " JSON report generated\n");
    }
    if (flag_csv && export_csv(results, count, output_dir) == 0) {
        printf("    " GRN "o" RESET " CSV report generated\n");
    }
    if (flag_html && export_html(results, count, output_dir) == 0) {
        printf("    " GRN "o" RESET " HTML report generated\n");
    }

    if (flag_webhook) {
        send_webhook(webhook_url, output_dir);
    }

    if (flag_apply) {
        printf("\n" BOLD "+---Remediation---------------------------------------------------------------+\n" RESET);
        apply_remediation(results, count, flag_force);
    }

    return 0;
}
