#ifndef REMEDIATOR_H
#define REMEDIATOR_H

#define REMEDIATOR_VERSION "1.0.0"
#define MAX_REMEDIATIONS 64
#define MAX_NAME 64
#define MAX_PATH 256
#define MAX_COMMAND 512
#define MAX_PERSISTENT 8192

typedef struct {
    int id;
    char name[MAX_NAME];
    char severity[16];
    int current_val;
    int recommended_val;
    char sysctl_param[MAX_PATH];
    char command[MAX_COMMAND];
    char persistent_line[MAX_PATH];
    int automated;
} remediation_t;

typedef struct {
    int total;
    int critical;
    int warning;
    remediation_t items[MAX_REMEDIATIONS];
    char persistent_block[MAX_PERSISTENT];
} remediation_plan_t;

int parse_linspec_report(const char *report_path, remediation_plan_t *plan);
int generate_remediation_json(const remediation_plan_t *plan, const char *outpath);
int apply_remediation_plan(const remediation_plan_t *plan, int force);

#endif
