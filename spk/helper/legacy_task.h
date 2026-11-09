#ifndef LEGACY_TASK_H
#define LEGACY_TASK_H

#include <stdio.h>

/* Reads synoschedtask --get output. Writes "id\tname" lines for enabled
 * tasks whose Command field contains update_blocklist.sh. */
void legacy_scan(FILE *in, FILE *out);

/* Runs synoschedtask --get state=enabled. Missing binary or a failed
 * call prints nothing and returns. The check is advisory. */
void cmd_legacy_task(void);

#endif
