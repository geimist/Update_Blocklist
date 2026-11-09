#include "legacy_task.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(const char *input, const char *want)
{
    char got[1024];
    FILE *in;
    FILE *out;
    size_t n;

    in = fmemopen((void *)input, strlen(input), "r");
    out = fmemopen(got, sizeof got, "w");
    if (in == NULL || out == NULL) {
        fprintf(stderr, "fmemopen failed\n");
        failures++;
        if (in != NULL)
            fclose(in);
        if (out != NULL)
            fclose(out);
        return;
    }
    legacy_scan(in, out);
    fclose(in);
    fflush(out);
    n = (size_t)ftell(out);
    fclose(out);
    if (n >= sizeof got)
        n = sizeof got - 1;
    got[n] = '\0';
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "got [%s]\nwant [%s]\n", got, want);
        failures++;
    }
}

int main(void)
{
    const char *enabled =
        "             User: [root]\n"
        "               ID: [93]\n"
        "             Name: [update_blocklist.sh]\n"
        "            State: [enabled]\n"
        "            Owner: [admin]\n"
        "          Command: [/volume1/homes/admin/script/update_blocklist.sh > /volume1/system/@Logfiles/update_blocklist/update_blocklistLOG_$(date +%Y-%m-%d_%H-%M).log 2>&1]\n"
        "           Status: [Success]\n";
    const char *disabled =
        "             User: [root]\n"
        "               ID: [93]\n"
        "             Name: [update_blocklist.sh]\n"
        "            State: [disabled]\n"
        "          Command: [/volume1/homes/admin/script/update_blocklist.sh]\n";
    const char *name_only =
        "             User: [root]\n"
        "               ID: [4]\n"
        "             Name: [update_blocklist.sh]\n"
        "            State: [enabled]\n"
        "          Command: [/bin/true > /volume1/system/@Logfiles/update_blocklist/update_blocklistLOG_x.log]\n";
    const char *multiline =
        "             User: [root]\n"
        "               ID: [7]\n"
        "             Name: [nightly]\n"
        "            State: [enabled]\n"
        "          Command: [/bin/bash -c '\n"
        "/volume1/homes/admin/script/update_blocklist.sh\n"
        "']\n"
        "    Last Run Time: Fri Oct 30 00:40:01 2026\n"
        "           Status: [Success]\n";
    char long_cmd[6000];
    size_t i;

    expect(enabled, "93\tupdate_blocklist.sh\n");
    expect(disabled, "");
    expect(name_only, "");
    expect(multiline, "7\tnightly\n");

    snprintf(long_cmd, sizeof long_cmd,
             "%s",
             "             User: [root]\n"
             "               ID: [8]\n"
             "             Name: [long]\n"
             "            State: [enabled]\n"
             "          Command: [");
    {
        size_t used = strlen(long_cmd);
        for (i = 0; i < 4000 && used + 1 < sizeof long_cmd; i++)
            long_cmd[used++] = 'x';
        snprintf(long_cmd + used, sizeof long_cmd - used,
                 "/volume1/script/update_blocklist.sh]\n"
                 "           Status: [Success]\n");
    }
    expect(long_cmd, "8\tlong\n");

    expect(
        "             User: [root]\n"
        "               ID: [1]\n"
        "             Name: [other]\n"
        "            State: [enabled]\n"
        "          Command: [/bin/true]\n"
        "             User: [root]\n"
        "               ID: [93]\n"
        "             Name: [update_blocklist.sh]\n"
        "            State: [enabled]\n"
        "          Command: [/volume1/homes/admin/script/update_blocklist.sh]\n",
        "93\tupdate_blocklist.sh\n");

    if (failures != 0) {
        fprintf(stderr, "%d failed\n", failures);
        return 1;
    }
    return 0;
}
