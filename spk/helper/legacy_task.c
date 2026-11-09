#include "legacy_task.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>

#define LEGACY_NEEDLE "update_blocklist.sh"
#define LEGACY_BIN "/usr/syno/bin/synoschedtask"

static const char *skip_space(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

static int line_label(const char *buf, const char *label)
{
    size_t n = strlen(label);
    buf = skip_space(buf);
    if (strncmp(buf, label, n) != 0)
        return 0;
    return buf[n] == ':';
}

static int is_sched_field(const char *buf)
{
    static const char *labels[] = {
        "User", "ID", "Name", "State", "Owner", "App", "AppName", "Type",
        "Start date", "Run time", "Next Trigger", "CmdArgv", "Command",
        "Last Run Time", "Status", NULL
    };
    int i;
    for (i = 0; labels[i] != NULL; i++) {
        if (line_label(buf, labels[i]))
            return 1;
    }
    return 0;
}

static void copy_bracket(const char *line, char *out, size_t outlen)
{
    const char *lb;
    const char *rb;
    size_t i, j, n;

    if (outlen == 0)
        return;
    out[0] = '\0';
    lb = strchr(line, '[');
    if (lb == NULL)
        return;
    lb++;
    rb = strrchr(lb, ']');
    if (rb == NULL)
        return;
    n = (size_t)(rb - lb);
    j = 0;
    for (i = 0; i < n && j + 1 < outlen; i++) {
        unsigned char c = (unsigned char)lb[i];
        if (c < 0x20 || c == 0x7f)
            out[j++] = ' ';
        else
            out[j++] = (char)c;
    }
    out[j] = '\0';
}

static void copy_id(const char *line, char *out, size_t outlen)
{
    char tmp[64];
    size_t i;

    out[0] = '\0';
    copy_bracket(line, tmp, sizeof tmp);
    if (tmp[0] == '\0')
        return;
    for (i = 0; tmp[i] != '\0'; i++) {
        if (!isdigit((unsigned char)tmp[i]) || i + 1 >= outlen)
            return;
    }
    memcpy(out, tmp, i + 1);
}

struct legacy_task {
    char id[32];
    char name[192];
    int enabled;
    int hit;
    int in_cmd;
};

static void task_clear(struct legacy_task *t)
{
    t->id[0] = '\0';
    t->name[0] = '\0';
    t->enabled = 0;
    t->hit = 0;
    t->in_cmd = 0;
}

static void task_flush(struct legacy_task *t, FILE *out)
{
    const char *name;
    if (!t->hit || !t->enabled || t->id[0] == '\0')
        return;
    name = t->name[0] != '\0' ? t->name : t->id;
    fprintf(out, "%s\t%s\n", t->id, name);
}

/* Reads one physical line. *saw is set when the needle appears anywhere
 * on that line, including past the stored prefix. */
static int read_physical_line(FILE *in, char *buf, size_t buflen, int *saw)
{
    char win[64];
    size_t n = 0;
    size_t wlen = 0;
    int any = 0;
    int c;

    *saw = 0;
    win[0] = '\0';
    while ((c = fgetc(in)) != EOF) {
        any = 1;
        if (c == '\n')
            break;
        if (c == '\r')
            continue;
        if (n + 1 < buflen)
            buf[n++] = (char)c;
        if (wlen + 1 < sizeof win) {
            win[wlen++] = (char)c;
            win[wlen] = '\0';
        } else {
            memmove(win, win + 1, sizeof win - 2);
            win[sizeof win - 2] = (char)c;
            win[sizeof win - 1] = '\0';
        }
        if (strstr(win, LEGACY_NEEDLE) != NULL)
            *saw = 1;
    }
    buf[n] = '\0';
    if (c == EOF && !any)
        return 0;
    return 1;
}

void legacy_scan(FILE *in, FILE *out)
{
    struct legacy_task task;
    char buf[512];
    int saw = 0;

    task_clear(&task);
    while (read_physical_line(in, buf, sizeof buf, &saw)) {
        if (task.in_cmd && !is_sched_field(buf)) {
            if (saw)
                task.hit = 1;
            continue;
        }
        task.in_cmd = 0;
        if (line_label(buf, "User")) {
            task_flush(&task, out);
            task_clear(&task);
        } else if (line_label(buf, "ID")) {
            copy_id(buf, task.id, sizeof task.id);
        } else if (line_label(buf, "Name")) {
            copy_bracket(buf, task.name, sizeof task.name);
        } else if (line_label(buf, "State")) {
            char state[32];
            copy_bracket(buf, state, sizeof state);
            task.enabled = strcmp(state, "enabled") == 0;
        } else if (line_label(buf, "Command")) {
            task.in_cmd = 1;
            if (saw)
                task.hit = 1;
        }
    }
    task_flush(&task, out);
}

void cmd_legacy_task(void)
{
    int pipefd[2];
    int devnull;
    pid_t pid;
    FILE *fp;

    if (access(LEGACY_BIN, X_OK) != 0)
        return;
    if (pipe(pipefd) != 0)
        return;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }
    if (pid == 0) {
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(pipefd[0]);
        close(pipefd[1]);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(LEGACY_BIN, "synoschedtask", "--get", "state=enabled", (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    fp = fdopen(pipefd[0], "r");
    if (fp == NULL) {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return;
    }
    legacy_scan(fp, stdout);
    fclose(fp);
    waitpid(pid, NULL, 0);
}
