/*
 * ab-helper.c
 *
 * Small setuid-root tool for AutoBan. DSM already ships sqlite3, so this
 * program only checks the fixed verbs and then calls that binary. It never
 * accepts free-form SQL.
 *
 * As root, --db / --backup-dir / --tmp-dir are ignored. Those flags exist
 * only so the same binary can be tested without setuid.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "addr.h"

#define PROD_DB "/etc/synoautoblock.db"
#define PROD_BACKUP "/var/packages/AutoBan/var/db_backups"
#define PROD_TMP "/var/packages/AutoBan/var/tmp"
#define MAX_INSERT (64L * 1024L * 1024L)

static const char *db_path = PROD_DB;
static const char *backup_dir = PROD_BACKUP;
static const char *tmp_dir = PROD_TMP;
static char sqlite_bin[PATH_MAX];
static uid_t caller_uid;
static gid_t caller_gid;

static void die(const char *msg)
{
    fprintf(stderr, "ab-helper: %s\n", msg);
    exit(1);
}

static void die_errno(const char *msg)
{
    fprintf(stderr, "ab-helper: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void usage(void)
{
    fprintf(stderr, "usage: ab-helper {ensure-schema|count|export-deny|delete-expired UNIX|insert-batch FILE RECORD EXPIRE DENY TYPE [META]|clear-blocklist|backup|restore SLOT|list-backups|export-db}\n");
}

static int parse_i64(const char *s, long long *out)
{
    char *end = NULL;
    long long v;
    if (s == NULL || *s == '\0')
        return -1;
    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0)
        return -1;
    *out = v;
    return 0;
}

static void find_sqlite(void)
{
    static const char *cands[] = {
        "/usr/bin/sqlite3",
        "/bin/sqlite3",
        "/usr/syno/bin/sqlite3",
        "/usr/local/bin/sqlite3",
        "/opt/homebrew/bin/sqlite3",
        NULL
    };
    int i;
    for (i = 0; cands[i] != NULL; i++) {
        if (access(cands[i], X_OK) == 0) {
            snprintf(sqlite_bin, sizeof sqlite_bin, "%s", cands[i]);
            return;
        }
    }
    die("sqlite3 not found");
}

static int wait_child(pid_t pid)
{
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        die_errno("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

/* sql == NULL means the child reads SQL from stdin_fd. */
static int run_sqlite_on(const char *path, const char *sql, int stdin_fd, int capture, char *out, size_t outlen)
{
    int pipefd[2] = {-1, -1};
    pid_t pid;
    char *argv[12];
    int argc = 0;

    if (capture) {
        if (pipe(pipefd) != 0)
            die_errno("pipe");
    }
    pid = fork();
    if (pid < 0)
        die_errno("fork");
    if (pid == 0) {
        if (stdin_fd >= 0 && dup2(stdin_fd, STDIN_FILENO) < 0)
            _exit(127);
        if (capture) {
            if (dup2(pipefd[1], STDOUT_FILENO) < 0)
                _exit(127);
            close(pipefd[0]);
            close(pipefd[1]);
        }
        argv[argc++] = "sqlite3";
        argv[argc++] = "-batch";
        argv[argc++] = "-cmd";
        argv[argc++] = ".timeout 5000";
        argv[argc++] = "-cmd";
        argv[argc++] = ".headers off";
        argv[argc++] = (char *)path;
        if (sql != NULL)
            argv[argc++] = (char *)sql;
        argv[argc] = NULL;
        execv(sqlite_bin, argv);
        _exit(127);
    }
    if (stdin_fd >= 0)
        close(stdin_fd);
    if (capture) {
        size_t n = 0;
        close(pipefd[1]);
        while (n + 1 < outlen) {
            ssize_t got = read(pipefd[0], out + n, outlen - 1 - n);
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (got == 0)
                break;
            n += (size_t)got;
        }
        out[n] = '\0';
        close(pipefd[0]);
    }
    return wait_child(pid);
}

static int run_sqlite(const char *sql, int stdin_fd, int capture, char *out, size_t outlen)
{
    return run_sqlite_on(db_path, sql, stdin_fd, capture, out, outlen);
}

static void sql_or_die(const char *sql)
{
    char buf[64];
    if (run_sqlite(sql, -1, 1, buf, sizeof buf) != 0)
        die("sqlite3 failed");
}

static long long sql_number(const char *sql)
{
    char buf[128];
    char *end = NULL;
    long long v;
    if (run_sqlite(sql, -1, 1, buf, sizeof buf) != 0)
        die("sqlite3 failed");
    errno = 0;
    v = strtoll(buf, &end, 10);
    if (end == buf || errno != 0)
        die("unexpected sqlite3 output");
    return v;
}

static const char *schema_sql =
    "CREATE TABLE IF NOT EXISTS AutoBlockIP("
    "IP varchar(50) PRIMARY KEY,"
    "RecordTime date NOT NULL,"
    "ExpireTime date NOT NULL,"
    "Deny boolean NOT NULL,"
    "IPStd varchar(50) NOT NULL,"
    "Type INTEGER,"
    "Meta varchar(256))";

static void cmd_ensure(void)
{
    sql_or_die(schema_sql);
}

static void cmd_count(void)
{
    long long n = sql_number("SELECT count(IP) FROM AutoBlockIP WHERE Deny='1'");
    printf("%lld\n", n);
}

static void cmd_export(void)
{
    if (run_sqlite("SELECT IP FROM AutoBlockIP WHERE Deny='1' ORDER BY IP ASC", -1, 0, NULL, 0) != 0)
        die("sqlite3 failed");
}

static void cmd_delete(const char *unix_s)
{
    long long now;
    char sql[160];
    if (parse_i64(unix_s, &now) != 0)
        die("bad timestamp");
    snprintf(sql, sizeof sql,
             "DELETE FROM AutoBlockIP WHERE ExpireTime <= %lld AND Deny='1' AND ExpireTime != '0'; SELECT changes();",
             now);
    printf("%lld\n", sql_number(sql));
}

static void cmd_clear(void)
{
    printf("%lld\n", sql_number("DELETE FROM AutoBlockIP WHERE Deny='1'; SELECT changes();"));
}

static int under_dir(const char *parent, const char *child, char *resolved, size_t n)
{
    char base[PATH_MAX];
    size_t blen;
    if (realpath(parent, base) == NULL || realpath(child, resolved) == NULL)
        return -1;
    blen = strlen(base);
    if (strncmp(resolved, base, blen) != 0)
        return -1;
    if (resolved[blen] != '/')
        return -1;
    if (strlen(resolved) >= n)
        return -1;
    return 0;
}

static void sql_escape(FILE *fp, const char *s)
{
    fputc('\'', fp);
    for (; *s != '\0'; s++) {
        if (*s == '\'')
            fputc('\'', fp);
        fputc(*s, fp);
    }
    fputc('\'', fp);
}

static void cmd_insert(int argc, char **argv)
{
    const char *file = argv[0];
    const char *meta = "";
    long long record, expire;
    long long deny, typ;
    char resolved[PATH_MAX];
    int in_fd, pipefd[2], outfd[2];
    pid_t pid;
    FILE *in, *sql;
    char line[512];
    char buf[128];
    size_t got = 0;
    struct stat st;

    if (argc != 5 && argc != 6)
        die("insert-batch FILE RECORD EXPIRE DENY TYPE [META]");
    if (parse_i64(argv[1], &record) != 0)
        die("bad record time");
    if (parse_i64(argv[2], &expire) != 0)
        die("bad expire time");
    if (parse_i64(argv[3], &deny) != 0 || (deny != 0 && deny != 1))
        die("deny must be 0 or 1");
    if (parse_i64(argv[4], &typ) != 0 || typ < 0 || typ > 3)
        die("type must be 0..3");
    if (argc == 6) {
        meta = argv[5];
        if (strlen(meta) > 256 || strchr(meta, '\n') != NULL || strchr(meta, '\r') != NULL)
            die("meta is too long");
    }
    if (under_dir(tmp_dir, file, resolved, sizeof resolved) != 0)
        die("insert file must be inside the temp directory");
    in_fd = open(resolved, O_RDONLY | O_NOFOLLOW);
    if (in_fd < 0)
        die_errno("open insert file");
    if (fstat(in_fd, &st) != 0 || !S_ISREG(st.st_mode))
        die("insert file is not a regular file");
    if (st.st_size > MAX_INSERT)
        die("insert file is too large");
    if (pipe(pipefd) != 0 || pipe(outfd) != 0)
        die_errno("pipe");
    pid = fork();
    if (pid < 0)
        die_errno("fork");
    if (pid == 0) {
        char *argv_sql[] = {
            "sqlite3", "-batch",
            "-cmd", ".timeout 5000",
            "-cmd", ".headers off",
            (char *)db_path, NULL
        };
        dup2(pipefd[0], STDIN_FILENO);
        dup2(outfd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        close(outfd[0]);
        close(outfd[1]);
        close(in_fd);
        execv(sqlite_bin, argv_sql);
        _exit(127);
    }
    close(pipefd[0]);
    close(outfd[1]);
    in = fdopen(in_fd, "r");
    sql = fdopen(pipefd[1], "w");
    if (in == NULL || sql == NULL)
        die("fdopen");
    fputs("BEGIN;\n", sql);
    fputs(schema_sql, sql);
    fputs(";\n", sql);
    while (fgets(line, sizeof line, in) != NULL) {
        char *p = line;
        size_t len;
        while (*p == ' ' || *p == '\t')
            p++;
        len = strlen(p);
        while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r' || p[len - 1] == ' ' || p[len - 1] == '\t'))
            p[--len] = '\0';
        if (*p == '\0' || strchr(p, '\n') != NULL)
            continue;
        {
            char ip[64], std[64];
            if (!addr_canonical(p, ip, sizeof ip, std, sizeof std))
                continue;
            fprintf(sql,
                    "INSERT OR IGNORE INTO AutoBlockIP (IP, RecordTime, ExpireTime, Deny, IPStd, Type, Meta) VALUES ("
                    "'%s',%lld,%lld,%lld,'%s',%lld,",
                    ip, record, expire, deny, std, typ);
        }
        sql_escape(sql, meta);
        fputs(");\n", sql);
    }
    fputs("SELECT total_changes();\nCOMMIT;\n", sql);
    fclose(in);
    fclose(sql);
    while (got + 1 < sizeof buf) {
        ssize_t n = read(outfd[0], buf + got, sizeof buf - 1 - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    buf[got] = '\0';
    close(outfd[0]);
    if (wait_child(pid) != 0)
        die("sqlite3 failed");
    printf("%lld\n", strtoll(buf, NULL, 10));
}

static int copy_file(const char *src, const char *dst, time_t when, int use_src_time)
{
    char tmp[PATH_MAX];
    int in, out;
    char block[8192];
    struct stat st;
    struct timespec ts[2];
    ssize_t n;

    if (snprintf(tmp, sizeof tmp, "%s.tmp", dst) >= (int)sizeof tmp)
        die("path too long");
    in = open(src, O_RDONLY);
    if (in < 0)
        return -1;
    if (fstat(in, &st) != 0) {
        close(in);
        return -1;
    }
    out = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }
    while ((n = read(in, block, sizeof block)) > 0) {
        char *p = block;
        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);
            if (w < 0) {
                close(in);
                close(out);
                unlink(tmp);
                return -1;
            }
            p += w;
            n -= w;
        }
    }
    if (n < 0 || fsync(out) != 0) {
        close(in);
        close(out);
        unlink(tmp);
        return -1;
    }
    close(in);
    if (close(out) != 0) {
        unlink(tmp);
        return -1;
    }
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    ts[0].tv_sec = ts[1].tv_sec = use_src_time ? st.st_mtime : when;
    if (utimensat(AT_FDCWD, tmp, ts, 0) != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, dst) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int snapshot(const char *dst)
{
    char tmp[PATH_MAX];
    char sql[PATH_MAX * 2];
    char quoted[PATH_MAX * 2];
    size_t i, j;
    if (snprintf(tmp, sizeof tmp, "%s.partial", dst) >= (int)sizeof tmp)
        die("path too long");
    unlink(tmp);
    j = 0;
    for (i = 0; tmp[i] != '\0' && j + 2 < sizeof quoted; i++) {
        if (tmp[i] == '\'')
            quoted[j++] = '\'';
        quoted[j++] = tmp[i];
    }
    quoted[j] = '\0';
    snprintf(sql, sizeof sql, "VACUUM INTO '%s'", quoted);
    if (run_sqlite(sql, -1, 1, (char[8]){0}, 8) != 0) {
        if (copy_file(db_path, tmp, 0, 1) != 0)
            return -1;
    }
    if (rename(tmp, dst) != 0)
        return -1;
    return 0;
}

static const char *cascade_name[] = {"hour", "day", "week", "month"};
static const time_t cascade_period[] = {3600, 86400, 7 * 86400, 30 * 86400};

/* Die Aufnahmezeit steht in der Kopie. Hyper Backup verwirft die Dateizeit. */
static void stamp_snapshot(const char *path, time_t when)
{
    char sql[256];
    snprintf(sql, sizeof sql,
             "CREATE TABLE IF NOT EXISTS autoban_taken(at INTEGER);"
             "DELETE FROM autoban_taken;"
             "INSERT INTO autoban_taken(at) VALUES (%lld);",
             (long long)when);
    if (run_sqlite_on(path, sql, -1, 0, NULL, 0) != 0)
        die("stamp failed");
}

static time_t snapshot_time(const char *path, time_t fallback)
{
    char buf[64];
    char *end = NULL;
    long long v;
    if (run_sqlite_on(path, "SELECT at FROM autoban_taken LIMIT 1", -1, 1, buf, sizeof buf) != 0)
        return fallback;
    errno = 0;
    v = strtoll(buf, &end, 10);
    if (end == buf || errno != 0 || v <= 0)
        return fallback;
    return (time_t)v;
}

/* Consistent copy of the system DB, owned by the caller so the UI can zip it. */
static void cmd_export_db(void)
{
    char dest[PATH_MAX];

    if (mkdir(tmp_dir, 0755) != 0 && errno != EEXIST)
        die_errno("tmp dir");
    if (snprintf(dest, sizeof dest, "%s/support-sys.db", tmp_dir) >= (int)sizeof dest)
        die("path too long");
    unlink(dest);
    if (snapshot(dest) != 0)
        die("snapshot failed");
    if (chown(dest, caller_uid, caller_gid) != 0)
        die_errno("chown");
    if (chmod(dest, 0600) != 0)
        die_errno("chmod");
}

static void cmd_backup(void)
{
    char incoming[PATH_MAX];
    char slot[PATH_MAX];
    char path_a[PATH_MAX];
    char path_b[PATH_MAX];
    char *disp = NULL;
    char *alt;
    struct timespec ts[2];
    time_t now = time(NULL);
    int i;
    struct stat st;

    if (stat(db_path, &st) != 0)
        die_errno("database");
    if (mkdir(backup_dir, 0755) != 0 && errno != EEXIST)
        die_errno("backup dir");
    if (snprintf(incoming, sizeof incoming, "%s/incoming.db", backup_dir) >= (int)sizeof incoming)
        die("path too long");
    unlink(incoming);
    if (snapshot(incoming) != 0)
        die("snapshot failed");
    ts[0].tv_sec = ts[1].tv_sec = now;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    utimensat(AT_FDCWD, incoming, ts, 0);
    stamp_snapshot(incoming, now);

    snprintf(slot, sizeof slot, "%s/pristine.db", backup_dir);
    if (stat(slot, &st) != 0) {
        if (errno != ENOENT || copy_file(incoming, slot, 0, 1) != 0)
            die("pristine backup failed");
    }
    snprintf(path_a, sizeof path_a, "%s/.cascade-a", backup_dir);
    snprintf(path_b, sizeof path_b, "%s/.cascade-b", backup_dir);
    snprintf(slot, sizeof slot, "%s/latest.db", backup_dir);
    if (stat(slot, &st) == 0) {
        if (copy_file(slot, path_a, 0, 1) != 0)
            die("backup rotation failed");
        disp = path_a;
    }
    if (copy_file(incoming, slot, 0, 1) != 0)
        die("latest backup failed");
    alt = path_b;
    for (i = 0; i < 4; i++) {
        int missing;
        if (disp == NULL)
            break;
        snprintf(slot, sizeof slot, "%s/%s.db", backup_dir, cascade_name[i]);
        missing = stat(slot, &st) != 0;
        if (!missing && now - snapshot_time(slot, st.st_mtime) < cascade_period[i])
            break;
        if (missing && errno != ENOENT)
            die_errno("backup slot");
        if (!missing) {
            if (copy_file(slot, alt, 0, 1) != 0)
                die("backup rotation failed");
        }
        if (copy_file(disp, slot, 0, 1) != 0)
            die("backup rotation failed");
        unlink(disp);
        if (missing) {
            disp = NULL;
        } else {
            disp = alt;
            alt = (strcmp(alt, path_b) == 0) ? path_a : path_b;
        }
    }
    unlink(path_a);
    unlink(path_b);
    unlink(incoming);
}

static int known_slot(const char *name)
{
    return strcmp(name, "pristine") == 0 || strcmp(name, "latest") == 0
        || strcmp(name, "hour") == 0 || strcmp(name, "day") == 0
        || strcmp(name, "week") == 0 || strcmp(name, "month") == 0;
}

static void cmd_restore(const char *slot)
{
    char src[PATH_MAX];
    char tmp[PATH_MAX];
    char side[PATH_MAX];
    struct stat st;
    if (!known_slot(slot))
        die("unknown backup slot");
    if (snprintf(src, sizeof src, "%s/%s.db", backup_dir, slot) >= (int)sizeof src)
        die("path too long");
    if (stat(src, &st) != 0)
        die("backup slot is missing");
    if (snprintf(tmp, sizeof tmp, "%s.restore", db_path) >= (int)sizeof tmp)
        die("path too long");
    if (copy_file(src, tmp, 0, 1) != 0)
        die("restore copy failed");
    if (rename(tmp, db_path) != 0)
        die_errno("restore");
    snprintf(side, sizeof side, "%s-wal", db_path);
    unlink(side);
    snprintf(side, sizeof side, "%s-shm", db_path);
    unlink(side);
}

static void cmd_list(void)
{
    static const char *names[] = {"pristine", "latest", "hour", "day", "week", "month"};
    int i;
    for (i = 0; i < 6; i++) {
        char path[PATH_MAX];
        struct stat st;
        snprintf(path, sizeof path, "%s/%s.db", backup_dir, names[i]);
        if (stat(path, &st) != 0)
            continue;
        printf("%s\t%lld\t%lld\n", names[i], (long long)snapshot_time(path, st.st_mtime), (long long)st.st_size);
    }
}

static void wipe_env(void)
{
    extern char **environ;
    while (environ != NULL && environ[0] != NULL) {
        char *eq = strchr(environ[0], '=');
        if (eq == NULL)
            break;
        *eq = '\0';
        unsetenv(environ[0]);
    }
}

static void lock_root(void)
{
    if (geteuid() != 0)
        return;
    if (setuid(0) != 0)
        die_errno("setuid");
    wipe_env();
    setenv("PATH", "/usr/bin:/bin:/usr/syno/bin:/usr/syno/sbin", 1);
    setenv("HOME", "/root", 1);
    db_path = PROD_DB;
    backup_dir = PROD_BACKUP;
    tmp_dir = PROD_TMP;
}

int main(int argc, char **argv)
{
    int root;
    int i;
    caller_uid = getuid();
    caller_gid = getgid();
    root = geteuid() == 0;
    lock_root();
    i = 1;
    if (!root) {
        while (i < argc) {
            if (strcmp(argv[i], "--db") == 0 || strcmp(argv[i], "--backup-dir") == 0 || strcmp(argv[i], "--tmp-dir") == 0) {
                if (i + 1 >= argc) {
                    usage();
                    return 2;
                }
                if (strcmp(argv[i], "--db") == 0)
                    db_path = argv[i + 1];
                else if (strcmp(argv[i], "--backup-dir") == 0)
                    backup_dir = argv[i + 1];
                else
                    tmp_dir = argv[i + 1];
                i += 2;
                continue;
            }
            break;
        }
    } else {
        while (i < argc && (strcmp(argv[i], "--db") == 0 || strcmp(argv[i], "--backup-dir") == 0 || strcmp(argv[i], "--tmp-dir") == 0)) {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            i += 2;
        }
    }
    if (i >= argc) {
        usage();
        return 2;
    }
    find_sqlite();
    if (strcmp(argv[i], "ensure-schema") == 0 && i + 1 == argc)
        cmd_ensure();
    else if (strcmp(argv[i], "count") == 0 && i + 1 == argc)
        cmd_count();
    else if (strcmp(argv[i], "export-deny") == 0 && i + 1 == argc)
        cmd_export();
    else if (strcmp(argv[i], "delete-expired") == 0 && i + 2 == argc)
        cmd_delete(argv[i + 1]);
    else if (strcmp(argv[i], "insert-batch") == 0)
        cmd_insert(argc - (i + 1), argv + i + 1);
    else if (strcmp(argv[i], "clear-blocklist") == 0 && i + 1 == argc)
        cmd_clear();
    else if (strcmp(argv[i], "backup") == 0 && i + 1 == argc)
        cmd_backup();
    else if (strcmp(argv[i], "restore") == 0 && i + 2 == argc)
        cmd_restore(argv[i + 1]);
    else if (strcmp(argv[i], "list-backups") == 0 && i + 1 == argc)
        cmd_list();
    else if (strcmp(argv[i], "export-db") == 0 && i + 1 == argc)
        cmd_export_db();
    else {
        usage();
        return 2;
    }
    return 0;
}
