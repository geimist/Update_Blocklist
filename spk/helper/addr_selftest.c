#include "addr.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(const char *in, const char *ip, const char *std)
{
    char got_ip[64], got_std[64];
    int ok = addr_canonical(in, got_ip, sizeof got_ip, got_std, sizeof got_std);
    if (ip == NULL) {
        if (ok) {
            fprintf(stderr, "accepted %s -> %s\n", in, got_ip);
            failures++;
        }
        return;
    }
    if (!ok || strcmp(got_ip, ip) != 0 || strcmp(got_std, std) != 0) {
        fprintf(stderr, "fail %s -> %s | %s\n", in, ok ? got_ip : "REJECT", ok ? got_std : "");
        failures++;
    }
}

int main(void)
{
    expect("2001:4451:3f7:c400:184f:4cdb:aa37:50ed",
           "2001:4451:3f7:c400:184f:4cdb:aa37:50ed",
           "2001:4451:03F7:C400:184F:4CDB:AA37:50ED");
    expect("2001:4451:03F7:C400:184F:4CDB:AA37:50ED",
           "2001:4451:3f7:c400:184f:4cdb:aa37:50ed",
           "2001:4451:03F7:C400:184F:4CDB:AA37:50ED");
    expect("2001:db8::1", "2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001");
    expect("::1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001");
    expect("::", "::", "0000:0000:0000:0000:0000:0000:0000:0000");
    expect("::ffff:1.2.3.4", "1.2.3.4", "0000:0000:0000:0000:0000:FFFF:0102:0304");
    expect("::ffff:102:304", "1.2.3.4", "0000:0000:0000:0000:0000:FFFF:0102:0304");
    expect("1.2.3.4", "1.2.3.4", "0000:0000:0000:0000:0000:FFFF:0102:0304");
    expect("01.2.3.4", "1.2.3.4", "0000:0000:0000:0000:0000:FFFF:0102:0304");
    expect("2001:DB8::1", "2001:db8::1", "2001:0DB8:0000:0000:0000:0000:0000:0001");
    expect("1:0:0:0:0:0:0:1", "1::1", "0001:0000:0000:0000:0000:0000:0000:0001");
    expect("2001:0:0:1:0:0:0:1", "2001:0:0:1::1", "2001:0000:0000:0001:0000:0000:0000:0001");
    expect("fe80::1%eth0", NULL, NULL);
    expect(":::1", NULL, NULL);
    expect("2001:db8::1::2", NULL, NULL);
    return failures == 0 ? 0 : 1;
}
