/*
 * DSM AutoBlockIP address forms.
 * IP is the text in the block list: dotted IPv4, or IPv6 in lowercase RFC 5952.
 * IPStd is what the firewall compares: IPv4-mapped, or eight uppercase groups.
 * An IPv4-mapped address is stored as IPv4, so it does not appear twice.
 */
#ifndef AUTOBAN_ADDR_H
#define AUTOBAN_ADDR_H

#include <stdio.h>
#include <string.h>

static int addr_hex(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int addr_ipv4(const char *s, unsigned char o[4])
{
    int i;
    if (s == NULL)
        return 0;
    for (i = 0; i < 4; i++) {
        int v = 0;
        int digits = 0;
        if (*s < '0' || *s > '9')
            return 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (*s - '0');
            digits++;
            s++;
            if (digits > 3 || v > 255)
                return 0;
        }
        if (digits == 0)
            return 0;
        o[i] = (unsigned char)v;
        if (i < 3) {
            if (*s != '.')
                return 0;
            s++;
        }
    }
    return *s == '\0';
}

static void addr_v4_text(const unsigned char o[4], char *dst, size_t n)
{
    snprintf(dst, n, "%u.%u.%u.%u", o[0], o[1], o[2], o[3]);
}

static void addr_v4_std(const unsigned char o[4], char *dst, size_t n)
{
    snprintf(dst, n, "0000:0000:0000:0000:0000:FFFF:%02X%02X:%02X%02X",
             o[0], o[1], o[2], o[3]);
}

static int addr_parse_v6(const char *s, unsigned int g[8])
{
    unsigned int head[8], tail[8];
    int hn = 0, tn = 0, seen = 0;
    int i;
    size_t len;

    if (s == NULL || *s == '\0' || strchr(s, '%') != NULL)
        return 0;
    len = strlen(s);
    if (len > 45 || strchr(s, ':') == NULL)
        return 0;
    if (*s == ':') {
        if (s[1] != ':')
            return 0;
        seen = 1;
        s += 2;
        if (*s == '\0') {
            for (i = 0; i < 8; i++)
                g[i] = 0;
            return 1;
        }
    }
    while (*s != '\0') {
        const char *look;
        int dot = 0;
        unsigned int v;
        int digits;
        int h;

        if (*s == ':')
            return 0;
        for (look = s; *look != '\0' && *look != ':'; look++) {
            if (*look == '.') {
                dot = 1;
                break;
            }
        }
        if (dot) {
            unsigned char o[4];
            unsigned int v1, v2;
            if (!addr_ipv4(s, o))
                return 0;
            v1 = ((unsigned int)o[0] << 8) | o[1];
            v2 = ((unsigned int)o[2] << 8) | o[3];
            if (seen) {
                if (tn > 6)
                    return 0;
                tail[tn++] = v1;
                tail[tn++] = v2;
            } else {
                if (hn > 6)
                    return 0;
                head[hn++] = v1;
                head[hn++] = v2;
            }
            break;
        }
        v = 0;
        digits = 0;
        while ((h = addr_hex(*s)) >= 0) {
            v = (v << 4) | (unsigned int)h;
            digits++;
            s++;
            if (digits > 4)
                return 0;
        }
        if (digits == 0)
            return 0;
        if (seen) {
            if (tn >= 8)
                return 0;
            tail[tn++] = v;
        } else {
            if (hn >= 8)
                return 0;
            head[hn++] = v;
        }
        if (*s == '\0')
            break;
        if (*s != ':')
            return 0;
        s++;
        if (*s == ':') {
            if (seen)
                return 0;
            seen = 1;
            s++;
            if (*s == '\0')
                break;
        } else if (*s == '\0') {
            return 0;
        }
    }
    if (!seen) {
        if (hn != 8)
            return 0;
        for (i = 0; i < 8; i++)
            g[i] = head[i];
        return 1;
    }
    if (hn + tn > 7)
        return 0;
    {
        int zeros = 8 - hn - tn;
        int idx = 0;
        for (i = 0; i < hn; i++)
            g[idx++] = head[i];
        for (i = 0; i < zeros; i++)
            g[idx++] = 0;
        for (i = 0; i < tn; i++)
            g[idx++] = tail[i];
        return idx == 8;
    }
}

static int addr_mapped(const unsigned int g[8])
{
    return g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xffff;
}

static void addr_compress(const unsigned int g[8], char *dst, size_t n)
{
    int best = -1, bestlen = 0, i = 0;
    size_t used = 0;

    while (i < 8) {
        int j;
        if (g[i] != 0) {
            i++;
            continue;
        }
        j = i;
        while (j < 8 && g[j] == 0)
            j++;
        if (j - i > bestlen) {
            best = i;
            bestlen = j - i;
        }
        i = j;
    }
    if (bestlen < 2)
        best = -1;
    dst[0] = '\0';
    i = 0;
    while (i < 8) {
        int wrote;
        if (best >= 0 && i == best) {
            if (used + 2 >= n)
                return;
            dst[used++] = ':';
            i += bestlen;
            if (i >= 8) {
                dst[used++] = ':';
                dst[used] = '\0';
                return;
            }
            dst[used++] = ':';
            dst[used] = '\0';
            continue;
        }
        if (used > 0 && dst[used - 1] != ':') {
            if (used + 1 >= n)
                return;
            dst[used++] = ':';
        }
        wrote = snprintf(dst + used, n - used, "%x", g[i]);
        if (wrote < 0 || (size_t)wrote >= n - used)
            return;
        used += (size_t)wrote;
        i++;
    }
}

static void addr_v6_std(const unsigned int g[8], char *dst, size_t n)
{
    snprintf(dst, n, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
             g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7]);
}

/* Fills the IP column and IPStd. Returns 0 when the text is not one host address. */
static int addr_canonical(const char *s, char *ip, size_t ip_n, char *std, size_t std_n)
{
    unsigned char o[4];
    unsigned int g[8];

    if (s == NULL || ip == NULL || std == NULL || ip_n == 0 || std_n == 0)
        return 0;
    if (strchr(s, ':') == NULL) {
        if (!addr_ipv4(s, o))
            return 0;
        addr_v4_text(o, ip, ip_n);
        addr_v4_std(o, std, std_n);
        return 1;
    }
    if (!addr_parse_v6(s, g))
        return 0;
    if (addr_mapped(g)) {
        o[0] = (unsigned char)(g[6] >> 8);
        o[1] = (unsigned char)(g[6] & 0xff);
        o[2] = (unsigned char)(g[7] >> 8);
        o[3] = (unsigned char)(g[7] & 0xff);
        addr_v4_text(o, ip, ip_n);
        addr_v4_std(o, std, std_n);
        return 1;
    }
    addr_compress(g, ip, ip_n);
    addr_v6_std(g, std, std_n);
    return ip[0] != '\0' && std[0] != '\0';
}

#endif
