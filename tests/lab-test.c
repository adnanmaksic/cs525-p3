#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

#define IP(a, b, c, d) \
  (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

static cidr_t block(uint32_t addr, uint8_t prefix)
{
  cidr_t b = {addr, prefix};
  return b;
}

static route_t route(uint32_t addr, uint8_t prefix, uint32_t gateway, const char *dev)
{
  route_t r;
  memset(&r, 0, sizeof r);
  r.dest = block(addr, prefix);
  r.gateway = gateway;
  strncpy(r.dev, dev, DEV_NAME_LEN - 1);
  return r;
}

/** Write text to a tmpfile() and rewind it, ready for table_load(). */
static FILE *file_with(const char *text)
{
  FILE *f = tmpfile();
  TEST_ASSERT_NOT_NULL(f);
  fputs(text, f);
  rewind(f);
  return f;
}

void setUp(void) {}

void tearDown(void) {}

/* ------------------------------------------------------------------------
 * Task 1
 * --------------------------------------------------------------------- */

void test_ip_parse_valid(void)
{
  uint32_t a = 0;
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &a));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010A, a);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &a));
  TEST_ASSERT_EQUAL_HEX32(0x00000000, a);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &a));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, a);
  TEST_ASSERT_TRUE(ip_parse("132.178.227.11", &a));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 11), a);
  TEST_ASSERT_TRUE(ip_parse("10.0.100.9", &a));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 100, 9), a);
}

void test_ip_parse_rejects(void)
{
  const char *bad[] = {
      "1.2.3",     "1.2.3.4.5", "1..2.3",   "256.1.1.1", "010.0.0.1", "1.2.3.4x",
      "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/", "1.2.3/24", "",          ".1.2.3",
      "1.2.3.",    "1.2.3.4.",  " 1.2.3.4", "1.2.3.4 ", "+1.2.3.4",  "-1.2.3.4",
      "1.2.3.-4",  "1.2.3.0004", "1.2.3.1000", "a.b.c.d", "1.2.3.00", "1,2,3,4",
      "1.2.3.4/24",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    uint32_t a = 0xDEADBEEF;
    TEST_ASSERT_FALSE_MESSAGE(ip_parse(bad[i], &a), bad[i]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xDEADBEEF, a, bad[i]);
  }
  uint32_t a;
  TEST_ASSERT_FALSE(ip_parse(NULL, &a));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
}

void test_ip_format(void)
{
  char buf[IP_STR_LEN];
  ip_format(0xC0A8010A, buf);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", buf);
  ip_format(0, buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", buf);
  ip_format(0xFFFFFFFF, buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", buf);
  ip_format(IP(10, 0, 100, 9), buf);
  TEST_ASSERT_EQUAL_STRING("10.0.100.9", buf);
}

void test_cidr_parse_valid(void)
{
  cidr_t b;
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &b));
  TEST_ASSERT_EQUAL_HEX32(IP(192, 168, 1, 0), b.addr);
  TEST_ASSERT_EQUAL_UINT8(24, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &b));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 11), b.addr);
  TEST_ASSERT_EQUAL_UINT8(25, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &b));
  TEST_ASSERT_EQUAL_HEX32(0, b.addr);
  TEST_ASSERT_EQUAL_UINT8(0, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("255.255.255.255/32", &b));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, b.addr);
  TEST_ASSERT_EQUAL_UINT8(32, b.prefix);
  TEST_ASSERT_TRUE(cidr_parse("10.0.0.0/8", &b));
  TEST_ASSERT_EQUAL_UINT8(8, b.prefix);
}

void test_cidr_parse_rejects(void)
{
  const char *bad[] = {
      "1.2.3",       "1.2.3.4.5",  "1..2.3",      "256.1.1.1", "010.0.0.1",
      "1.2.3.4x",    "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/",  "1.2.3/24",
      "1.2.3.4",     "1.2.3.4/00", "1.2.3.4/100", "1.2.3.4/-1", "1.2.3.4/+8",
      "1.2.3.4/8x",  "1.2.3.4/ 8", "1.2.3.4 /8", "/24",       "",
      "1.2.3.4//24", "1.2.3.4/24/", "010.0.0.0/8",
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    cidr_t b = {0xDEADBEEF, 99};
    TEST_ASSERT_FALSE_MESSAGE(cidr_parse(bad[i], &b), bad[i]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xDEADBEEF, b.addr, bad[i]);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(99, b.prefix, bad[i]);
  }
  cidr_t b;
  TEST_ASSERT_FALSE(cidr_parse(NULL, &b));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.0/24", NULL));
}

void test_cidr_format(void)
{
  char buf[CIDR_STR_LEN];
  cidr_format(block(IP(192, 168, 1, 0), 24), buf);
  TEST_ASSERT_EQUAL_STRING("192.168.1.0/24", buf);
  cidr_format(block(IP(132, 178, 227, 11), 25), buf);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", buf);
  cidr_format(block(0, 0), buf);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", buf);
  cidr_format(block(0xFFFFFFFF, 32), buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", buf);
  cidr_format(block(0xFFFFFFFF, 200), buf);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", buf);
}

/* ------------------------------------------------------------------------
 * Task 2
 * --------------------------------------------------------------------- */

void test_cidr_mask(void)
{
  TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0x80000000, cidr_mask(1));
  TEST_ASSERT_EQUAL_HEX32(0xFF000000, cidr_mask(8));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF80, cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_mask(31));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(255));
}

void test_onyx(void)
{
  cidr_t onyx = block(IP(132, 178, 227, 11), 25);
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 0), cidr_network(onyx));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 127), cidr_broadcast(onyx));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 1), cidr_first_host(onyx));
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 126), cidr_last_host(onyx));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(onyx));
  TEST_ASSERT_TRUE(cidr_contains(onyx, IP(132, 178, 227, 50)));
  TEST_ASSERT_FALSE(cidr_contains(onyx, IP(132, 178, 227, 200)));
  TEST_ASSERT_FALSE(cidr_is_network(onyx));
}

void test_prefix_0(void)
{
  cidr_t all = block(IP(1, 2, 3, 4), 0);
  TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_network(all));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_broadcast(all));
  TEST_ASSERT_EQUAL_HEX32(0x00000001, cidr_first_host(all));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_last_host(all));
  TEST_ASSERT_EQUAL_UINT64(4294967294ULL, cidr_host_count(all));
  TEST_ASSERT_TRUE(cidr_contains(all, 0));
  TEST_ASSERT_TRUE(cidr_contains(all, 0xFFFFFFFF));
  TEST_ASSERT_TRUE(cidr_contains(all, IP(8, 8, 8, 8)));
  TEST_ASSERT_FALSE(cidr_is_network(all));
  TEST_ASSERT_TRUE(cidr_is_network(block(0, 0)));
}

void test_prefix_30(void)
{
  cidr_t b = block(IP(10, 0, 0, 5), 30);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 4), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 5), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 6), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(b));
}

void test_prefix_31(void)
{
  cidr_t link = block(IP(10, 0, 0, 7), 31);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 6), cidr_network(link));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), cidr_broadcast(link));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 6), cidr_first_host(link));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), cidr_last_host(link));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(link));
  TEST_ASSERT_TRUE(cidr_contains(link, IP(10, 0, 0, 6)));
  TEST_ASSERT_TRUE(cidr_contains(link, IP(10, 0, 0, 7)));
  TEST_ASSERT_FALSE(cidr_contains(link, IP(10, 0, 0, 8)));
  TEST_ASSERT_FALSE(cidr_is_network(link));
  TEST_ASSERT_TRUE(cidr_is_network(block(IP(10, 0, 0, 6), 31)));
}

void test_prefix_32(void)
{
  cidr_t host = block(0xFFFFFFFF, 32);
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_network(host));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_broadcast(host));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_first_host(host));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_last_host(host));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(host));
  TEST_ASSERT_TRUE(cidr_contains(host, 0xFFFFFFFF));
  TEST_ASSERT_FALSE(cidr_contains(host, 0xFFFFFFFE));
  TEST_ASSERT_TRUE(cidr_is_network(host));

  cidr_t zero = block(0, 32);
  TEST_ASSERT_EQUAL_HEX32(0, cidr_first_host(zero));
  TEST_ASSERT_EQUAL_HEX32(0, cidr_last_host(zero));
  TEST_ASSERT_TRUE(cidr_contains(zero, 0));
  TEST_ASSERT_FALSE(cidr_contains(zero, 1));
}

void test_prefix_over_32_acts_like_32(void)
{
  cidr_t b = block(IP(10, 0, 0, 1), 40);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 1), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_is_network(b));
}

void test_cidr_contains_boundaries(void)
{
  cidr_t net = block(IP(192, 168, 1, 0), 24);
  TEST_ASSERT_TRUE(cidr_contains(net, IP(192, 168, 1, 0)));
  TEST_ASSERT_TRUE(cidr_contains(net, IP(192, 168, 1, 255)));
  TEST_ASSERT_FALSE(cidr_contains(net, IP(192, 168, 0, 255)));
  TEST_ASSERT_FALSE(cidr_contains(net, IP(192, 168, 2, 0)));
  TEST_ASSERT_TRUE(cidr_is_network(net));
  TEST_ASSERT_FALSE(cidr_is_network(block(IP(192, 168, 1, 5), 24)));
}

void test_cidr_subnet_split_24_in_4(void)
{
  cidr_t net = block(IP(192, 168, 1, 0), 24);
  const uint32_t expect[] = {IP(192, 168, 1, 0), IP(192, 168, 1, 64), IP(192, 168, 1, 128),
                             IP(192, 168, 1, 192)};
  for (uint32_t i = 0; i < 4; i++) {
    cidr_t out = {0, 0};
    TEST_ASSERT_TRUE(cidr_subnet(net, 4, i, &out));
    TEST_ASSERT_EQUAL_HEX32(expect[i], out.addr);
    TEST_ASSERT_EQUAL_UINT8(26, out.prefix);
  }
}

void test_cidr_subnet_edges(void)
{
  cidr_t out;
  // n = 1 hands back the block itself, even for /0 and /32.
  TEST_ASSERT_TRUE(cidr_subnet(block(0, 0), 1, 0, &out));
  TEST_ASSERT_EQUAL_HEX32(0, out.addr);
  TEST_ASSERT_EQUAL_UINT8(0, out.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block(0xFFFFFFFF, 32), 1, 0, &out));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, out.addr);
  TEST_ASSERT_EQUAL_UINT8(32, out.prefix);

  // 0.0.0.0/0 in two halves.
  TEST_ASSERT_TRUE(cidr_subnet(block(0, 0), 2, 1, &out));
  TEST_ASSERT_EQUAL_HEX32(0x80000000, out.addr);
  TEST_ASSERT_EQUAL_UINT8(1, out.prefix);

  // 0.0.0.0/0 into 2^31 pieces: the last one is a /31 at the very top.
  TEST_ASSERT_TRUE(cidr_subnet(block(0, 0), 0x80000000u, 0x7FFFFFFFu, &out));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, out.addr);
  TEST_ASSERT_EQUAL_UINT8(31, out.prefix);

  // A /30 into four /32s.
  TEST_ASSERT_TRUE(cidr_subnet(block(IP(10, 0, 0, 4), 30), 4, 3, &out));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), out.addr);
  TEST_ASSERT_EQUAL_UINT8(32, out.prefix);

  // A /31 into two /32s.
  TEST_ASSERT_TRUE(cidr_subnet(block(IP(10, 0, 0, 6), 31), 2, 1, &out));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 7), out.addr);
  TEST_ASSERT_EQUAL_UINT8(32, out.prefix);
}

void test_cidr_subnet_rejects(void)
{
  cidr_t net = block(IP(192, 168, 1, 0), 24);
  cidr_t out = {0xDEADBEEF, 99};
  TEST_ASSERT_FALSE(cidr_subnet(net, 4, 0, NULL));
  TEST_ASSERT_FALSE(cidr_subnet(block(IP(192, 168, 1, 5), 24), 4, 0, &out)); // host bits
  TEST_ASSERT_FALSE(cidr_subnet(net, 0, 0, &out));                          // n = 0
  TEST_ASSERT_FALSE(cidr_subnet(net, 3, 0, &out));                          // not 2^k
  TEST_ASSERT_FALSE(cidr_subnet(net, 6, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(net, 512, 0, &out));                        // past /32
  TEST_ASSERT_FALSE(cidr_subnet(block(0xFFFFFFFF, 32), 2, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(net, 4, 4, &out));                          // i out of range
  TEST_ASSERT_FALSE(cidr_subnet(net, 1, 1, &out));
  TEST_ASSERT_EQUAL_HEX32(0xDEADBEEF, out.addr);
  TEST_ASSERT_EQUAL_UINT8(99, out.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(net, 256, 255, &out)); // exactly /32 is fine
  TEST_ASSERT_EQUAL_HEX32(IP(192, 168, 1, 255), out.addr);
  TEST_ASSERT_EQUAL_UINT8(32, out.prefix);
}

/* ------------------------------------------------------------------------
 * Task 3
 * --------------------------------------------------------------------- */

void test_route_parse_valid(void)
{
  route_t r;
  TEST_ASSERT_TRUE(route_parse("10.1.2.128/25 10.1.2.1 eth2", &r));
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 128), r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(25, r.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 1), r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth2", r.dev);

  TEST_ASSERT_TRUE(route_parse("  default\t132.178.227.1   eno1  \r\n", &r));
  TEST_ASSERT_EQUAL_HEX32(0, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, r.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 1), r.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", r.dev);

  TEST_ASSERT_TRUE(route_parse("\v10.0.0.0/8\fdirect eth1\f\v", &r));
  TEST_ASSERT_EQUAL_STRING("eth1", r.dev);

  TEST_ASSERT_TRUE(route_parse("132.178.227.0/25 direct eno1\n", &r));
  TEST_ASSERT_EQUAL_HEX32(0, r.gateway);

  TEST_ASSERT_TRUE(route_parse("0.0.0.0/0 direct abcdefghijklmno", &r)); // 15 chars
  TEST_ASSERT_EQUAL_STRING("abcdefghijklmno", r.dev);

  TEST_ASSERT_TRUE(route_parse("255.255.255.255/32 0.0.0.0 x", &r));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(32, r.dest.prefix);
}

void test_route_parse_rejects(void)
{
  const char *bad[] = {
      "",
      "   \n",
      "10.0.0.0/8",
      "10.0.0.0/8 10.1.0.1",
      "10.0.0.0/8 10.1.0.1 eth1 extra",
      "10.0.0.5/8 10.1.0.1 eth1",            // host bits set
      "10.0.0.0 10.1.0.1 eth1",              // no prefix
      "10.0.0.0/33 10.1.0.1 eth1",
      "255.255.255.255/320 10.1.0.1 eth1",   // destination too long
      "Default 10.1.0.1 eth1",
      "10.0.0.0/8 10.1.0.1/32 eth1",
      "10.0.0.0/8 Direct eth1",
      "10.0.0.0/8 010.1.0.1 eth1",
      "10.0.0.0/8 255.255.255.2555 eth1",    // gateway too long
      "10.0.0.0/8 10.1.0.1 abcdefghijklmnop", // 16 chars
  };
  for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    route_t r = route(0xDEADBEEF, 7, 0xDEADBEEF, "keep");
    TEST_ASSERT_FALSE_MESSAGE(route_parse(bad[i], &r), bad[i]);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0xDEADBEEF, r.dest.addr, bad[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("keep", r.dev, bad[i]);
  }
  route_t r;
  TEST_ASSERT_FALSE(route_parse(NULL, &r));
  TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

void test_table_create_destroy_count(void)
{
  fwd_table_t *t = table_create();
  TEST_ASSERT_NOT_NULL(t);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  TEST_ASSERT_NULL(table_lookup(t, IP(8, 8, 8, 8)));
  table_destroy(t);
  table_destroy(NULL);
  TEST_ASSERT_EQUAL_size_t(0, table_count(NULL));
  TEST_ASSERT_NULL(table_lookup(NULL, 0));
}

void test_table_add_rejects(void)
{
  fwd_table_t *t = table_create();
  route_t r = route(IP(10, 0, 0, 0), 8, 0, "eth0");
  TEST_ASSERT_FALSE(table_add(NULL, &r));
  TEST_ASSERT_FALSE(table_add(t, NULL));
  TEST_ASSERT_TRUE(table_add(t, &r));
  TEST_ASSERT_FALSE(table_add(t, &r)); // same block again
  route_t other_gw = route(IP(10, 0, 0, 0), 8, IP(1, 1, 1, 1), "eth9");
  TEST_ASSERT_FALSE(table_add(t, &other_gw));
  route_t host_bits = route(IP(10, 0, 0, 1), 8, 0, "eth0");
  TEST_ASSERT_FALSE(table_add(t, &host_bits));
  route_t long_prefix = route(IP(10, 0, 0, 0), 33, 0, "eth0");
  TEST_ASSERT_FALSE(table_add(t, &long_prefix));
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));
  // Same address, different prefix, is a different block.
  route_t r16 = route(IP(10, 0, 0, 0), 16, 0, "eth1");
  TEST_ASSERT_TRUE(table_add(t, &r16));
  TEST_ASSERT_EQUAL_size_t(2, table_count(t));
  table_destroy(t);
}

void test_table_add_copies_and_terminates(void)
{
  fwd_table_t *t = table_create();
  route_t r = route(IP(10, 0, 0, 0), 8, 0, "eth0");
  memset(r.dev, 'x', DEV_NAME_LEN); // no '\0' at all
  TEST_ASSERT_TRUE(table_add(t, &r));
  r.dest.prefix = 16; // changing the caller's copy must not change the table's
  const route_t *got = table_lookup(t, IP(10, 200, 0, 1));
  TEST_ASSERT_NOT_NULL(got);
  TEST_ASSERT_EQUAL_UINT8(8, got->dest.prefix);
  TEST_ASSERT_EQUAL_size_t(DEV_NAME_LEN - 1, strlen(got->dev));
  table_destroy(t);
}

void test_table_grows(void)
{
  fwd_table_t *t = table_create();
  for (uint32_t i = 0; i < 1000; i++) {
    route_t r = route(IP(10, 0, 0, 0) | (i << 8), 24, 0, "eth0");
    TEST_ASSERT_TRUE(table_add(t, &r));
  }
  TEST_ASSERT_EQUAL_size_t(1000, table_count(t));
  const route_t *got = table_lookup(t, IP(10, 0, 0, 0) | (999u << 8) | 7);
  TEST_ASSERT_NOT_NULL(got);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 0, 0, 0) | (999u << 8), got->dest.addr);
  table_destroy(t);
}

static const route_t nested[] = {
    {{0x0A000000, 8}, 0x0A010001, "eth1"},  // 10.0.0.0/8
    {{0x0A010000, 16}, 0, "eth1"},          // 10.1.0.0/16
    {{0x0A010200, 24}, 0, "eth2"},          // 10.1.2.0/24
    {{0x0A010280, 25}, 0x0A010201, "eth2"}, // 10.1.2.128/25
};

static void check_nested(const fwd_table_t *t)
{
  const route_t *r = table_lookup(t, IP(10, 1, 2, 200));
  TEST_ASSERT_NOT_NULL(r);
  TEST_ASSERT_EQUAL_UINT8(25, r->dest.prefix);
  r = table_lookup(t, IP(10, 1, 2, 5));
  TEST_ASSERT_NOT_NULL(r);
  TEST_ASSERT_EQUAL_UINT8(24, r->dest.prefix);
  r = table_lookup(t, IP(10, 1, 9, 9));
  TEST_ASSERT_NOT_NULL(r);
  TEST_ASSERT_EQUAL_UINT8(16, r->dest.prefix);
  r = table_lookup(t, IP(10, 2, 0, 1));
  TEST_ASSERT_NOT_NULL(r);
  TEST_ASSERT_EQUAL_UINT8(8, r->dest.prefix);
  // No default route, so anything outside 10/8 is unreachable.
  TEST_ASSERT_NULL(table_lookup(t, IP(11, 0, 0, 0)));
  TEST_ASSERT_NULL(table_lookup(t, IP(9, 255, 255, 255)));
  TEST_ASSERT_NULL(table_lookup(t, 0));
  TEST_ASSERT_NULL(table_lookup(t, 0xFFFFFFFF));
}

void test_lookup_longest_wins_any_order(void)
{
  const size_t orders[][4] = {
      {0, 1, 2, 3}, {3, 2, 1, 0}, {1, 3, 0, 2}, {2, 0, 3, 1},
  };
  for (size_t o = 0; o < sizeof orders / sizeof orders[0]; o++) {
    fwd_table_t *t = table_create();
    for (size_t i = 0; i < 4; i++) {
      TEST_ASSERT_TRUE(table_add(t, &nested[orders[o][i]]));
    }
    check_nested(t);
    table_destroy(t);
  }
}

void test_lookup_default_is_last_resort(void)
{
  fwd_table_t *t = table_create();
  route_t def = route(0, 0, IP(132, 178, 227, 1), "eno1");
  route_t lan = route(IP(132, 178, 227, 0), 25, 0, "eno1");
  route_t host = route(IP(132, 178, 227, 50), 32, IP(9, 9, 9, 9), "lo");
  TEST_ASSERT_TRUE(table_add(t, &host));
  TEST_ASSERT_TRUE(table_add(t, &lan));
  TEST_ASSERT_TRUE(table_add(t, &def));

  const route_t *r = table_lookup(t, IP(8, 8, 8, 8));
  TEST_ASSERT_NOT_NULL(r);
  TEST_ASSERT_EQUAL_UINT8(0, r->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 1), r->gateway);
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(t, 0)->dest.prefix);
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(t, 0xFFFFFFFF)->dest.prefix);
  TEST_ASSERT_EQUAL_UINT8(25, table_lookup(t, IP(132, 178, 227, 51))->dest.prefix);
  TEST_ASSERT_EQUAL_UINT8(32, table_lookup(t, IP(132, 178, 227, 50))->dest.prefix);
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(t, IP(132, 178, 227, 128))->dest.prefix);
  table_destroy(t);
}

static const char example[] =
    "# destination      gateway          device\n"
    "default            132.178.227.1    eno1\n"
    "132.178.227.0/25   direct           eno1\n"
    "10.0.0.0/8         10.1.0.1         eth1\n"
    "10.1.0.0/16        direct           eth1\n"
    "10.1.2.0/24        direct           eth2\n"
    "10.1.2.128/25      10.1.2.1         eth2   # a router behind eth2\n"
    "192.168.0.0/16     10.1.0.1         eth1\n";

void test_table_load_example(void)
{
  fwd_table_t *t = table_create();
  FILE *f = file_with(example);
  size_t bad = 99;
  TEST_ASSERT_TRUE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(7, table_count(t));

  const route_t *r = table_lookup(t, IP(132, 178, 227, 50));
  TEST_ASSERT_EQUAL_STRING("eno1", r->dev);
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);
  r = table_lookup(t, IP(8, 8, 8, 8));
  TEST_ASSERT_EQUAL_STRING("eno1", r->dev);
  TEST_ASSERT_EQUAL_HEX32(IP(132, 178, 227, 1), r->gateway);
  r = table_lookup(t, IP(10, 1, 2, 5));
  TEST_ASSERT_EQUAL_STRING("eth2", r->dev);
  TEST_ASSERT_EQUAL_HEX32(0, r->gateway);
  r = table_lookup(t, IP(10, 1, 2, 200));
  TEST_ASSERT_EQUAL_STRING("eth2", r->dev);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 2, 1), r->gateway);
  r = table_lookup(t, IP(192, 168, 4, 4));
  TEST_ASSERT_EQUAL_UINT8(16, r->dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(IP(10, 1, 0, 1), r->gateway);
  table_destroy(t);
}

void test_table_load_comments_and_blanks(void)
{
  fwd_table_t *t = table_create();
  FILE *f = file_with("\n   \n# only a comment\n\t# indented comment\n"
                      "default direct eth0#no space before comment\n"
                      "10.0.0.0/8 direct eth1"); // no trailing newline
  TEST_ASSERT_TRUE(table_load(t, f, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(2, table_count(t));
  TEST_ASSERT_EQUAL_STRING("eth0", table_lookup(t, IP(1, 1, 1, 1))->dev);
  table_destroy(t);

  t = table_create();
  f = file_with("");
  size_t bad = 99;
  TEST_ASSERT_TRUE(table_load(t, f, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  fclose(f);
  table_destroy(t);
}

void test_table_load_bad_line_in_middle(void)
{
  fwd_table_t *t = table_create();
  FILE *f = file_with("# header\n"
                      "default direct eth0\n"
                      "10.0.0.0/8 direct eth1\n"
                      "10.0.0.1/8 direct eth1\n" // host bits: line 4
                      "192.168.0.0/16 direct eth2\n");
  size_t bad = 0;
  TEST_ASSERT_FALSE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(4, bad);
  TEST_ASSERT_EQUAL_size_t(2, table_count(t)); // lines before stay
  TEST_ASSERT_EQUAL_UINT8(0, table_lookup(t, IP(192, 168, 0, 1))->dest.prefix);
  table_destroy(t);

  // A duplicate route is a bad line too, and bad_line may be NULL.
  t = table_create();
  f = file_with("default direct eth0\ndefault direct eth1\n");
  TEST_ASSERT_FALSE(table_load(t, f, NULL));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(1, table_count(t));
  table_destroy(t);

  // Garbage on the first line.
  t = table_create();
  f = file_with("hello world\n");
  TEST_ASSERT_FALSE(table_load(t, f, &bad));
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(1, bad);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  table_destroy(t);
}

void test_table_load_bad_args_and_unreadable(void)
{
  fwd_table_t *t = table_create();
  size_t bad = 99;
  TEST_ASSERT_FALSE(table_load(NULL, stdin, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  bad = 99;
  TEST_ASSERT_FALSE(table_load(t, NULL, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  TEST_ASSERT_FALSE(table_load(t, NULL, NULL));

  // A write-only stream can not be read: getline() fails with an error.
  FILE *f = fopen("/dev/null", "w");
  TEST_ASSERT_NOT_NULL(f);
  bad = 99;
  TEST_ASSERT_FALSE(table_load(t, f, &bad));
  TEST_ASSERT_EQUAL_size_t(0, bad);
  fclose(f);
  TEST_ASSERT_EQUAL_size_t(0, table_count(t));
  table_destroy(t);
}

int main(void)
{
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_valid);
  RUN_TEST(test_ip_parse_rejects);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse_valid);
  RUN_TEST(test_cidr_parse_rejects);
  RUN_TEST(test_cidr_format);
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_onyx);
  RUN_TEST(test_prefix_0);
  RUN_TEST(test_prefix_30);
  RUN_TEST(test_prefix_31);
  RUN_TEST(test_prefix_32);
  RUN_TEST(test_prefix_over_32_acts_like_32);
  RUN_TEST(test_cidr_contains_boundaries);
  RUN_TEST(test_cidr_subnet_split_24_in_4);
  RUN_TEST(test_cidr_subnet_edges);
  RUN_TEST(test_cidr_subnet_rejects);
  RUN_TEST(test_route_parse_valid);
  RUN_TEST(test_route_parse_rejects);
  RUN_TEST(test_table_create_destroy_count);
  RUN_TEST(test_table_add_rejects);
  RUN_TEST(test_table_add_copies_and_terminates);
  RUN_TEST(test_table_grows);
  RUN_TEST(test_lookup_longest_wins_any_order);
  RUN_TEST(test_lookup_default_is_last_resort);
  RUN_TEST(test_table_load_example);
  RUN_TEST(test_table_load_comments_and_blanks);
  RUN_TEST(test_table_load_bad_line_in_middle);
  RUN_TEST(test_table_load_bad_args_and_unreadable);
  return UNITY_END();
}
