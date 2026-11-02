#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

/** Exit codes. */
enum {
  EXIT_OK = 0,
  EXIT_USAGE = 1,       /* bad command line or malformed address */
  EXIT_TABLE = 2,       /* table file can not be opened or has a bad line */
  EXIT_UNREACHABLE = 3, /* an address matched no route */
};

static void usage(FILE *out)
{
  fprintf(out, "Usage: myapp info <address>/<prefix>\n"
               "       myapp split <network>/<prefix> <count>\n"
               "       myapp lookup <table-file> <address>...\n");
}

static int cmd_info(const char *arg)
{
  cidr_t block;
  if (!cidr_parse(arg, &block)) {
    fprintf(stderr, "myapp: '%s' is not a valid <address>/<prefix>\n", arg);
    return EXIT_USAGE;
  }
  char buf[IP_STR_LEN];
  ip_format(block.addr, buf);
  printf("address    %s\n", buf);
  printf("prefix     /%u\n", (unsigned)block.prefix);
  ip_format(cidr_mask(block.prefix), buf);
  printf("netmask    %s\n", buf);
  ip_format(cidr_network(block), buf);
  printf("network    %s\n", buf);
  ip_format(cidr_broadcast(block), buf);
  printf("broadcast  %s\n", buf);
  ip_format(cidr_first_host(block), buf);
  printf("first host %s\n", buf);
  ip_format(cidr_last_host(block), buf);
  printf("last host  %s\n", buf);
  printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
  return EXIT_OK;
}

/** Parse a subnet count: decimal digits only, no sign, no leading zero. */
static bool parse_count(const char *text, uint32_t *count)
{
  if (text[0] < '1' || text[0] > '9') {
    return false;
  }
  errno = 0;
  char *end;
  unsigned long value = strtoul(text, &end, 10);
  if (*end != '\0' || errno == ERANGE || value > UINT32_MAX) {
    return false;
  }
  *count = (uint32_t)value;
  return true;
}

static int cmd_split(const char *block_arg, const char *count_arg)
{
  cidr_t block;
  if (!cidr_parse(block_arg, &block)) {
    fprintf(stderr, "myapp: '%s' is not a valid <network>/<prefix>\n", block_arg);
    return EXIT_USAGE;
  }
  if (!cidr_is_network(block)) {
    char network[CIDR_STR_LEN];
    cidr_t fixed = {cidr_network(block), block.prefix};
    cidr_format(fixed, network);
    fprintf(stderr, "myapp: '%s' has host bits set; the network is %s\n", block_arg,
            network);
    return EXIT_USAGE;
  }
  uint32_t count;
  if (!parse_count(count_arg, &count) || (count & (count - 1)) != 0) {
    fprintf(stderr, "myapp: '%s' is not a power of two\n", count_arg);
    return EXIT_USAGE;
  }
  cidr_t subnet;
  if (!cidr_subnet(block, count, 0, &subnet)) {
    fprintf(stderr, "myapp: can not split a /%u into %s subnets, the prefix would pass /32\n",
            (unsigned)block.prefix, count_arg);
    return EXIT_USAGE;
  }
  char buf[CIDR_STR_LEN];
  for (uint32_t i = 0; i < count; i++) {
    cidr_subnet(block, count, i, &subnet);
    cidr_format(subnet, buf);
    printf("%s\n", buf);
  }
  return EXIT_OK;
}

static int cmd_lookup(const char *path, int naddrs, char **addrs)
{
  FILE *in = fopen(path, "r");
  if (in == NULL) {
    fprintf(stderr, "myapp: %s: %s\n", path, strerror(errno));
    return EXIT_TABLE;
  }
  fwd_table_t *table = table_create();
  if (table == NULL) {
    fprintf(stderr, "myapp: out of memory\n");
    fclose(in);
    return EXIT_TABLE;
  }
  size_t bad_line;
  bool loaded = table_load(table, in, &bad_line);
  fclose(in);
  if (!loaded) {
    if (bad_line == 0) {
      fprintf(stderr, "myapp: %s: could not be read\n", path);
    } else {
      fprintf(stderr, "myapp: %s:%zu: not a valid route\n", path, bad_line);
    }
    table_destroy(table);
    return EXIT_TABLE;
  }

  bool malformed = false;
  bool unreachable = false;
  for (int i = 0; i < naddrs; i++) {
    uint32_t dest;
    if (!ip_parse(addrs[i], &dest)) {
      fprintf(stderr, "myapp: '%s' is not a valid address\n", addrs[i]);
      malformed = true;
      continue;
    }
    char buf[IP_STR_LEN];
    ip_format(dest, buf);
    const route_t *route = table_lookup(table, dest);
    if (route == NULL) {
      printf("%s unreachable\n", buf);
      unreachable = true;
    } else if (route->gateway != 0) {
      char gw[IP_STR_LEN];
      ip_format(route->gateway, gw);
      printf("%s via %s dev %s\n", buf, gw, route->dev);
    } else {
      printf("%s dev %s\n", buf, route->dev);
    }
  }
  table_destroy(table);

  if (malformed) {
    return EXIT_USAGE;
  }
  return unreachable ? EXIT_UNREACHABLE : EXIT_OK;
}

int main(int argc, char **argv)
{
  if (argc == 1) {
    usage(stdout);
    return EXIT_OK;
  }
  if (strcmp(argv[1], "info") == 0 && argc == 3) {
    return cmd_info(argv[2]);
  }
  if (strcmp(argv[1], "split") == 0 && argc == 4) {
    return cmd_split(argv[2], argv[3]);
  }
  if (strcmp(argv[1], "lookup") == 0 && argc >= 4) {
    return cmd_lookup(argv[2], argc - 3, argv + 3);
  }
  usage(stderr);
  return EXIT_USAGE;
}
