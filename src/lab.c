#define _POSIX_C_SOURCE 200809L // getline()

#include "lab.h"
#include <stdlib.h>
#include <string.h>

/** A forwarding table: a growable array of routes, scanned in full on lookup. */
struct fwd_table {
  route_t *routes; /**< the routes, in the order they were added */
  size_t count;    /**< how many routes are in use */
  size_t capacity; /**< how many routes fit before the next realloc() */
};

/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

/**
 * Parse an unsigned decimal number of at most max_digits digits with no
 * leading zero ("0" itself is fine). On success *value holds the number and
 * the returned pointer is the first character after it; NULL on failure.
 */
static const char *parse_decimal(const char *p, int max_digits, uint32_t *value)
{
  if (!is_digit(*p)) {
    return NULL;
  }
  if (p[0] == '0' && is_digit(p[1])) {
    return NULL;
  }
  uint32_t v = 0;
  int digits = 0;
  while (is_digit(*p)) {
    if (++digits > max_digits) {
      return NULL;
    }
    v = v * 10 + (uint32_t)(*p - '0');
    p++;
  }
  *value = v;
  return p;
}

/**
 * Parse a dotted quad at the start of text. Returns a pointer just past it,
 * or NULL if text does not start with a valid one.
 */
static const char *parse_quad(const char *text, uint32_t *addr)
{
  const char *p = text;
  uint32_t result = 0;
  for (int i = 0; i < 4; i++) {
    if (i > 0) {
      if (*p != '.') {
        return NULL;
      }
      p++;
    }
    uint32_t octet;
    p = parse_decimal(p, 3, &octet);
    if (p == NULL || octet > 255) {
      return NULL;
    }
    result = (result << 8) | octet;
  }
  *addr = result;
  return p;
}

bool ip_parse(const char *text, uint32_t *addr)
{
  if (text == NULL || addr == NULL) {
    return false;
  }
  uint32_t value;
  const char *end = parse_quad(text, &value);
  if (end == NULL || *end != '\0') {
    return false;
  }
  *addr = value;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u", (unsigned)(addr >> 24) & 0xFFu,
           (unsigned)(addr >> 16) & 0xFFu, (unsigned)(addr >> 8) & 0xFFu,
           (unsigned)addr & 0xFFu);
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL || block == NULL) {
    return false;
  }
  uint32_t addr;
  const char *p = parse_quad(text, &addr);
  if (p == NULL || *p != '/') {
    return false;
  }
  uint32_t prefix;
  p = parse_decimal(p + 1, 2, &prefix);
  if (p == NULL || *p != '\0' || prefix > 32) {
    return false;
  }
  block->addr = addr;
  block->prefix = (uint8_t)prefix;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char ip[IP_STR_LEN];
  ip_format(block.addr, ip);
  unsigned prefix = block.prefix > 32 ? 32u : block.prefix;
  snprintf(out, CIDR_STR_LEN, "%s/%u", ip, prefix);
}

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

/** The prefix clamped to 32, the way cidr_mask() reads it. */
static unsigned prefix_of(cidr_t block)
{
  return block.prefix > 32 ? 32u : block.prefix;
}

uint32_t cidr_mask(uint8_t prefix)
{
  if (prefix == 0) {
    return 0; // 0xFFFFFFFF << 32 is undefined behavior, not 0
  }
  if (prefix > 32) {
    prefix = 32;
  }
  return UINT32_MAX << (32u - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return prefix_of(block) >= 31 ? network : network + 1;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return prefix_of(block) >= 31 ? broadcast : broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block)
{
  unsigned prefix = prefix_of(block);
  if (prefix == 32) {
    return 1;
  }
  if (prefix == 31) {
    return 2;
  }
  return ((uint64_t)1 << (32u - prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return (block.addr & ~cidr_mask(block.prefix)) == 0;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || !cidr_is_network(block)) {
    return false;
  }
  if (n == 0 || (n & (n - 1)) != 0) {
    return false;
  }
  unsigned borrowed = 0;
  while ((1u << borrowed) < n) {
    borrowed++;
  }
  unsigned prefix = prefix_of(block) + borrowed;
  if (prefix > 32 || i >= n) {
    return false;
  }
  // Shift in 64 bits: when n is 1 and the block is a /0, the shift is 32.
  uint64_t offset = (uint64_t)i << (32u - prefix);
  out->addr = cidr_network(block) + (uint32_t)offset;
  out->prefix = (uint8_t)prefix;
  return true;
}

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

static bool is_space(char c)
{
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static const char *skip_space(const char *p)
{
  while (is_space(*p)) {
    p++;
  }
  return p;
}

/**
 * Copy the next whitespace-separated field from *p into buf, which holds size
 * bytes including the '\0', and advance *p past it. Returns false if there is
 * no field or it does not fit.
 */
static bool next_field(const char **p, char *buf, size_t size)
{
  const char *start = skip_space(*p);
  const char *end = start;
  while (*end != '\0' && !is_space(*end)) {
    end++;
  }
  size_t len = (size_t)(end - start);
  if (len == 0 || len >= size) {
    return false;
  }
  memcpy(buf, start, len);
  buf[len] = '\0';
  *p = end;
  return true;
}

bool route_parse(const char *line, route_t *route)
{
  if (line == NULL || route == NULL) {
    return false;
  }
  char dest[CIDR_STR_LEN];
  char gateway[IP_STR_LEN];
  char dev[DEV_NAME_LEN];
  const char *p = line;
  if (!next_field(&p, dest, sizeof dest) || !next_field(&p, gateway, sizeof gateway) ||
      !next_field(&p, dev, sizeof dev) || *skip_space(p) != '\0') {
    return false;
  }

  route_t result;
  memset(&result, 0, sizeof result);
  if (strcmp(dest, "default") == 0) {
    result.dest.addr = 0;
    result.dest.prefix = 0;
  } else if (!cidr_parse(dest, &result.dest) || !cidr_is_network(result.dest)) {
    return false;
  }
  if (strcmp(gateway, "direct") == 0) {
    result.gateway = 0;
  } else if (!ip_parse(gateway, &result.gateway)) {
    return false;
  }
  memcpy(result.dev, dev, sizeof dev);
  *route = result;
  return true;
}

fwd_table_t *table_create(void)
{
  fwd_table_t *table = calloc(1, sizeof *table);
  return table; // NULL if calloc() failed
}

void table_destroy(fwd_table_t *table)
{
  if (table == NULL) {
    return;
  }
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL) {
    return false;
  }
  if (route->dest.prefix > 32 || !cidr_is_network(route->dest)) {
    return false;
  }
  for (size_t i = 0; i < table->count; i++) {
    const cidr_t *have = &table->routes[i].dest;
    if (have->addr == route->dest.addr && have->prefix == route->dest.prefix) {
      return false;
    }
  }
  if (table->count == table->capacity) {
    size_t capacity = table->capacity == 0 ? 8 : table->capacity * 2;
    route_t *routes = realloc(table->routes, capacity * sizeof *routes);
    if (routes == NULL) { // GCOVR_EXCL_START
      return false;
    } // GCOVR_EXCL_STOP
    table->routes = routes;
    table->capacity = capacity;
  }
  route_t *slot = &table->routes[table->count];
  *slot = *route;
  slot->dev[DEV_NAME_LEN - 1] = '\0';
  table->count++;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL) {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL) {
    return false;
  }

  char *line = NULL;
  size_t size = 0;
  size_t number = 0;
  bool ok = true;
  while (getline(&line, &size, in) != -1) {
    number++;
    char *comment = strchr(line, '#');
    if (comment != NULL) {
      *comment = '\0';
    }
    if (*skip_space(line) == '\0') {
      continue;
    }
    route_t route;
    if (!route_parse(line, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) {
        *bad_line = number;
      }
      ok = false;
      break;
    }
  }
  if (ok && ferror(in)) {
    ok = false; // bad_line stays 0: the file itself could not be read
  }
  free(line);
  return ok;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
  if (table == NULL) {
    return NULL;
  }
  const route_t *best = NULL;
  for (size_t i = 0; i < table->count; i++) {
    const route_t *route = &table->routes[i];
    if (cidr_contains(route->dest, dest) &&
        (best == NULL || route->dest.prefix > best->dest.prefix)) {
      best = route;
    }
  }
  return best;
}
