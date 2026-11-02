# P3: Subnetting and Forwarding

- Name: Adnan Maksic
- Email: [adnan.maksic06@gmail.com](mailto:adnan.maksic06@gmail.com)
- Class: CS525

## Overview

`myapp` does the address arithmetic CIDR notation hides and the longest prefix match a router runs on every packet.

```bash
make all
./build/release/myapp info 132.178.227.11/25
./build/release/myapp split 192.168.1.0/24 4
./build/release/myapp lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
```

Exit codes: 0 on success (and with no arguments, which prints the usage), 1 for a bad command line or malformed address, 2 when the table file cannot be opened or has a bad line, 3 when an address matches no route. A lookup run with both a malformed and an unreachable address exits 1.

## Design

1. **Parsing.** `ip_parse` and `cidr_parse` share a hand-written scanner that reads a bounded number of decimal digits and refuses a leading zero, then insist on `.`, `/` or `'\0'` right after. Signs, spaces, octal-looking octets and trailing junk are rejected rather than guessed at.
2. **/0, /31 and /32.** `cidr_mask(0)` returns 0 before it ever shifts, since `0xFFFFFFFF << 32` is undefined behavior and on x86 would make the default route match only 0.0.0.0. Host counts and subnet offsets are computed in 64 bits so a /0 gives 4294967294 instead of overflowing. For /31 (RFC 3021) and /32 the first and last host are the network and broadcast addresses themselves, and the host count is 2 and 1 instead of the formula.
3. **Forwarding table.** `fwd_table_t` is an array of `route_t` that doubles with `realloc`. `table_add` copies the route and refuses host bits and duplicate blocks. `table_lookup` scans every route and keeps the containing one with the longest prefix. It never stops at the first match, so insertion order does not matter, and the default route wins only when nothing more specific matches.

`tests/lab-test.c` covers every function, including the boundary prefixes, each kind of malformed input, nested routes added in several orders, a table with no default route and a file with a bad line in the middle. `src/lab.c` has 100% line and branch coverage. The only exclusion is the `realloc` failure path.

## Known Bugs or Issues

None known. `make leak` / `make leak-test` are clean.

## Experience

Once the mask was right, each subnet function was a line or two, so most of the work was in the edge cases. The /0 mask was the trap: the obvious shift is undefined behavior, and on x86 it seems to work while quietly breaking the default route. Writing the parser by hand showed how much `sscanf` and `inet_aton` accept that a router should not.
