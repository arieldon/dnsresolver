# DNS Resolver

Map a hostname to an IP address on the Internet using DNS.


## Usage

```shell
$ ./dnsresolver example.com
(A) example.com 93.184.216.34
```

## Compilation

To build the program, simply run the script `compile.sh`, optionally pass
`--debug` as an argument.


## Tools & Sources

- `dig(1)`
- `wireshark(1)`
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
- [Julia Evans on DNS](https://jvns.ca/categories/dns/)
- [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/)
- [Computer Networking: A Top-Down Approach](https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm)
- [Ryan Fleury on Arena Allocators](https://www.rfleury.com/p/untangling-lifetimes-the-arena-allocator)
