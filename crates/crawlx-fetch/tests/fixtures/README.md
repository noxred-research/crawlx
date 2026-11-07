# Test fixtures

Throwaway TLS material for loopback tests. None of it protects anything, none of it is
trusted outside the tests, and none of it may be reused for any real service.

- `selfsigned.crt` / `selfsigned.key`: self-signed pair for `crawlx-test.invalid`,
  `localhost` and `127.0.0.1`.
- `proxy-ca.crt`: self-signed test CA (`crawlx-test-proxy-ca`) used to exercise a TLS
  intercepting proxy.
- `proxy-leaf.crt` / `proxy-leaf.key`: leaf certificate issued by that CA for
  `proxy.crawlx-test.invalid`, `localhost` and `127.0.0.1`.
