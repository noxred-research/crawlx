# Test fixtures

Throwaway TLS material for loopback tests. None of it protects anything, none of it is
trusted outside the tests, and none of it may be reused for any real service.

- `selfsigned.crt` / `selfsigned.key`: self-signed pair for `crawlx-test.invalid`,
  `localhost` and `127.0.0.1`.
- `proxy-ca.crt`: self-signed test CA (`crawlx-test-proxy-ca`) used to exercise a TLS
  intercepting proxy.
- `proxy-leaf.crt` / `proxy-leaf.key`: leaf certificate issued by that CA for
  `proxy.crawlx-test.invalid`, `localhost` and `127.0.0.1`.
- `mtls-ca.crt`: self-signed test CA (`crawlx-test-mtls-ca`) a loopback TLS server trusts to
  verify client certificates. Its key was discarded after signing.
- `mtls-client.crt` / `mtls-client.key`: client certificate issued by that CA
  (`crawlx-test-mtls-client`, `clientAuth`) and its unencrypted PKCS#8 EC key.
- `mtls-rogue.crt` / `mtls-rogue.key`: self-signed `clientAuth` pair the same server must
  refuse, because no trusted CA issued it.
