# Test fixtures

`selfsigned.crt` / `selfsigned.key` are a throwaway self-signed certificate and key pair
for `crawlx-test.invalid`, `localhost` and `127.0.0.1`. They exist only so tests can run a
loopback TLS server. They protect nothing, are trusted by nothing outside the tests, and
must never be reused for any real service.
