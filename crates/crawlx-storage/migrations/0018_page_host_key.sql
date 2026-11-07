-- crawlx-storage 0018: the stored pages of one site. `POST /v2/map` extends its live
-- results with the URLs earlier runs of the tenant recorded for the same host or domain.
-- `host_key` is the page's host, lower-case and REVERSED, so a domain and all its subdomains
-- share a prefix (`moc.elpmaxe` and `moc.elpmaxe.sub`) and one `text_pattern_ops` index serves
-- both the exact-host and the domain-with-subdomains lookup. Generated, so it needs no writer
-- and covers the rows that exist already.
ALTER TABLE pages ADD COLUMN host_key text GENERATED ALWAYS AS (
  reverse(lower(substring(canonical_url FROM '^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@]*@)?(\[[^]/?#]*\]|[^/?#:@]*)')))
) STORED;
CREATE INDEX pages_host_key ON pages (host_key text_pattern_ops);
