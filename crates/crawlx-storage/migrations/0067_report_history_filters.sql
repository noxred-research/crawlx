CREATE INDEX report_history_kind_keyset ON report_history(tenant_id,run_id,kind,fact_sequence);
CREATE INDEX report_history_host_keyset ON report_history(tenant_id,host_key,fact_sequence);
CREATE INDEX report_history_url_keyset ON report_history(tenant_id,url_key,fact_sequence);
CREATE INDEX report_history_expiry ON report_history(expires_at);
