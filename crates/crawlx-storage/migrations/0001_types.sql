-- crawlx-storage 0001: vocabularies and the fencing-token sequence.
-- Enum labels match `as_str()` of the corresponding crawlx-core types so the
-- Rust side never needs a mapping table; where a design-doc label differs the
-- core label wins (risk_class, action_fidelity, terminal_reason).
CREATE TYPE run_status        AS ENUM ('queued','running','pausing','paused','cancelling','completed','failed','cancelled');
CREATE TYPE terminal_reason   AS ENUM ('frontier_exhausted','limit_reached','deadline_reached','policy_stopped','cancelled','fatal_error','recovery_exhausted');
CREATE TYPE crawl_mode        AS ENUM ('static','dynamic','hybrid');
CREATE TYPE safety_profile    AS ENUM ('read_only','test_environment','authorized_security_test');
CREATE TYPE retention_mode    AS ENUM ('standard','extended','zdr');
CREATE TYPE sensitivity_class AS ENUM ('metadata','content','sensitive','credential_bearing');
CREATE TYPE action_kind       AS ENUM ('click','keyboard_activate','type','select','set_checked','set_range','hover','drag','upload','scroll','keys','navigate','switch_tab','close_tab','synthetic_click');
CREATE TYPE action_status     AS ENUM ('proposed','intended','succeeded','failed','unknown','reconciled');
CREATE TYPE trust_lane        AS ENUM ('trusted_ui','diagnostic');
CREATE TYPE action_fidelity   AS ENUM ('native_pointer','native_keyboard','native_text_input','file_chooser','scripted_navigation','synthetic_dom_event','fetch_plane');
CREATE TYPE resource_context  AS ENUM ('own','other_user_same_role','higher_role','shared','none');
CREATE TYPE risk_class        AS ENUM ('navigation_reveal','reversible_local_preference','persistent_write_own','persistent_write_other_principal','external_communication','financial_transaction','destructive','security_change','file_upload','out_of_scope','unclassified');
CREATE SEQUENCE lease_fence_seq;
