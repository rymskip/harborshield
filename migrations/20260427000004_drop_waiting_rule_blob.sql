-- Drop the unused `rule` blob from waiting_container_rules.
--
-- The blob is a residue of the persistence-removal in
-- 20240103000003_remove_persistence.sql: production never deserializes
-- it (handlers/mod.rs::process_waiting_rules_for_container recomputes
-- rules from the source container's config). Today the column is part
-- of the primary key, so two writes from the same src to the same dst
-- with different bytes deduplicate as separate rows. After this
-- migration, dedup is by (src, dst) only — which matches the read
-- path's actual semantics.

CREATE TABLE waiting_container_rules_new (
  src_container_id   TEXT    NOT NULL,
  dst_container_name TEXT    NOT NULL,

  PRIMARY KEY (src_container_id, dst_container_name),
  FOREIGN KEY (src_container_id) REFERENCES containers(id)
) STRICT;

INSERT OR IGNORE INTO waiting_container_rules_new (src_container_id, dst_container_name)
SELECT src_container_id, dst_container_name FROM waiting_container_rules;

DROP TABLE waiting_container_rules;
ALTER TABLE waiting_container_rules_new RENAME TO waiting_container_rules;
