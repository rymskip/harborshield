-- Container references are resolved from Docker's live state on every reconcile, so the
-- tables that cached addresses, aliases, established pairs and pending references go.
DROP TABLE IF EXISTS waiting_container_rules;
DROP TABLE IF EXISTS est_containers;
DROP TABLE IF EXISTS container_aliases;
DROP TABLE IF EXISTS addrs;
