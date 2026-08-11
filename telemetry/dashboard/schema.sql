-- One column per field in ../event-schema.json, and nothing else.
--
-- That is deliberate and it is the whole trick: because the table is the schema
-- flattened, a Sigma rule written against the published schema converts to SQL
-- that runs here unchanged. telemetry/sigma/*.yml -> `sigma convert -t sqlite`
-- -> a WHERE clause this table answers. The dashboard's detection panel embeds
-- those converted clauses verbatim, and
-- tests/test_telemetry_controls.py::test_the_dashboard_detection_panel_matches_the_sigma_rules
-- fails if the two ever drift apart.
--
-- `arguments` is text rather than jsonb: the field is a JSON object on most
-- events but a plain redaction-marker STRING when a credential was detected
-- (see the schema), and a jsonb column would force that distinction into a
-- cast. Detections match the marker as a literal, so text is the honest type.

CREATE TABLE IF NOT EXISTS events (
    ts           timestamptz      NOT NULL,
    agent_id     text             NOT NULL,
    run_id       text,
    server       text,
    method       text             NOT NULL,
    tool         text,
    arguments    text,
    verdict      text,
    rule_id      text,
    owasp        text,
    reason       text,
    decision_ms  double precision,
    action       text
);

CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts);
CREATE INDEX IF NOT EXISTS events_rule_id_idx ON events (rule_id);
-- run_id is the grouping key for anything stateful (it is the scope the
-- `limit:` caps are counted over), so it earns an index of its own.
CREATE INDEX IF NOT EXISTS events_run_id_idx ON events (run_id);
