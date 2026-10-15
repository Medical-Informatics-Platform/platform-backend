-- Results of studio runs that have not been saved yet.
--
-- "Run experiment" keeps its successful result here so "Save experiment" can persist exactly the
-- result the user reviewed instead of executing the analysis a second time. Rows are never listed
-- or shared; they only exist to be copied into "experiment", and the backend purges them once they
-- are older than experiments.run-draft-ttl.

CREATE TABLE IF NOT EXISTS experiment_run (
    uuid UUID PRIMARY KEY,
    created_by_username CHARACTER VARYING NOT NULL REFERENCES "user"(username) ON DELETE CASCADE,
    result TEXT,
    algorithm TEXT NOT NULL,
    algorithm_id TEXT,
    created TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    finished TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    mip_version TEXT
);

CREATE INDEX IF NOT EXISTS idx_experiment_run_created
    ON experiment_run (created);
