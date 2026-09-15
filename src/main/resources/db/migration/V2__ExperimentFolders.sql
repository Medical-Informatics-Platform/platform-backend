-- Experiment folders ("analysis sets") and the named subsets ("sets") inside them.
--
-- One member row per (folder, experiment) gives a strict partition for free: a run sits in at most
-- one set because moving it only repoints set_id. Set ordering and folder ordering live in
-- sort_order, member ordering inside a folder in folder_position, member ordering inside a set in
-- set_position.

CREATE TABLE IF NOT EXISTS experiment_folder (
    id UUID PRIMARY KEY,
    owner_username CHARACTER VARYING NOT NULL REFERENCES "user"(username) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sort_order INTEGER NOT NULL,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_experiment_folder_owner_name
    ON experiment_folder (owner_username, lower(name));

CREATE TABLE IF NOT EXISTS experiment_set (
    id UUID PRIMARY KEY,
    folder_id UUID NOT NULL REFERENCES experiment_folder(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sort_order INTEGER NOT NULL,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_experiment_set_folder_name
    ON experiment_set (folder_id, lower(name));

CREATE TABLE IF NOT EXISTS experiment_folder_member (
    id UUID PRIMARY KEY,
    folder_id UUID NOT NULL REFERENCES experiment_folder(id) ON DELETE CASCADE,
    experiment_uuid UUID NOT NULL REFERENCES experiment(uuid) ON DELETE CASCADE,
    set_id UUID REFERENCES experiment_set(id) ON DELETE SET NULL,
    folder_position INTEGER NOT NULL,
    set_position INTEGER,
    CONSTRAINT uq_experiment_folder_member UNIQUE (folder_id, experiment_uuid)
);

CREATE INDEX IF NOT EXISTS idx_experiment_folder_member_set
    ON experiment_folder_member(set_id);
CREATE INDEX IF NOT EXISTS idx_experiment_folder_member_experiment
    ON experiment_folder_member(experiment_uuid);
