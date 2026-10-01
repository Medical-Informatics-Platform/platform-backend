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

-- Rewrite experiment.algorithm rows stored before the analysis refactor into the AnalysisRequestDTO shape.
--
-- Legacy rows:  {name, inputdata: {data_model, datasets, x, y, validation_datasets, filters},
--                parameters, preprocessing: {step_name: params | [params, ...]}}
-- Current rows: {request_id, inputdata: {data_model, datasets, validation_datasets, filters, variables},
--                preprocessing: [{name, parameters}], algorithm: {name, x, y, parameters}, flags}
--
-- A preprocessing map becomes one step per entry (one per element for an array value), in the stored
-- key order, which is why it is read as json and not jsonb. Non-object values are dropped, matching the
-- UI's preprocessingConfigToSteps. inputdata.variables becomes y then x, deduplicated, and [] when both are
-- missing: Exaflow requires the list, so a replayed run must not send null.
-- Rows that are not a JSON object (JsonConverters stores the error message on a failed write) are left alone.

DO $$
DECLARE
    r RECORD;
    src JSON;
    doc JSONB;
    input JSONB;
    steps JSONB;
    rewritten INTEGER := 0;
BEGIN
    FOR r IN SELECT uuid, algorithm FROM experiment WHERE algorithm IS NOT NULL AND algorithm <> '' LOOP
        BEGIN
            src := r.algorithm::json;
            -- Valid json can still be invalid jsonb (a \u0000 escape): skip that row too, never abort startup.
            doc := src::jsonb;
        EXCEPTION WHEN others THEN
            RAISE WARNING 'V2: experiment % has an algorithm that is not valid JSON, left unchanged', r.uuid;
            CONTINUE;
        END;
        IF json_typeof(src) <> 'object' THEN
            CONTINUE;
        END IF;

        IF json_typeof(src -> 'preprocessing') = 'object' THEN
            SELECT jsonb_agg(jsonb_build_object('name', e.key, 'parameters', p.value::jsonb) ORDER BY e.ord, p.ord)
            INTO steps
            FROM json_each(src -> 'preprocessing') WITH ORDINALITY AS e(key, value, ord)
            CROSS JOIN LATERAL json_array_elements(
                CASE json_typeof(e.value)
                    WHEN 'array' THEN e.value
                    WHEN 'object' THEN json_build_array(e.value)
                    ELSE '[]'::json
                END) WITH ORDINALITY AS p(value, ord)
            WHERE json_typeof(p.value) = 'object';
            doc := jsonb_set(doc, '{preprocessing}', COALESCE(steps, 'null'::jsonb));
        END IF;

        IF NOT doc ? 'algorithm' AND doc ? 'name' THEN
            input := CASE WHEN jsonb_typeof(doc -> 'inputdata') = 'object' THEN doc -> 'inputdata' ELSE '{}'::jsonb END;
            doc := jsonb_build_object(
                'request_id', NULL,
                'inputdata', jsonb_build_object(
                    'data_model', input -> 'data_model',
                    'datasets', input -> 'datasets',
                    'validation_datasets', input -> 'validation_datasets',
                    'filters', input -> 'filters',
                    'variables', (
                        SELECT COALESCE(jsonb_agg(v ORDER BY rank, ord), '[]'::jsonb)
                        FROM (
                            SELECT DISTINCT ON (v) v, rank, ord
                            FROM (
                                SELECT v, 1 AS rank, ord FROM jsonb_array_elements_text(
                                    CASE WHEN jsonb_typeof(input -> 'y') = 'array' THEN input -> 'y' ELSE '[]'::jsonb END
                                ) WITH ORDINALITY AS y(v, ord)
                                UNION ALL
                                SELECT v, 2 AS rank, ord FROM jsonb_array_elements_text(
                                    CASE WHEN jsonb_typeof(input -> 'x') = 'array' THEN input -> 'x' ELSE '[]'::jsonb END
                                ) WITH ORDINALITY AS x(v, ord)
                            ) vars
                            ORDER BY v, rank, ord
                        ) distinct_vars)),
                'preprocessing', doc -> 'preprocessing',
                'algorithm', jsonb_build_object(
                    'name', doc -> 'name',
                    'x', input -> 'x',
                    'y', input -> 'y',
                    'parameters', doc -> 'parameters'),
                'flags', NULL);
        END IF;

        IF doc IS DISTINCT FROM src::jsonb THEN
            UPDATE experiment SET algorithm = doc::text WHERE uuid = r.uuid;
            rewritten := rewritten + 1;
        END IF;
    END LOOP;
    RAISE NOTICE 'V2: rewrote % legacy experiment analysis rows', rewritten;
END $$;
