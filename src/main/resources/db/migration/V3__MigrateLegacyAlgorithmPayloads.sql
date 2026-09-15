-- One-time conversion of experiment.algorithm payloads written in the old
-- AlgorithmExecutionDTO shape (top-level name/inputdata/parameters/preprocessing map)
-- into the AnalysisRequestDTO shape (top-level algorithm plus preprocessing list).
-- Rows already in the new shape are left untouched, and malformed/unrelated JSON is skipped.
DO $$
DECLARE
    experiment_row RECORD;
    legacy_json JSON;
    legacy JSONB;
    preprocessing JSONB;
    migrated JSONB;
BEGIN
    FOR experiment_row IN
        SELECT uuid, algorithm
        FROM experiment
        WHERE algorithm IS NOT NULL AND btrim(algorithm) <> ''
    LOOP
        BEGIN
            legacy_json := experiment_row.algorithm::json;
        EXCEPTION WHEN OTHERS THEN
            CONTINUE;
        END;

        legacy := legacy_json::jsonb;

        -- The new shape always carries the top-level algorithm object.
        IF legacy ? 'algorithm' THEN
            CONTINUE;
        END IF;

        -- The old AlgorithmExecutionDTO always had a top-level name.
        IF NOT (legacy ? 'name') THEN
            CONTINUE;
        END IF;

        IF legacy->'preprocessing' IS NULL OR legacy->'preprocessing' = 'null'::jsonb THEN
            preprocessing := NULL;
        ELSIF jsonb_typeof(legacy->'preprocessing') = 'object' THEN
            -- jsonb has no key order; json_each over the original json text preserves it.
            SELECT COALESCE(
                       jsonb_agg(jsonb_build_object('name', key, 'parameters', value::jsonb)),
                       '[]'::jsonb)
            INTO preprocessing
            FROM json_each(legacy_json->'preprocessing');
        ELSIF jsonb_typeof(legacy->'preprocessing') = 'array' THEN
            preprocessing := legacy->'preprocessing';
        ELSE
            preprocessing := NULL;
        END IF;

        migrated := jsonb_build_object(
            'request_id', NULL,
            'inputdata', jsonb_build_object(
                'data_model', legacy->'inputdata'->'data_model',
                'datasets', legacy->'inputdata'->'datasets',
                'validation_datasets', legacy->'inputdata'->'validation_datasets',
                'filters', legacy->'inputdata'->'filters',
                'variables', NULL
            ),
            'preprocessing', preprocessing,
            'algorithm', jsonb_build_object(
                'name', legacy->'name',
                'x', legacy->'inputdata'->'x',
                'y', legacy->'inputdata'->'y',
                'parameters', legacy->'parameters'
            ),
            'flags', NULL
        );

        UPDATE experiment
        SET algorithm = migrated::text
        WHERE uuid = experiment_row.uuid;
    END LOOP;
END $$;
