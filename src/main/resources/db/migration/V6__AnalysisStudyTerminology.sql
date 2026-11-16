-- Structural renames only: stored request/result text and identifiers are never rewritten.
ALTER TABLE experiment RENAME TO analysis;
ALTER TABLE experiment_run RENAME TO analysis_run;
ALTER TABLE experiment_folder RENAME TO study;
ALTER TABLE experiment_set RENAME TO analysis_group;
ALTER TABLE experiment_folder_member RENAME TO study_member;

ALTER TABLE analysis RENAME COLUMN analysis TO analysis_request;
ALTER TABLE analysis_run RENAME COLUMN analysis TO analysis_request;
ALTER TABLE analysis_group RENAME COLUMN folder_id TO study_id;
ALTER TABLE study_member RENAME COLUMN folder_id TO study_id;
ALTER TABLE study_member RENAME COLUMN experiment_uuid TO analysis_id;
ALTER TABLE study_member RENAME COLUMN set_id TO group_id;
ALTER TABLE study_member RENAME COLUMN folder_position TO study_position;
ALTER TABLE study_member RENAME COLUMN set_position TO group_position;

-- Renaming a primary-key/unique constraint also renames its backing index.
ALTER TABLE analysis RENAME CONSTRAINT experiment_pkey TO analysis_pkey;
ALTER TABLE analysis RENAME CONSTRAINT experiment_status_check TO analysis_status_check;
ALTER TABLE analysis RENAME CONSTRAINT experiment_created_by_username_fkey TO analysis_created_by_username_fkey;
ALTER TABLE analysis_run RENAME CONSTRAINT experiment_run_pkey TO analysis_run_pkey;
ALTER TABLE analysis_run RENAME CONSTRAINT experiment_run_created_by_username_fkey TO analysis_run_created_by_username_fkey;
ALTER TABLE study RENAME CONSTRAINT experiment_folder_pkey TO study_pkey;
ALTER TABLE study RENAME CONSTRAINT experiment_folder_owner_username_fkey TO study_owner_username_fkey;
ALTER TABLE analysis_group RENAME CONSTRAINT experiment_set_pkey TO analysis_group_pkey;
ALTER TABLE analysis_group RENAME CONSTRAINT experiment_set_folder_id_fkey TO analysis_group_study_id_fkey;
ALTER TABLE study_member RENAME CONSTRAINT experiment_folder_member_pkey TO study_member_pkey;
ALTER TABLE study_member RENAME CONSTRAINT experiment_folder_member_folder_id_fkey TO study_member_study_id_fkey;
ALTER TABLE study_member RENAME CONSTRAINT experiment_folder_member_experiment_uuid_fkey TO study_member_analysis_id_fkey;
ALTER TABLE study_member RENAME CONSTRAINT experiment_folder_member_set_id_fkey TO study_member_group_id_fkey;
ALTER TABLE study_member RENAME CONSTRAINT uq_experiment_folder_member TO uq_study_member;

ALTER INDEX uq_experiment_folder_owner_name RENAME TO uq_study_owner_name;
ALTER INDEX uq_experiment_set_folder_name RENAME TO uq_analysis_group_study_name;
ALTER INDEX idx_experiment_folder_member_set RENAME TO idx_study_member_group;
ALTER INDEX idx_experiment_folder_member_experiment RENAME TO idx_study_member_analysis;
ALTER INDEX idx_experiment_run_created RENAME TO idx_analysis_run_created;

-- Identical to the shipped V5 rule, including fail-closed handling of malformed requests.
CREATE FUNCTION analysis_datasets_readable(analysis_request TEXT, allowed TEXT) RETURNS BOOLEAN AS $$
DECLARE
    input JSONB;
    validation JSONB;
BEGIN
    input := analysis_request::jsonb -> 'inputdata';
    IF jsonb_typeof(input -> 'datasets') IS DISTINCT FROM 'array' OR jsonb_array_length(input -> 'datasets') = 0 THEN
        RETURN FALSE;
    END IF;

    validation := COALESCE(NULLIF(input -> 'validation_datasets', 'null'::jsonb), '[]'::jsonb);
    IF jsonb_typeof(validation) <> 'array' THEN
        RETURN FALSE;
    END IF;

    RETURN NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text((input -> 'datasets') || validation) AS dataset
        WHERE (allowed::jsonb ? lower(dataset)) IS NOT TRUE);
EXCEPTION
    WHEN data_exception THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;

DROP FUNCTION experiment_datasets_readable(TEXT, TEXT);
