-- Dataset access now depends on the dataset label, and a dataset code means something only inside its data model.
-- allowed is a JSON object from data model (inputdata.data_model) to the array of lowercase dataset codes and labels
-- the user may use (ClaimUtils.usableDatasets). Labels are included because experiments saved before codes became
-- numeric name their datasets by the old text code, which has to equal a label, ignoring case.
-- Same rule as ClaimUtils.hasAccessRightsOnDatasets: no datasets, no data model, a data model with nothing allowed,
-- or an analysis that is not valid JSON proves no access.
CREATE OR REPLACE FUNCTION experiment_datasets_readable(analysis TEXT, allowed TEXT) RETURNS BOOLEAN AS $$
DECLARE
    input JSONB;
    validation JSONB;
    allowed_for_model JSONB;
BEGIN
    input := analysis::jsonb -> 'inputdata';
    IF jsonb_typeof(input -> 'datasets') IS DISTINCT FROM 'array' OR jsonb_array_length(input -> 'datasets') = 0 THEN
        RETURN FALSE;
    END IF;

    validation := COALESCE(NULLIF(input -> 'validation_datasets', 'null'::jsonb), '[]'::jsonb);
    IF jsonb_typeof(validation) <> 'array' THEN
        RETURN FALSE;
    END IF;

    IF jsonb_typeof(input -> 'data_model') IS DISTINCT FROM 'string' THEN
        RETURN FALSE;
    END IF;
    allowed_for_model := allowed::jsonb -> (input ->> 'data_model');
    IF jsonb_typeof(allowed_for_model) IS DISTINCT FROM 'array' THEN
        RETURN FALSE;
    END IF;

    RETURN NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text((input -> 'datasets') || validation) AS dataset
        WHERE (allowed_for_model ? lower(dataset)) IS NOT TRUE);
EXCEPTION
    WHEN data_exception THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;
