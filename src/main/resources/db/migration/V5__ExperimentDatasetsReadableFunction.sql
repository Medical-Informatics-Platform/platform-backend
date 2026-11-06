-- True when every dataset an analysis reads is in allowed, a JSON array of lowercase dataset codes.
-- Lets experiment lists hide shared experiments in the query, so totals and filters cannot reveal them.
-- Same rule as ClaimUtils.hasAccessRightsOnDatasets and AnalysisInputDataDTO.allDatasets: no datasets named, or an
-- analysis that is not valid JSON (JsonConverters stores the error message on a failed write), proves no access.
CREATE FUNCTION experiment_datasets_readable(analysis TEXT, allowed TEXT) RETURNS BOOLEAN AS $$
DECLARE
    input JSONB;
    validation JSONB;
BEGIN
    input := analysis::jsonb -> 'inputdata';
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
