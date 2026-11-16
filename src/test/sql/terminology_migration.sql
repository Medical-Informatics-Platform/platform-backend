-- Run with: psql -X -v ON_ERROR_STOP=1 -f src/test/sql/terminology_migration.sql DATABASE
-- Both scenarios use isolated schemas and roll back all changes.
BEGIN;
CREATE SCHEMA terminology_fresh_test;
SET LOCAL search_path TO terminology_fresh_test;
\ir ../../main/resources/db/migration/V1__InitialSchema.sql
\ir ../../main/resources/db/migration/V2__ExperimentFoldersAndLegacyAnalysis.sql
\ir ../../main/resources/db/migration/V3__ExperimentRunDrafts.sql
\ir ../../main/resources/db/migration/V4__RenameAlgorithmColumnToAnalysis.sql
\ir ../../main/resources/db/migration/V5__ExperimentDatasetsReadableFunction.sql
\ir ../../main/resources/db/migration/V6__UnifyAnalysisStudyTerminology.sql
SELECT analysis_request, algorithm_id FROM analysis;
SELECT study_id, analysis_uuid, group_id, study_position, group_position FROM study_member;
ROLLBACK;

BEGIN;
CREATE SCHEMA terminology_populated_test;
SET LOCAL search_path TO terminology_populated_test;
\ir ../../main/resources/db/migration/V1__InitialSchema.sql
\ir ../../main/resources/db/migration/V2__ExperimentFoldersAndLegacyAnalysis.sql
\ir ../../main/resources/db/migration/V3__ExperimentRunDrafts.sql
\ir ../../main/resources/db/migration/V4__RenameAlgorithmColumnToAnalysis.sql
\ir ../../main/resources/db/migration/V5__ExperimentDatasetsReadableFunction.sql
INSERT INTO "user" (username) VALUES ('owner');
INSERT INTO experiment (uuid, name, created_by_username, status, result, analysis, algorithm_id, shared, viewed, mip_version)
VALUES ('00000000-0000-0000-0000-000000000001', 'Historical analysis', 'owner', 'success', '{"ok":true}',
'{"inputdata":{"data_model":"dm:1","datasets":["ds1"],"variables":["age"]},"preprocessing":[],"algorithm":{"name":"histogram"}}', 'histogram', true, true, '1');
INSERT INTO experiment_folder (id, owner_username, name, sort_order) VALUES
('00000000-0000-0000-0000-000000000002', 'owner', 'First study', 0),
('00000000-0000-0000-0000-000000000003', 'owner', 'Second study', 1);
INSERT INTO experiment_set (id, folder_id, name, sort_order) VALUES
('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000002', 'Models', 0);
INSERT INTO experiment_folder_member (id, folder_id, experiment_uuid, set_id, folder_position, set_position) VALUES
('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000004', 3, 2),
('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', NULL, 5, NULL);
CREATE TEMP TABLE expected_analysis AS SELECT uuid, name, created_by_username, status, result, finished,
analysis AS analysis_request, algorithm_id, created, updated, shared, viewed, mip_version FROM experiment;
CREATE TEMP TABLE expected_members AS SELECT id, folder_id AS study_id, experiment_uuid AS analysis_uuid,
set_id AS group_id, folder_position AS study_position, set_position AS group_position FROM experiment_folder_member;
\ir ../../main/resources/db/migration/V6__UnifyAnalysisStudyTerminology.sql
DO $$ BEGIN
    IF EXISTS (SELECT * FROM expected_analysis EXCEPT SELECT * FROM analysis)
       OR EXISTS (SELECT * FROM analysis EXCEPT SELECT * FROM expected_analysis) THEN
        RAISE EXCEPTION 'Analysis contents changed';
    END IF;
    IF EXISTS (SELECT * FROM expected_members EXCEPT SELECT * FROM study_member)
       OR EXISTS (SELECT * FROM study_member EXCEPT SELECT * FROM expected_members) THEN
        RAISE EXCEPTION 'Membership contents changed';
    END IF;
    IF (SELECT count(*) FROM study) <> 2 OR (SELECT count(*) FROM analysis_group) <> 1 THEN
        RAISE EXCEPTION 'Studies or groups lost';
    END IF;
END $$;
DELETE FROM analysis_group;
DO $$ BEGIN
    IF (SELECT count(*) FROM study_member) <> 2 OR EXISTS (SELECT 1 FROM study_member WHERE group_id IS NOT NULL) THEN
        RAISE EXCEPTION 'Deleting a group must ungroup its members';
    END IF;
END $$;
DELETE FROM study;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM study_member) OR (SELECT count(*) FROM analysis) <> 1 THEN
        RAISE EXCEPTION 'Deleting studies must preserve analyses';
    END IF;
END $$;
ROLLBACK;
