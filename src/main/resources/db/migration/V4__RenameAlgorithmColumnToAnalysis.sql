-- The "algorithm" column stores the whole AnalysisRequestDTO (inputdata, preprocessing, algorithm, flags),
-- not just the algorithm; the algorithm name stays in algorithm_id. Rename it to say what it holds.

ALTER TABLE experiment RENAME COLUMN algorithm TO analysis;
ALTER TABLE experiment_run RENAME COLUMN algorithm TO analysis;
