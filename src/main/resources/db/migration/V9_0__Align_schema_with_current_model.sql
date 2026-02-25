DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'user' AND column_name = 'subjectid'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'user' AND column_name = 'subject_id'
    ) THEN
        ALTER TABLE "user" RENAME COLUMN subjectid TO subject_id;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'user' AND column_name = 'agreenda'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'user' AND column_name = 'agree_nda'
    ) THEN
        ALTER TABLE "user" RENAME COLUMN agreenda TO agree_nda;
    END IF;
END
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'experiment' AND column_name = 'algorithmid'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'experiment' AND column_name = 'algorithm_id'
    ) THEN
        ALTER TABLE experiment RENAME COLUMN algorithmid TO algorithm_id;
    END IF;
END
$$;

ALTER TABLE experiment ADD COLUMN IF NOT EXISTS mip_version TEXT;
