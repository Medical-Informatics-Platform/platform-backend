# Analysis and study terminology migration

This release uses Study → Analysis Group → Analysis. It requires the matching UI
release and breaks the previous platform API names; there are no legacy aliases.

## API contract for the UI

- `/services/analyses` replaces `/services/experiments`. Existing methods, query
  parameters and suffixes (including `/preview` and `/runs`) retain their behavior.
- `/services/studies` replaces `/services/experiment-folders`.
- Groups live at `/services/studies/{studyId}/groups/{groupId}`. Assign or remove
  a group with `PATCH /services/studies/{studyId}/members/{analysisUuid}/group`
  and `{ "groupId": "..." }`, or `{ "groupId": null }` to ungroup.
- Study/group creation accepts `{ "name": "...", "analysisUuid": "..." }`;
  the initial analysis is optional. Renaming accepts `{ "name": "..." }`.
- Collection response keys are `analyses` and `studies`; the analysis total is
  `totalAnalyses` (formerly `totalExperiments`). Study responses expose
  `analysisIds` and `groups`; each group exposes `id`, `name`, and `analysisIds`.
- Analysis preview/run bodies use `{ "name": "...", "analysisRequest": {...} }`.
  Analysis responses also use `analysisRequest`. Its contents retain `inputdata`,
  `preprocessing`, `algorithm`, `request_id`, and `flags` unchanged.
- The execution gateway stays internal, as on master. `/services/analyses/preview`
  computes without storing; `/services/analyses/runs` keeps a successful result;
  `POST /services/analyses` saves a kept result using `{ "runId": "...", "name": "..." }`.
- IDs, membership rules, ordering, pagination, authorization, sharing, and result
  behavior are unchanged. The existing unsaved run entity from master is retained as AnalysisRun.

## Data-model errors and UI messages

Backend source, exceptions and messages use Data model. For `GET
/services/data-models`, the UI must map HTTP status to its own Pathology wording:

| HTTP status | Meaning | Suggested UI message |
| --- | --- | --- |
| 404 | Federation exposes no data models | No pathologies are available for this federation. |
| 403 | User has access to none of the available data models | You do not have access to any pathologies in this federation. |

The existing body is `{ statusCode, timestamp, message, description }`. Map the
status in the data-model loading context, without matching `message` text. Other
403/404 responses, network failures and server errors need their normal handling.
A 404 here does not mean that an individual requested pathology is missing.
The UI retains Pathology labels; this repository does not implement UI messages.

## Database and deployment

V6 renames the domain tables (including `analysis_run`), relationship/order columns, constraints and
indexes. The full-request `analysis` column (renamed from `algorithm` by V4) becomes `analysis_request`;
`algorithm_id` continues to store the algorithm name for filtering and sorting.
V6 does not rewrite request JSON. V1 through V5 remain unchanged, and still run first
on fresh installations. Hibernate mappings and package scanning use the new names.

The configuration key `authentication.all_experiments_allowed_claim` and its
external authority value `research_experiment_all` are intentionally retained:
renaming product entities must not change identity-provider access grants.

Back up PostgreSQL, stop old backend instances, apply the migration with the new
backend, and release the matching UI before reopening access. Update external API
clients too. Verify historical results, execution, permissions and memberships.
Rollback requires restoring the database backup and the matching old backend/UI;
old binaries cannot run against the renamed schema.

## Validation

Run `mvn -B -ntp test`, then validate Hibernate startup against migrated PostgreSQL.
Use a disposable database to run the transaction-isolated migration scenarios:

```sh
psql -X -v ON_ERROR_STOP=1 -f src/test/sql/terminology_migration.sql DATABASE
```

The SQL scenarios cover fresh and populated schemas, request/result preservation,
grouped and ungrouped memberships, ordering, and group/study deletion semantics.
