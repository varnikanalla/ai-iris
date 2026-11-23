# AI-IRIS Database Preparation

This directory contains AI-IRIS PostgreSQL schema, role, trigger, function and disposable-database test files; it does not implement the frontend, FastAPI application, AI modules, Celery task code or deployment configuration.

## Requirements

- PostgreSQL 15 or later.
- `psql`, `createdb` and `dropdb` client tools in `PATH`.
- A PostgreSQL administrator for database and role setup, plus a dedicated migration identity.
- Separate runtime credentials for the API and worker.
- Docker is optional; if used, its Engine must be running.

The schema uses PostgreSQL's `pgcrypto` extension for UUID generation. Enable it as an appropriately privileged database administrator if the installation does not permit the schema setup identity to do so.

**Secrets:** Never store database passwords, KMS keys, token peppers or connector secrets in SQL files, source control or command-line arguments. Provision credentials through a secret manager or an interactive prompt.

## Database roles and security boundary

The database uses three PostgreSQL roles:

### `ai_iris_owner`

- `NOLOGIN`; owns schema objects and is used only for migrations and controlled maintenance.
- Grant a dedicated migration identity membership through the environment's administrator process. Runtime roles must not be members.

### `ai_iris_api`

- Shared database login used by FastAPI, with permissions limited to application operations.
- FastAPI is the trusted boundary for authentication, USER/ADMIN authorization and record ownership. PostgreSQL does not independently identify end users through this shared login.

### `ai_iris_worker`

- Separate Celery runtime login limited to opportunity collection and shared catalog verification.
- Has no general access to private user records, authentication records, applications, notifications, conversations or interview records.

No runtime role may be superuser or have `BYPASSRLS`. RLS policies and PostgreSQL session variables are not treated as proof of end-user identity. Client-supplied user IDs, role values and actor IDs are not authorization evidence. Public registration must create only `USER` accounts; provisioning an `ADMIN` is a controlled, audited process with MFA enrollment.

`roles.sql` supports bootstrap before schema creation and explicit object grants after schema creation. Future objects owned by `ai_iris_owner` receive no automatic public, API or worker table, sequence or function privileges.

### Permission summary

| Area | `ai_iris_api` | `ai_iris_worker` |
|---|---|---|
| User-owned profiles, resumes, analyses, recommendations, skill gaps, roadmaps, progress, applications, notifications, chat, interviews | Required operations; FastAPI repositories/services must scope every request to its authenticated principal | No table access |
| `users` | No direct table access; registration and verifier lookup functions only | None |
| Password verifier | Execute `lookup_password_verifier`; verifier is returned only to authentication code for Argon2id verification. Registration/update use narrow functions | None |
| Sessions/token family | Narrow create, rotate/reuse-detect and revoke functions; no direct table or hash reads | None |
| MFA | Narrow ciphertext storage/retrieval/confirmation operations; no direct table access or key access | None |
| Shared opportunity/skill/resource catalog | Read | Read catalog; write collection and verification data only |
| Source collection | No access | Limited source configuration columns, health fields, `collection_runs`, `collection_items`, `opportunities` and `opportunity_skills` |
| Applications/events | Application state/outcome through `transition_application`; event table is read-only | No transition function or application/event access |
| Audit | Append redacted events; `admin_list_audit_events` checks an asserted active ADMIN and bounds page size | Append task events only |
| Notification outbox | API-owned table and result function | No outbox or notification access; receives minimized Celery payloads and reports delivery through an authorized API endpoint |

Because end-user requests share `ai_iris_api`, database grants cannot distinguish USER from ADMIN or enforce per-user ownership. FastAPI must obtain identity and role from its authenticated server-side principal, ignore request-supplied ownership/role values, scope repository queries, and centrally authorize admin routes. These database permissions separate API, worker and migration responsibilities; they do not prove end-user identity.

## Authentication and sensitive data

- FastAPI hashes and verifies passwords with Argon2id. PostgreSQL does not perform password verification with bcrypt or `pgcrypto`. `lookup_password_verifier(email)` is the only operation returning a stored verifier; ordinary queries, API responses and user-facing errors must not expose it. Login failures should be generic and rate limited.
- Configure FastAPI and SQL logging to redact verifier values and credentials. Where supported, configure PostgreSQL `log_parameter_max_length=0` and `log_parameter_max_length_on_error=0`; do not log result rows or authentication function output. Verify logging configuration in each deployment environment.
- A compromised FastAPI process or shared API credential can invoke verifier lookup and may expose password verifiers. The database cannot validate that a user ID supplied to authentication/session functions represents the authenticated end user; FastAPI must authorize those calls. A compromised API credential can invoke every function granted to it.
- MFA material is encrypted before storage with KMS-managed keys. PostgreSQL stores ciphertext, not encryption keys. Only the authentication service identity should have KMS decrypt permission; compromise of that service or identity can expose MFA material.
- Refresh tokens are random opaque values. The application hashes them with an application-held pepper and sends only hashes, plus a non-secret pepper version, to PostgreSQL. `session_refresh_tokens` holds token history. Rotation is atomic; reuse of any consumed token revokes the entire affected login/session family. A family represents one login/device session, not all sessions for an account.

## Worker isolation and notifications

Workers do not query private user tables. The API assembles minimized, task-specific Celery inputs for private-data tasks; results return through an authenticated API persistence endpoint that checks ownership. A record ID in a task is not database authorization.

The API writes `notifications` and `notification_outbox` transactionally and dispatches minimized delivery payloads. The worker sends the delivery and reports the result through an authorized API endpoint; it has no database grant on either notification table. Outbox payloads should avoid unnecessary personal data and use explicit templates.

## Application transitions

`transition_application` and other security-sensitive functions are `SECURITY DEFINER`, owned by `ai_iris_owner`, use a fixed safe `search_path` and schema-qualified object references, and are not executable by `PUBLIC`. Intended functions receive explicit grants to `ai_iris_api`. Direct state/outcome updates are revoked. The transition function updates the application and appends its event in one transaction; runtime roles cannot update or delete application events.

FastAPI must authenticate and authorize external integration results before calling the transition function. The actor ID/type arguments are supplied by trusted FastAPI after its checks. The function can validate transition rules and check an asserted admin account, but the shared database credential can supply arguments, so this is not independent end-user authentication. FastAPI admin authorization tests remain necessary.

## Fresh disposable database setup (Windows PowerShell)

Run from the repository root against a local PostgreSQL 15+ instance. These commands create only the explicitly named disposable database; never use the cleanup command on a database containing user data.

```powershell
$env:PGHOST = "localhost"
$env:PGPORT = "5432"
$env:PGUSER = "postgres"

createdb ai_iris_dbcheck
psql -d ai_iris_dbcheck -v ON_ERROR_STOP=1 -f .\database\roles.sql
psql -d ai_iris_dbcheck -v ON_ERROR_STOP=1 -c "GRANT ai_iris_owner TO postgres"
psql -d ai_iris_dbcheck -v ON_ERROR_STOP=1 -f .\database\schema.sql
psql -d ai_iris_dbcheck -v ON_ERROR_STOP=1 -f .\database\triggers.sql
psql -d ai_iris_dbcheck -v ON_ERROR_STOP=1 -f .\database\roles.sql
psql -d ai_iris_dbcheck -v ON_ERROR_STOP=1 -f .\database\tests.sql
```

The local example grants migration membership to `postgres`; in a shared environment, grant `ai_iris_owner` only to a dedicated migration identity. `tests.sql` requires a PostgreSQL superuser as its test driver: it creates deterministic fixtures as `ai_iris_owner`, switches session authorization to each runtime role outside test transactions, runs each runtime phase in a rolled-back transaction, restores the original authorization, and deletes fixtures. It does not create or set passwords.

Expected successful test output ends with `Database assertions completed`; this is expected output, not a claim that tests have run. SQL tests cover table/function permissions, sensitive-column denial, token rotation and family-wide reuse revocation, worker restrictions, ownership foreign keys, learning progress, verification evidence, and application transitions/history. Cross-user SELECT/INSERT/UPDATE/DELETE and IDOR behavior require FastAPI tests because SQL cannot isolate users sharing `ai_iris_api`.

### Execution order

1. Create a fresh disposable PostgreSQL database.
2. Run `roles.sql` as an administrator to create roles and bootstrap defaults.
3. Grant the migration identity membership in `ai_iris_owner`.
4. Run `schema.sql` so schema objects are owned by `ai_iris_owner`.
5. Run `triggers.sql` as the migration owner.
6. Rerun `roles.sql` to apply explicit object grants.
7. Run `tests.sql` as the disposable database test administrator.
8. Run FastAPI ownership/authorization and IDOR tests separately when backend development is approved.

If setup fails or leaves a partially initialized disposable database, stop and inspect the error. For a clean retry, remove only `ai_iris_dbcheck` after confirming it contains no needed data, then recreate it and repeat the steps. To remove the disposable database after testing:

```powershell
$env:PGUSER = "postgres"
dropdb ai_iris_dbcheck
```

## Schema inventory

The schema contains **43 tables**: the 41-table business schema plus two additions:

- `session_refresh_tokens` stores hashed token lifecycle history for atomic rotation and reuse detection; `user_sessions.token_family_id` identifies the affected login family.
- `notification_outbox` stores durable API-owned delivery work associated with `notifications`; workers receive delivery payloads outside direct database access.

All prior module tables remain. The application has exactly two roles, `USER` and `ADMIN`; there are no employer, company or faculty account tables.

## Validation status and limitations

- Runtime PostgreSQL validation in this environment: **NOT RUN**. PostgreSQL client/server tools were unavailable, and the installed Docker CLI could not reach its Engine.
- Static review is not runtime validation. Run the setup and test commands in a working PostgreSQL 15+ disposable environment before backend development.
- SQL tests do not prove FastAPI repository ownership, IDOR resistance, login rate limiting, generic HTTP errors, KMS IAM isolation, Celery task authorization or log redaction; application/infrastructure tests are needed before release.
- The shared API credential remains high value: if compromised, it can exercise all API grants and invoke password-verifier lookup. Restrict network access, rotate credentials, monitor use, and protect FastAPI/KMS identities.
