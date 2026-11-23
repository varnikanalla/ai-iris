-- Run as a PostgreSQL administrator before schema.sql, then rerun after
-- schema.sql and triggers.sql. Credentials are provisioned out of band.
-- This script never sets or changes a role password.

DO $bootstrap$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ai_iris_owner') THEN
        CREATE ROLE ai_iris_owner;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ai_iris_api') THEN
        CREATE ROLE ai_iris_api;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ai_iris_worker') THEN
        CREATE ROLE ai_iris_worker;
    END IF;
END
$bootstrap$;

-- Correct security attributes on rerun without replacing existing credentials.
ALTER ROLE ai_iris_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ai_iris_api LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ai_iris_worker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Runtime roles must not inherit privileges from other roles or be usable as
-- membership roles by other logins. Remove the forbidden owner membership,
-- then fail closed on any other unreviewed memberships.
REVOKE ai_iris_owner FROM ai_iris_api, ai_iris_worker;
DO $memberships$
DECLARE
    unexpected text;
BEGIN
    SELECT pg_catalog.string_agg(pg_catalog.format('%I is a member of %I', member_role.rolname, granted_role.rolname), ', ')
      INTO unexpected
      FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE member_role.rolname IN ('ai_iris_api', 'ai_iris_worker')
       AND granted_role.rolname <> 'ai_iris_owner';
    IF unexpected IS NOT NULL THEN
        RAISE EXCEPTION 'Remove unapproved runtime role memberships before continuing: %', unexpected;
    END IF;

    SELECT pg_catalog.string_agg(pg_catalog.format('%I is granted to %I', granted_role.rolname, member_role.rolname), ', ')
      INTO unexpected
      FROM pg_catalog.pg_auth_members m
      JOIN pg_catalog.pg_roles member_role ON member_role.oid = m.member
      JOIN pg_catalog.pg_roles granted_role ON granted_role.oid = m.roleid
     WHERE granted_role.rolname IN ('ai_iris_api', 'ai_iris_worker');
    IF unexpected IS NOT NULL THEN
        RAISE EXCEPTION 'Remove unapproved memberships in runtime roles before continuing: %', unexpected;
    END IF;
END
$memberships$;

DO $database_grants$
BEGIN
    EXECUTE pg_catalog.format(
        'GRANT CONNECT ON DATABASE %I TO ai_iris_owner, ai_iris_api, ai_iris_worker',
        pg_catalog.current_database()
    );
END
$database_grants$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC, ai_iris_api, ai_iris_worker;
GRANT USAGE, CREATE ON SCHEMA public TO ai_iris_owner;
GRANT USAGE ON SCHEMA public TO ai_iris_api, ai_iris_worker;

-- Every invocation first removes stale table, sequence, function, PUBLIC and
-- column-level grants. Column grants require a separate revoke in PostgreSQL.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, ai_iris_api, ai_iris_worker;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, ai_iris_api, ai_iris_worker;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, ai_iris_api, ai_iris_worker;
DO $column_grant_reset$
DECLARE
    col record;
BEGIN
    FOR col IN
        SELECT n.nspname, c.relname, a.attname
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
         WHERE n.nspname = 'public'
           AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND a.attnum > 0
           AND NOT a.attisdropped
    LOOP
        EXECUTE pg_catalog.format(
            'REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM PUBLIC, ai_iris_api, ai_iris_worker',
            col.attname, col.nspname, col.relname
        );
    END LOOP;
END
$column_grant_reset$;

-- On the first/bootstrap run the schema objects do not yet exist. The second
-- run applies only the grants below, after schema.sql and triggers.sql.
DO $object_grants$
BEGIN
    IF pg_catalog.to_regclass('public.users') IS NULL THEN
        RETURN;
    END IF;

    -- Shared catalog reads available to the API.
    GRANT SELECT ON public.skills, public.opportunities, public.learning_resources,
        public.learning_resource_skills, public.opportunity_skills TO ai_iris_api;

    -- FastAPI is the trusted per-user ownership boundary. These grants enable
    -- required repository operations but do not authenticate an end user.
    GRANT SELECT, INSERT, UPDATE, DELETE ON
        public.user_profiles, public.user_skills, public.experiences, public.experience_skills,
        public.projects, public.project_skills, public.certifications, public.certification_skills,
        public.resumes, public.resume_analyses, public.resume_skills,
        public.recommendation_runs, public.recommendation_items,
        public.skill_gap_runs, public.skill_gap_items, public.roadmaps, public.roadmap_steps,
        public.learning_progress, public.learning_progress_roadmap_steps,
        public.application_answers, public.saved_opportunities, public.notification_preferences,
        public.chat_sessions, public.chat_messages, public.interview_sessions, public.interview_items
    TO ai_iris_api;

    -- Authentication-sensitive tables have no direct API or worker grants.
    -- Their approved SECURITY DEFINER entry points are granted below.
    REVOKE ALL PRIVILEGES ON public.users, public.user_sessions,
        public.session_refresh_tokens, public.user_mfa_methods FROM ai_iris_api, ai_iris_worker;

    -- Application state changes are only through transition_application.
    GRANT SELECT ON public.applications TO ai_iris_api;
    GRANT INSERT (
        user_id, opportunity_id, selected_resume_id, cover_letter, portfolio_urls, submission_method
    ) ON public.applications TO ai_iris_api;
    GRANT UPDATE (
        selected_resume_id, cover_letter, portfolio_urls, submission_method, planned_at,
        external_link_opened_at, user_confirmed_submitted_at, externally_confirmed_submitted_at,
        external_application_url, submission_evidence_reference, submission_evidence_note, updated_at
    ) ON public.applications TO ai_iris_api;
    GRANT SELECT ON public.application_events TO ai_iris_api;

    GRANT SELECT, INSERT ON public.notifications TO ai_iris_api;
    GRANT UPDATE (read_at) ON public.notifications TO ai_iris_api;
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.notification_outbox TO ai_iris_api;

    GRANT INSERT (
        actor_user_id, action, target_type, target_id, request_id, result, metadata_redacted
    ) ON public.audit_events TO ai_iris_api;

    -- Worker permissions are limited to shared opportunity collection and
    -- catalog verification. No private user-owned table is granted here.
    GRANT SELECT ON public.skills TO ai_iris_worker;
    GRANT SELECT (
        id, name, source_type, terms_reference, enabled, poll_interval_minutes, connector_key,
        connector_version, secret_reference, sync_enabled, sync_settings, retry_policy,
        consecutive_failures, health_status, last_success_at, last_attempt_at, last_error_at,
        last_error_code, last_error_summary, next_sync_at, paused_at, updated_at
    ) ON public.opportunity_sources TO ai_iris_worker;
    GRANT UPDATE (
        last_success_at, consecutive_failures, health_status, last_attempt_at, last_error_at,
        last_error_code, last_error_summary, next_sync_at, updated_at
    ) ON public.opportunity_sources TO ai_iris_worker;

    GRANT SELECT ON public.collection_runs TO ai_iris_worker;
    GRANT INSERT (
        source_id, started_at, status, worker_version, attempt_number, retry_of_run_id,
        next_retry_at
    ) ON public.collection_runs TO ai_iris_worker;
    GRANT UPDATE (
        finished_at, status, items_seen, items_created, items_updated, error_summary,
        attempt_number, next_retry_at, error_code, failure_class, duration_ms,
        source_health_after_run
    ) ON public.collection_runs TO ai_iris_worker;

    GRANT SELECT ON public.collection_items TO ai_iris_worker;
    GRANT INSERT (
        run_id, source_external_id, canonicalized_source_url, content_hash, outcome,
        opportunity_id, error_code
    ) ON public.collection_items TO ai_iris_worker;

    GRANT SELECT (
        id, source_id, source_external_id, source_url, title, organization_name, description,
        location, work_mode, employment_type, posted_at, expires_at, status, first_seen_at,
        last_seen_at, content_hash, application_url, application_method,
        source_provided_verification, opportunity_type, salary_min, salary_max,
        compensation_currency, compensation_period, duration_value, duration_unit,
        application_deadline, eligibility_criteria, experience_requirements, verification_status,
        last_verified_at, verification_evidence
    ) ON public.opportunities TO ai_iris_worker;
    GRANT INSERT (
        source_id, source_external_id, source_url, title, organization_name, description,
        location, work_mode, employment_type, posted_at, expires_at, status, last_seen_at,
        content_hash, application_url, application_method, source_provided_verification,
        opportunity_type, salary_min, salary_max, compensation_currency, compensation_period,
        duration_value, duration_unit, application_deadline, eligibility_criteria,
        experience_requirements, verification_status, last_verified_at, verification_evidence
    ) ON public.opportunities TO ai_iris_worker;
    GRANT UPDATE (
        source_external_id, source_url, title, organization_name, description, location,
        work_mode, employment_type, posted_at, expires_at, status, last_seen_at, content_hash,
        application_url, application_method, source_provided_verification, opportunity_type,
        salary_min, salary_max, compensation_currency, compensation_period, duration_value,
        duration_unit, application_deadline, eligibility_criteria, experience_requirements,
        verification_status, last_verified_at, verification_evidence
    ) ON public.opportunities TO ai_iris_worker;

    GRANT SELECT ON public.opportunity_skills TO ai_iris_worker;
    GRANT INSERT (
        opportunity_id, skill_id, requirement_type, required_level, importance,
        extraction_confidence, evidence
    ) ON public.opportunity_skills TO ai_iris_worker;
    GRANT UPDATE (
        required_level, importance, extraction_confidence, evidence
    ) ON public.opportunity_skills TO ai_iris_worker;
    GRANT DELETE ON public.opportunity_skills TO ai_iris_worker;

    GRANT SELECT (
        id, provider, title, url, canonical_url, resource_type, difficulty, duration_minutes,
        pricing_type, price_amount, currency, pricing_verified_at, pricing_evidence_url,
        pricing_evidence_note, verification_status, verification_evidence_url,
        verification_evidence_note, last_verified_at, updated_at, retired_at
    ) ON public.learning_resources TO ai_iris_worker;
    GRANT INSERT (
        provider, title, url, canonical_url, resource_type, difficulty, duration_minutes,
        pricing_type, price_amount, currency, pricing_verified_at, pricing_evidence_url,
        pricing_evidence_note, verification_status, verification_evidence_url,
        verification_evidence_note, last_verified_at, retired_at
    ) ON public.learning_resources TO ai_iris_worker;
    GRANT UPDATE (
        pricing_type, price_amount, currency, pricing_verified_at, pricing_evidence_url,
        pricing_evidence_note, verification_status, verification_evidence_url,
        verification_evidence_note, last_verified_at, retired_at, updated_at
    ) ON public.learning_resources TO ai_iris_worker;

    GRANT SELECT ON public.learning_resource_skills TO ai_iris_worker;
    GRANT INSERT (
        resource_id, skill_id, coverage_level, mapping_confidence, evidence_note
    ) ON public.learning_resource_skills TO ai_iris_worker;
    GRANT UPDATE (
        coverage_level, mapping_confidence, evidence_note
    ) ON public.learning_resource_skills TO ai_iris_worker;

    -- Workers can append task-level audit events, but cannot claim a user actor.
    GRANT INSERT (
        action, target_type, target_id, request_id, result, metadata_redacted
    ) ON public.audit_events TO ai_iris_worker;

    -- Explicit API-only SECURITY DEFINER operations. The preceding global
    -- revoke removes PUBLIC and stale worker grants before this allowlist.
    GRANT EXECUTE ON FUNCTION public.register_user(text, text),
        public.lookup_password_verifier(text),
        public.set_password_verifier(uuid, text),
        public.create_session_family(uuid, text, text, timestamptz, text, text),
        public.rotate_refresh_token(text, text, text, text, timestamptz),
        public.revoke_session_family(uuid, uuid),
        public.revoke_all_user_sessions(uuid),
        public.get_mfa_ciphertext(uuid, uuid),
        public.save_mfa_ciphertext(uuid, text, bytea),
        public.confirm_mfa_method(uuid, uuid),
        public.disable_mfa_method(uuid, uuid),
        public.admin_list_audit_events(uuid, timestamptz, integer),
        public.set_notification_delivery_result(uuid, text, text),
        public.transition_application(uuid, uuid, text, text, text, text, text, text, text)
    TO ai_iris_api;
END
$object_grants$;

-- Future objects created as ai_iris_owner receive no PUBLIC or runtime grants.
-- Global defaults are revoked too; a schema-specific revoke cannot cancel a
-- privilege inherited from a global default ACL.
ALTER DEFAULT PRIVILEGES FOR ROLE ai_iris_owner
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, ai_iris_api, ai_iris_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE ai_iris_owner
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, ai_iris_api, ai_iris_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE ai_iris_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, ai_iris_api, ai_iris_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE ai_iris_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, ai_iris_api, ai_iris_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE ai_iris_owner IN SCHEMA public
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, ai_iris_api, ai_iris_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE ai_iris_owner IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, ai_iris_api, ai_iris_worker;

-- Provision login passwords interactively or through the environment's secret manager.
