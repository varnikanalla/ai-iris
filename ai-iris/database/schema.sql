-- AI-IRIS fresh PostgreSQL schema. Requires PostgreSQL 15+.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
SET ROLE ai_iris_owner;

CREATE TABLE users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL,
 password_verifier text NOT NULL, role text NOT NULL DEFAULT 'USER' CHECK (role IN ('USER','ADMIN')),
 is_active boolean NOT NULL DEFAULT true, email_verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz
);
CREATE UNIQUE INDEX uq_users_email ON users(lower(email));
CREATE TABLE user_profiles (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 display_name text, location text, experience_level text,
 career_interests jsonb NOT NULL DEFAULT '[]', preferred_roles jsonb NOT NULL DEFAULT '[]',
 education_level text, institution text, graduation_date date, preferences jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE user_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_family_id uuid NOT NULL DEFAULT gen_random_uuid(), created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 revoked_at timestamptz, last_seen_at timestamptz, user_agent text, ip_hash text, CHECK(expires_at>created_at)
);
CREATE UNIQUE INDEX uq_user_sessions_family ON user_sessions(token_family_id);
CREATE INDEX ix_user_sessions_active ON user_sessions(user_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE session_refresh_tokens (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
 pepper_version text NOT NULL, token_hash text NOT NULL UNIQUE,
 issued_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 consumed_at timestamptz, revoked_at timestamptz,
 CHECK(length(btrim(pepper_version))>0),
 CHECK(expires_at>issued_at), CHECK(consumed_at IS NULL OR consumed_at>=issued_at),
 CHECK(revoked_at IS NULL OR revoked_at>=issued_at)
);
CREATE INDEX ix_session_refresh_tokens_session ON session_refresh_tokens(session_id,issued_at DESC);
CREATE INDEX ix_session_refresh_tokens_active ON session_refresh_tokens(expires_at) WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE TABLE user_mfa_methods (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 method text NOT NULL CHECK(method IN ('TOTP','WEBAUTHN')), encrypted_secret_or_credential bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), verified_at timestamptz, disabled_at timestamptz
);
CREATE INDEX ix_user_mfa_user ON user_mfa_methods(user_id);
CREATE TABLE audit_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 action text NOT NULL, target_type text NOT NULL, target_id uuid, occurred_at timestamptz NOT NULL DEFAULT now(),
 request_id text, result text NOT NULL, metadata_redacted jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ix_audit_actor_time ON audit_events(actor_user_id,occurred_at DESC);
CREATE INDEX ix_audit_target ON audit_events(target_type,target_id);
CREATE INDEX ix_audit_action_time ON audit_events(action,occurred_at DESC);

CREATE TABLE skills (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, normalized_name text NOT NULL UNIQUE,
 category text, taxonomy_version text, retired_at timestamptz
);
CREATE TABLE user_skills (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT, proficiency_level text,
 source text NOT NULL DEFAULT 'USER_REPORTED', years_experience numeric(5,2) CHECK(years_experience>=0),
 evidence_note text, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(user_id,skill_id)
);
CREATE INDEX ix_user_skills_skill ON user_skills(skill_id);
CREATE TABLE experiences (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title text NOT NULL, organization_name text, employment_type text, location text, start_date date, end_date date,
 description text, is_current boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz,
 CHECK(end_date IS NULL OR start_date IS NULL OR end_date>=start_date)
);
CREATE INDEX ix_experiences_user_dates ON experiences(user_id,start_date);
CREATE TABLE projects (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL, description text, project_url text, start_date date, end_date date,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz,
 CHECK(end_date IS NULL OR start_date IS NULL OR end_date>=start_date)
);
CREATE INDEX ix_projects_user_dates ON projects(user_id,start_date);
CREATE TABLE experience_skills (
 experience_id uuid NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT, PRIMARY KEY(experience_id,skill_id)
);
CREATE INDEX ix_experience_skills_skill ON experience_skills(skill_id);
CREATE TABLE project_skills (
 project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT, PRIMARY KEY(project_id,skill_id)
);
CREATE INDEX ix_project_skills_skill ON project_skills(skill_id);
CREATE TABLE certifications (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL, issuer text, credential_id text, credential_url text, issued_at date, expires_at date,
 verification_status text NOT NULL DEFAULT 'USER_ASSERTED' CHECK(verification_status IN
 ('USER_ASSERTED','PENDING','EXTERNALLY_VERIFIED','EXPIRED')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz,
 CHECK(expires_at IS NULL OR issued_at IS NULL OR expires_at>=issued_at)
);
CREATE INDEX ix_certifications_user_issued ON certifications(user_id,issued_at);
CREATE TABLE certification_skills (
 certification_id uuid NOT NULL REFERENCES certifications(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT, PRIMARY KEY(certification_id,skill_id)
);
CREATE INDEX ix_certification_skills_skill ON certification_skills(skill_id);

CREATE TABLE resumes (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 storage_key text NOT NULL UNIQUE, original_filename text NOT NULL, mime_type text NOT NULL,
 size_bytes bigint NOT NULL CHECK(size_bytes>0), sha256 char(64) NOT NULL, status text NOT NULL,
 uploaded_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz, UNIQUE(id,user_id)
);
CREATE INDEX ix_resumes_user_uploaded ON resumes(user_id,uploaded_at DESC);
CREATE TABLE resume_analyses (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), resume_id uuid NOT NULL, user_id uuid NOT NULL,
 parser_version text NOT NULL, model_version text, status text NOT NULL, extracted_text text,
 ats_results jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz,
 retention_expires_at timestamptz, UNIQUE(id,user_id),
 FOREIGN KEY(resume_id,user_id) REFERENCES resumes(id,user_id) ON DELETE CASCADE
);
CREATE INDEX ix_resume_analyses_resume_time ON resume_analyses(resume_id,created_at DESC);
CREATE INDEX ix_resume_analyses_user_time ON resume_analyses(user_id,created_at DESC);
CREATE INDEX ix_resume_analyses_retention ON resume_analyses(retention_expires_at) WHERE retention_expires_at IS NOT NULL;
CREATE TABLE resume_skills (
 resume_analysis_id uuid NOT NULL REFERENCES resume_analyses(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT, proficiency_level text,
 confidence numeric(4,3) CHECK(confidence BETWEEN 0 AND 1), evidence text,
 PRIMARY KEY(resume_analysis_id,skill_id)
);
CREATE INDEX ix_resume_skills_skill ON resume_skills(skill_id);

CREATE TABLE opportunity_sources (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE, source_type text NOT NULL,
 terms_reference text, enabled boolean NOT NULL DEFAULT false, poll_interval_minutes integer CHECK(poll_interval_minutes>0),
 last_success_at timestamptz, connector_key text, connector_version text, secret_reference text,
 sync_enabled boolean NOT NULL DEFAULT false, sync_settings jsonb NOT NULL DEFAULT '{}',
 retry_policy jsonb NOT NULL DEFAULT '{"max_attempts":3,"base_delay_seconds":30,"max_delay_seconds":1800}',
 consecutive_failures integer NOT NULL DEFAULT 0 CHECK(consecutive_failures>=0),
 health_status text NOT NULL DEFAULT 'UNKNOWN' CHECK(health_status IN ('UNKNOWN','HEALTHY','DEGRADED','FAILING','DISABLED')),
 last_attempt_at timestamptz, last_error_at timestamptz, last_error_code text, last_error_summary text,
 next_sync_at timestamptz, paused_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE opportunities (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), source_id uuid NOT NULL REFERENCES opportunity_sources(id) ON DELETE RESTRICT,
 source_external_id text, source_url text NOT NULL, title text NOT NULL, organization_name text, description text NOT NULL,
 location text, work_mode text, employment_type text, posted_at timestamptz, expires_at timestamptz,
 status text NOT NULL, first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(),
 content_hash char(64), application_url text, application_method text, source_provided_verification text,
 opportunity_type text NOT NULL DEFAULT 'JOB' CHECK(opportunity_type IN ('INTERNSHIP','JOB','GRADUATE_ROLE')),
 salary_min numeric(14,2), salary_max numeric(14,2), compensation_currency char(3),
 compensation_period text CHECK(compensation_period IS NULL OR compensation_period IN ('HOURLY','DAILY','WEEKLY','MONTHLY','YEARLY','TOTAL')),
 duration_value numeric(8,2), duration_unit text CHECK(duration_unit IS NULL OR duration_unit IN ('DAYS','WEEKS','MONTHS','YEARS')),
 application_deadline timestamptz, eligibility_criteria jsonb NOT NULL DEFAULT '{}',
 experience_requirements jsonb NOT NULL DEFAULT '{}',
 verification_status text NOT NULL DEFAULT 'UNVERIFIED' CHECK(verification_status IN
 ('UNVERIFIED','SOURCE_CONFIRMED','INDEPENDENTLY_CHECKED','REPORTED','DISPUTED','EXPIRED')),
 last_verified_at timestamptz, verification_evidence jsonb NOT NULL DEFAULT '{}',
 UNIQUE(id,source_id), CHECK(expires_at IS NULL OR posted_at IS NULL OR expires_at>=posted_at),
 CHECK(salary_min IS NULL OR salary_max IS NULL OR salary_max>=salary_min),
 CHECK((salary_min IS NULL AND salary_max IS NULL) OR compensation_currency IS NOT NULL),
 CHECK((duration_value IS NULL AND duration_unit IS NULL) OR (duration_value>0 AND duration_unit IS NOT NULL)),
 CHECK(verification_status NOT IN ('SOURCE_CONFIRMED','INDEPENDENTLY_CHECKED') OR
  (last_verified_at IS NOT NULL AND verification_evidence <> '{}'::jsonb))
);
CREATE UNIQUE INDEX uq_opportunities_source_external ON opportunities(source_id,source_external_id) WHERE source_external_id IS NOT NULL;
CREATE INDEX ix_opportunities_status_dates ON opportunities(status,posted_at DESC);
CREATE INDEX ix_opportunities_location ON opportunities(location);
CREATE INDEX ix_opportunities_type_deadline ON opportunities(opportunity_type,status,application_deadline);
CREATE INDEX ix_opportunities_verification ON opportunities(verification_status,last_verified_at);
CREATE TABLE collection_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), source_id uuid NOT NULL REFERENCES opportunity_sources(id) ON DELETE RESTRICT,
 started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz, status text NOT NULL,
 items_seen integer NOT NULL DEFAULT 0 CHECK(items_seen>=0), items_created integer NOT NULL DEFAULT 0 CHECK(items_created>=0),
 items_updated integer NOT NULL DEFAULT 0 CHECK(items_updated>=0), error_summary text, worker_version text,
 attempt_number integer NOT NULL DEFAULT 1 CHECK(attempt_number>0), retry_of_run_id uuid REFERENCES collection_runs(id) ON DELETE SET NULL,
 next_retry_at timestamptz, error_code text, failure_class text CHECK(failure_class IS NULL OR failure_class IN
 ('AUTH','RATE_LIMIT','NETWORK','SOURCE_FORMAT','VALIDATION','TIMEOUT','INTERNAL')),
 duration_ms bigint CHECK(duration_ms IS NULL OR duration_ms>=0),
 source_health_after_run text CHECK(source_health_after_run IS NULL OR source_health_after_run IN
 ('UNKNOWN','HEALTHY','DEGRADED','FAILING','DISABLED')),
 CHECK(finished_at IS NULL OR finished_at>=started_at)
);
CREATE INDEX ix_collection_runs_source_time ON collection_runs(source_id,started_at DESC);
CREATE INDEX ix_collection_runs_status_time ON collection_runs(status,started_at DESC);
CREATE INDEX ix_collection_runs_retry ON collection_runs(status,next_retry_at) WHERE next_retry_at IS NOT NULL;
CREATE TABLE collection_items (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), run_id uuid NOT NULL REFERENCES collection_runs(id) ON DELETE CASCADE,
 source_external_id text, canonicalized_source_url text, content_hash char(64), outcome text NOT NULL,
 opportunity_id uuid REFERENCES opportunities(id) ON DELETE SET NULL, error_code text,
 processed_at timestamptz NOT NULL DEFAULT now(),
 CHECK(source_external_id IS NOT NULL OR canonicalized_source_url IS NOT NULL)
);
CREATE UNIQUE INDEX uq_collection_run_external ON collection_items(run_id,source_external_id) WHERE source_external_id IS NOT NULL;
CREATE UNIQUE INDEX uq_collection_run_url ON collection_items(run_id,canonicalized_source_url)
 WHERE source_external_id IS NULL AND canonicalized_source_url IS NOT NULL;
CREATE INDEX ix_collection_items_run_outcome ON collection_items(run_id,outcome);
CREATE INDEX ix_collection_items_opportunity ON collection_items(opportunity_id);
CREATE TABLE opportunity_skills (
 opportunity_id uuid NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT,
 requirement_type text NOT NULL CHECK(requirement_type IN ('MANDATORY','PREFERRED')),
 required_level text, importance numeric(5,2), extraction_confidence numeric(4,3) CHECK(extraction_confidence BETWEEN 0 AND 1),
 evidence text, PRIMARY KEY(opportunity_id,skill_id,requirement_type)
);
CREATE INDEX ix_opportunity_skills_skill ON opportunity_skills(skill_id);

CREATE TABLE recommendation_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 resume_id uuid, profile_version text, input_snapshot jsonb NOT NULL DEFAULT '{}', model_version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), status text NOT NULL, filters_snapshot jsonb NOT NULL DEFAULT '{}',
 UNIQUE(id,user_id), FOREIGN KEY(resume_id,user_id) REFERENCES resumes(id,user_id) ON DELETE RESTRICT
);
CREATE INDEX ix_recommendation_runs_user_time ON recommendation_runs(user_id,created_at DESC);
CREATE TABLE recommendation_items (
 run_id uuid NOT NULL REFERENCES recommendation_runs(id) ON DELETE CASCADE,
 opportunity_id uuid NOT NULL REFERENCES opportunities(id) ON DELETE RESTRICT,
 rank integer NOT NULL CHECK(rank>0), score numeric(8,6) NOT NULL,
 score_components jsonb NOT NULL DEFAULT '{}', explanation text, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(run_id,opportunity_id), UNIQUE(run_id,rank)
);
CREATE INDEX ix_recommendation_items_rank ON recommendation_items(run_id,rank);
CREATE TABLE skill_gap_runs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 opportunity_id uuid NOT NULL REFERENCES opportunities(id) ON DELETE RESTRICT, resume_analysis_id uuid,
 profile_version text, taxonomy_version text NOT NULL, method_version text NOT NULL, status text NOT NULL,
 input_snapshot jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id,user_id), UNIQUE(id,user_id,opportunity_id),
 FOREIGN KEY(resume_analysis_id,user_id) REFERENCES resume_analyses(id,user_id) ON DELETE RESTRICT
);
CREATE INDEX ix_skill_gap_runs_user_time ON skill_gap_runs(user_id,created_at DESC);
CREATE INDEX ix_skill_gap_runs_opportunity_time ON skill_gap_runs(opportunity_id,created_at DESC);
CREATE TABLE skill_gap_items (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), run_id uuid NOT NULL REFERENCES skill_gap_runs(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT,
 requirement_type text NOT NULL CHECK(requirement_type IN ('MANDATORY','PREFERRED')),
 required_level text, reported_level text, resume_level text, evidence_summary text,
 confidence numeric(4,3) CHECK(confidence BETWEEN 0 AND 1),
 assessment_status text NOT NULL CHECK(assessment_status IN ('MATCHED','PARTIAL','CONFIRMED_MISSING','UNKNOWN','NEEDS_REVIEW')),
 gap_score numeric(8,6), created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(run_id,skill_id,requirement_type)
);
CREATE INDEX ix_skill_gap_items_skill ON skill_gap_items(skill_id);
CREATE INDEX ix_skill_gap_items_status ON skill_gap_items(run_id,assessment_status);

CREATE TABLE learning_resources (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), provider text NOT NULL, title text NOT NULL, url text NOT NULL,
 canonical_url text NOT NULL, resource_type text NOT NULL, difficulty text,
 duration_minutes integer CHECK(duration_minutes IS NULL OR duration_minutes>0),
 pricing_type text NOT NULL DEFAULT 'UNKNOWN' CHECK(pricing_type IN ('FREE','PAID','FREEMIUM','UNKNOWN')),
 price_amount numeric(12,2) CHECK(price_amount IS NULL OR price_amount>=0), currency char(3), pricing_verified_at timestamptz,
 pricing_evidence_url text, pricing_evidence_note text,
 verification_status text NOT NULL DEFAULT 'UNVERIFIED' CHECK(verification_status IN ('UNVERIFIED','CHECKED','UNAVAILABLE','RETIRED')),
 verification_evidence_url text, verification_evidence_note text, last_verified_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), retired_at timestamptz,
 UNIQUE(provider,canonical_url), CHECK((price_amount IS NULL)=(currency IS NULL)),
 CHECK(pricing_verified_at IS NOT NULL OR pricing_type='UNKNOWN'),
 CHECK(pricing_verified_at IS NULL OR
  (NULLIF(btrim(pricing_evidence_url),'') IS NOT NULL OR NULLIF(btrim(pricing_evidence_note),'') IS NOT NULL)),
 CHECK(verification_status<>'CHECKED' OR (last_verified_at IS NOT NULL AND
  (NULLIF(btrim(verification_evidence_url),'') IS NOT NULL OR NULLIF(btrim(verification_evidence_note),'') IS NOT NULL)))
);
CREATE INDEX ix_learning_resources_verification ON learning_resources(verification_status,last_verified_at);
CREATE INDEX ix_learning_resources_type_difficulty ON learning_resources(resource_type,difficulty);
CREATE TABLE learning_resource_skills (
 resource_id uuid NOT NULL REFERENCES learning_resources(id) ON DELETE CASCADE,
 skill_id uuid NOT NULL REFERENCES skills(id) ON DELETE RESTRICT, coverage_level text,
 mapping_confidence numeric(4,3) CHECK(mapping_confidence BETWEEN 0 AND 1), evidence_note text,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(resource_id,skill_id)
);
CREATE INDEX ix_learning_resource_skills_skill ON learning_resource_skills(skill_id,resource_id);
CREATE TABLE roadmaps (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 opportunity_id uuid REFERENCES opportunities(id) ON DELETE RESTRICT, skill_gap_run_id uuid,
 version integer NOT NULL DEFAULT 1 CHECK(version>0), status text NOT NULL DEFAULT 'ACTIVE'
 CHECK(status IN ('ACTIVE','COMPLETED','ARCHIVED')), title text NOT NULL,
 constraints_snapshot jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(), archived_at timestamptz,
 UNIQUE(id,user_id), CHECK(skill_gap_run_id IS NULL OR opportunity_id IS NOT NULL),
 FOREIGN KEY(skill_gap_run_id,user_id,opportunity_id)
 REFERENCES skill_gap_runs(id,user_id,opportunity_id) ON DELETE RESTRICT
);
CREATE INDEX ix_roadmaps_user_time ON roadmaps(user_id,created_at DESC);
CREATE INDEX ix_roadmaps_skill_gap ON roadmaps(skill_gap_run_id);
CREATE INDEX ix_roadmaps_opportunity ON roadmaps(opportunity_id);
CREATE TABLE roadmap_steps (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), roadmap_id uuid NOT NULL, user_id uuid NOT NULL,
 position integer NOT NULL CHECK(position>0), title text NOT NULL, description text,
 skill_id uuid REFERENCES skills(id) ON DELETE RESTRICT,
 learning_resource_id uuid REFERENCES learning_resources(id) ON DELETE RESTRICT,
 estimated_hours numeric(7,2) CHECK(estimated_hours IS NULL OR estimated_hours>0),
 activity_status text NOT NULL DEFAULT 'NOT_STARTED'
 CHECK(activity_status IN ('NOT_STARTED','IN_PROGRESS','COMPLETED','SKIPPED')),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(roadmap_id,position), UNIQUE(id,user_id,learning_resource_id),
 FOREIGN KEY(roadmap_id,user_id) REFERENCES roadmaps(id,user_id) ON DELETE CASCADE
);
CREATE INDEX ix_roadmap_steps_user ON roadmap_steps(user_id,roadmap_id);
CREATE INDEX ix_roadmap_steps_resource ON roadmap_steps(learning_resource_id);
CREATE INDEX ix_roadmap_steps_skill ON roadmap_steps(skill_id);
CREATE TABLE learning_progress (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 learning_resource_id uuid NOT NULL REFERENCES learning_resources(id) ON DELETE RESTRICT,
 status text NOT NULL DEFAULT 'NOT_STARTED' CHECK(status IN ('NOT_STARTED','IN_PROGRESS','COMPLETED','ABANDONED')),
 progress_percent numeric(5,2) NOT NULL DEFAULT 0 CHECK(progress_percent BETWEEN 0 AND 100),
 started_at timestamptz, completed_at timestamptz,
 time_spent_minutes integer NOT NULL DEFAULT 0 CHECK(time_spent_minutes>=0), notes text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(user_id,learning_resource_id), UNIQUE(id,user_id,learning_resource_id),
 CHECK((status='COMPLETED' AND progress_percent=100 AND completed_at IS NOT NULL)
 OR (status<>'COMPLETED' AND completed_at IS NULL))
);
CREATE INDEX ix_learning_progress_user_status ON learning_progress(user_id,status);
CREATE INDEX ix_learning_progress_resource_status ON learning_progress(learning_resource_id,status);
CREATE TABLE learning_progress_roadmap_steps (
 learning_progress_id uuid NOT NULL, user_id uuid NOT NULL, learning_resource_id uuid NOT NULL,
 roadmap_step_id uuid NOT NULL PRIMARY KEY,
 FOREIGN KEY(learning_progress_id,user_id,learning_resource_id)
 REFERENCES learning_progress(id,user_id,learning_resource_id) ON DELETE CASCADE,
 FOREIGN KEY(roadmap_step_id,user_id,learning_resource_id)
 REFERENCES roadmap_steps(id,user_id,learning_resource_id) ON DELETE CASCADE
);
CREATE INDEX ix_learning_progress_steps_progress ON learning_progress_roadmap_steps(learning_progress_id);
CREATE INDEX ix_learning_progress_steps_user ON learning_progress_roadmap_steps(user_id,roadmap_step_id);

CREATE TABLE applications (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 opportunity_id uuid NOT NULL REFERENCES opportunities(id) ON DELETE RESTRICT,
 selected_resume_id uuid, cover_letter text, portfolio_urls jsonb NOT NULL DEFAULT '[]',
 submission_state text NOT NULL DEFAULT 'SAVED' CHECK(submission_state IN
 ('SAVED','PLANNED','EXTERNAL_LINK_OPENED','USER_CONFIRMED_SUBMITTED','EXTERNALLY_CONFIRMED_SUBMITTED')),
 application_outcome text NOT NULL DEFAULT 'NOT_UPDATED' CHECK(application_outcome IN
 ('NOT_UPDATED','UNDER_REVIEW','SHORTLISTED','INTERVIEW_SCHEDULED','SELECTED','REJECTED','WITHDRAWN')),
 submission_method text NOT NULL DEFAULT 'EXTERNAL_LINK' CHECK(submission_method IN ('EXTERNAL_LINK','AUTHORIZED_INTEGRATION','MANUAL')),
 planned_at timestamptz, external_link_opened_at timestamptz, user_confirmed_submitted_at timestamptz,
 externally_confirmed_submitted_at timestamptz, external_application_url text,
 submission_evidence_reference text, submission_evidence_note text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(user_id,opportunity_id),
 FOREIGN KEY(selected_resume_id,user_id) REFERENCES resumes(id,user_id) ON DELETE RESTRICT
);
CREATE INDEX ix_applications_user_submission ON applications(user_id,submission_state,updated_at DESC);
CREATE INDEX ix_applications_user_outcome ON applications(user_id,application_outcome,updated_at DESC);
CREATE INDEX ix_applications_opportunity ON applications(opportunity_id);
CREATE TABLE application_answers (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 question_key text NOT NULL, question_text text NOT NULL, answer_text text,
 answer_type text NOT NULL DEFAULT 'TEXT' CHECK(answer_type IN ('TEXT','URL','BOOLEAN','DATE','JSON')),
 required boolean NOT NULL DEFAULT false, source_question_id text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(application_id,question_key)
);
CREATE INDEX ix_application_answers_app ON application_answers(application_id);
CREATE TABLE application_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 actor_type text NOT NULL CHECK(actor_type IN ('USER','ADMIN','SYSTEM','INTEGRATION')),
 event_type text NOT NULL CHECK(event_type IN ('SUBMISSION_STATE_CHANGED','APPLICATION_OUTCOME_CHANGED',
 'EXTERNAL_LINK_OPENED','SUBMISSION_EVIDENCE_RECORDED','ADMIN_CORRECTION')),
 previous_submission_state text, new_submission_state text, previous_outcome text, new_outcome text,
 evidence_type text, evidence_reference text, evidence_note text, correction_reason text,
 occurred_at timestamptz NOT NULL DEFAULT now(), request_id text,
 CHECK(previous_submission_state IS NULL OR previous_submission_state IN
 ('SAVED','PLANNED','EXTERNAL_LINK_OPENED','USER_CONFIRMED_SUBMITTED','EXTERNALLY_CONFIRMED_SUBMITTED')),
 CHECK(new_submission_state IS NULL OR new_submission_state IN
 ('SAVED','PLANNED','EXTERNAL_LINK_OPENED','USER_CONFIRMED_SUBMITTED','EXTERNALLY_CONFIRMED_SUBMITTED')),
 CHECK(previous_outcome IS NULL OR previous_outcome IN
 ('NOT_UPDATED','UNDER_REVIEW','SHORTLISTED','INTERVIEW_SCHEDULED','SELECTED','REJECTED','WITHDRAWN')),
 CHECK(new_outcome IS NULL OR new_outcome IN
 ('NOT_UPDATED','UNDER_REVIEW','SHORTLISTED','INTERVIEW_SCHEDULED','SELECTED','REJECTED','WITHDRAWN'))
);
CREATE INDEX ix_application_events_app_time ON application_events(application_id,occurred_at);
CREATE INDEX ix_application_events_actor_time ON application_events(actor_user_id,occurred_at DESC);
CREATE TABLE saved_opportunities (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 opportunity_id uuid NOT NULL REFERENCES opportunities(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(user_id,opportunity_id)
);
CREATE INDEX ix_saved_opportunities_opportunity ON saved_opportunities(opportunity_id);

CREATE TABLE notification_preferences (
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 email_enabled boolean NOT NULL DEFAULT false, in_app_enabled boolean NOT NULL DEFAULT true,
 opportunity_alerts_enabled boolean NOT NULL DEFAULT true, learning_reminders_enabled boolean NOT NULL DEFAULT true,
 opportunity_alert_frequency text NOT NULL DEFAULT 'DAILY'
 CHECK(opportunity_alert_frequency IN ('IMMEDIATE','DAILY','WEEKLY','OFF')),
 learning_reminder_frequency text NOT NULL DEFAULT 'WEEKLY'
 CHECK(learning_reminder_frequency IN ('DAILY','WEEKLY','OFF')),
 timezone text NOT NULL DEFAULT 'UTC', quiet_hours_start time, quiet_hours_end time,
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK((quiet_hours_start IS NULL)=(quiet_hours_end IS NULL))
);
CREATE TABLE notifications (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 type text NOT NULL, payload jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(),
 read_at timestamptz, expires_at timestamptz,
 email_delivery_status text NOT NULL DEFAULT 'NOT_REQUESTED' CHECK(email_delivery_status IN
 ('NOT_REQUESTED','QUEUED','SENT','FAILED','SUPPRESSED')),
 email_sent_at timestamptz, delivery_error_code text, dedupe_key text,
 CHECK(expires_at IS NULL OR expires_at>created_at)
);
CREATE UNIQUE INDEX uq_notifications_dedupe ON notifications(user_id,dedupe_key) WHERE dedupe_key IS NOT NULL;
CREATE INDEX ix_notifications_inbox ON notifications(user_id,read_at,created_at DESC);
CREATE INDEX ix_notifications_delivery ON notifications(email_delivery_status,created_at)
 WHERE email_delivery_status IN ('QUEUED','FAILED');

-- Durable API-owned queue. Workers receive minimized Celery payloads and never query this table.
CREATE TABLE notification_outbox (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), notification_id uuid NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
 template_key text NOT NULL, delivery_payload jsonb NOT NULL DEFAULT '{}', status text NOT NULL DEFAULT 'PENDING'
 CHECK(status IN ('PENDING','DISPATCHED','DELIVERED','FAILED','CANCELLED')),
 attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count>=0), available_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(), dispatched_at timestamptz, completed_at timestamptz,
 last_error_code text, dedupe_key text,
 UNIQUE(notification_id,template_key), CHECK(completed_at IS NULL OR completed_at>=created_at)
);
CREATE INDEX ix_notification_outbox_pending ON notification_outbox(status,available_at,created_at)
 WHERE status IN ('PENDING','FAILED');

CREATE TABLE chat_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 created_at timestamptz NOT NULL DEFAULT now(), ended_at timestamptz, retention_expires_at timestamptz NOT NULL,
 deleted_at timestamptz, CHECK(ended_at IS NULL OR ended_at>=created_at)
);
CREATE INDEX ix_chat_sessions_user_time ON chat_sessions(user_id,created_at DESC);
CREATE INDEX ix_chat_sessions_retention ON chat_sessions(retention_expires_at);
CREATE TABLE chat_messages (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
 sequence_no integer NOT NULL CHECK(sequence_no>0), role text NOT NULL CHECK(role IN ('USER','ASSISTANT','TOOL')),
 content text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), safety_metadata jsonb NOT NULL DEFAULT '{}',
 UNIQUE(session_id,sequence_no)
);
CREATE INDEX ix_chat_messages_session_time ON chat_messages(session_id,created_at);
CREATE TABLE interview_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 opportunity_id uuid REFERENCES opportunities(id) ON DELETE RESTRICT, created_at timestamptz NOT NULL DEFAULT now(),
 status text NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','COMPLETED','ABANDONED')),
 settings jsonb NOT NULL DEFAULT '{}', retention_expires_at timestamptz NOT NULL, deleted_at timestamptz
);
CREATE INDEX ix_interview_sessions_user_time ON interview_sessions(user_id,created_at DESC);
CREATE INDEX ix_interview_sessions_retention ON interview_sessions(retention_expires_at);
CREATE TABLE interview_items (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL REFERENCES interview_sessions(id) ON DELETE CASCADE,
 position integer NOT NULL CHECK(position>0), question text NOT NULL, answer text, feedback text,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(session_id,position)
);
CREATE INDEX ix_interview_items_session_position ON interview_items(session_id,position);
RESET ROLE;
