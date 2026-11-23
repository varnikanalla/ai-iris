\set ON_ERROR_STOP on
-- Run as a disposable-database superuser/test administrator. Fixtures are committed under
-- ai_iris_owner; each runtime phase uses SET SESSION AUTHORIZATION and is rolled back.
CREATE OR REPLACE FUNCTION pg_temp.expect_failure(command text, expected_state text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE got text;
BEGIN
    BEGIN
        EXECUTE command;
        RAISE EXCEPTION 'Expected SQLSTATE %, statement succeeded', expected_state USING ERRCODE='P0001';
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS got=RETURNED_SQLSTATE;
        IF got<>expected_state THEN
            RAISE EXCEPTION 'Expected SQLSTATE %, received %',expected_state,got;
        END IF;
    END;
END $$;

DO $$ DECLARE owner_login boolean; api_super boolean; api_bypass boolean; worker_super boolean; worker_bypass boolean; BEGIN
 SELECT rolcanlogin INTO owner_login FROM pg_catalog.pg_roles WHERE rolname='ai_iris_owner';
 SELECT rolsuper,rolbypassrls INTO api_super,api_bypass FROM pg_catalog.pg_roles WHERE rolname='ai_iris_api';
 IF owner_login OR api_super OR api_bypass THEN RAISE EXCEPTION 'Owner/API role flags violate least privilege'; END IF;
 SELECT rolsuper,rolbypassrls INTO worker_super,worker_bypass FROM pg_catalog.pg_roles WHERE rolname='ai_iris_worker';
 IF worker_super OR worker_bypass THEN RAISE EXCEPTION 'Worker role flags violate least privilege'; END IF;
 IF pg_catalog.pg_has_role('ai_iris_api','ai_iris_owner','MEMBER') OR pg_catalog.pg_has_role('ai_iris_worker','ai_iris_owner','MEMBER') THEN
   RAISE EXCEPTION 'Runtime role is a member of owner role';
 END IF;
END $$;

BEGIN;
SET LOCAL ROLE ai_iris_owner;
INSERT INTO users(id,email,password_verifier,role) VALUES
 ('10000000-0000-0000-0000-000000000001','user1@test.invalid','$argon2id$fixture1','USER'),
 ('10000000-0000-0000-0000-000000000002','user2@test.invalid','$argon2id$fixture2','USER'),
 ('10000000-0000-0000-0000-000000000003','admin@test.invalid','$argon2id$fixture3','ADMIN');
INSERT INTO user_profiles(user_id,display_name) VALUES
 ('10000000-0000-0000-0000-000000000001','user one'),
 ('10000000-0000-0000-0000-000000000002','user two');
INSERT INTO opportunity_sources(id,name,source_type) VALUES
 ('30000000-0000-0000-0000-000000000001','test-source','TEST');
INSERT INTO opportunities(id,source_id,source_url,title,description,status,opportunity_type) VALUES
 ('40000000-0000-0000-0000-000000000001','30000000-0000-0000-0000-000000000001','https://test.invalid/1','internship','desc','ACTIVE','INTERNSHIP'),
 ('40000000-0000-0000-0000-000000000002','30000000-0000-0000-0000-000000000001','https://test.invalid/2','job','desc','ACTIVE','JOB');
INSERT INTO resumes(id,user_id,storage_key,original_filename,mime_type,size_bytes,sha256,status) VALUES
 ('50000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','test/key','resume.pdf','application/pdf',10,repeat('a',64),'READY');
INSERT INTO resume_analyses(id,resume_id,user_id,parser_version,status) VALUES
 ('51000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','test','DONE');
INSERT INTO recommendation_runs(user_id,resume_id,model_version,status) VALUES
 ('10000000-0000-0000-0000-000000000001','50000000-0000-0000-0000-000000000001','test','DONE');
SELECT pg_temp.expect_failure($q$INSERT INTO recommendation_runs(user_id,resume_id,model_version,status)
 VALUES('10000000-0000-0000-0000-000000000002','50000000-0000-0000-0000-000000000001','test','DONE')$q$,'23503');
INSERT INTO skill_gap_runs(id,user_id,opportunity_id,resume_analysis_id,taxonomy_version,method_version,status) VALUES
 ('53000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001',
  '51000000-0000-0000-0000-000000000001','t1','m1','DONE');
SELECT pg_temp.expect_failure($q$INSERT INTO skill_gap_runs(user_id,opportunity_id,resume_analysis_id,taxonomy_version,method_version,status)
 VALUES('10000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000001',
 '51000000-0000-0000-0000-000000000001','t1','m1','DONE')$q$,'23503');
INSERT INTO roadmaps(id,user_id,opportunity_id,skill_gap_run_id,title) VALUES
 ('54000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',
 '40000000-0000-0000-0000-000000000001','53000000-0000-0000-0000-000000000001','owned');
SELECT pg_temp.expect_failure($q$INSERT INTO roadmaps(user_id,opportunity_id,skill_gap_run_id,title)
 VALUES('10000000-0000-0000-0000-000000000002','40000000-0000-0000-0000-000000000001',
 '53000000-0000-0000-0000-000000000001','cross-user')$q$,'23503');
SELECT pg_temp.expect_failure($q$INSERT INTO roadmaps(user_id,opportunity_id,skill_gap_run_id,title)
 VALUES('10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002',
 '53000000-0000-0000-0000-000000000001','mismatch')$q$,'23503');
SELECT pg_temp.expect_failure($q$INSERT INTO roadmap_steps(roadmap_id,user_id,position,title)
 VALUES('54000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002',1,'bad owner')$q$,'23503');
INSERT INTO learning_resources(id,provider,title,url,canonical_url,resource_type) VALUES
 ('60000000-0000-0000-0000-000000000001','provider','course','https://learn.invalid/c','https://learn.invalid/c','COURSE');
INSERT INTO learning_progress(id,user_id,learning_resource_id) VALUES
 ('61000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000001');
SELECT pg_temp.expect_failure($q$INSERT INTO learning_progress(user_id,learning_resource_id)
 VALUES('10000000-0000-0000-0000-000000000001','60000000-0000-0000-0000-000000000001')$q$,'23505');
INSERT INTO roadmap_steps(id,roadmap_id,user_id,position,title,learning_resource_id) VALUES
 ('62000000-0000-0000-0000-000000000001','54000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000001',1,'course step','60000000-0000-0000-0000-000000000001');
INSERT INTO learning_progress_roadmap_steps(learning_progress_id,user_id,learning_resource_id,roadmap_step_id) VALUES
 ('61000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',
 '60000000-0000-0000-0000-000000000001','62000000-0000-0000-0000-000000000001');
SET CONSTRAINTS require_resource_step_progress IMMEDIATE;
SET CONSTRAINTS require_resource_step_progress DEFERRED;
INSERT INTO roadmap_steps(id,roadmap_id,user_id,position,title,learning_resource_id) VALUES
 ('62000000-0000-0000-0000-000000000002','54000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000001',2,'orphan resource step','60000000-0000-0000-0000-000000000001');
SELECT pg_temp.expect_failure('SET CONSTRAINTS require_resource_step_progress IMMEDIATE','23514');
SET CONSTRAINTS require_resource_step_progress DEFERRED;
DELETE FROM roadmap_steps WHERE id='62000000-0000-0000-0000-000000000002';
SELECT pg_temp.expect_failure($q$INSERT INTO learning_resources(provider,title,url,canonical_url,resource_type,
 verification_status,last_verified_at) VALUES('p','bad','https://bad.invalid','https://bad.invalid','COURSE','CHECKED',now())$q$,'23514');
INSERT INTO learning_resources(provider,title,url,canonical_url,resource_type,verification_status,
 verification_evidence_note,last_verified_at) VALUES
 ('p','verified','https://ok.invalid','https://ok.invalid','COURSE','CHECKED','Provider page checked',now());
INSERT INTO applications(id,user_id,opportunity_id) VALUES
 ('70000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000001');
INSERT INTO application_events(application_id,actor_type,event_type) VALUES
 ('70000000-0000-0000-0000-000000000001','SYSTEM','SUBMISSION_STATE_CHANGED');
SELECT pg_temp.expect_failure($q$UPDATE application_events SET event_type='APPLICATION_OUTCOME_CHANGED'$q$,'P0001');
SELECT pg_temp.expect_failure('DELETE FROM application_events','P0001');
INSERT INTO notifications(id,user_id,type) VALUES
 ('80000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001','TEST');
INSERT INTO notification_outbox(id,notification_id,template_key,status) VALUES
 ('81000000-0000-0000-0000-000000000001','80000000-0000-0000-0000-000000000001','test','DISPATCHED');
COMMIT;

-- API runtime checks. Session authorization is switched outside the test transaction because
-- PostgreSQL requires this operation to be controlled by the test administrator.
SET SESSION AUTHORIZATION ai_iris_api;
BEGIN;
SELECT pg_temp.expect_failure('SELECT password_verifier FROM public.users','42501');
SELECT pg_temp.expect_failure('SELECT token_hash FROM public.session_refresh_tokens','42501');
SELECT pg_temp.expect_failure('SELECT encrypted_secret_or_credential FROM public.user_mfa_methods','42501');
SELECT pg_temp.expect_failure('UPDATE public.application_events SET event_type=event_type','42501');
SELECT pg_temp.expect_failure('DELETE FROM public.application_events','42501');
SELECT pg_temp.expect_failure('UPDATE public.applications SET submission_state=''PLANNED''','42501');
DO $$ BEGIN
 IF NOT has_function_privilege(current_user,'public.lookup_password_verifier(text)','EXECUTE') THEN RAISE EXCEPTION 'API cannot lookup verifier'; END IF;
 IF NOT has_function_privilege(current_user,'public.rotate_refresh_token(text,text,text,text,timestamp with time zone)','EXECUTE') THEN RAISE EXCEPTION 'API cannot rotate session'; END IF;
 IF has_table_privilege(current_user,'public.session_refresh_tokens','SELECT') THEN RAISE EXCEPTION 'API can read token table'; END IF;
 IF has_table_privilege(current_user,'public.user_mfa_methods','SELECT') THEN RAISE EXCEPTION 'API can read MFA table'; END IF;
 IF has_table_privilege(current_user,'public.users','SELECT') THEN RAISE EXCEPTION 'API can select users table'; END IF;
END $$;
-- This assertion documents the chosen shared-login boundary: SQL permissions alone do not
-- isolate USER rows. FastAPI ownership/IDOR tests must prove user one cannot receive user two's row.
DO $$ DECLARE row_count integer; BEGIN
 SELECT count(*) INTO row_count FROM public.user_profiles;
 IF row_count<>2 THEN RAISE EXCEPTION 'Shared API role fixture visibility differs from the documented trust model'; END IF;
END $$;
DO $$ DECLARE v text; BEGIN
 SELECT password_verifier INTO v FROM public.lookup_password_verifier('user1@test.invalid');
 IF v IS DISTINCT FROM '$argon2id$fixture1' THEN RAISE EXCEPTION 'Verifier lookup returned wrong value'; END IF;
END $$;
SELECT * FROM public.create_session_family('10000000-0000-0000-0000-000000000001','pepper-v1',repeat('a',64),now()+interval '1 day','test','ip-hash');
SELECT * FROM public.rotate_refresh_token('pepper-v1',repeat('a',64),'pepper-v1',repeat('b',64),now()+interval '1 day');
DO $$ DECLARE r record; fam uuid; BEGIN
 SELECT * INTO r FROM public.rotate_refresh_token('pepper-v1',repeat('a',64),'pepper-v1',repeat('c',64),now()+interval '1 day');
 IF NOT r.reused THEN RAISE EXCEPTION 'Consumed-token reuse was not detected'; END IF;
 fam:=r.token_family_id;
 SELECT * INTO r FROM public.rotate_refresh_token('pepper-v1',repeat('b',64),'pepper-v1',repeat('d',64),now()+interval '1 day');
 IF r.session_id IS NOT NULL THEN RAISE EXCEPTION 'Reuse did not revoke the active token family'; END IF;
 IF public.revoke_session_family('10000000-0000-0000-0000-000000000001',fam) THEN
   RAISE EXCEPTION 'Reused token family was not atomically revoked';
 END IF;
END $$;
DO $$ DECLARE mid uuid; BEGIN
 mid:=public.save_mfa_ciphertext('10000000-0000-0000-0000-000000000001','TOTP',decode(repeat('ab',32),'hex'));
 IF NOT public.confirm_mfa_method('10000000-0000-0000-0000-000000000001',mid) THEN RAISE EXCEPTION 'MFA confirm failed'; END IF;
 IF public.get_mfa_ciphertext('10000000-0000-0000-0000-000000000001',mid)
    IS DISTINCT FROM decode(repeat('ab',32),'hex') THEN RAISE EXCEPTION 'MFA ciphertext operation failed'; END IF;
END $$;
SELECT pg_temp.expect_failure($q$SELECT count(*) FROM public.admin_list_audit_events(
 '10000000-0000-0000-0000-000000000002',NULL,100)$q$,'42501');
DO $$ DECLARE n integer; BEGIN
 SELECT count(*) INTO n FROM public.admin_list_audit_events('10000000-0000-0000-0000-000000000003',NULL,100)
  WHERE action='REFRESH_TOKEN_REUSE_DETECTED';
 IF n<>1 THEN RAISE EXCEPTION 'Token reuse audit event missing'; END IF;
END $$;
SELECT * FROM public.set_notification_delivery_result('81000000-0000-0000-0000-000000000001','DELIVERED',NULL);
SELECT public.transition_application('70000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000001','USER','PLANNED');
SELECT pg_temp.expect_failure($q$SELECT public.transition_application(
 '70000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002',
 'USER','USER_CONFIRMED_SUBMITTED')$q$,'42501');
SELECT pg_temp.expect_failure($q$SELECT public.transition_application(
 '70000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000002',
 'ADMIN','REJECTED',NULL,NULL,NULL,NULL,'unauthorized admin identity')$q$,'42501');
SELECT pg_temp.expect_failure($q$SELECT public.transition_application(
 '70000000-0000-0000-0000-000000000001','10000000-0000-0000-0000-000000000001',
 'USER','EXTERNALLY_CONFIRMED_SUBMITTED')$q$,'23514');
SAVEPOINT app_rollback;
SELECT public.transition_application('70000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000001','USER','USER_CONFIRMED_SUBMITTED');
ROLLBACK TO SAVEPOINT app_rollback;
DO $$ BEGIN
 IF (SELECT submission_state FROM public.applications WHERE id='70000000-0000-0000-0000-000000000001')<>'PLANNED' THEN
   RAISE EXCEPTION 'Application state did not roll back'; END IF;
 IF EXISTS(SELECT 1 FROM public.application_events WHERE application_id='70000000-0000-0000-0000-000000000001'
    AND new_submission_state='USER_CONFIRMED_SUBMITTED') THEN RAISE EXCEPTION 'Application event did not roll back'; END IF;
END $$;
SELECT public.transition_application('70000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000001','USER','USER_CONFIRMED_SUBMITTED');
SELECT public.transition_application('70000000-0000-0000-0000-000000000001',
 NULL,'INTEGRATION','EXTERNALLY_CONFIRMED_SUBMITTED',NULL,'AUTHORIZED_SOURCE','evidence-ref','confirmed',NULL);
SELECT public.transition_application('70000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000003','ADMIN',NULL,'UNDER_REVIEW',NULL,NULL,NULL,NULL);
ROLLBACK;
RESET SESSION AUTHORIZATION;

-- Worker boundary checks. No private user-owned/authentication tables are granted.
SET SESSION AUTHORIZATION ai_iris_worker;
BEGIN;
SELECT pg_temp.expect_failure('SELECT id FROM public.user_profiles','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.user_skills','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.users','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.resumes','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.resume_analyses','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.recommendation_runs','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.skill_gap_runs','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.applications','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.roadmaps','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.learning_progress','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.notifications','42501');
SELECT pg_temp.expect_failure('SELECT user_id FROM public.notification_preferences','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.chat_sessions','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.interview_sessions','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.user_sessions','42501');
SELECT pg_temp.expect_failure('SELECT id FROM public.user_mfa_methods','42501');
SELECT pg_temp.expect_failure('SELECT public.transition_application(''70000000-0000-0000-0000-000000000001'',
 ''10000000-0000-0000-0000-000000000001'',''SYSTEM'',''PLANNED'')','42501');
DO $$ BEGIN
 IF NOT has_table_privilege(current_user,'public.opportunities','SELECT') THEN RAISE EXCEPTION 'Worker lacks catalog read'; END IF;
 IF has_table_privilege(current_user,'public.notifications','SELECT') THEN RAISE EXCEPTION 'Worker can read notifications'; END IF;
 IF has_table_privilege(current_user,'public.notification_outbox','SELECT') THEN RAISE EXCEPTION 'Worker can read outbox'; END IF;
 IF has_function_privilege(current_user,'public.lookup_password_verifier(text)','EXECUTE') THEN RAISE EXCEPTION 'Worker can lookup verifier'; END IF;
END $$;
SELECT id FROM public.opportunities LIMIT 1;
INSERT INTO public.learning_resources(provider,title,url,canonical_url,resource_type)
 VALUES('worker-test','worker catalog entry','https://worker.invalid/r','https://worker.invalid/r','ARTICLE');
ROLLBACK;
RESET SESSION AUTHORIZATION;

-- Remove controlled fixtures after all runtime transactions have rolled back.
BEGIN;
SET LOCAL ROLE ai_iris_owner;
DELETE FROM users WHERE id IN ('10000000-0000-0000-0000-000000000001',
 '10000000-0000-0000-0000-000000000002','10000000-0000-0000-0000-000000000003');
DELETE FROM opportunities WHERE id IN ('40000000-0000-0000-0000-000000000001','40000000-0000-0000-0000-000000000002');
DELETE FROM opportunity_sources WHERE id='30000000-0000-0000-0000-000000000001';
DELETE FROM learning_resources WHERE id='60000000-0000-0000-0000-000000000001';
DELETE FROM learning_resources WHERE provider='p' AND title='verified';
COMMIT;
\echo 'Database assertions completed. Backend ownership and IDOR tests are separate FastAPI tests and are not replaced by shared-role SQL tests.'
