-- Install after schema.sql. Functions are owned by ai_iris_owner.
SET ROLE ai_iris_owner;

CREATE OR REPLACE FUNCTION enforce_resource_step_status()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.learning_resource_id IS NOT NULL AND NEW.activity_status <> 'NOT_STARTED' THEN
        RAISE EXCEPTION 'Resource step progress is derived from learning_progress'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER roadmap_step_resource_status
BEFORE INSERT OR UPDATE OF learning_resource_id, activity_status ON roadmap_steps
FOR EACH ROW EXECUTE FUNCTION enforce_resource_step_status();

CREATE OR REPLACE FUNCTION check_resource_step_link()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    step_resource uuid;
BEGIN
    SELECT learning_resource_id INTO step_resource FROM roadmap_steps
     WHERE id = NEW.roadmap_step_id AND user_id = NEW.user_id;
    IF NOT FOUND OR step_resource IS NULL OR step_resource <> NEW.learning_resource_id THEN
        RAISE EXCEPTION 'Progress link must match an owned resource roadmap step'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER validate_progress_link
BEFORE INSERT OR UPDATE ON learning_progress_roadmap_steps
FOR EACH ROW EXECUTE FUNCTION check_resource_step_link();

CREATE OR REPLACE FUNCTION require_resource_step_link_at_commit()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.learning_resource_id IS NOT NULL
       AND EXISTS (SELECT 1 FROM roadmap_steps s WHERE s.id = NEW.id)
       AND NOT EXISTS (
        SELECT 1 FROM learning_progress_roadmap_steps l
         WHERE l.roadmap_step_id = NEW.id
           AND l.user_id = NEW.user_id
           AND l.learning_resource_id = NEW.learning_resource_id
    ) THEN
        RAISE EXCEPTION 'Resource roadmap step requires learning progress association'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER require_resource_step_progress
AFTER INSERT OR UPDATE ON roadmap_steps
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_resource_step_link_at_commit();

CREATE OR REPLACE FUNCTION reject_link_to_nonresource_step()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM roadmap_steps s
         WHERE s.id = NEW.roadmap_step_id AND s.user_id = NEW.user_id
           AND s.learning_resource_id = NEW.learning_resource_id
           AND s.learning_resource_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'Association requires matching resource step and owner'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER reject_invalid_progress_association
BEFORE INSERT OR UPDATE ON learning_progress_roadmap_steps
FOR EACH ROW EXECUTE FUNCTION reject_link_to_nonresource_step();

CREATE OR REPLACE FUNCTION require_initial_application_state()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.submission_state <> 'SAVED' OR NEW.application_outcome <> 'NOT_UPDATED' THEN
        RAISE EXCEPTION 'New application must start SAVED / NOT_UPDATED'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER application_initial_state
BEFORE INSERT ON applications
FOR EACH ROW EXECUTE FUNCTION require_initial_application_state();

CREATE OR REPLACE FUNCTION require_link_after_association_change()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    step_id uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        step_id := OLD.roadmap_step_id;
        IF EXISTS (SELECT 1 FROM roadmap_steps s WHERE s.id = step_id AND s.learning_resource_id IS NOT NULL)
           AND NOT EXISTS (SELECT 1 FROM learning_progress_roadmap_steps l WHERE l.roadmap_step_id = step_id) THEN
            RAISE EXCEPTION 'Cannot remove the only progress association for a resource step'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        step_id := NEW.roadmap_step_id;
        IF EXISTS (SELECT 1 FROM roadmap_steps s WHERE s.id = step_id AND s.learning_resource_id IS NOT NULL)
           AND NOT EXISTS (SELECT 1 FROM learning_progress_roadmap_steps l WHERE l.roadmap_step_id = step_id) THEN
            RAISE EXCEPTION 'Resource step must retain a progress association at commit'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER require_link_after_association_change
AFTER INSERT OR UPDATE OR DELETE ON learning_progress_roadmap_steps
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_link_after_association_change();

-- Trusted backend boundary: only the authenticated API calls this transition function.
-- actor_id is supplied by trusted server code after session and ownership checks; it is
-- not read from a client-settable PostgreSQL setting. Direct table writes are revoked.
CREATE OR REPLACE FUNCTION transition_application(
    p_application_id uuid,
    p_actor_id uuid,
    p_actor_type text,
    p_submission_state text DEFAULT NULL,
    p_outcome text DEFAULT NULL,
    p_evidence_type text DEFAULT NULL,
    p_evidence_reference text DEFAULT NULL,
    p_evidence_note text DEFAULT NULL,
    p_correction_reason text DEFAULT NULL
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    a public.applications%ROWTYPE;
    allowed boolean := false;
    event_kind text;
BEGIN
    IF session_user <> 'ai_iris_api' THEN
        RAISE EXCEPTION 'Transition function may only be called by the API role'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_actor_type NOT IN ('USER','ADMIN','SYSTEM','INTEGRATION') THEN
        RAISE EXCEPTION 'Invalid actor type' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO a FROM public.applications WHERE id = p_application_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Application not found' USING ERRCODE = 'no_data_found'; END IF;

    IF p_actor_type = 'USER' AND (p_actor_id IS DISTINCT FROM a.user_id OR NOT EXISTS
        (SELECT 1 FROM public.users WHERE id=p_actor_id AND is_active AND deleted_at IS NULL)) THEN
        RAISE EXCEPTION 'User may update only own application' USING ERRCODE = 'insufficient_privilege';
    ELSIF p_actor_type = 'ADMIN' AND NOT EXISTS
        (SELECT 1 FROM public.users WHERE id = p_actor_id AND role = 'ADMIN' AND is_active AND deleted_at IS NULL) THEN
        RAISE EXCEPTION 'Active admin identity required' USING ERRCODE = 'insufficient_privilege';
    ELSIF p_actor_type = 'INTEGRATION' AND session_user <> 'ai_iris_api' THEN
        RAISE EXCEPTION 'Integration transitions require authenticated API processing'
            USING ERRCODE = 'insufficient_privilege';
    ELSIF p_actor_type = 'SYSTEM' AND session_user <> 'ai_iris_api' THEN
        RAISE EXCEPTION 'System transitions require API processing'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF p_submission_state IS NOT NULL AND p_submission_state <> a.submission_state THEN
        allowed :=
          (a.submission_state = 'SAVED' AND p_submission_state IN ('PLANNED','EXTERNAL_LINK_OPENED','USER_CONFIRMED_SUBMITTED')) OR
          (a.submission_state = 'PLANNED' AND p_submission_state IN ('SAVED','EXTERNAL_LINK_OPENED','USER_CONFIRMED_SUBMITTED')) OR
          (a.submission_state = 'EXTERNAL_LINK_OPENED' AND p_submission_state IN ('PLANNED','USER_CONFIRMED_SUBMITTED')) OR
          (a.submission_state = 'USER_CONFIRMED_SUBMITTED' AND p_submission_state = 'EXTERNALLY_CONFIRMED_SUBMITTED' AND p_actor_type = 'INTEGRATION') OR
          (p_actor_type = 'ADMIN' AND p_correction_reason IS NOT NULL AND length(trim(p_correction_reason)) > 0);
        IF NOT allowed THEN RAISE EXCEPTION 'Invalid or unauthorized submission transition' USING ERRCODE = 'check_violation'; END IF;
        IF p_submission_state = 'EXTERNALLY_CONFIRMED_SUBMITTED' AND
           (p_actor_type <> 'INTEGRATION' OR p_evidence_reference IS NULL) THEN
            RAISE EXCEPTION 'External confirmation requires integration evidence' USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    IF p_outcome IS NOT NULL AND p_outcome <> a.application_outcome THEN
        allowed :=
          (a.application_outcome = 'NOT_UPDATED' AND p_outcome IN ('UNDER_REVIEW','SHORTLISTED','INTERVIEW_SCHEDULED','SELECTED','REJECTED','WITHDRAWN')) OR
          (a.application_outcome = 'UNDER_REVIEW' AND p_outcome IN ('SHORTLISTED','INTERVIEW_SCHEDULED','SELECTED','REJECTED','WITHDRAWN')) OR
          (a.application_outcome = 'SHORTLISTED' AND p_outcome IN ('INTERVIEW_SCHEDULED','SELECTED','REJECTED','WITHDRAWN')) OR
          (a.application_outcome = 'INTERVIEW_SCHEDULED' AND p_outcome IN ('SELECTED','REJECTED','WITHDRAWN')) OR
          (p_actor_type = 'ADMIN' AND p_correction_reason IS NOT NULL AND length(trim(p_correction_reason)) > 0);
        IF NOT allowed THEN RAISE EXCEPTION 'Invalid or unauthorized outcome transition' USING ERRCODE = 'check_violation'; END IF;
    END IF;

    UPDATE public.applications SET
        submission_state = COALESCE(p_submission_state, submission_state),
        application_outcome = COALESCE(p_outcome, application_outcome),
        planned_at = CASE WHEN p_submission_state = 'PLANNED' THEN now() ELSE planned_at END,
        external_link_opened_at = CASE WHEN p_submission_state = 'EXTERNAL_LINK_OPENED' THEN now() ELSE external_link_opened_at END,
        user_confirmed_submitted_at = CASE WHEN p_submission_state = 'USER_CONFIRMED_SUBMITTED' THEN now() ELSE user_confirmed_submitted_at END,
        externally_confirmed_submitted_at = CASE WHEN p_submission_state = 'EXTERNALLY_CONFIRMED_SUBMITTED' THEN now() ELSE externally_confirmed_submitted_at END,
        submission_evidence_reference = COALESCE(p_evidence_reference, submission_evidence_reference),
        submission_evidence_note = COALESCE(p_evidence_note, submission_evidence_note),
        updated_at = now()
    WHERE id = p_application_id;

    IF p_submission_state IS NOT NULL THEN
        event_kind := CASE WHEN p_correction_reason IS NOT NULL THEN 'ADMIN_CORRECTION'
                           ELSE 'SUBMISSION_STATE_CHANGED' END;
        INSERT INTO public.application_events(
            application_id, actor_user_id, actor_type, event_type,
            previous_submission_state, new_submission_state,
            previous_outcome, new_outcome, evidence_type, evidence_reference,
            evidence_note, correction_reason
        ) VALUES (
            p_application_id, p_actor_id, p_actor_type, event_kind,
            a.submission_state, COALESCE(p_submission_state, a.submission_state),
            a.application_outcome, a.application_outcome,
            p_evidence_type, p_evidence_reference, p_evidence_note, p_correction_reason
        );
    END IF;
    IF p_outcome IS NOT NULL THEN
        event_kind := CASE WHEN p_correction_reason IS NOT NULL THEN 'ADMIN_CORRECTION'
                           ELSE 'APPLICATION_OUTCOME_CHANGED' END;
        INSERT INTO public.application_events(
            application_id, actor_user_id, actor_type, event_type,
            previous_submission_state, new_submission_state,
            previous_outcome, new_outcome, evidence_type, evidence_reference,
            evidence_note, correction_reason
        ) VALUES (
            p_application_id, p_actor_id, p_actor_type, event_kind,
            a.submission_state, a.submission_state,
            a.application_outcome, COALESCE(p_outcome, a.application_outcome),
            p_evidence_type, p_evidence_reference, p_evidence_note, p_correction_reason
        );
    END IF;
END $$;

CREATE OR REPLACE FUNCTION reject_application_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Application events are append-only';
END $$;
CREATE TRIGGER application_events_append_only
BEFORE UPDATE OR DELETE ON application_events
FOR EACH ROW EXECUTE FUNCTION reject_application_event_mutation();

-- Authentication operations. Password hashing/verification remains Argon2id in FastAPI.
-- The verifier lookup is intentionally the only function returning a stored password verifier; callers
-- must be the trusted authentication service. A shared API credential can still enumerate it.
CREATE OR REPLACE FUNCTION register_user(p_email text, p_argon2id_verifier text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE new_id uuid;
BEGIN
    IF p_argon2id_verifier NOT LIKE '$argon2id$%' THEN
        RAISE EXCEPTION 'Invalid password verifier' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO public.users(email,password_verifier)
    VALUES (lower(btrim(p_email)),p_argon2id_verifier) RETURNING id INTO new_id;
    RETURN new_id;
END $$;

CREATE OR REPLACE FUNCTION lookup_password_verifier(p_email text)
RETURNS TABLE(user_id uuid, password_verifier text, is_active boolean, deleted_at timestamptz, app_role text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT u.id,u.password_verifier,u.is_active,u.deleted_at,u.role
      FROM public.users AS u WHERE lower(u.email)=lower(btrim(p_email))
$$;

CREATE OR REPLACE FUNCTION set_password_verifier(p_user_id uuid, p_argon2id_verifier text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF p_argon2id_verifier NOT LIKE '$argon2id$%' THEN
        RAISE EXCEPTION 'Invalid password verifier' USING ERRCODE = 'check_violation';
    END IF;
    UPDATE public.users SET password_verifier=p_argon2id_verifier,updated_at=pg_catalog.now()
     WHERE id=p_user_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'Account unavailable' USING ERRCODE = 'no_data_found'; END IF;
    UPDATE public.user_sessions SET revoked_at=pg_catalog.now()
     WHERE user_id=p_user_id AND revoked_at IS NULL;
    UPDATE public.session_refresh_tokens t SET revoked_at=pg_catalog.now()
      FROM public.user_sessions s WHERE t.session_id=s.id AND s.user_id=p_user_id AND t.revoked_at IS NULL;
    INSERT INTO public.audit_events(actor_user_id,action,target_type,target_id,result)
    VALUES(p_user_id,'PASSWORD_VERIFIER_CHANGED','USER',p_user_id,'SUCCESS');
END $$;

CREATE OR REPLACE FUNCTION create_session_family(
    p_user_id uuid, p_pepper_version text, p_refresh_token_hash text, p_expires_at timestamptz,
    p_user_agent text DEFAULT NULL, p_ip_hash text DEFAULT NULL
) RETURNS TABLE(session_id uuid, token_family_id uuid, expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE sid uuid; family_id uuid;
BEGIN
    IF length(p_refresh_token_hash)<32 OR length(btrim(p_pepper_version))=0 OR p_expires_at<=pg_catalog.now() THEN
        RAISE EXCEPTION 'Invalid session parameters' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO public.user_sessions(user_id,token_family_id,expires_at,user_agent,ip_hash)
    VALUES(p_user_id,pg_catalog.gen_random_uuid(),p_expires_at,p_user_agent,p_ip_hash)
    RETURNING user_sessions.id,user_sessions.token_family_id INTO sid,family_id;
    INSERT INTO public.session_refresh_tokens(session_id,pepper_version,token_hash,expires_at)
    VALUES(sid,p_pepper_version,p_refresh_token_hash,p_expires_at);
    INSERT INTO public.audit_events(actor_user_id,action,target_type,target_id,result)
    VALUES(p_user_id,'SESSION_FAMILY_CREATED','SESSION',sid,'SUCCESS');
    RETURN QUERY SELECT sid,family_id,p_expires_at;
END $$;

CREATE OR REPLACE FUNCTION rotate_refresh_token(
    p_presented_pepper_version text, p_presented_token_hash text,
    p_replacement_pepper_version text, p_replacement_token_hash text, p_expires_at timestamptz
) RETURNS TABLE(session_id uuid, user_id uuid, token_family_id uuid, reused boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE token_row public.session_refresh_tokens%ROWTYPE; session_row public.user_sessions%ROWTYPE;
BEGIN
    IF length(btrim(p_presented_pepper_version))=0 OR length(btrim(p_replacement_pepper_version))=0
       OR length(p_presented_token_hash)<32 OR length(p_replacement_token_hash)<32 THEN
        RAISE EXCEPTION 'Invalid refresh token parameters' USING ERRCODE='check_violation';
    END IF;
    SELECT t.* INTO token_row FROM public.session_refresh_tokens t
     WHERE t.pepper_version=p_presented_pepper_version AND t.token_hash=p_presented_token_hash;
    IF NOT FOUND THEN RETURN QUERY SELECT NULL::uuid,NULL::uuid,NULL::uuid,false; RETURN; END IF;
    SELECT s.* INTO session_row FROM public.user_sessions s
     WHERE s.id=token_row.session_id FOR UPDATE;
    SELECT t.* INTO token_row FROM public.session_refresh_tokens t
     WHERE t.id=token_row.id FOR UPDATE;
    IF token_row.consumed_at IS NOT NULL THEN
        UPDATE public.user_sessions SET revoked_at=pg_catalog.now()
         WHERE id=session_row.id AND revoked_at IS NULL;
        UPDATE public.session_refresh_tokens AS t SET revoked_at=pg_catalog.now()
         WHERE t.session_id=session_row.id AND t.revoked_at IS NULL;
        INSERT INTO public.audit_events(actor_user_id,action,target_type,target_id,result,metadata_redacted)
        VALUES(session_row.user_id,'REFRESH_TOKEN_REUSE_DETECTED','SESSION',session_row.id,'FAMILY_REVOKED',
            pg_catalog.jsonb_build_object('token_family_id',session_row.token_family_id));
        RETURN QUERY SELECT session_row.id,session_row.user_id,session_row.token_family_id,true; RETURN;
    END IF;
    IF token_row.revoked_at IS NOT NULL OR session_row.revoked_at IS NOT NULL
       OR token_row.expires_at<=pg_catalog.now() OR session_row.expires_at<=pg_catalog.now()
       OR p_expires_at<=pg_catalog.now() THEN
        RETURN QUERY SELECT NULL::uuid,NULL::uuid,NULL::uuid,false; RETURN;
    END IF;
    UPDATE public.session_refresh_tokens SET consumed_at=pg_catalog.now()
     WHERE id=token_row.id;
    INSERT INTO public.session_refresh_tokens(session_id,pepper_version,token_hash,expires_at)
    VALUES(session_row.id,p_replacement_pepper_version,p_replacement_token_hash,LEAST(p_expires_at,session_row.expires_at));
    UPDATE public.user_sessions SET last_seen_at=pg_catalog.now() WHERE id=session_row.id;
    RETURN QUERY SELECT session_row.id,session_row.user_id,session_row.token_family_id,false;
END $$;

CREATE OR REPLACE FUNCTION revoke_session_family(p_user_id uuid, p_token_family_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE sid uuid;
BEGIN
    UPDATE public.user_sessions SET revoked_at=pg_catalog.now()
     WHERE user_id=p_user_id AND token_family_id=p_token_family_id AND revoked_at IS NULL
     RETURNING id INTO sid;
    IF sid IS NULL THEN RETURN false; END IF;
    UPDATE public.session_refresh_tokens SET revoked_at=pg_catalog.now()
     WHERE session_id=sid AND revoked_at IS NULL;
    RETURN true;
END $$;

CREATE OR REPLACE FUNCTION revoke_all_user_sessions(p_user_id uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE n integer;
BEGIN
    UPDATE public.user_sessions SET revoked_at=pg_catalog.now()
     WHERE user_id=p_user_id AND revoked_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    UPDATE public.session_refresh_tokens t SET revoked_at=pg_catalog.now()
      FROM public.user_sessions s WHERE t.session_id=s.id AND s.user_id=p_user_id AND t.revoked_at IS NULL;
    RETURN n;
END $$;

-- Ciphertext only. KMS decryption is performed by the authentication service, never PostgreSQL.
CREATE OR REPLACE FUNCTION get_mfa_ciphertext(p_user_id uuid, p_method_id uuid)
RETURNS bytea LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT m.encrypted_secret_or_credential FROM public.user_mfa_methods m
     WHERE m.id=p_method_id AND m.user_id=p_user_id AND m.disabled_at IS NULL AND m.verified_at IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION save_mfa_ciphertext(
    p_user_id uuid, p_method text, p_ciphertext bytea
) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE mid uuid;
BEGIN
    IF p_method NOT IN ('TOTP','WEBAUTHN') OR octet_length(p_ciphertext)<16 THEN
        RAISE EXCEPTION 'Invalid MFA material' USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO public.user_mfa_methods(user_id,method,encrypted_secret_or_credential)
    VALUES(p_user_id,p_method,p_ciphertext) RETURNING id INTO mid;
    INSERT INTO public.audit_events(actor_user_id,action,target_type,target_id,result,metadata_redacted)
    VALUES(p_user_id,'MFA_METHOD_ENROLLED','MFA_METHOD',mid,'PENDING',pg_catalog.jsonb_build_object('method',p_method));
    RETURN mid;
END $$;

CREATE OR REPLACE FUNCTION confirm_mfa_method(p_user_id uuid, p_method_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    UPDATE public.user_mfa_methods SET verified_at=pg_catalog.now()
     WHERE id=p_method_id AND user_id=p_user_id AND disabled_at IS NULL;
    IF FOUND THEN
        INSERT INTO public.audit_events(actor_user_id,action,target_type,target_id,result)
        VALUES(p_user_id,'MFA_METHOD_CONFIRMED','MFA_METHOD',p_method_id,'SUCCESS');
    END IF;
    RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION disable_mfa_method(p_user_id uuid, p_method_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    UPDATE public.user_mfa_methods SET disabled_at=pg_catalog.now()
     WHERE id=p_method_id AND user_id=p_user_id AND disabled_at IS NULL;
    IF FOUND THEN
        INSERT INTO public.audit_events(actor_user_id,action,target_type,target_id,result)
        VALUES(p_user_id,'MFA_METHOD_DISABLED','MFA_METHOD',p_method_id,'SUCCESS');
    END IF;
    RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION admin_list_audit_events(
    p_actor_id uuid, p_before timestamptz DEFAULT NULL, p_limit integer DEFAULT 100
) RETURNS TABLE(id uuid,actor_user_id uuid,action text,target_type text,target_id uuid,
    occurred_at timestamptz,request_id text,result text,metadata_redacted jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF p_limit<1 OR p_limit>200 OR NOT EXISTS (
        SELECT 1 FROM public.users u WHERE u.id=p_actor_id AND u.role='ADMIN' AND u.is_active AND u.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'Administrative authorization required' USING ERRCODE='insufficient_privilege';
    END IF;
    RETURN QUERY SELECT a.id,a.actor_user_id,a.action,a.target_type,a.target_id,
        a.occurred_at,a.request_id,a.result,a.metadata_redacted
      FROM public.audit_events a WHERE p_before IS NULL OR a.occurred_at<p_before
      ORDER BY a.occurred_at DESC LIMIT p_limit;
END $$;

-- Outbox lifecycle is API-owned. No worker database grant is provided.
CREATE OR REPLACE FUNCTION set_notification_delivery_result(
    p_outbox_id uuid, p_status text, p_error_code text DEFAULT NULL
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF p_status NOT IN ('DELIVERED','FAILED') THEN
        RAISE EXCEPTION 'Invalid delivery result' USING ERRCODE = 'check_violation';
    END IF;
    UPDATE public.notification_outbox SET status=p_status,attempt_count=attempt_count+1,
        completed_at=CASE WHEN p_status='DELIVERED' THEN pg_catalog.now() ELSE NULL END,
        last_error_code=p_error_code
     WHERE id=p_outbox_id AND status IN ('DISPATCHED','FAILED');
    RETURN FOUND;
END $$;

-- Security-definer entry points are not callable by PUBLIC. Runtime grants are installed
-- explicitly by roles.sql after all objects exist.
REVOKE EXECUTE ON FUNCTION public.transition_application(uuid,uuid,text,text,text,text,text,text,text),
 public.register_user(text,text), public.lookup_password_verifier(text),
 public.set_password_verifier(uuid,text), public.create_session_family(uuid,text,text,timestamptz,text,text),
 public.rotate_refresh_token(text,text,text,text,timestamptz), public.revoke_session_family(uuid,uuid),
 public.revoke_all_user_sessions(uuid), public.get_mfa_ciphertext(uuid,uuid),
 public.save_mfa_ciphertext(uuid,text,bytea), public.confirm_mfa_method(uuid,uuid),
 public.disable_mfa_method(uuid,uuid), public.admin_list_audit_events(uuid,timestamptz,integer),
 public.set_notification_delivery_result(uuid,text,text)
 FROM PUBLIC;
RESET ROLE;
