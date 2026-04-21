import boto3
import json
from cryptography.fernet import Fernet
from config import Config
from models.proyecto import Proyecto
from models.cloud_ejecucion import CloudEjecucion
from botocore.exceptions import ClientError
from datetime import datetime, timezone


# ══════════════════════════════════════════════════════════════════
# HELPERS GLOBALES
# ══════════════════════════════════════════════════════════════════

def _get_aws_session(proyecto_id):
    """Crea y retorna una sesión AWS autenticada para el proyecto dado."""
    config = Proyecto.get_cloud_config(proyecto_id)
    if not config:
        raise Exception("No existe configuración Cloud para este proyecto")

    fernet = Fernet(Config.FERNET_KEY)
    region = config["region"]

    if config.get("auth_method") == "role":
        # ── Modo AssumeRole ──────────────────────────────────────────
        secret_key = fernet.decrypt(config["secret_key"].encode()).decode()

        sts = boto3.client(
            "sts",
            aws_access_key_id=config["access_key"],
            aws_secret_access_key=secret_key
        )

        assume_params = {
            "RoleArn": config["role_arn"],
            "RoleSessionName": "RedScopeSession",
            "DurationSeconds": 3600
        }

        if config.get("external_id"):
            assume_params["ExternalId"] = config["external_id"]

        response = sts.assume_role(**assume_params)
        creds = response["Credentials"]

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region
        )

    else:
        # ── Modo keys directas ───────────────────────────────────────
        secret_key = fernet.decrypt(config["secret_key"].encode()).decode()

        session = boto3.Session(
            aws_access_key_id=config["access_key"],
            aws_secret_access_key=secret_key,
            region_name=region
        )

    return session, region

def _get_account_id(session):
    """Retorna el account ID de la sesión actual."""
    return session.client("sts").get_caller_identity()["Account"]


def _run_job(ejecucion_id, fn):
    """
    Wrapper genérico para todos los jobs.
    Maneja mark_running / mark_completed / mark_failed de forma centralizada.
    """
    try:
        CloudEjecucion.mark_running(ejecucion_id)
        resultado = fn()
        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2, default=str),
            ejecucion_id
        )
    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def _build_resultado(provider, service, inventory_type, account_id, region, resources, **extra):
    """Construye el envelope estándar de resultado."""
    base = {
        "provider": provider,
        "service": service,
        "inventory_type": inventory_type,
        "account_id": account_id,
        "region": region,
        "total_resources": len(resources),
        "resources": resources
    }
    base.update(extra)
    return base


def _base_resource(provider, service, resource_type, resource_id, account_id, region, analysis, **extra):
    """Construye un recurso estándar para incluir en resources[]."""
    base = {
        "provider": provider,
        "service": service,
        "account_id": account_id,
        "region": region,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "analysis": analysis
    }
    base.update(extra)
    return base


# ══════════════════════════════════════════════════════════════════
# IAM
# ══════════════════════════════════════════════════════════════════

def discovery_roles_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        account_id = _get_account_id(session)
        collection_timestamp = datetime.now(timezone.utc).isoformat()

        resources = []
        paginator = iam.get_paginator("list_roles")

        for page in paginator.paginate():
            for role in page.get("Roles", []):
                resources.append(_base_resource(
                    provider="AWS",
                    service="IAM",
                    resource_type="IAMRole",
                    resource_id=role["Arn"],
                    account_id=account_id,
                    region=region,
                    analysis={
                        "role_name": role["RoleName"],
                        "arn": role["Arn"],
                        "path": role.get("Path"),
                        "create_date": role["CreateDate"].isoformat(),
                        "max_session_duration": role.get("MaxSessionDuration"),
                        "assume_role_policy": role.get("AssumeRolePolicyDocument")
                    },
                    errors=[]
                ))

        return _build_resultado(
            "AWS", "IAM", "ROLE_METADATA",
            account_id, region, resources,
            collection_timestamp=collection_timestamp
        )

    _run_job(ejecucion_id, _execute)


def discovery_policies_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        account_id = _get_account_id(session)

        resources = []
        paginator = iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="All"):
            for policy in page.get("Policies", []):

                if policy.get("AttachmentCount", 0) == 0:
                    continue

                policy_arn = policy["Arn"]

                resources.append(_base_resource(
                    provider="AWS",
                    service="IAM",
                    resource_type="IAMPolicy",
                    resource_id=policy_arn,
                    account_id=account_id,
                    region=region,
                    analysis={
                        "policy_name": policy["PolicyName"],
                        "arn": policy_arn,
                        "attachment_count": policy.get("AttachmentCount"),
                        "is_attachable": policy.get("IsAttachable"),
                        "default_version_id": policy.get("DefaultVersionId"),
                        "create_date": policy["CreateDate"].isoformat() if policy.get("CreateDate") else None,
                        "update_date": policy["UpdateDate"].isoformat() if policy.get("UpdateDate") else None
                    },
                    errors=[]
                ))

        return _build_resultado("AWS", "IAM", "ACTIVE_POLICY_METADATA", account_id, region, resources)

    _run_job(ejecucion_id, _execute)


def password_policy_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        account_id = _get_account_id(session)

        analysis = {
            "password_policy": None,
            "exists": False,
            "summary": None
        }
        errors = []

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy")
            analysis["password_policy"] = policy
            analysis["exists"] = True
            analysis["summary"] = {
                "minimum_length": policy.get("MinimumPasswordLength"),
                "require_symbols": policy.get("RequireSymbols"),
                "require_numbers": policy.get("RequireNumbers"),
                "require_uppercase": policy.get("RequireUppercaseCharacters"),
                "require_lowercase": policy.get("RequireLowercaseCharacters"),
                "allow_user_change": policy.get("AllowUsersToChangePassword"),
                "hard_expiry": policy.get("HardExpiry"),
                "max_age": policy.get("MaxPasswordAge"),
                "reuse_prevention": policy.get("PasswordReusePrevention")
            }
        except iam.exceptions.NoSuchEntityException:
            analysis["exists"] = False
        except Exception as e:
            errors.append(f"password_policy_error: {e}")

        resource = _base_resource(
            provider="AWS",
            service="IAM",
            resource_type="AccountPasswordPolicy",
            resource_id="account_password_policy",
            account_id=account_id,
            region=region,
            analysis=analysis,
            errors=errors
        )

        return _build_resultado("AWS", "IAM", "ACCOUNT_PASSWORD_POLICY", account_id, region, [resource])

    _run_job(ejecucion_id, _execute)
    
def iam_users_review_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        account_id = _get_account_id(session)
        collection_timestamp = datetime.now(timezone.utc).isoformat()

        resources = []
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                user_arn = user["Arn"]
                errors = []

                # MFA CHECK
                mfa_enabled = False
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                    mfa_enabled = len(mfa_devices) > 0
                except Exception as e:
                    errors.append(f"mfa_check_error: {e}")

                # CONSOLE ACCESS CHECK
                console_access = False
                try:
                    iam.get_login_profile(UserName=username)
                    console_access = True
                except iam.exceptions.NoSuchEntityException:
                    console_access = False
                except Exception as e:
                    errors.append(f"console_access_error: {e}")

                # ACCESS KEYS CHECK
                access_keys = []
                old_access_key = False
                try:
                    keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                    for key in keys:
                        created = key.get("CreateDate")
                        days_old = (datetime.now(timezone.utc) - created).days if created else None
                        is_old = days_old > 90 if days_old is not None else False
                        if is_old:
                            old_access_key = True
                        access_keys.append({
                            "access_key_id": key.get("AccessKeyId"),
                            "status": key.get("Status"),
                            "created_date": created.isoformat() if created else None,
                            "days_old": days_old,
                            "is_old": is_old
                        })
                except Exception as e:
                    errors.append(f"access_keys_error: {e}")

                # ATTACHED POLICIES CHECK
                attached_policies = []
                has_admin_policy = False
                try:
                    policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                    for p in policies:
                        if p["PolicyName"] == "AdministratorAccess":
                            has_admin_policy = True
                        attached_policies.append({
                            "policy_name": p["PolicyName"],
                            "policy_arn": p["PolicyArn"]
                        })
                except Exception as e:
                    errors.append(f"attached_policies_error: {e}")

                # GROUPS CHECK
                groups = []
                try:
                    user_groups = iam.list_groups_for_user(UserName=username).get("Groups", [])
                    groups = [g["GroupName"] for g in user_groups]
                except Exception as e:
                    errors.append(f"groups_error: {e}")

                resources.append(_base_resource(
                    provider="AWS",
                    service="IAM",
                    resource_type="IAMUser",
                    resource_id=user_arn,
                    account_id=account_id,
                    region=region,
                    analysis={
                        "username": username,
                        "arn": user_arn,
                        "create_date": user["CreateDate"].isoformat(),
                        "mfa_enabled": mfa_enabled,
                        "console_access": console_access,
                        "console_without_mfa": console_access and not mfa_enabled,
                        "access_keys": access_keys,
                        "old_access_key": old_access_key,
                        "attached_policies": attached_policies,
                        "has_admin_policy": has_admin_policy,
                        "groups": groups
                    },
                    errors=errors
                ))

        return _build_resultado(
            "AWS", "IAM", "IAM_USERS_REVIEW",
            account_id, region, resources,
            collection_timestamp=collection_timestamp
        )

    _run_job(ejecucion_id, _execute)


def iam_privilege_escalation_job(ejecucion_id, proyecto_id):

    ESCALATION_PERMISSIONS = {
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:AddUserToGroup",
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "ec2:RunInstances",
        "cloudformation:CreateStack",
        "glue:CreateDevEndpoint"
    }

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        account_id = _get_account_id(session)
        resources = []

        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                escalation_permissions_found = []
                errors = []

                try:
                    # Attached policies
                    for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                        p_arn = p["PolicyArn"]
                        version = iam.get_policy(PolicyArn=p_arn)["Policy"]["DefaultVersionId"]
                        doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=version)["PolicyVersion"]["Document"]
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            # Wildcard total
                            if "*" in actions or "iam:*" in actions:
                                escalation_permissions_found.append("*")
                                break
                            for action in actions:
                                if action in ESCALATION_PERMISSIONS:
                                    escalation_permissions_found.append(action)

                    # Inline policies
                    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            if "*" in actions or "iam:*" in actions:
                                escalation_permissions_found.append("*")
                                break
                            for action in actions:
                                if action in ESCALATION_PERMISSIONS:
                                    escalation_permissions_found.append(action)

                except Exception as e:
                    errors.append(f"policy_review_error: {e}")

                escalation_permissions_found = list(set(escalation_permissions_found))
                has_privilege_escalation_risk = len(escalation_permissions_found) > 0

                if has_privilege_escalation_risk:
                    resources.append(_base_resource(
                        provider="AWS",
                        service="IAM",
                        resource_type="IAMRole",
                        resource_id=role_arn,
                        account_id=account_id,
                        region=region,
                        analysis={
                            "role_name": role_name,
                            "arn": role_arn,
                            "has_privilege_escalation_risk": has_privilege_escalation_risk,
                            "escalation_permissions_found": escalation_permissions_found,
                            "total_dangerous_permissions": len(escalation_permissions_found)
                        },
                        errors=errors
                    ))

        return _build_resultado(
            "AWS", "IAM", "IAM_PRIVILEGE_ESCALATION_REVIEW",
            account_id, region, resources
        )

    _run_job(ejecucion_id, _execute)


# ══════════════════════════════════════════════════════════════════
# S3 — HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════

def _s3_context(proyecto_id):
    """Retorna (session, s3_client, account_id, region, buckets)."""
    session, region = _get_aws_session(proyecto_id)
    s3 = session.client("s3")
    account_id = _get_account_id(session)
    buckets = s3.list_buckets().get("Buckets", [])
    return session, s3, account_id, region, buckets


# ══════════════════════════════════════════════════════════════════
# S3
# ══════════════════════════════════════════════════════════════════

def s3_public_exposure_job(ejecucion_id, proyecto_id):

    def _execute():
        session, s3, account_id, region, buckets = _s3_context(proyecto_id)

        # ── Account-level Public Access Block (check que faltaba vs Prowler) ──
        account_block_enabled = False
        account_block_error = None
        try:
            s3control = session.client("s3control", region_name=region)
            pab = s3control.get_public_access_block(AccountId=account_id)
            cfg = pab["PublicAccessBlockConfiguration"]
            account_block_enabled = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                account_block_enabled = False
            else:
                account_block_error = str(e)

        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            public_via_acl = False
            public_via_policy = False
            public_write = False
            block_public_disabled = False
            errors = []

            # ACL CHECK
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    permission = grant.get("Permission")
                    if "AllUsers" in uri:
                        public_via_acl = True
                        if permission in ["WRITE", "FULL_CONTROL"]:
                            public_write = True
            except Exception as e:
                errors.append(f"acl_check_error: {e}")

            # POLICY CHECK
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy["Policy"])
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal")
                    actions = stmt.get("Action", [])
                    if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                        public_via_policy = True
                        if isinstance(actions, str):
                            actions = [actions]
                        if any(a in ["s3:*", "s3:PutObject"] for a in actions):
                            public_write = True
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    errors.append(f"policy_check_error: {e}")

            # BUCKET-LEVEL BLOCK PUBLIC ACCESS CHECK
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    block_public_disabled = True
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    block_public_disabled = True
                else:
                    errors.append(f"pab_check_error: {e}")

            is_effectively_public = (public_via_acl or public_via_policy) and block_public_disabled

            resources.append(_base_resource(
                provider="AWS", service="S3",
                resource_type="S3Bucket", resource_id=bucket_name,
                account_id=account_id, region=region,
                analysis={
                    "public_via_acl": public_via_acl,
                    "public_via_policy": public_via_policy,
                    "public_write": public_write,
                    "block_public_access_disabled": block_public_disabled,
                    "is_effectively_public": is_effectively_public
                },
                errors=errors
            ))

        return _build_resultado(
            "AWS", "S3", "PUBLIC_EXPOSURE_ANALYSIS",
            account_id, region, resources,
            account_level_block_public_access={
                "enabled": account_block_enabled,
                "error": account_block_error
            }
        )

    _run_job(ejecucion_id, _execute)


def s3_encryption_logging_job(ejecucion_id, proyecto_id):

    def _execute():
        _, s3, account_id, region, buckets = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            encryption_enabled = False
            encryption_type = None
            versioning_enabled = False
            logging_enabled = False
            errors = []

            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    encryption_enabled = True
                    encryption_type = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            except ClientError as e:
                if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                    errors.append(f"encryption_check_error: {e}")

            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                versioning_enabled = versioning.get("Status") == "Enabled"
            except Exception as e:
                errors.append(f"versioning_check_error: {e}")

            try:
                logging_cfg = s3.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = bool(logging_cfg.get("LoggingEnabled"))
            except Exception as e:
                errors.append(f"logging_check_error: {e}")

            resources.append(_base_resource(
                provider="AWS", service="S3",
                resource_type="S3Bucket", resource_id=bucket_name,
                account_id=account_id, region=region,
                analysis={
                    "encryption_enabled": encryption_enabled,
                    "encryption_type": encryption_type,
                    "versioning_enabled": versioning_enabled,
                    "logging_enabled": logging_enabled
                },
                errors=errors
            ))

        return _build_resultado("AWS", "S3", "SECURITY_POSTURE_ANALYSIS", account_id, region, resources)

    _run_job(ejecucion_id, _execute)


def s3_iam_access_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, s3, account_id, region, buckets = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            is_public = False
            cross_account = False
            wildcard_action = False
            dangerous_write = False
            wildcard_resource = False
            errors = []

            dangerous_actions = {"s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy", "s3:PutObjectAcl", "s3:*"}

            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy["Policy"])

                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") != "Allow":
                        continue

                    principal = stmt.get("Principal")
                    actions = stmt.get("Action", [])
                    resource = stmt.get("Resource", [])

                    # PRINCIPAL CHECK
                    if principal == "*":
                        is_public = True
                    elif isinstance(principal, dict):
                        aws_p = principal.get("AWS")
                        if aws_p == "*":
                            is_public = True
                        principals = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
                        for p in principals:
                            if f":{account_id}:" not in p:
                                cross_account = True

                    # ACTION CHECK
                    if isinstance(actions, str):
                        actions = [actions]
                    if "*" in actions or any(a.endswith("*") for a in actions):
                        wildcard_action = True
                    if any(a in dangerous_actions for a in actions):
                        dangerous_write = True

                    # RESOURCE CHECK
                    if isinstance(resource, str):
                        resource = [resource]
                    if any(r == "*" or r.endswith("/*") for r in resource):
                        wildcard_resource = True

            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    errors.append(f"policy_check_error: {e}")

            resources.append(_base_resource(
                provider="AWS", service="S3",
                resource_type="S3Bucket", resource_id=bucket_name,
                account_id=account_id, region=region,
                analysis={
                    "public_access": is_public,
                    "cross_account_access": cross_account,
                    "wildcard_action": wildcard_action,
                    "dangerous_write_permissions": dangerous_write,
                    "wildcard_resource": wildcard_resource
                },
                errors=errors
            ))

        return _build_resultado("AWS", "S3", "IAM_POLICY_ANALYSIS", account_id, region, resources)

    _run_job(ejecucion_id, _execute)

def s3_replication_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, s3, account_id, region, buckets = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            replication_enabled = False
            replication_rules = []
            errors = []

            try:
                replication = s3.get_bucket_replication(Bucket=bucket_name)
                config = replication.get("ReplicationConfiguration", {})
                rules = config.get("Rules", [])

                if rules:
                    replication_enabled = True
                    for rule in rules:
                        replication_rules.append({
                            "rule_id": rule.get("ID"),
                            "status": rule.get("Status"),
                            "destination_bucket": rule.get("Destination", {}).get("Bucket"),
                            "destination_region": rule.get("Destination", {}).get("Bucket", "").split(":::")[1] if ":::" in rule.get("Destination", {}).get("Bucket", "") else None,
                            "prefix": rule.get("Prefix"),
                            "delete_marker_replication": rule.get("DeleteMarkerReplication", {}).get("Status")
                        })

            except ClientError as e:
                if e.response["Error"]["Code"] == "ReplicationConfigurationNotFoundError":
                    replication_enabled = False
                else:
                    errors.append(f"replication_check_error: {e}")

            resources.append(_base_resource(
                provider="AWS", service="S3",
                resource_type="S3Bucket", resource_id=bucket_name,
                account_id=account_id, region=region,
                analysis={
                    "replication_enabled": replication_enabled,
                    "replication_rules": replication_rules,
                    "total_rules": len(replication_rules)
                },
                errors=errors
            ))

        return _build_resultado(
            "AWS", "S3", "REPLICATION_CONFIGURATION_REVIEW",
            account_id, region, resources
        )

    _run_job(ejecucion_id, _execute)


def s3_lifecycle_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, s3, account_id, region, buckets = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            lifecycle_enabled = False
            lifecycle_rules = []
            errors = []

            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                rules = lifecycle.get("Rules", [])

                if rules:
                    lifecycle_enabled = True
                    for rule in rules:
                        transitions = rule.get("Transitions", [])
                        expiration = rule.get("Expiration", {})
                        lifecycle_rules.append({
                            "rule_id": rule.get("ID"),
                            "status": rule.get("Status"),
                            "prefix": rule.get("Prefix"),
                            "expiration_days": expiration.get("Days"),
                            "expiration_date": str(expiration.get("Date")) if expiration.get("Date") else None,
                            "transitions": [
                                {
                                    "days": t.get("Days"),
                                    "storage_class": t.get("StorageClass")
                                }
                                for t in transitions
                            ],
                            "noncurrent_version_expiration": rule.get("NoncurrentVersionExpiration", {}).get("NoncurrentDays"),
                            "abort_incomplete_multipart_upload": rule.get("AbortIncompleteMultipartUpload", {}).get("DaysAfterInitiation")
                        })

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                    lifecycle_enabled = False
                else:
                    errors.append(f"lifecycle_check_error: {e}")

            resources.append(_base_resource(
                provider="AWS", service="S3",
                resource_type="S3Bucket", resource_id=bucket_name,
                account_id=account_id, region=region,
                analysis={
                    "lifecycle_enabled": lifecycle_enabled,
                    "lifecycle_rules": lifecycle_rules,
                    "total_rules": len(lifecycle_rules),
                    "has_expiration_policy": any(
                        r.get("expiration_days") or r.get("expiration_date")
                        for r in lifecycle_rules
                    ),
                    "has_transition_policy": any(
                        r.get("transitions")
                        for r in lifecycle_rules
                    )
                },
                errors=errors
            ))

        return _build_resultado(
            "AWS", "S3", "LIFECYCLE_POLICY_REVIEW",
            account_id, region, resources
        )

    _run_job(ejecucion_id, _execute)

# ══════════════════════════════════════════════════════════════════
# EC2
# ══════════════════════════════════════════════════════════════════

def ec2_security_groups_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        ec2 = session.client("ec2")
        account_id = _get_account_id(session)
        COMMON_PORTS = CloudEjecucion.top_100_common_ports()

        all_sgs = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            all_sgs.extend(page.get("SecurityGroups", []))

        resources = []

        for sg in all_sgs:
            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName")
            exposed_rules = []

            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                is_public_ipv4 = "0.0.0.0/0" in [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                is_public_ipv6 = "::/0" in [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]

                if not (is_public_ipv4 or is_public_ipv6):
                    continue

                rule_detail = {
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port,
                    "public_ipv4": is_public_ipv4,
                    "public_ipv6": is_public_ipv6,
                    "analysis": {}
                }

                if protocol == "-1":
                    rule_detail["analysis"]["all_traffic_exposed"] = True
                    exposed_rules.append(rule_detail)
                    continue

                if from_port is None:
                    rule_detail["analysis"]["non_tcp_udp_exposed"] = True
                    exposed_rules.append(rule_detail)
                    continue

                port_span = (to_port - from_port) if to_port else 0

                if port_span > 200:
                    rule_detail["analysis"]["large_port_range_exposed"] = {
                        "from": from_port, "to": to_port, "range_size": port_span
                    }
                else:
                    critical = [
                        {"port": p, "service": COMMON_PORTS[p]}
                        for p in range(from_port, (to_port or from_port) + 1)
                        if p in COMMON_PORTS
                    ]
                    rule_detail["analysis"]["critical_ports_exposed"] = critical
                    rule_detail["analysis"]["port_range"] = {"from": from_port, "to": to_port}

                exposed_rules.append(rule_detail)

            if exposed_rules:
                resources.append(_base_resource(
                    provider="AWS", service="EC2",
                    resource_type="SecurityGroup", resource_id=sg_id,
                    account_id=account_id, region=region,
                    analysis={
                        "public_ingress_rules_detected": True,
                        "total_public_rules": len(exposed_rules),
                        "rules": exposed_rules
                    },
                    resource_name=sg_name
                ))

        return _build_resultado(
            "AWS", "EC2", "SECURITY_GROUP_EXPOSURE_ANALYSIS",
            account_id, region, resources,
            total_security_groups=len(all_sgs),
            total_exposed_groups=len(resources)
        )

    _run_job(ejecucion_id, _execute)


def ec2_public_instances_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        ec2 = session.client("ec2")
        account_id = _get_account_id(session)

        sg_cache = {}
        findings = []
        instance_count = 0

        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_count += 1
                    instance_id = instance.get("InstanceId")
                    state = instance.get("State", {}).get("Name")
                    public_ip = instance.get("PublicIpAddress")

                    if state != "running" or not public_ip:
                        continue

                    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                    sg_public = False

                    for sg_id in sg_ids:
                        if sg_id not in sg_cache:
                            sg_cache[sg_id] = ec2.describe_security_groups(
                                GroupIds=[sg_id]
                            )["SecurityGroups"][0]

                        for rule in sg_cache[sg_id].get("IpPermissions", []):
                            ipv4 = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                            ipv6 = [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]
                            if "0.0.0.0/0" in ipv4 or "::/0" in ipv6:
                                sg_public = True

                    findings.append(_base_resource(
                        provider="AWS", service="EC2",
                        resource_type="EC2Instance", resource_id=instance_id,
                        account_id=account_id, region=region,
                        analysis={
                            "state": state,
                            "public_ip": public_ip,
                            "security_groups": sg_ids,
                            "sg_allows_public_ingress": sg_public,
                            "exposure_reason": (
                                "Public IP + SG allows 0.0.0.0/0 or ::/0"
                                if sg_public else "Instance has Public IP"
                            )
                        }
                    ))

        return _build_resultado(
            "AWS", "EC2", "PUBLIC_INSTANCE_ANALYSIS",
            account_id, region, findings,
            total_instances_checked=instance_count,
            total_findings=len(findings)
        )

    _run_job(ejecucion_id, _execute)


def ec2_iam_role_review_job(ejecucion_id, proyecto_id):

    def _execute():
        session, region = _get_aws_session(proyecto_id)
        ec2 = session.client("ec2")
        iam = session.client("iam")
        account_id = _get_account_id(session)

        role_cache = {}
        findings = []
        instance_count = 0

        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_count += 1
                    instance_id = instance.get("InstanceId")
                    iam_profile = instance.get("IamInstanceProfile")

                    if not iam_profile:
                        continue

                    profile_name = iam_profile["Arn"].split("/")[-1]
                    profile = iam.get_instance_profile(InstanceProfileName=profile_name)

                    for role in profile["InstanceProfile"]["Roles"]:
                        role_name = role["RoleName"]

                        if role_name not in role_cache:
                            issues = set()

                            for policy in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                                p_arn = policy["PolicyArn"]
                                if policy["PolicyName"] == "AdministratorAccess":
                                    issues.add("AdministratorAccess attached")

                                version_id = iam.get_policy(PolicyArn=p_arn)["Policy"]["DefaultVersionId"]
                                doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=version_id)["PolicyVersion"]["Document"]

                                for stmt in doc.get("Statement", []):
                                    actions = stmt.get("Action", [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if "*" in actions or actions == ["*"]:
                                        issues.add("Wildcard action '*' detected")
                                    for a in actions:
                                        if isinstance(a, str) and a.endswith(":*"):
                                            issues.add(f"Broad permission: {a}")

                            for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                                doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
                                for stmt in doc.get("Statement", []):
                                    actions = stmt.get("Action", [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if "*" in actions or actions == ["*"]:
                                        issues.add("Wildcard action '*' detected (inline)")
                                    for a in actions:
                                        if isinstance(a, str) and a.endswith(":*"):
                                            issues.add(f"Broad permission inline: {a}")

                            role_cache[role_name] = list(issues)

                        role_issues = role_cache.get(role_name)
                        if role_issues:
                            findings.append(_base_resource(
                                provider="AWS", service="EC2",
                                resource_type="EC2Instance", resource_id=instance_id,
                                account_id=account_id, region=region,
                                analysis={"iam_role": role_name, "issues": role_issues}
                            ))

        return _build_resultado(
            "AWS", "EC2", "EC2_IAM_ROLE_ANALYSIS",
            account_id, region, findings,
            total_instances_checked=instance_count,
            total_findings=len(findings)
        )

    _run_job(ejecucion_id, _execute)


# ══════════════════════════════════════════════════════════════════
# API GATEWAY — HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════

def _apigw_context(proyecto_id):
    """Retorna (session, apigw_v1, apigw_v2, account_id, region)."""
    session, region = _get_aws_session(proyecto_id)
    return (
        session,
        session.client("apigateway"),
        session.client("apigatewayv2"),
        _get_account_id(session),
        region
    )


def _iter_rest_apis(apigw):
    for page in apigw.get_paginator("get_rest_apis").paginate():
        yield from page.get("items", [])


def _iter_http_apis(apigw2):
    for page in apigw2.get_paginator("get_apis").paginate():
        yield from page.get("Items", [])


def _iter_rest_stages(apigw, api_id):
    for page in apigw.get_paginator("get_stages").paginate(restApiId=api_id):
        yield from page.get("item", [])


def _iter_http_stages(apigw2, api_id):
    for page in apigw2.get_paginator("get_stages").paginate(ApiId=api_id):
        yield from page.get("Items", [])


def _iter_rest_resources(apigw, api_id):
    for page in apigw.get_paginator("get_resources").paginate(restApiId=api_id):
        yield from page.get("items", [])


def _iter_http_routes(apigw2, api_id):
    for page in apigw2.get_paginator("get_routes").paginate(ApiId=api_id):
        yield from page.get("Items", [])


# ══════════════════════════════════════════════════════════════════
# API GATEWAY
# ══════════════════════════════════════════════════════════════════

def apigateway_public_exposure_job(ejecucion_id, proyecto_id):

    def _execute():
        session, apigw, apigw2, account_id, region = _apigw_context(proyecto_id)
        resources = []
        total_apis = 0

        # REST APIs (v1)
        for api in _iter_rest_apis(apigw):
            total_apis += 1
            api_id, api_name = api["id"], api["name"]

            policy_public = False
            try:
                api_full = apigw.get_rest_api(restApiId=api_id)
                policy = api_full.get("policy", "")
                if policy and '"Principal":"*"' in policy:
                    policy_public = True
            except Exception:
                pass

            stages = [
                {
                    "stage_name": s.get("stageName"),
                    "cache_enabled": s.get("cacheClusterEnabled"),
                    "logging_enabled": s.get("methodSettings", {}),
                    "web_acl_associated": bool(s.get("webAclArn"))
                }
                for s in _iter_rest_stages(apigw, api_id)
            ]

            methods = []
            for res in _iter_rest_resources(apigw, api_id):
                if "resourceMethods" not in res:
                    continue
                path = res.get("path", "/")
                for method_name in res["resourceMethods"]:
                    method = apigw.get_method(
                        restApiId=api_id, resourceId=res["id"], httpMethod=method_name
                    )
                    methods.append({
                        "path": path, "method": method_name,
                        "authorization_type": method.get("authorizationType"),
                        "api_key_required": method.get("apiKeyRequired"),
                        "authorizer_id": method.get("authorizerId")
                    })

            resources.append(_base_resource(
                provider="AWS", service="APIGateway",
                resource_type="REST_API", resource_id=api_id,
                account_id=account_id, region=region,
                analysis={
                    "endpoint_types": api.get("endpointConfiguration", {}).get("types", []),
                    "resource_policy_public": policy_public,
                    "stages": stages, "methods": methods
                },
                resource_name=api_name
            ))

        # HTTP / WebSocket APIs (v2)
        for api in _iter_http_apis(apigw2):
            total_apis += 1
            api_id, api_name = api["ApiId"], api["Name"]
            cors = api.get("CorsConfiguration")

            routes = [
                {
                    "route_key": r.get("RouteKey"),
                    "authorization_type": r.get("AuthorizationType"),
                    "api_key_required": r.get("ApiKeyRequired"),
                    "authorizer_id": r.get("AuthorizerId")
                }
                for r in _iter_http_routes(apigw2, api_id)
            ]

            stages = [
                {
                    "stage_name": s.get("StageName"),
                    "auto_deploy": s.get("AutoDeploy"),
                    "access_log_settings": s.get("AccessLogSettings"),
                    "web_acl_associated": bool(s.get("WebAclArn"))
                }
                for s in _iter_http_stages(apigw2, api_id)
            ]

            resources.append(_base_resource(
                provider="AWS", service="APIGateway",
                resource_type="HTTP_API", resource_id=api_id,
                account_id=account_id, region=region,
                analysis={
                    "protocol_type": api.get("ProtocolType"),
                    "cors_configuration": {
                        "allow_origins": cors.get("AllowOrigins"),
                        "allow_methods": cors.get("AllowMethods"),
                        "allow_headers": cors.get("AllowHeaders")
                    } if cors else None,
                    "routes": routes, "stages": stages
                },
                resource_name=api_name
            ))

        return _build_resultado(
            "AWS", "APIGateway", "FULL_CONFIGURATION_ANALYSIS",
            account_id, region, resources,
            total_apis_checked=total_apis
        )

    _run_job(ejecucion_id, _execute)


def apigateway_discovery_stages_job(ejecucion_id, proyecto_id):

    def _execute():
        _, apigw, apigw2, account_id, region = _apigw_context(proyecto_id)
        resources = []
        total_apis = 0

        for api in _iter_rest_apis(apigw):
            total_apis += 1
            api_id, api_name = api["id"], api["name"]
            for stage in _iter_rest_stages(apigw, api_id):
                resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API_STAGE",
                    resource_id=f"{api_id}:{stage.get('stageName')}",
                    account_id=account_id, region=region,
                    analysis={
                        "api_id": api_id, "api_name": api_name,
                        "tracing_enabled": stage.get("tracingEnabled"),
                        "cache_cluster_enabled": stage.get("cacheClusterEnabled"),
                        "cache_cluster_size": stage.get("cacheClusterSize"),
                        "web_acl_associated": stage.get("webAclArn"),
                        "method_settings": stage.get("methodSettings"),
                        "access_log_settings": stage.get("accessLogSettings"),
                        "variables": stage.get("variables")
                    },
                    resource_name=stage.get("stageName")
                ))

        for api in _iter_http_apis(apigw2):
            total_apis += 1
            api_id, api_name = api["ApiId"], api["Name"]
            for stage in _iter_http_stages(apigw2, api_id):
                resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="HTTP_API_STAGE",
                    resource_id=f"{api_id}:{stage.get('StageName')}",
                    account_id=account_id, region=region,
                    analysis={
                        "api_id": api_id, "api_name": api_name,
                        "auto_deploy": stage.get("AutoDeploy"),
                        "default_route_settings": stage.get("DefaultRouteSettings"),
                        "access_log_settings": stage.get("AccessLogSettings"),
                        "web_acl_associated": stage.get("WebAclArn"),
                        "stage_variables": stage.get("StageVariables")
                    },
                    resource_name=stage.get("StageName")
                ))

        return _build_resultado(
            "AWS", "APIGateway", "STAGE_CONFIGURATION_DISCOVERY",
            account_id, region, resources,
            total_apis_checked=total_apis
        )

    _run_job(ejecucion_id, _execute)


def apigateway_review_authorizers_job(ejecucion_id, proyecto_id):

    def _execute():
        _, apigw, apigw2, account_id, region = _apigw_context(proyecto_id)
        resources = []
        total_apis = 0

        for api in _iter_rest_apis(apigw):
            total_apis += 1
            api_id, api_name = api["id"], api["name"]

            authorizers = [
                {
                    "authorizer_id": a.get("id"), "name": a.get("name"),
                    "type": a.get("type"), "identity_source": a.get("identitySource"),
                    "provider_arns": a.get("providerARNs"), "authorizer_uri": a.get("authorizerUri"),
                    "auth_ttl": a.get("authorizerResultTtlInSeconds")
                }
                for page in apigw.get_paginator("get_authorizers").paginate(restApiId=api_id)
                for a in page.get("items", [])
            ]

            methods = []
            for res in _iter_rest_resources(apigw, api_id):
                if "resourceMethods" not in res:
                    continue
                path = res.get("path")
                for method_name in res["resourceMethods"]:
                    m = apigw.get_method(restApiId=api_id, resourceId=res["id"], httpMethod=method_name)
                    methods.append({
                        "path": path, "method": method_name,
                        "authorization_type": m.get("authorizationType"),
                        "authorizer_id": m.get("authorizerId"),
                        "authorization_scopes": m.get("authorizationScopes")
                    })

            resources.append(_base_resource(
                provider="AWS", service="APIGateway",
                resource_type="REST_API_AUTHORIZERS", resource_id=api_id,
                account_id=account_id, region=region,
                analysis={"authorizers_defined": authorizers, "methods_authorization": methods},
                resource_name=api_name
            ))

        for api in _iter_http_apis(apigw2):
            total_apis += 1
            api_id, api_name = api["ApiId"], api["Name"]

            authorizers = [
                {
                    "authorizer_id": a.get("AuthorizerId"), "name": a.get("Name"),
                    "authorizer_type": a.get("AuthorizerType"), "identity_sources": a.get("IdentitySource"),
                    "jwt_configuration": a.get("JwtConfiguration"), "authorizer_uri": a.get("AuthorizerUri"),
                    "authorizer_payload_format_version": a.get("AuthorizerPayloadFormatVersion"),
                    "enable_simple_responses": a.get("EnableSimpleResponses")
                }
                for page in apigw2.get_paginator("get_authorizers").paginate(ApiId=api_id)
                for a in page.get("Items", [])
            ]

            routes = [
                {
                    "route_key": r.get("RouteKey"),
                    "authorization_type": r.get("AuthorizationType"),
                    "authorizer_id": r.get("AuthorizerId"),
                    "authorization_scopes": r.get("AuthorizationScopes")
                }
                for r in _iter_http_routes(apigw2, api_id)
            ]

            resources.append(_base_resource(
                provider="AWS", service="APIGateway",
                resource_type="HTTP_API_AUTHORIZERS", resource_id=api_id,
                account_id=account_id, region=region,
                analysis={"authorizers_defined": authorizers, "routes_authorization": routes},
                resource_name=api_name
            ))

        return _build_resultado(
            "AWS", "APIGateway", "AUTHORIZER_CONFIGURATION_DISCOVERY",
            account_id, region, resources,
            total_apis_checked=total_apis
        )

    _run_job(ejecucion_id, _execute)


def apigateway_security_exposure_job(ejecucion_id, proyecto_id):

    def _execute():
        _, apigw, apigw2, account_id, region = _apigw_context(proyecto_id)
        resources = []
        total_apis = 0

        for api in _iter_rest_apis(apigw):
            total_apis += 1
            api_id, api_name = api["id"], api["name"]
            methods = []

            for res in _iter_rest_resources(apigw, api_id):
                if "resourceMethods" not in res:
                    continue
                path = res.get("path", "/")
                for method_name in res["resourceMethods"]:
                    m = apigw.get_method(restApiId=api_id, resourceId=res["id"], httpMethod=method_name)
                    integ = apigw.get_integration(restApiId=api_id, resourceId=res["id"], httpMethod=method_name)
                    methods.append({
                        "path": path, "method": method_name,
                        "authorization_type": m.get("authorizationType"),
                        "api_key_required": m.get("apiKeyRequired"),
                        "integration_type": integ.get("type"),
                        "integration_uri": integ.get("uri"),
                        "cors_headers": integ.get("integrationResponses")
                    })

            resources.append(_base_resource(
                provider="AWS", service="APIGateway",
                resource_type="REST_API_SECURITY_EXPOSURE", resource_id=api_id,
                account_id=account_id, region=region,
                analysis={"methods": methods},
                resource_name=api_name
            ))

        for api in _iter_http_apis(apigw2):
            total_apis += 1
            api_id, api_name = api["ApiId"], api["Name"]

            integrations_map = {
                i["IntegrationId"]: {
                    "integration_type": i.get("IntegrationType"),
                    "integration_uri": i.get("IntegrationUri"),
                    "connection_type": i.get("ConnectionType")
                }
                for page in apigw2.get_paginator("get_integrations").paginate(ApiId=api_id)
                for i in page.get("Items", [])
            }

            routes = [
                {
                    "route_key": r.get("RouteKey"),
                    "authorization_type": r.get("AuthorizationType"),
                    "api_key_required": r.get("ApiKeyRequired"),
                    "integration": integrations_map.get(
                        r["Target"].replace("integrations/", "") if r.get("Target") else None
                    )
                }
                for r in _iter_http_routes(apigw2, api_id)
            ]

            resources.append(_base_resource(
                provider="AWS", service="APIGateway",
                resource_type="HTTP_API_SECURITY_EXPOSURE", resource_id=api_id,
                account_id=account_id, region=region,
                analysis={"routes": routes},
                resource_name=api_name
            ))

        return _build_resultado(
            "AWS", "APIGateway", "SECURITY_EXPOSURE_DISCOVERY",
            account_id, region, resources,
            total_apis_checked=total_apis
        )

    _run_job(ejecucion_id, _execute)


def apigateway_logging_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, apigw, apigw2, account_id, region = _apigw_context(proyecto_id)
        resources = []
        total_apis = 0

        for api in _iter_rest_apis(apigw):
            total_apis += 1
            api_id, api_name = api["id"], api["name"]
            for stage in _iter_rest_stages(apigw, api_id):
                resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API_LOGGING_CONFIG",
                    resource_id=f"{api_id}:{stage.get('stageName')}",
                    account_id=account_id, region=region,
                    analysis={
                        "api_id": api_id, "api_name": api_name,
                        "tracing_enabled": stage.get("tracingEnabled"),
                        "access_log_settings": stage.get("accessLogSettings"),
                        "method_settings": stage.get("methodSettings"),
                        "cache_cluster_enabled": stage.get("cacheClusterEnabled"),
                        "web_acl_associated": stage.get("webAclArn")
                    },
                    resource_name=stage.get("stageName")
                ))

        for api in _iter_http_apis(apigw2):
            total_apis += 1
            api_id, api_name = api["ApiId"], api["Name"]
            for stage in _iter_http_stages(apigw2, api_id):
                resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="HTTP_API_LOGGING_CONFIG",
                    resource_id=f"{api_id}:{stage.get('StageName')}",
                    account_id=account_id, region=region,
                    analysis={
                        "api_id": api_id, "api_name": api_name,
                        "auto_deploy": stage.get("AutoDeploy"),
                        "access_log_settings": stage.get("AccessLogSettings"),
                        "default_route_settings": stage.get("DefaultRouteSettings"),
                        "route_settings": stage.get("RouteSettings"),
                        "web_acl_associated": stage.get("WebAclArn")
                    },
                    resource_name=stage.get("StageName")
                ))

        return _build_resultado(
            "AWS", "APIGateway", "LOGGING_CONFIGURATION_DISCOVERY",
            account_id, region, resources,
            total_apis_checked=total_apis
        )

    _run_job(ejecucion_id, _execute)


# ══════════════════════════════════════════════════════════════════
# LAMBDA — HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════

def _lambda_context(proyecto_id):
    """Retorna (lambda_client, iam_client, account_id, region, paginator)."""
    session, region = _get_aws_session(proyecto_id)
    lc = session.client("lambda")
    iam = session.client("iam")
    account_id = _get_account_id(session)
    return session, lc, iam, account_id, region


def _iter_functions(lc):
    for page in lc.get_paginator("list_functions").paginate():
        yield from page.get("Functions", [])


def _get_lambda_policy(lc, function_name):
    """Retorna la policy JSON de una función o None si no tiene."""
    try:
        resp = lc.get_policy(FunctionName=function_name)
        return json.loads(resp.get("Policy", "{}"))
    except lc.exceptions.ResourceNotFoundException:
        return None


def _is_principal_public(principal):
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return principal.get("AWS") == "*" or principal.get("Service") == "*"
    return False


def _analyze_policy_statements(policy_doc):
    """Normaliza y retorna todos los statements de una policy."""
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    result = []
    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        def _to_list(v):
            return [v] if isinstance(v, str) else (v or [])

        result.append({
            "statement_index": idx,
            "sid": stmt.get("Sid"),
            "effect": stmt.get("Effect"),
            "actions": _to_list(stmt.get("Action", [])),
            "not_actions": _to_list(stmt.get("NotAction", [])),
            "resources": _to_list(stmt.get("Resource", [])),
            "not_resources": _to_list(stmt.get("NotResource", [])),
            "principal": stmt.get("Principal"),
            "not_principal": stmt.get("NotPrincipal"),
            "condition": stmt.get("Condition")
        })
    return result


def _analyze_wildcards(policy_doc):
    """Detecta wildcards en statements Allow."""
    result = []
    for stmt in policy_doc.get("Statement", []):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        result.append({
            "actions": actions,
            "resources": resources,
            "action_wildcard_full": "*" in actions,
            "resource_wildcard_full": "*" in resources,
            "action_wildcard_partial": [a for a in actions if isinstance(a, str) and "*" in a and a != "*"]
        })
    return result


def _analyze_role_policies(iam, role_name, mode="statements"):
    """
    Analiza las políticas attached e inline de un rol.
    mode: 'statements' | 'wildcards' | 'raw'
    """
    attached = []
    inline = []

    for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
        for policy in page.get("AttachedPolicies", []):
            p_arn = policy["PolicyArn"]
            version = iam.get_policy(PolicyArn=p_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=p_arn, VersionId=version)["PolicyVersion"]["Document"]

            entry = {"policy_name": policy["PolicyName"], "policy_arn": p_arn}
            if mode == "statements":
                entry["statements"] = _analyze_policy_statements(doc)
            elif mode == "wildcards":
                entry["statements"] = _analyze_wildcards(doc)
            else:
                entry["policy_document"] = doc
            attached.append(entry)

    for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
        for policy_name in page.get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
            entry = {"policy_name": policy_name}
            if mode == "statements":
                entry["statements"] = _analyze_policy_statements(doc)
            elif mode == "wildcards":
                entry["statements"] = _analyze_wildcards(doc)
            else:
                entry["policy_document"] = doc
            inline.append(entry)

    return attached, inline


# ══════════════════════════════════════════════════════════════════
# LAMBDA
# ══════════════════════════════════════════════════════════════════

def discovery_functions_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        for fn in _iter_functions(lc):
            total += 1
            vpc = fn.get("VpcConfig", {}) or {}
            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaFunction", resource_id=fn.get("FunctionName"),
                account_id=account_id, region=region,
                analysis={
                    "function_arn": fn.get("FunctionArn"),
                    "runtime": fn.get("Runtime"),
                    "role": fn.get("Role"),
                    "handler": fn.get("Handler"),
                    "timeout": fn.get("Timeout"),
                    "memory_size": fn.get("MemorySize"),
                    "last_modified": fn.get("LastModified"),
                    "package_type": fn.get("PackageType"),
                    "architectures": fn.get("Architectures"),
                    "vpc_configured": bool(vpc.get("VpcId")),
                    "subnet_ids": vpc.get("SubnetIds"),
                    "security_group_ids": vpc.get("SecurityGroupIds"),
                    "tracing_mode": fn.get("TracingConfig", {}).get("Mode"),
                    "dead_letter_config": fn.get("DeadLetterConfig"),
                    "layers": [layer.get("Arn") for layer in fn.get("Layers", [])],
                    "environment_variables": list(fn.get("Environment", {}).get("Variables", {}).keys())
                }
            ))

        return _build_resultado(
            "AWS", "Lambda", "FUNCTION_CONFIGURATION_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def discovery_permissions_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            policy_json = _get_lambda_policy(lc, function_name)

            is_public = False
            statements_count = 0
            error = None

            if policy_json:
                statements = policy_json.get("Statement", [])
                statements_count = len(statements)
                is_public = any(_is_principal_public(s.get("Principal")) for s in statements)

            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaPermissionPolicy", resource_id=function_name,
                account_id=account_id, region=region,
                analysis={
                    "has_policy": policy_json is not None,
                    "is_public": is_public,
                    "statements_count": statements_count,
                    "policy_document": policy_json,
                    "error": error
                }
            ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_PERMISSION_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def discovery_triggers_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            event_mappings = []
            policy_triggers = []
            error = None

            try:
                for page in lc.get_paginator("list_event_source_mappings").paginate(FunctionName=function_name):
                    for m in page.get("EventSourceMappings", []):
                        event_mappings.append({
                            "event_source_arn": m.get("EventSourceArn"),
                            "state": m.get("State"),
                            "batch_size": m.get("BatchSize"),
                            "maximum_batching_window": m.get("MaximumBatchingWindowInSeconds"),
                            "parallelization_factor": m.get("ParallelizationFactor"),
                            "function_response_types": m.get("FunctionResponseTypes")
                        })
            except Exception as e:
                error = f"EventSourceMappingError: {e}"

            policy_json = _get_lambda_policy(lc, function_name)
            if policy_json:
                for stmt in policy_json.get("Statement", []):
                    condition = stmt.get("Condition", {})
                    source_arn = (
                        condition.get("ArnLike", {}).get("AWS:SourceArn") or
                        condition.get("ArnEquals", {}).get("AWS:SourceArn")
                    )
                    policy_triggers.append({
                        "principal": stmt.get("Principal"),
                        "effect": stmt.get("Effect"),
                        "action": stmt.get("Action"),
                        "source_arn": source_arn
                    })

            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaTriggerConfiguration", resource_id=function_name,
                account_id=account_id, region=region,
                analysis={
                    "event_source_mappings": event_mappings,
                    "policy_triggers": policy_triggers,
                    "error": error
                }
            ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_TRIGGER_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def public_exposure_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0
        total_exposed = 0

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            policy_json = _get_lambda_policy(lc, function_name)

            is_public = False
            policy_statements = []

            if policy_json:
                for stmt in policy_json.get("Statement", []):
                    principal = stmt.get("Principal")
                    stmt_public = _is_principal_public(principal)
                    if stmt_public:
                        is_public = True
                    policy_statements.append({
                        "principal": principal,
                        "action": stmt.get("Action"),
                        "condition": stmt.get("Condition"),
                        "statement_public": stmt_public
                    })

            if is_public:
                total_exposed += 1

            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaPublicExposure", resource_id=function_name,
                account_id=account_id, region=region,
                analysis={
                    "is_public": is_public,
                    "policy_statements": policy_statements
                }
            ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_PUBLIC_EXPOSURE_ANALYSIS",
            account_id, region, resources,
            total_functions_checked=total,
            total_exposed_functions=total_exposed
        )

    _run_job(ejecucion_id, _execute)


def overprivileged_role_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, iam, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            role_arn = fn.get("Role")
            if not role_arn:
                continue

            role_name = role_arn.split("/")[-1]
            error = None
            attached, inline = [], []

            try:
                attached, inline = _analyze_role_policies(iam, role_name, mode="raw")
            except Exception as e:
                error = str(e)

            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaExecutionRole", resource_id=role_name,
                account_id=account_id, region=region,
                analysis={
                    "function_name": function_name,
                    "role_arn": role_arn,
                    "attached_policies": attached,
                    "inline_policies": inline,
                    "error": error
                },
                resource_name=role_name
            ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_ROLE_CONFIGURATION_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def wildcard_permissions_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, iam, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            role_arn = fn.get("Role")
            if not role_arn:
                continue

            role_name = role_arn.split("/")[-1]
            error = None
            attached, inline = [], []

            try:
                attached, inline = _analyze_role_policies(iam, role_name, mode="statements")
            except Exception as e:
                error = str(e)

            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaWildcardPermissionDiscovery", resource_id=role_name,
                account_id=account_id, region=region,
                analysis={
                    "function_name": function_name,
                    "role_arn": role_arn,
                    "attached_policies": attached,
                    "inline_policies": inline,
                    "error": error
                }
            ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_WILDCARD_PERMISSION_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def no_vpc_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            vpc = fn.get("VpcConfig", {}) or {}
            vpc_id = vpc.get("VpcId")
            subnets = vpc.get("SubnetIds", []) or []
            sgs = vpc.get("SecurityGroupIds", []) or []

            resources.append(_base_resource(
                provider="AWS", service="Lambda",
                resource_type="LambdaVpcConfiguration", resource_id=function_name,
                account_id=account_id, region=region,
                analysis={
                    "vpc_id": vpc_id,
                    "subnet_ids": subnets,
                    "security_group_ids": sgs,
                    "vpc_configured": bool(vpc_id and subnets and sgs)
                }
            ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_VPC_CONFIGURATION_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def lambda_runtime_review_job(ejecucion_id, proyecto_id):
    # Alias mantenido por compatibilidad — llama al job real
    old_runtime_review_job(ejecucion_id, proyecto_id)


def old_runtime_review_job(ejecucion_id, proyecto_id):

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        resources = []
        total = 0

        deprecated_runtimes = CloudEjecucion.versiones_deprecadas(
            tipo_proyecto_id=proyecto_id,
            proveedor="AWS", servicio="Lambda", categoria="Runtime"
        )

        for fn in _iter_functions(lc):
            total += 1
            function_name = fn.get("FunctionName")
            runtime = fn.get("Runtime")

            if runtime in deprecated_runtimes:
                resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaRuntime", resource_id=function_name,
                    account_id=account_id, region=region,
                    analysis={
                        "runtime": runtime,
                        "deprecated": True,
                        "recommendation": "Actualizar a una versión soportada oficialmente por AWS"
                    }
                ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_RUNTIME_DISCOVERY",
            account_id, region, resources,
            total_functions_checked=total
        )

    _run_job(ejecucion_id, _execute)


def env_secrets_review_job(ejecucion_id, proyecto_id):

    SUSPICIOUS_KEYWORDS = [
        "password", "secret", "token", "apikey", "api_key",
        "access_key", "private_key", "jwt", "db_", "database"
    ]

    def _execute():
        _, lc, _, account_id, region = _lambda_context(proyecto_id)
        findings = []

        for fn in _iter_functions(lc):
            function_name = fn.get("FunctionName")
            variables = fn.get("Environment", {}).get("Variables", {})

            for key, value in variables.items():
                key_lower = key.lower()

                if any(kw in key_lower for kw in SUSPICIOUS_KEYWORDS):
                    findings.append({
                        "FunctionName": function_name,
                        "Issue": "Potential secret stored in environment variable",
                        "VariableName": key,
                        "VariableValue": value,
                        "Recommendation": "Mover secretos a AWS Secrets Manager o Parameter Store"
                    })

                # Heurística: valor largo alfanumérico = posible secret
                if isinstance(value, str) and len(value) > 30:
                    if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
                        findings.append({
                            "FunctionName": function_name,
                            "Issue": "Suspicious high-entropy environment variable value",
                            "VariableName": key,
                            "Recommendation": "Revisar si el valor es un secreto en texto plano"
                        })

        return findings  # Lista directa, sin envelope (mantiene formato original)

    _run_job(ejecucion_id, _execute)


def logging_review_job(ejecucion_id, proyecto_id):

    def _execute():
        session, lc, _, account_id, region = _lambda_context(proyecto_id)
        logs_client = session.client("logs")
        findings = []

        for fn in _iter_functions(lc):
            function_name = fn.get("FunctionName")
            log_group_name = f"/aws/lambda/{function_name}"

            try:
                response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                log_groups = response.get("logGroups", [])

                if not log_groups:
                    findings.append({
                        "FunctionName": function_name,
                        "Issue": "CloudWatch Log Group not found",
                        "Recommendation": "Verificar que la Lambda tenga permisos para escribir logs"
                    })
                    continue

                retention = log_groups[0].get("retentionInDays")
                if not retention:
                    findings.append({
                        "FunctionName": function_name,
                        "Issue": "Log retention not configured (Never expire)",
                        "Recommendation": "Configurar retención para evitar almacenamiento indefinido"
                    })

            except Exception as e:
                findings.append({
                    "FunctionName": function_name,
                    "Issue": "Error reviewing logging",
                    "Error": str(e)
                })

        return findings  # Lista directa, mantiene formato original

    _run_job(ejecucion_id, _execute)