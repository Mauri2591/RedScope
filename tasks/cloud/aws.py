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
def _get_aws_credentials(proyecto_id):
    """Núcleo de autenticación. Retorna (creds_dict, region_base)."""
    config = Proyecto.get_cloud_config(proyecto_id)
    if not config:
        raise Exception("No existe configuración Cloud para este proyecto")

    fernet = Fernet(Config.FERNET_KEY)
    region_base = config["region"]

    if config.get("auth_method") == "role":
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
        creds = sts.assume_role(**assume_params)["Credentials"]
        return {
            "aws_access_key_id":     creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token":     creds["SessionToken"]
        }, region_base
    else:
        secret_key = fernet.decrypt(config["secret_key"].encode()).decode()
        return {
            "aws_access_key_id":     config["access_key"],
            "aws_secret_access_key": secret_key
        }, region_base
        
def _get_aws_session(proyecto_id):
    """Backwards-compat para jobs de IAM (globales). No usar en jobs nuevos."""
    creds, region = _get_aws_credentials(proyecto_id)
    return boto3.Session(region_name=region, **creds), region

def _get_account_id(session_or_creds):
    """Acepta session boto3 o dict de creds."""
    if isinstance(session_or_creds, dict):
        return boto3.client("sts", **session_or_creds).get_caller_identity()["Account"]
    return session_or_creds.client("sts").get_caller_identity()["Account"]

def _get_enabled_regions(creds):
    """Regiones habilitadas en la cuenta del cliente. Llamar una vez por scan."""
    ec2 = boto3.client("ec2", region_name="us-east-1", **creds)
    response = ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
    )
    return [r["RegionName"] for r in response["Regions"]]

def _make_client(service_name, creds, region):
    """Factory de clientes boto3 por servicio y región."""
    return boto3.client(service_name, region_name=region, **creds)

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
# Contextos regionales
# ══════════════════════════════════════════════════════════════════
def _vpc_context(creds, region):
    ec2 = _make_client("ec2", creds, region)
    return ec2

def _rds_context(creds, region):
    return _make_client("rds", creds, region)

def _kms_context(creds, region):
    return _make_client("kms", creds, region)

def _secretsmanager_context(creds, region):
    return _make_client("secretsmanager", creds, region)

def _cloudtrail_context(creds, region):
    return _make_client("cloudtrail", creds, region)

def _lambda_context(creds, region):
    lc  = _make_client("lambda", creds, region)
    iam = _make_client("iam", creds, "us-east-1")  # IAM siempre global
    return lc, iam

def _apigw_context(creds, region):
    return (
        _make_client("apigateway",   creds, region),
        _make_client("apigatewayv2", creds, region)
    )

def _inspector_context(creds, region):
    return _make_client("inspector2", creds, region)

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
    session, region = _get_aws_session(proyecto_id)
    s3 = session.client("s3")
    account_id = _get_account_id(session)
    buckets_raw = s3.list_buckets().get("Buckets", [])
    bucket_regions = {}
    for b in buckets_raw:
        name = b["Name"]
        try:
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            bucket_regions[name] = loc or "us-east-1"
        except Exception:
            bucket_regions[name] = region
    return session, s3, account_id, region, buckets_raw, bucket_regions


# ══════════════════════════════════════════════════════════════════
# S3
# ══════════════════════════════════════════════════════════════════
def s3_public_exposure_job(ejecucion_id, proyecto_id):
    def _execute():
        session, s3, account_id, region, buckets, bucket_regions = _s3_context(proyecto_id)
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
            bucket_region = bucket_regions.get(bucket_name, region)
            public_via_acl = False
            public_via_policy = False
            public_write = False
            block_public_disabled = False
            errors = []

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
                account_id=account_id, region=bucket_region,
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
        session, s3, account_id, region, buckets, bucket_regions = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_region = bucket_regions.get(bucket_name, region)
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
                account_id=account_id, region=bucket_region,
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
        _, s3, account_id, region, buckets, bucket_regions = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_region = bucket_regions.get(bucket_name, region)
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
                    if isinstance(actions, str):
                        actions = [actions]
                    if "*" in actions or any(a.endswith("*") for a in actions):
                        wildcard_action = True
                    if any(a in dangerous_actions for a in actions):
                        dangerous_write = True
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
                account_id=account_id, region=bucket_region,
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
        _, s3, account_id, region, buckets, bucket_regions = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_region = bucket_regions.get(bucket_name, region)
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
                account_id=account_id, region=bucket_region,
                analysis={
                    "replication_enabled": replication_enabled,
                    "replication_rules": replication_rules,
                    "total_rules": len(replication_rules)
                },
                errors=errors
            ))

        return _build_resultado("AWS", "S3", "REPLICATION_CONFIGURATION_REVIEW", account_id, region, resources)
    _run_job(ejecucion_id, _execute)


def s3_lifecycle_review_job(ejecucion_id, proyecto_id):
    def _execute():
        _, s3, account_id, region, buckets, bucket_regions = _s3_context(proyecto_id)
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            bucket_region = bucket_regions.get(bucket_name, region)
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
                            "transitions": [{"days": t.get("Days"), "storage_class": t.get("StorageClass")} for t in transitions],
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
                account_id=account_id, region=bucket_region,
                analysis={
                    "lifecycle_enabled": lifecycle_enabled,
                    "lifecycle_rules": lifecycle_rules,
                    "total_rules": len(lifecycle_rules),
                    "has_expiration_policy": any(r.get("expiration_days") or r.get("expiration_date") for r in lifecycle_rules),
                    "has_transition_policy": any(r.get("transitions") for r in lifecycle_rules)
                },
                errors=errors
            ))

        return _build_resultado("AWS", "S3", "LIFECYCLE_POLICY_REVIEW", account_id, region, resources)
    _run_job(ejecucion_id, _execute)
# ══════════════════════════════════════════════════════════════════
# EC2
# ══════════════════════════════════════════════════════════════════

def ec2_security_groups_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        COMMON_PORTS = CloudEjecucion.top_100_common_ports()
        all_resources = []

        for region in regiones:
            ec2 = _make_client("ec2", creds, region)
            try:
                all_sgs = []
                for page in ec2.get_paginator("describe_security_groups").paginate():
                    all_sgs.extend(page.get("SecurityGroups", []))

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
                        all_resources.append(_base_resource(
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
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="EC2",
                    resource_type="SecurityGroup",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado(
            "AWS", "EC2", "SECURITY_GROUP_EXPOSURE_ANALYSIS",
            account_id, region_base, all_resources
        )

    _run_job(ejecucion_id, _execute)


def ec2_public_instances_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ec2 = _make_client("ec2", creds, region)
            sg_cache = {}
            try:
                for page in ec2.get_paginator("describe_instances").paginate():
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
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

                            all_resources.append(_base_resource(
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
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="EC2",
                    resource_type="EC2Instance",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado(
            "AWS", "EC2", "PUBLIC_INSTANCE_ANALYSIS",
            account_id, region_base, all_resources
        )

    _run_job(ejecucion_id, _execute)


def ec2_iam_role_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        iam = _make_client("iam", creds, "us-east-1")  # IAM global
        role_cache = {}
        all_resources = []

        for region in regiones:
            ec2 = _make_client("ec2", creds, region)
            try:
                for page in ec2.get_paginator("describe_instances").paginate():
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            instance_id = instance.get("InstanceId")
                            iam_profile = instance.get("IamInstanceProfile")
                            if not iam_profile:
                                continue

                            profile_name = iam_profile["Arn"].split("/")[-1]
                            try:
                                profile = iam.get_instance_profile(InstanceProfileName=profile_name)
                            except Exception:
                                continue

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
                                    all_resources.append(_base_resource(
                                        provider="AWS", service="EC2",
                                        resource_type="EC2Instance", resource_id=instance_id,
                                        account_id=account_id, region=region,
                                        analysis={"iam_role": role_name, "issues": role_issues}
                                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="EC2",
                    resource_type="EC2Instance",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado(
            "AWS", "EC2", "EC2_IAM_ROLE_ANALYSIS",
            account_id, region_base, all_resources
        )

    _run_job(ejecucion_id, _execute)

# ══════════════════════════════════════════════════════════════════
# API GATEWAY — HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════
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
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            apigw, apigw2 = _apigw_context(creds, region)
            try:
                for api in _iter_rest_apis(apigw):
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
                            method = apigw.get_method(restApiId=api_id, resourceId=res["id"], httpMethod=method_name)
                            methods.append({
                                "path": path, "method": method_name,
                                "authorization_type": method.get("authorizationType"),
                                "api_key_required": method.get("apiKeyRequired"),
                                "authorizer_id": method.get("authorizerId")
                            })

                    all_resources.append(_base_resource(
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

                for api in _iter_http_apis(apigw2):
                    api_id, api_name = api["ApiId"], api["Name"]
                    cors = api.get("CorsConfiguration")
                    all_resources.append(_base_resource(
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
                            "routes": [
                                {
                                    "route_key": r.get("RouteKey"),
                                    "authorization_type": r.get("AuthorizationType"),
                                    "api_key_required": r.get("ApiKeyRequired"),
                                    "authorizer_id": r.get("AuthorizerId")
                                }
                                for r in _iter_http_routes(apigw2, api_id)
                            ],
                            "stages": [
                                {
                                    "stage_name": s.get("StageName"),
                                    "auto_deploy": s.get("AutoDeploy"),
                                    "access_log_settings": s.get("AccessLogSettings"),
                                    "web_acl_associated": bool(s.get("WebAclArn"))
                                }
                                for s in _iter_http_stages(apigw2, api_id)
                            ]
                        },
                        resource_name=api_name
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "APIGateway", "FULL_CONFIGURATION_ANALYSIS", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def apigateway_discovery_stages_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            apigw, apigw2 = _apigw_context(creds, region)
            try:
                for api in _iter_rest_apis(apigw):
                    api_id, api_name = api["id"], api["name"]
                    for stage in _iter_rest_stages(apigw, api_id):
                        all_resources.append(_base_resource(
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
                    api_id, api_name = api["ApiId"], api["Name"]
                    for stage in _iter_http_stages(apigw2, api_id):
                        all_resources.append(_base_resource(
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
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API_STAGE",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "APIGateway", "STAGE_CONFIGURATION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def apigateway_review_authorizers_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            apigw, apigw2 = _apigw_context(creds, region)
            try:
                for api in _iter_rest_apis(apigw):
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
                        for method_name in res["resourceMethods"]:
                            m = apigw.get_method(restApiId=api_id, resourceId=res["id"], httpMethod=method_name)
                            methods.append({
                                "path": res.get("path"), "method": method_name,
                                "authorization_type": m.get("authorizationType"),
                                "authorizer_id": m.get("authorizerId"),
                                "authorization_scopes": m.get("authorizationScopes")
                            })
                    all_resources.append(_base_resource(
                        provider="AWS", service="APIGateway",
                        resource_type="REST_API_AUTHORIZERS", resource_id=api_id,
                        account_id=account_id, region=region,
                        analysis={"authorizers_defined": authorizers, "methods_authorization": methods},
                        resource_name=api_name
                    ))

                for api in _iter_http_apis(apigw2):
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
                    all_resources.append(_base_resource(
                        provider="AWS", service="APIGateway",
                        resource_type="HTTP_API_AUTHORIZERS", resource_id=api_id,
                        account_id=account_id, region=region,
                        analysis={"authorizers_defined": authorizers, "routes_authorization": routes},
                        resource_name=api_name
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API_AUTHORIZERS",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "APIGateway", "AUTHORIZER_CONFIGURATION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def apigateway_security_exposure_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            apigw, apigw2 = _apigw_context(creds, region)
            try:
                for api in _iter_rest_apis(apigw):
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
                    all_resources.append(_base_resource(
                        provider="AWS", service="APIGateway",
                        resource_type="REST_API_SECURITY_EXPOSURE", resource_id=api_id,
                        account_id=account_id, region=region,
                        analysis={"methods": methods},
                        resource_name=api_name
                    ))

                for api in _iter_http_apis(apigw2):
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
                    all_resources.append(_base_resource(
                        provider="AWS", service="APIGateway",
                        resource_type="HTTP_API_SECURITY_EXPOSURE", resource_id=api_id,
                        account_id=account_id, region=region,
                        analysis={"routes": routes},
                        resource_name=api_name
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API_SECURITY_EXPOSURE",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "APIGateway", "SECURITY_EXPOSURE_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def apigateway_logging_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            apigw, apigw2 = _apigw_context(creds, region)
            try:
                for api in _iter_rest_apis(apigw):
                    api_id, api_name = api["id"], api["name"]
                    for stage in _iter_rest_stages(apigw, api_id):
                        all_resources.append(_base_resource(
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
                    api_id, api_name = api["ApiId"], api["Name"]
                    for stage in _iter_http_stages(apigw2, api_id):
                        all_resources.append(_base_resource(
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
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="APIGateway",
                    resource_type="REST_API_LOGGING_CONFIG",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "APIGateway", "LOGGING_CONFIGURATION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)

# ══════════════════════════════════════════════════════════════════
# LAMBDA — HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════
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
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
                    vpc = fn.get("VpcConfig", {}) or {}
                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaFunction",
                        resource_id=fn.get("FunctionName"),
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
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaFunction",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "FUNCTION_CONFIGURATION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def discovery_permissions_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
                    function_name = fn.get("FunctionName")
                    policy_json = _get_lambda_policy(lc, function_name)
                    is_public = False
                    statements_count = 0

                    if policy_json:
                        statements_count = len(policy_json.get("Statement", []))
                        is_public = any(_is_principal_public(s.get("Principal")) for s in policy_json.get("Statement", []))

                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaPermissionPolicy",
                        resource_id=function_name,
                        account_id=account_id, region=region,
                        analysis={
                            "has_policy": policy_json is not None,
                            "is_public": is_public,
                            "statements_count": statements_count,
                            "policy_document": policy_json,
                            "error": None
                        }
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaPermissionPolicy",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "LAMBDA_PERMISSION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def discovery_triggers_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
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

                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaTriggerConfiguration",
                        resource_id=function_name,
                        account_id=account_id, region=region,
                        analysis={
                            "event_source_mappings": event_mappings,
                            "policy_triggers": policy_triggers,
                            "error": error
                        }
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaTriggerConfiguration",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "LAMBDA_TRIGGER_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def public_exposure_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []
        total_exposed = 0

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
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

                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaPublicExposure",
                        resource_id=function_name,
                        account_id=account_id, region=region,
                        analysis={
                            "is_public": is_public,
                            "policy_statements": policy_statements
                        }
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaPublicExposure",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado(
            "AWS", "Lambda", "LAMBDA_PUBLIC_EXPOSURE_ANALYSIS",
            account_id, region_base, all_resources,
            total_exposed_functions=total_exposed
        )

    _run_job(ejecucion_id, _execute)


def overprivileged_role_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            lc, iam = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
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

                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaExecutionRole",
                        resource_id=role_name,
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
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaExecutionRole",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "LAMBDA_ROLE_CONFIGURATION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def wildcard_permissions_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            lc, iam = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
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

                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaWildcardPermissionDiscovery",
                        resource_id=role_name,
                        account_id=account_id, region=region,
                        analysis={
                            "function_name": function_name,
                            "role_arn": role_arn,
                            "attached_policies": attached,
                            "inline_policies": inline,
                            "error": error
                        }
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaWildcardPermissionDiscovery",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "LAMBDA_WILDCARD_PERMISSION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def no_vpc_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
                    function_name = fn.get("FunctionName")
                    vpc = fn.get("VpcConfig", {}) or {}
                    vpc_id = vpc.get("VpcId")
                    subnets = vpc.get("SubnetIds", []) or []
                    sgs = vpc.get("SecurityGroupIds", []) or []

                    all_resources.append(_base_resource(
                        provider="AWS", service="Lambda",
                        resource_type="LambdaVpcConfiguration",
                        resource_id=function_name,
                        account_id=account_id, region=region,
                        analysis={
                            "vpc_id": vpc_id,
                            "subnet_ids": subnets,
                            "security_group_ids": sgs,
                            "vpc_configured": bool(vpc_id and subnets and sgs)
                        }
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaVpcConfiguration",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "LAMBDA_VPC_CONFIGURATION_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def lambda_runtime_review_job(ejecucion_id, proyecto_id):
    old_runtime_review_job(ejecucion_id, proyecto_id)


def old_runtime_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        deprecated_runtimes = CloudEjecucion.versiones_deprecadas(
            tipo_proyecto_id=proyecto_id,
            proveedor="AWS", servicio="Lambda", categoria="Runtime"
        )
        all_resources = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
                    function_name = fn.get("FunctionName")
                    runtime = fn.get("Runtime")
                    if runtime in deprecated_runtimes:
                        all_resources.append(_base_resource(
                            provider="AWS", service="Lambda",
                            resource_type="LambdaRuntime",
                            resource_id=function_name,
                            account_id=account_id, region=region,
                            analysis={
                                "runtime": runtime,
                                "deprecated": True,
                                "recommendation": "Actualizar a una versión soportada oficialmente por AWS"
                            }
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Lambda",
                    resource_type="LambdaRuntime",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Lambda", "LAMBDA_RUNTIME_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def env_secrets_review_job(ejecucion_id, proyecto_id):
    SUSPICIOUS_KEYWORDS = [
        "password", "secret", "token", "apikey", "api_key",
        "access_key", "private_key", "jwt", "db_", "database"
    ]

    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        findings = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            try:
                for fn in _iter_functions(lc):
                    function_name = fn.get("FunctionName")
                    variables = fn.get("Environment", {}).get("Variables", {})
                    for key, value in variables.items():
                        key_lower = key.lower()
                        if any(kw in key_lower for kw in SUSPICIOUS_KEYWORDS):
                            findings.append({
                                "FunctionName": function_name,
                                "Region": region,
                                "Issue": "Potential secret stored in environment variable",
                                "VariableName": key,
                                "VariableValue": value,
                                "Recommendation": "Mover secretos a AWS Secrets Manager o Parameter Store"
                            })
                        if isinstance(value, str) and len(value) > 30:
                            if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
                                findings.append({
                                    "FunctionName": function_name,
                                    "Region": region,
                                    "Issue": "Suspicious high-entropy environment variable value",
                                    "VariableName": key,
                                    "Recommendation": "Revisar si el valor es un secreto en texto plano"
                                })
            except Exception:
                pass

        return findings

    _run_job(ejecucion_id, _execute)


def logging_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        findings = []

        for region in regiones:
            lc, _ = _lambda_context(creds, region)
            logs_client = _make_client("logs", creds, region)
            try:
                for fn in _iter_functions(lc):
                    function_name = fn.get("FunctionName")
                    log_group_name = f"/aws/lambda/{function_name}"
                    try:
                        response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                        log_groups = response.get("logGroups", [])
                        if not log_groups:
                            findings.append({
                                "FunctionName": function_name,
                                "Region": region,
                                "Issue": "CloudWatch Log Group not found",
                                "Recommendation": "Verificar que la Lambda tenga permisos para escribir logs"
                            })
                            continue
                        retention = log_groups[0].get("retentionInDays")
                        if not retention:
                            findings.append({
                                "FunctionName": function_name,
                                "Region": region,
                                "Issue": "Log retention not configured (Never expire)",
                                "Recommendation": "Configurar retención para evitar almacenamiento indefinido"
                            })
                    except Exception as e:
                        findings.append({
                            "FunctionName": function_name,
                            "Region": region,
                            "Issue": "Error reviewing logging",
                            "Error": str(e)
                        })
            except Exception:
                pass

        return findings

    _run_job(ejecucion_id, _execute)
    
# ══════════════════════════════════════════════════════════════════
# AMAZON INSPECTOR
# ══════════════════════════════════════════════════════════════════

def inspector_status_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            inspector = _inspector_context(creds, region)
            try:
                status = inspector.batch_get_account_status(accountIds=[account_id])
                account_status = status.get("accounts", [{}])[0]
                state = account_status.get("state", {})
                resource_state = account_status.get("resourceState", {})
                all_resources.append(_base_resource(
                    provider="AWS", service="Inspector",
                    resource_type="InspectorStatus",
                    resource_id=f"inspector-status-{region}",
                    account_id=account_id, region=region,
                    analysis={
                        "inspector_enabled": state.get("status") == "ENABLED",
                        "status": state.get("status"),
                        "ec2_scanning": resource_state.get("ec2", {}).get("status"),
                        "lambda_scanning": resource_state.get("lambda", {}).get("status"),
                        "ecr_scanning": resource_state.get("ecr", {}).get("status"),
                    },
                    errors=[]
                ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Inspector",
                    resource_type="InspectorStatus",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Inspector", "INSPECTOR_STATUS_CHECK", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def _inspector_findings_job(ejecucion_id, proyecto_id, filter_criteria, inventory_type, resource_type, analysis_fn):
    """Helper interno para todos los jobs de findings de Inspector."""
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            inspector = _inspector_context(creds, region)
            try:
                paginator = inspector.get_paginator("list_findings")
                for page in paginator.paginate(filterCriteria=filter_criteria):
                    for finding in page.get("findings", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="Inspector",
                            resource_type=resource_type,
                            resource_id=finding.get("resources", [{}])[0].get("id", "unknown"),
                            account_id=account_id, region=region,
                            analysis=analysis_fn(finding),
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Inspector",
                    resource_type=resource_type,
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Inspector", inventory_type, account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def _finding_base_analysis(finding):
    return {
        "finding_arn": finding.get("findingArn"),
        "title": finding.get("title"),
        "description": finding.get("description"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
        "type": finding.get("type"),
        "first_observed": str(finding.get("firstObservedAt")),
        "last_observed": str(finding.get("lastObservedAt")),
        "remediation": finding.get("remediation", {}).get("recommendation", {}).get("text"),
        "cvss_score": finding.get("inspectorScore"),
        "vulnerability_id": finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId"),
        "vulnerable_packages": [
            {
                "name": p.get("name"),
                "version": p.get("version"),
                "fixed_in_version": p.get("fixedInVersion")
            }
            for p in finding.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [])
        ]
    }


def inspector_ec2_findings_job(ejecucion_id, proyecto_id):
    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"resourceType": [{"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"}]},
        inventory_type="INSPECTOR_EC2_CVE_FINDINGS",
        resource_type="EC2Finding",
        analysis_fn=_finding_base_analysis
    )


def inspector_lambda_findings_job(ejecucion_id, proyecto_id):
    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"resourceType": [{"comparison": "EQUALS", "value": "AWS_LAMBDA_FUNCTION"}]},
        inventory_type="INSPECTOR_LAMBDA_CVE_FINDINGS",
        resource_type="LambdaFinding",
        analysis_fn=_finding_base_analysis
    )


def inspector_ecr_findings_job(ejecucion_id, proyecto_id):
    def _ecr_analysis(finding):
        base = _finding_base_analysis(finding)
        base["image_tags"] = finding.get("resources", [{}])[0].get("details", {}).get("awsEcrContainerImage", {}).get("imageTags", [])
        return base

    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}]},
        inventory_type="INSPECTOR_ECR_CVE_FINDINGS",
        resource_type="ECRFinding",
        analysis_fn=_ecr_analysis
    )


def inspector_critical_findings_job(ejecucion_id, proyecto_id):
    def _critical_analysis(finding):
        return {
            "finding_arn": finding.get("findingArn"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "resource_type": finding.get("resources", [{}])[0].get("type"),
            "status": finding.get("status"),
            "cvss_score": finding.get("inspectorScore"),
            "vulnerability_id": finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId"),
            "remediation": finding.get("remediation", {}).get("recommendation", {}).get("text"),
        }

    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"severity": [{"comparison": "EQUALS", "value": "CRITICAL"}]},
        inventory_type="INSPECTOR_CRITICAL_FINDINGS",
        resource_type="CriticalFinding",
        analysis_fn=_critical_analysis
    )


def inspector_high_findings_job(ejecucion_id, proyecto_id):
    def _high_analysis(finding):
        return {
            "finding_arn": finding.get("findingArn"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "resource_type": finding.get("resources", [{}])[0].get("type"),
            "status": finding.get("status"),
            "cvss_score": finding.get("inspectorScore"),
            "vulnerability_id": finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId"),
            "remediation": finding.get("remediation", {}).get("recommendation", {}).get("text"),
        }

    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"severity": [{"comparison": "EQUALS", "value": "HIGH"}]},
        inventory_type="INSPECTOR_HIGH_FINDINGS",
        resource_type="HighFinding",
        analysis_fn=_high_analysis
    )


def inspector_coverage_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            inspector = _inspector_context(creds, region)
            try:
                for page in inspector.get_paginator("list_coverage").paginate():
                    for item in page.get("coveredResources", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="Inspector",
                            resource_type="InspectorCoverage",
                            resource_id=item.get("resourceId", "unknown"),
                            account_id=account_id, region=region,
                            analysis={
                                "resource_type": item.get("resourceType"),
                                "scan_type": item.get("scanType"),
                                "scan_status": item.get("scanStatus", {}).get("statusCode"),
                                "scan_status_reason": item.get("scanStatus", {}).get("reason"),
                                "last_scanned_at": str(item.get("lastScannedAt"))
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="Inspector",
                    resource_type="InspectorCoverage",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "Inspector", "INSPECTOR_COVERAGE_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def inspector_suppressed_findings_job(ejecucion_id, proyecto_id):
    def _suppressed_analysis(finding):
        return {
            "finding_arn": finding.get("findingArn"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "resource_type": finding.get("resources", [{}])[0].get("type"),
            "status": finding.get("status"),
            "suppression_reason": finding.get("suppressionReason"),
            "vulnerability_id": finding.get("packageVulnerabilityDetails", {}).get("vulnerabilityId"),
        }

    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"findingStatus": [{"comparison": "EQUALS", "value": "SUPPRESSED"}]},
        inventory_type="INSPECTOR_SUPPRESSED_FINDINGS",
        resource_type="SuppressedFinding",
        analysis_fn=_suppressed_analysis
    )


def inspector_sbom_job(ejecucion_id, proyecto_id):
    def _sbom_analysis(finding):
        pkg_details = finding.get("packageVulnerabilityDetails", {})
        return {
            "vulnerability_id": pkg_details.get("vulnerabilityId"),
            "source": pkg_details.get("source"),
            "severity": finding.get("severity"),
            "cvss_score": finding.get("inspectorScore"),
            "vulnerable_packages": [
                {
                    "name": p.get("name"),
                    "version": p.get("version"),
                    "fixed_in_version": p.get("fixedInVersion"),
                    "package_manager": p.get("packageManager"),
                    "file_path": p.get("filePath")
                }
                for p in pkg_details.get("vulnerablePackages", [])
            ],
            "resource_type": finding.get("resources", [{}])[0].get("type"),
        }

    _inspector_findings_job(
        ejecucion_id, proyecto_id,
        filter_criteria={"findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]},
        inventory_type="INSPECTOR_SBOM_EXPORT",
        resource_type="SBOMEntry",
        analysis_fn=_sbom_analysis
    )


def inspector_summary_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        summary = {
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
            "by_resource_type": {},
            "total_findings": 0
        }
        errors = []

        for region in regiones:
            inspector = _inspector_context(creds, region)
            try:
                for page in inspector.get_paginator("list_findings").paginate():
                    for finding in page.get("findings", []):
                        severity = finding.get("severity", "UNKNOWN")
                        resource_type = finding.get("resources", [{}])[0].get("type", "UNKNOWN")
                        summary["total_findings"] += 1
                        if severity in summary["by_severity"]:
                            summary["by_severity"][severity] += 1
                        summary["by_resource_type"][resource_type] = summary["by_resource_type"].get(resource_type, 0) + 1
            except Exception as e:
                errors.append(f"region_scan_error ({region}): {e}")

        return _build_resultado(
            "AWS", "Inspector", "INSPECTOR_FINDINGS_SUMMARY",
            account_id, region_base,
            [_base_resource(
                provider="AWS", service="Inspector",
                resource_type="InspectorSummary",
                resource_id=f"inspector-summary-{account_id}",
                account_id=account_id, region=region_base,
                analysis=summary, errors=errors
            )]
        )

    _run_job(ejecucion_id, _execute)

# ══════════════════════════════════════════════════════════════════
# FIN AMAZON INSPECTOR
# ══════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════
# VPC
# ══════════════════════════════════════════════════════════════════

def vpc_discovery_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ec2 = _vpc_context(creds, region)
            try:
                for page in ec2.get_paginator("describe_vpcs").paginate():
                    for vpc in page.get("Vpcs", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="VPC",
                            resource_type="VPC",
                            resource_id=vpc.get("VpcId"),
                            account_id=account_id, region=region,
                            analysis={
                                "cidr_block": vpc.get("CidrBlock"),
                                "state": vpc.get("State"),
                                "default_vpc_active": vpc.get("IsDefault", False),
                                "instance_tenancy": vpc.get("InstanceTenancy"),
                                "tags": vpc.get("Tags", [])
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="VPC",
                    resource_type="VPC",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "VPC", "VPC_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def vpc_subnets_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ec2 = _vpc_context(creds, region)
            try:
                for page in ec2.get_paginator("describe_subnets").paginate():
                    for subnet in page.get("Subnets", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="VPC",
                            resource_type="Subnet",
                            resource_id=subnet.get("SubnetId"),
                            account_id=account_id, region=region,
                            analysis={
                                "vpc_id": subnet.get("VpcId"),
                                "cidr_block": subnet.get("CidrBlock"),
                                "availability_zone": subnet.get("AvailabilityZone"),
                                "subnet_auto_assign_public_ip": subnet.get("MapPublicIpOnLaunch", False),
                                "available_ip_count": subnet.get("AvailableIpAddressCount"),
                                "state": subnet.get("State")
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="VPC",
                    resource_type="Subnet",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "VPC", "VPC_SUBNETS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def vpc_security_groups_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        sensitive_ports = CloudEjecucion.get_sensitive_ingress_ports()
        all_resources = []

        for region in regiones:
            ec2 = _vpc_context(creds, region)
            try:
                for page in ec2.get_paginator("describe_security_groups").paginate():
                    for sg in page.get("SecurityGroups", []):
                        open_ingress_sensitive = False
                        unrestricted_egress = False
                        matched_ports = []

                        for perm in sg.get("IpPermissions", []):
                            if _has_open_cidr(perm.get("IpRanges"), perm.get("Ipv6Ranges")) and _covers_sensitive_port(perm, sensitive_ports):
                                open_ingress_sensitive = True
                                matched_ports.append({
                                    "protocol": perm.get("IpProtocol"),
                                    "from_port": perm.get("FromPort"),
                                    "to_port": perm.get("ToPort")
                                })

                        for perm in sg.get("IpPermissionsEgress", []):
                            if perm.get("IpProtocol") == "-1" and _has_open_cidr(perm.get("IpRanges"), perm.get("Ipv6Ranges")):
                                unrestricted_egress = True

                        all_resources.append(_base_resource(
                            provider="AWS", service="VPC",
                            resource_type="SecurityGroup",
                            resource_id=sg.get("GroupId"),
                            account_id=account_id, region=region,
                            analysis={
                                "group_name": sg.get("GroupName"),
                                "vpc_id": sg.get("VpcId"),
                                "description": sg.get("Description"),
                                "open_ingress_sensitive_ports": open_ingress_sensitive,
                                "matched_sensitive_rules": matched_ports,
                                "unrestricted_egress_all_ports": unrestricted_egress
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="VPC",
                    resource_type="SecurityGroup",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "VPC", "VPC_SECURITY_GROUPS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def vpc_network_acls_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ec2 = _vpc_context(creds, region)
            try:
                for page in ec2.get_paginator("describe_network_acls").paginate():
                    for nacl in page.get("NetworkAcls", []):
                        allow_all = False
                        matched_entries = []

                        for entry in nacl.get("Entries", []):
                            if entry.get("RuleNumber") == 32767:
                                continue
                            is_open_cidr = entry.get("CidrBlock") == "0.0.0.0/0" or entry.get("Ipv6CidrBlock") == "::/0"
                            if (
                                entry.get("RuleAction") == "allow"
                                and entry.get("Protocol") == "-1"
                                and is_open_cidr
                            ):
                                allow_all = True
                                matched_entries.append({
                                    "rule_number": entry.get("RuleNumber"),
                                    "egress": entry.get("Egress")
                                })

                        all_resources.append(_base_resource(
                            provider="AWS", service="VPC",
                            resource_type="NetworkAcl",
                            resource_id=nacl.get("NetworkAclId"),
                            account_id=account_id, region=region,
                            analysis={
                                "vpc_id": nacl.get("VpcId"),
                                "is_default": nacl.get("IsDefault", False),
                                "nacl_allow_all": allow_all,
                                "matched_entries": matched_entries
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="VPC",
                    resource_type="NetworkAcl",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "VPC", "VPC_NETWORK_ACLS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def vpc_route_tables_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ec2 = _vpc_context(creds, region)
            try:
                for page in ec2.get_paginator("describe_route_tables").paginate():
                    for rt in page.get("RouteTables", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="VPC",
                            resource_type="RouteTable",
                            resource_id=rt.get("RouteTableId"),
                            account_id=account_id, region=region,
                            analysis={
                                "vpc_id": rt.get("VpcId"),
                                "routes": [
                                    {
                                        "destination_cidr": r.get("DestinationCidrBlock"),
                                        "destination_ipv6_cidr": r.get("DestinationIpv6CidrBlock"),
                                        "gateway_id": r.get("GatewayId"),
                                        "nat_gateway_id": r.get("NatGatewayId"),
                                        "vpc_peering_connection_id": r.get("VpcPeeringConnectionId"),
                                        "state": r.get("State")
                                    }
                                    for r in rt.get("Routes", [])
                                ],
                                "associations": [
                                    a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")
                                ]
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="VPC",
                    resource_type="RouteTable",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "VPC", "VPC_ROUTE_TABLES_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def vpc_peering_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ec2 = _vpc_context(creds, region)
            try:
                peerings = {}
                for page in ec2.get_paginator("describe_vpc_peering_connections").paginate():
                    for pc in page.get("VpcPeeringConnections", []):
                        peerings[pc.get("VpcPeeringConnectionId")] = pc

                for page in ec2.get_paginator("describe_route_tables").paginate():
                    for rt in page.get("RouteTables", []):
                        for route in rt.get("Routes", []):
                            pcx_id = route.get("VpcPeeringConnectionId")
                            if not pcx_id or pcx_id not in peerings:
                                continue

                            pc = peerings[pcx_id]
                            accepter_cidr = pc.get("AccepterVpcInfo", {}).get("CidrBlock")
                            requester_cidr = pc.get("RequesterVpcInfo", {}).get("CidrBlock")
                            dest_cidr = route.get("DestinationCidrBlock")

                            all_resources.append(_base_resource(
                                provider="AWS", service="VPC",
                                resource_type="VpcPeeringRoute",
                                resource_id=f"{rt.get('RouteTableId')}-{pcx_id}",
                                account_id=account_id, region=region,
                                analysis={
                                    "route_table_id": rt.get("RouteTableId"),
                                    "peering_connection_id": pcx_id,
                                    "destination_cidr": dest_cidr,
                                    "accepter_cidr": accepter_cidr,
                                    "requester_cidr": requester_cidr,
                                    "peering_status": pc.get("Status", {}).get("Code"),
                                    "peering_unrestricted_cidr": dest_cidr in (accepter_cidr, requester_cidr)
                                },
                                errors=[]
                            ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="VPC",
                    resource_type="VpcPeeringRoute",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "VPC", "VPC_PEERING_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)
# ══════════════════════════════════════════════════════════════════
# FIN VPC
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# AMAZON RDS
# ══════════════════════════════════════════════════════════════════

def rds_instances_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for db in page.get("DBInstances", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBInstance",
                            resource_id=db.get("DBInstanceIdentifier"),
                            account_id=account_id, region=region,
                            analysis={
                                "engine": db.get("Engine"),
                                "engine_version": db.get("EngineVersion"),
                                "instance_class": db.get("DBInstanceClass"),
                                "status": db.get("DBInstanceStatus"),
                                "multi_az": db.get("MultiAZ", False),
                                "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId"),
                                "availability_zone": db.get("AvailabilityZone"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBInstance",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_INSTANCES_DISCOVERY", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def rds_public_access_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for db in page.get("DBInstances", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBInstancePublicAccess",
                            resource_id=db.get("DBInstanceIdentifier"),
                            account_id=account_id, region=region,
                            analysis={
                                "publicly_accessible": db.get("PubliclyAccessible", False),
                                "endpoint": db.get("Endpoint", {}).get("Address"),
                                "port": db.get("Endpoint", {}).get("Port"),
                                "vpc_id": db.get("DBSubnetGroup", {}).get("VpcId"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBInstancePublicAccess",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_PUBLIC_ACCESS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def rds_encryption_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for db in page.get("DBInstances", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBInstanceEncryption",
                            resource_id=db.get("DBInstanceIdentifier"),
                            account_id=account_id, region=region,
                            analysis={
                                "unencrypted_storage": not db.get("StorageEncrypted", False),
                                "kms_key_id": db.get("KmsKeyId"),
                                "storage_type": db.get("StorageType"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBInstanceEncryption",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_ENCRYPTION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def rds_snapshots_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_snapshots").paginate(SnapshotType="manual"):
                    for snap in page.get("DBSnapshots", []):
                        snapshot_id = snap.get("DBSnapshotIdentifier")
                        is_public = False
                        try:
                            attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_id)
                            for attr in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                                if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                                    is_public = True
                        except Exception:
                            pass

                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBSnapshot",
                            resource_id=snapshot_id,
                            account_id=account_id, region=region,
                            analysis={
                                "snapshot_public": is_public,
                                "db_instance_identifier": snap.get("DBInstanceIdentifier"),
                                "encrypted": snap.get("Encrypted", False),
                                "status": snap.get("Status"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBSnapshot",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_SNAPSHOTS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def rds_backups_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for db in page.get("DBInstances", []):
                        retention = db.get("BackupRetentionPeriod", 0)
                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBInstanceBackup",
                            resource_id=db.get("DBInstanceIdentifier"),
                            account_id=account_id, region=region,
                            analysis={
                                "automated_backups_disabled": retention == 0,
                                "backup_retention_period": retention,
                                "preferred_backup_window": db.get("PreferredBackupWindow"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBInstanceBackup",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_BACKUPS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def rds_iam_auth_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for db in page.get("DBInstances", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBInstanceIamAuth",
                            resource_id=db.get("DBInstanceIdentifier"),
                            account_id=account_id, region=region,
                            analysis={
                                "iam_auth_disabled": not db.get("IAMDatabaseAuthenticationEnabled", False),
                                "engine": db.get("Engine"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBInstanceIamAuth",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_IAM_AUTH_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def rds_maintenance_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            rds = _rds_context(creds, region)
            try:
                for page in rds.get_paginator("describe_db_instances").paginate():
                    for db in page.get("DBInstances", []):
                        all_resources.append(_base_resource(
                            provider="AWS", service="RDS",
                            resource_type="DBInstanceMaintenance",
                            resource_id=db.get("DBInstanceIdentifier"),
                            account_id=account_id, region=region,
                            analysis={
                                "minor_version_upgrade_disabled": not db.get("AutoMinorVersionUpgrade", False),
                                "deletion_protection_disabled": not db.get("DeletionProtection", False),
                                "engine_version": db.get("EngineVersion"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="RDS",
                    resource_type="DBInstanceMaintenance",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "RDS", "RDS_MAINTENANCE_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)
# ══════════════════════════════════════════════════════════════════
# FIN AMAZON RDS
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# AWS CLOUDTRAIL
# ══════════════════════════════════════════════════════════════════

def cloudtrail_enabled_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ct = _cloudtrail_context(creds, region)
            try:
                trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
                if not trails:
                    all_resources.append(_base_resource(
                        provider="AWS", service="CloudTrail",
                        resource_type="Trail",
                        resource_id=f"no-trail-{region}",
                        account_id=account_id, region=region,
                        analysis={"cloudtrail_enabled": False},
                        errors=[]
                    ))
                else:
                    for trail in trails:
                        status = ct.get_trail_status(Name=trail["TrailARN"])
                        all_resources.append(_base_resource(
                            provider="AWS", service="CloudTrail",
                            resource_type="Trail",
                            resource_id=trail.get("TrailARN"),
                            account_id=account_id, region=region,
                            analysis={
                                "cloudtrail_enabled": status.get("IsLogging", False),
                                "is_multi_region": trail.get("IsMultiRegionTrail", False),
                                "trail_name": trail.get("Name"),
                            },
                            errors=[]
                        ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="CloudTrail",
                    resource_type="Trail",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "CloudTrail", "CLOUDTRAIL_ENABLED_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def cloudtrail_log_validation_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ct = _cloudtrail_context(creds, region)
            try:
                for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
                    all_resources.append(_base_resource(
                        provider="AWS", service="CloudTrail",
                        resource_type="Trail",
                        resource_id=trail.get("TrailARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "log_file_validation_disabled": not trail.get("LogFileValidationEnabled", False),
                            "trail_name": trail.get("Name"),
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="CloudTrail",
                    resource_type="Trail",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "CloudTrail", "CLOUDTRAIL_LOG_VALIDATION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def cloudtrail_s3_bucket_public_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        s3 = _make_client("s3", creds, region_base)
        all_resources = []

        for region in regiones:
            ct = _cloudtrail_context(creds, region)
            try:
                for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
                    bucket = trail.get("S3BucketName")
                    if not bucket:
                        continue

                    is_public = False
                    errors = []
                    try:
                        pab = s3.get_public_access_block(Bucket=bucket)
                        cfg = pab.get("PublicAccessBlockConfiguration", {})
                        is_public = not all([
                            cfg.get("BlockPublicAcls", False),
                            cfg.get("IgnorePublicAcls", False),
                            cfg.get("BlockPublicPolicy", False),
                            cfg.get("RestrictPublicBuckets", False),
                        ])
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                            is_public = True
                        else:
                            errors.append(f"s3_public_access_block_error ({bucket}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="CloudTrail",
                        resource_type="Trail",
                        resource_id=trail.get("TrailARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "s3_bucket_public": is_public,
                            "s3_bucket_name": bucket,
                            "trail_name": trail.get("Name"),
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="CloudTrail",
                    resource_type="Trail",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "CloudTrail", "CLOUDTRAIL_S3_BUCKET_PUBLIC_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def cloudtrail_s3_access_logging_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        s3 = _make_client("s3", creds, region_base)
        all_resources = []

        for region in regiones:
            ct = _cloudtrail_context(creds, region)
            try:
                for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
                    bucket = trail.get("S3BucketName")
                    if not bucket:
                        continue

                    logging_enabled = False
                    errors = []
                    try:
                        log_cfg = s3.get_bucket_logging(Bucket=bucket)
                        logging_enabled = "LoggingEnabled" in log_cfg
                    except Exception as e:
                        errors.append(f"s3_logging_error ({bucket}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="CloudTrail",
                        resource_type="Trail",
                        resource_id=trail.get("TrailARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "s3_access_logging_disabled": not logging_enabled,
                            "s3_bucket_name": bucket,
                            "trail_name": trail.get("Name"),
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="CloudTrail",
                    resource_type="Trail",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "CloudTrail", "CLOUDTRAIL_S3_ACCESS_LOGGING_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def cloudtrail_cloudwatch_integration_job(ejecucion_id, proyecto_id):
    def _execute():
        from datetime import timedelta
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ct = _cloudtrail_context(creds, region)
            try:
                for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
                    log_group = trail.get("CloudWatchLogsLogGroupArn")
                    integrated = bool(log_group)
                    delivery_recent = False

                    if integrated:
                        try:
                            status = ct.get_trail_status(Name=trail["TrailARN"])
                            last_delivery = status.get("LatestCloudWatchLogsDeliveryTime")
                            if last_delivery:
                                now = datetime.now(timezone.utc)
                                last = last_delivery if last_delivery.tzinfo else last_delivery.replace(tzinfo=timezone.utc)
                                delivery_recent = (now - last) < timedelta(hours=24)
                        except Exception:
                            pass

                    all_resources.append(_base_resource(
                        provider="AWS", service="CloudTrail",
                        resource_type="Trail",
                        resource_id=trail.get("TrailARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "cloudwatch_integration_disabled": not integrated,
                            "log_group_arn": log_group,
                            "delivery_recent": delivery_recent,
                            "trail_name": trail.get("Name"),
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="CloudTrail",
                    resource_type="Trail",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "CloudTrail", "CLOUDTRAIL_CLOUDWATCH_INTEGRATION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def cloudtrail_kms_encryption_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            ct = _cloudtrail_context(creds, region)
            try:
                for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
                    kms_key = trail.get("KMSKeyId")
                    all_resources.append(_base_resource(
                        provider="AWS", service="CloudTrail",
                        resource_type="Trail",
                        resource_id=trail.get("TrailARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "kms_encryption_disabled": not bool(kms_key),
                            "kms_key_id": kms_key,
                            "trail_name": trail.get("Name"),
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="CloudTrail",
                    resource_type="Trail",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "CloudTrail", "CLOUDTRAIL_KMS_ENCRYPTION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)
# ══════════════════════════════════════════════════════════════════
# FIN AWS CLOUDTRAIL
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# AWS KMS
# ══════════════════════════════════════════════════════════════════

def kms_key_rotation_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for meta in _iter_customer_keys(kms):
                    key_id = meta["KeyId"]
                    rotation_enabled = False
                    errors = []
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        rotation_enabled = rotation.get("KeyRotationEnabled", False)
                    except Exception as e:
                        errors.append(f"rotation_check_error ({key_id}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="KMS",
                        resource_type="KMSKey",
                        resource_id=key_id,
                        account_id=account_id, region=region,
                        analysis={
                            "key_alias": meta.get("Description"),
                            "key_state": meta.get("KeyState"),
                            "key_rotation_disabled": not rotation_enabled,
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_ROTATION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def kms_key_exposed_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for meta in _iter_customer_keys(kms):
                    key_id = meta["KeyId"]
                    is_public = False
                    is_cross_account = False
                    errors = []

                    try:
                        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "{}")
                        policy_doc = json.loads(policy_str)
                        for stmt in policy_doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            principal = stmt.get("Principal")
                            if principal == "*":
                                is_public = True
                            elif isinstance(principal, dict):
                                aws_p = principal.get("AWS", [])
                                if aws_p == "*":
                                    is_public = True
                                principals = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
                                for p in principals:
                                    if f":{account_id}:" not in str(p) and p != "*":
                                        is_cross_account = True
                    except Exception as e:
                        errors.append(f"policy_check_error ({key_id}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="KMS",
                        resource_type="KMSKey",
                        resource_id=key_id,
                        account_id=account_id, region=region,
                        analysis={
                            "key_state": meta.get("KeyState"),
                            "key_exposed_public": is_public,
                            "key_cross_account_access": is_cross_account,
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_EXPOSED_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def kms_key_unused_job(ejecucion_id, proyecto_id):
    def _execute():
        from datetime import timedelta
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        threshold = datetime.now(timezone.utc) - timedelta(days=90)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for meta in _iter_customer_keys(kms):
                    key_id = meta["KeyId"]
                    unused = False
                    errors = []

                    try:
                        creation = meta.get("CreationDate")
                        if creation:
                            creation = creation if creation.tzinfo else creation.replace(tzinfo=timezone.utc)
                            unused = creation < threshold
                    except Exception as e:
                        errors.append(f"unused_check_error ({key_id}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="KMS",
                        resource_type="KMSKey",
                        resource_id=key_id,
                        account_id=account_id, region=region,
                        analysis={
                            "key_state": meta.get("KeyState"),
                            "key_unused_90_days": unused,
                            "creation_date": str(meta.get("CreationDate")),
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_UNUSED_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def kms_key_pending_deletion_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for page in kms.get_paginator("list_keys").paginate():
                    for key in page.get("Keys", []):
                        try:
                            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                            if meta.get("KeyManager") != "CUSTOMER":
                                continue
                            if meta.get("KeyState") == "PendingDeletion":
                                all_resources.append(_base_resource(
                                    provider="AWS", service="KMS",
                                    resource_type="KMSKey",
                                    resource_id=meta["KeyId"],
                                    account_id=account_id, region=region,
                                    analysis={
                                        "key_pending_deletion": True,
                                        "deletion_date": str(meta.get("DeletionDate")),
                                        "key_state": meta.get("KeyState"),
                                    },
                                    errors=[]
                                ))
                        except Exception as e:
                            all_resources.append(_base_resource(
                                provider="AWS", service="KMS",
                                resource_type="KMSKey",
                                resource_id=key["KeyId"],
                                account_id=account_id, region=region,
                                analysis={}, errors=[f"describe_key_error: {e}"]
                            ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_PENDING_DELETION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def kms_key_disabled_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for page in kms.get_paginator("list_keys").paginate():
                    for key in page.get("Keys", []):
                        try:
                            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                            if meta.get("KeyManager") != "CUSTOMER":
                                continue
                            if meta.get("KeyState") == "Disabled":
                                all_resources.append(_base_resource(
                                    provider="AWS", service="KMS",
                                    resource_type="KMSKey",
                                    resource_id=meta["KeyId"],
                                    account_id=account_id, region=region,
                                    analysis={
                                        "key_disabled": True,
                                        "key_state": meta.get("KeyState"),
                                        "creation_date": str(meta.get("CreationDate")),
                                    },
                                    errors=[]
                                ))
                        except Exception as e:
                            all_resources.append(_base_resource(
                                provider="AWS", service="KMS",
                                resource_type="KMSKey",
                                resource_id=key["KeyId"],
                                account_id=account_id, region=region,
                                analysis={}, errors=[f"describe_key_error: {e}"]
                            ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_DISABLED_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def kms_key_no_policy_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for meta in _iter_customer_keys(kms):
                    key_id = meta["KeyId"]
                    has_custom_policy = False
                    errors = []

                    try:
                        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "{}")
                        policy_doc = json.loads(policy_str)
                        stmts = policy_doc.get("Statement", [])
                        has_custom_policy = len(stmts) > 1 or any(
                            stmt.get("Sid") not in ("", "Enable IAM User Permissions", None)
                            for stmt in stmts
                        )
                    except Exception as e:
                        errors.append(f"policy_check_error ({key_id}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="KMS",
                        resource_type="KMSKey",
                        resource_id=key_id,
                        account_id=account_id, region=region,
                        analysis={
                            "key_state": meta.get("KeyState"),
                            "key_default_policy_only": not has_custom_policy,
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_NO_POLICY_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def kms_key_grants_review_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            kms = _kms_context(creds, region)
            try:
                for meta in _iter_customer_keys(kms):
                    key_id = meta["KeyId"]
                    grants = []
                    has_external_grants = False
                    errors = []

                    try:
                        for page in kms.get_paginator("list_grants").paginate(KeyId=key_id):
                            for grant in page.get("Grants", []):
                                grantee = grant.get("GranteePrincipal", "")
                                is_external = f":{account_id}:" not in grantee
                                if is_external:
                                    has_external_grants = True
                                grants.append({
                                    "grant_id": grant.get("GrantId"),
                                    "grantee_principal": grantee,
                                    "operations": grant.get("Operations", []),
                                    "is_external": is_external,
                                })
                    except Exception as e:
                        errors.append(f"grants_check_error ({key_id}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="KMS",
                        resource_type="KMSKey",
                        resource_id=key_id,
                        account_id=account_id, region=region,
                        analysis={
                            "key_state": meta.get("KeyState"),
                            "total_grants": len(grants),
                            "key_external_grants": has_external_grants,
                            "grants": grants,
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="KMS",
                    resource_type="KMSKey",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "KMS", "KMS_KEY_GRANTS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)
# ══════════════════════════════════════════════════════════════════
# FIN AWS KMS
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# AWS SECRETS MANAGER
# ══════════════════════════════════════════════════════════════════

def secretsmanager_rotation_disabled_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret.get("ARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "rotation_disabled": not secret.get("RotationEnabled", False),
                            "rotation_rules": secret.get("RotationRules"),
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_ROTATION_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def secretsmanager_unused_secret_job(ejecucion_id, proyecto_id):
    def _execute():
        from datetime import timedelta
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        threshold = datetime.now(timezone.utc) - timedelta(days=90)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    last_accessed = secret.get("LastAccessedDate")
                    if last_accessed and last_accessed.tzinfo is None:
                        last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                    unused = last_accessed is None or last_accessed < threshold

                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret.get("ARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "secret_unused_90_days": unused,
                            "last_accessed_date": str(last_accessed) if last_accessed else None,
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_UNUSED_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def secretsmanager_exposed_secret_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    secret_arn = secret.get("ARN")
                    is_public = False
                    is_cross_account = False
                    errors = []

                    try:
                        policy_str = sm.get_resource_policy(SecretId=secret_arn).get("ResourcePolicy")
                        if policy_str:
                            policy_doc = json.loads(policy_str)
                            for stmt in policy_doc.get("Statement", []):
                                if stmt.get("Effect") != "Allow":
                                    continue
                                principal = stmt.get("Principal")
                                if principal == "*":
                                    is_public = True
                                elif isinstance(principal, dict):
                                    aws_p = principal.get("AWS", [])
                                    if aws_p == "*":
                                        is_public = True
                                    principals = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
                                    for p in principals:
                                        if f":{account_id}:" not in str(p) and p != "*":
                                            is_cross_account = True
                    except Exception as e:
                        errors.append(f"policy_check_error ({secret_arn}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret_arn,
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "secret_exposed_public": is_public,
                            "secret_cross_account_access": is_cross_account,
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_EXPOSED_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def secretsmanager_no_kms_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    kms_key = secret.get("KmsKeyId")
                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret.get("ARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "secret_no_customer_kms": not kms_key or kms_key == "aws/secretsmanager",
                            "kms_key_id": kms_key,
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_KMS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def secretsmanager_old_secret_job(ejecucion_id, proyecto_id):
    def _execute():
        from datetime import timedelta
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        threshold = datetime.now(timezone.utc) - timedelta(days=90)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    last_rotated = secret.get("LastRotatedDate")
                    last_changed = secret.get("LastChangedDate")

                    if last_rotated and last_rotated.tzinfo is None:
                        last_rotated = last_rotated.replace(tzinfo=timezone.utc)
                    if last_changed and last_changed.tzinfo is None:
                        last_changed = last_changed.replace(tzinfo=timezone.utc)

                    reference_date = last_rotated or last_changed
                    secret_outdated = reference_date is None or reference_date < threshold

                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret.get("ARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "secret_not_rotated_90_days": secret_outdated,
                            "last_rotated_date": str(last_rotated) if last_rotated else None,
                            "last_changed_date": str(last_changed) if last_changed else None,
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_OLD_SECRET_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def secretsmanager_missing_tags_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    tags = secret.get("Tags", [])
                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret.get("ARN"),
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "secret_missing_tags": len(tags) == 0,
                            "tags": tags,
                        },
                        errors=[]
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_MISSING_TAGS_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)


def secretsmanager_cross_account_access_job(ejecucion_id, proyecto_id):
    def _execute():
        creds, region_base = _get_aws_credentials(proyecto_id)
        account_id = _get_account_id(creds)
        regiones = _get_enabled_regions(creds)
        all_resources = []

        for region in regiones:
            sm = _secretsmanager_context(creds, region)
            try:
                for secret in _iter_secrets(sm):
                    secret_arn = secret.get("ARN")
                    cross_account_principals = []
                    errors = []

                    try:
                        policy_str = sm.get_resource_policy(SecretId=secret_arn).get("ResourcePolicy")
                        if policy_str:
                            policy_doc = json.loads(policy_str)
                            for stmt in policy_doc.get("Statement", []):
                                if stmt.get("Effect") != "Allow":
                                    continue
                                principal = stmt.get("Principal")
                                aws_p = principal if isinstance(principal, str) else principal.get("AWS", []) if isinstance(principal, dict) else []
                                principals = [aws_p] if isinstance(aws_p, str) else (aws_p or [])
                                for p in principals:
                                    if f":{account_id}:" not in str(p) and p != "*":
                                        cross_account_principals.append(p)
                    except Exception as e:
                        errors.append(f"policy_check_error ({secret_arn}): {e}")

                    all_resources.append(_base_resource(
                        provider="AWS", service="SecretsManager",
                        resource_type="Secret",
                        resource_id=secret_arn,
                        account_id=account_id, region=region,
                        analysis={
                            "secret_name": secret.get("Name"),
                            "secret_cross_account_access": len(cross_account_principals) > 0,
                            "cross_account_principals": cross_account_principals,
                        },
                        errors=errors
                    ))
            except Exception as e:
                all_resources.append(_base_resource(
                    provider="AWS", service="SecretsManager",
                    resource_type="Secret",
                    resource_id=f"region-error-{region}",
                    account_id=account_id, region=region,
                    analysis={}, errors=[f"region_scan_error: {e}"]
                ))

        return _build_resultado("AWS", "SecretsManager", "SECRETSMANAGER_CROSS_ACCOUNT_REVIEW", account_id, region_base, all_resources)

    _run_job(ejecucion_id, _execute)
# ══════════════════════════════════════════════════════════════════
# FIN AWS SECRETS MANAGER
# ══════════════════════════════════════════════════════════════════