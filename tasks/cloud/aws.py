import boto3
import json
from cryptography.fernet import Fernet
from config import Config
from models.proyecto import Proyecto
from models.cloud_ejecucion import CloudEjecucion
from botocore.exceptions import ClientError
from datetime import datetime, timezone


#Helper session AWS
def _get_aws_session(proyecto_id):
    config = Proyecto.get_cloud_config(proyecto_id)
    if not config:
        raise Exception("No existe configuración Cloud para este proyecto")

    fernet = Fernet(Config.FERNET_KEY)
    secret_key = fernet.decrypt(config['secret_key'].encode()).decode()

    return boto3.Session(
        aws_access_key_id=config['access_key'],
        aws_secret_access_key=secret_key,
        region_name=config['region']
    ), config["region"]


# ===================== Inicio IAM ==================== #
def discovery_roles_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]
        collection_timestamp = datetime.now(timezone.utc).isoformat()

        paginator = iam.get_paginator("list_roles")
        roles = []

        for page in paginator.paginate():
            for role in page.get("Roles", []):

                role_info = {
                    "provider": "AWS",
                    "service": "IAM",
                    "region": region,
                    "resource_type": "IAMRole",
                    "resource_id": role["Arn"],
                    "metadata": {
                        "role_name": role["RoleName"],
                        "arn": role["Arn"],
                        "path": role.get("Path"),
                        "create_date": role["CreateDate"].isoformat(),
                        "max_session_duration": role.get("MaxSessionDuration"),
                        "assume_role_policy": role.get("AssumeRolePolicyDocument")
                    },
                    "errors": []
                }

                roles.append(role_info)

        resultado = {
            "provider": "AWS",
            "service": "IAM",
            "inventory_type": "ROLE_METADATA",
            "account_id": account_id,
            "region": region,
            "collection_timestamp": collection_timestamp,
            "total_resources": len(roles),
            "resources": roles
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def discovery_policies_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = iam.get_paginator("list_policies")
        resources = []

        for page in paginator.paginate(Scope="All"):
            for policy in page.get("Policies", []):

                # Solo policies que están adjuntas a algo
                if policy.get("AttachmentCount", 0) == 0:
                    continue

                policy_arn = policy["Arn"]

                resources.append({
                    "provider": "AWS",
                    "service": "IAM",
                    "region": region,
                    "resource_type": "IAMPolicy",
                    "resource_id": policy_arn,
                    "metadata": {
                        "policy_name": policy["PolicyName"],
                        "arn": policy_arn,
                        "attachment_count": policy.get("AttachmentCount"),
                        "is_attachable": policy.get("IsAttachable"),
                        "default_version_id": policy.get("DefaultVersionId"),
                        "create_date": policy.get("CreateDate").isoformat() if policy.get("CreateDate") else None,
                        "update_date": policy.get("UpdateDate").isoformat() if policy.get("UpdateDate") else None
                    },
                    "errors": []
                })

        resultado = {
            "provider": "AWS",
            "service": "IAM",
            "inventory_type": "ACTIVE_POLICY_METADATA",
            "account_id": account_id,
            "region": region,
            "total_resources": len(resources),
            "resources": resources
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def password_policy_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        iam = session.client("iam")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        resource = {
            "provider": "AWS",
            "service": "IAM",
            "region": region,
            "resource_type": "AccountPasswordPolicy",
            "resource_id": "account_password_policy",
            "metadata": {
                "password_policy": None,
                "exists": False,
                "summary": None
            },
            "errors": []
        }

        try:
            policy = iam.get_account_password_policy()
            password_policy = policy.get("PasswordPolicy")

            resource["metadata"]["password_policy"] = password_policy
            resource["metadata"]["exists"] = True

            resource["metadata"]["summary"] = {
                "minimum_length": password_policy.get("MinimumPasswordLength"),
                "require_symbols": password_policy.get("RequireSymbols"),
                "require_numbers": password_policy.get("RequireNumbers"),
                "require_uppercase": password_policy.get("RequireUppercaseCharacters"),
                "require_lowercase": password_policy.get("RequireLowercaseCharacters"),
                "allow_user_change": password_policy.get("AllowUsersToChangePassword"),
                "hard_expiry": password_policy.get("HardExpiry"),
                "max_age": password_policy.get("MaxPasswordAge"),
                "reuse_prevention": password_policy.get("PasswordReusePrevention")
            }

        except iam.exceptions.NoSuchEntityException:
            # No existe policy configurada
            resource["metadata"]["exists"] = False

        except Exception as e:
            resource["errors"].append(f"password_policy_error: {str(e)}")

        resultado = {
            "provider": "AWS",
            "service": "IAM",
            "inventory_type": "ACCOUNT_PASSWORD_POLICY",
            "account_id": account_id,
            "region": region,
            "total_resources": 1,
            "resources": [resource]
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2, default=str),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)
        
# ===================== Final IAM ==================== #


# ===================== Inicio S3 ==================== #
def s3_public_exposure_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        s3 = session.client("s3")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        buckets = s3.list_buckets().get("Buckets", [])
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            public_via_acl = False
            public_via_policy = False
            public_write = False
            block_public_disabled = False
            errors = []

            # 🔹 ACL CHECK
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    uri = grantee.get("URI", "")
                    permission = grant.get("Permission")

                    if "AllUsers" in uri:
                        public_via_acl = True
                        if permission in ["WRITE", "FULL_CONTROL"]:
                            public_write = True

            except Exception as e:
                errors.append(f"acl_check_error: {str(e)}")

            # 🔹 POLICY CHECK
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy["Policy"])

                for statement in policy_doc.get("Statement", []):
                    if statement.get("Effect") != "Allow":
                        continue

                    principal = statement.get("Principal")
                    actions = statement.get("Action")

                    principal_is_public = (
                        principal == "*" or
                        (isinstance(principal, dict) and principal.get("AWS") == "*")
                    )

                    if principal_is_public:
                        public_via_policy = True

                        if isinstance(actions, str):
                            actions = [actions]

                        if any(a in ["s3:*", "s3:PutObject"] for a in actions):
                            public_write = True

            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    errors.append(f"policy_check_error: {str(e)}")

            # 🔹 BLOCK PUBLIC ACCESS CHECK
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab["PublicAccessBlockConfiguration"]

                if not all(config.values()):
                    block_public_disabled = True

            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    block_public_disabled = True
                else:
                    errors.append(f"pab_check_error: {str(e)}")

            # 🔥 Evaluación final real
            is_effectively_public = (
                (public_via_acl or public_via_policy)
                and not block_public_disabled
            )

            resources.append({
                "provider": "AWS",
                "service": "S3",
                "region": region,
                "resource_type": "S3Bucket",
                "resource_id": bucket_name,
                "analysis": {
                    "public_via_acl": public_via_acl,
                    "public_via_policy": public_via_policy,
                    "public_write": public_write,
                    "block_public_access_disabled": block_public_disabled,
                    "is_effectively_public": is_effectively_public
                },
                "errors": errors
            })

        resultado = {
            "provider": "AWS",
            "service": "S3",
            "inventory_type": "PUBLIC_EXPOSURE_ANALYSIS",
            "account_id": account_id,
            "region": region,
            "total_resources": len(resources),
            "resources": resources
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

def s3_encryption_logging_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        s3 = session.client("s3")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        buckets = s3.list_buckets().get("Buckets", [])
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            encryption_enabled = False
            encryption_type = None
            versioning_enabled = False
            logging_enabled = False
            errors = []

            # 🔐 ENCRYPTION CHECK
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

                if rules:
                    encryption_enabled = True
                    encryption_type = (
                        rules[0]
                        .get("ApplyServerSideEncryptionByDefault", {})
                        .get("SSEAlgorithm")
                    )

            except ClientError as e:
                if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                    errors.append(f"encryption_check_error: {str(e)}")

            # ♻ VERSIONING CHECK
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") == "Enabled":
                    versioning_enabled = True
            except Exception as e:
                errors.append(f"versioning_check_error: {str(e)}")

            # 📜 LOGGING CHECK
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                if logging.get("LoggingEnabled"):
                    logging_enabled = True
            except Exception as e:
                errors.append(f"logging_check_error: {str(e)}")

            resources.append({
                "provider": "AWS",
                "service": "S3",
                "region": region,
                "resource_type": "S3Bucket",
                "resource_id": bucket_name,
                "analysis": {
                    "encryption_enabled": encryption_enabled,
                    "encryption_type": encryption_type,
                    "versioning_enabled": versioning_enabled,
                    "logging_enabled": logging_enabled
                },
                "errors": errors
            })

        resultado = {
            "provider": "AWS",
            "service": "S3",
            "inventory_type": "SECURITY_POSTURE_ANALYSIS",
            "account_id": account_id,
            "region": region,
            "total_resources": len(resources),
            "resources": resources
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

def s3_iam_access_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        s3 = session.client("s3")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        buckets = s3.list_buckets().get("Buckets", [])
        resources = []

        for bucket in buckets:
            bucket_name = bucket["Name"]

            is_public = False
            cross_account = False
            wildcard_action = False
            dangerous_write = False
            wildcard_resource = False
            errors = []

            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy["Policy"])

                for statement in policy_doc.get("Statement", []):

                    if statement.get("Effect") != "Allow":
                        continue

                    principal = statement.get("Principal")
                    actions = statement.get("Action")
                    resource = statement.get("Resource")

                    # ---------- PRINCIPAL CHECK ----------
                    if principal == "*":
                        is_public = True

                    elif isinstance(principal, dict):
                        aws_principal = principal.get("AWS")

                        if aws_principal == "*":
                            is_public = True

                        principals = []
                        if isinstance(aws_principal, str):
                            principals = [aws_principal]
                        elif isinstance(aws_principal, list):
                            principals = aws_principal

                        for p in principals:
                            if f":{account_id}:" not in p:
                                cross_account = True

                    # ---------- ACTION CHECK ----------
                    if isinstance(actions, str):
                        actions = [actions]

                    if "*" in actions:
                        wildcard_action = True

                    if any(a.endswith("*") for a in actions):
                        wildcard_action = True

                    dangerous_actions = [
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:PutBucketPolicy",
                        "s3:PutObjectAcl"
                    ]

                    if any(a in dangerous_actions or a == "s3:*" for a in actions):
                        dangerous_write = True

                    # ---------- RESOURCE CHECK ----------
                    if isinstance(resource, str):
                        resource = [resource]

                    for r in resource:
                        if r == "*" or r.endswith("/*"):
                            wildcard_resource = True

            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                    errors.append(f"policy_check_error: {str(e)}")

            resources.append({
                "provider": "AWS",
                "service": "S3",
                "region": region,
                "resource_type": "S3Bucket",
                "resource_id": bucket_name,
                "analysis": {
                    "public_access": is_public,
                    "cross_account_access": cross_account,
                    "wildcard_action": wildcard_action,
                    "dangerous_write_permissions": dangerous_write,
                    "wildcard_resource": wildcard_resource
                },
                "errors": errors
            })

        resultado = {
            "provider": "AWS",
            "service": "S3",
            "inventory_type": "IAM_POLICY_ANALYSIS",
            "account_id": account_id,
            "region": region,
            "total_resources": len(resources),
            "resources": resources
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)
        
# ===================== Final S3 ==================== #


# ===================== Inicio EC2 ==================== #

def ec2_security_groups_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        ec2 = session.client("ec2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        COMMON_PORTS = CloudEjecucion.top_100_common_ports()

        paginator = ec2.get_paginator("describe_security_groups")
        security_groups = []

        for page in paginator.paginate():
            security_groups.extend(page.get("SecurityGroups", []))

        resources = []

        for sg in security_groups:

            sg_id = sg.get("GroupId")
            sg_name = sg.get("GroupName")

            exposed_rules = []

            for rule in sg.get("IpPermissions", []):

                protocol = rule.get("IpProtocol")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                ipv4_ranges = [r.get("CidrIp") for r in rule.get("IpRanges", [])]
                ipv6_ranges = [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])]

                is_public_ipv4 = "0.0.0.0/0" in ipv4_ranges
                is_public_ipv6 = "::/0" in ipv6_ranges

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

                # All traffic
                if protocol == "-1":
                    rule_detail["analysis"]["all_traffic_exposed"] = True
                    exposed_rules.append(rule_detail)
                    continue

                # ICMP / sin puerto
                if from_port is None:
                    rule_detail["analysis"]["non_tcp_udp_exposed"] = True
                    exposed_rules.append(rule_detail)
                    continue

                critical_ports_exposed = []

                # 🔥 Evitamos expandir rango enorme
                port_span = (to_port - from_port) if to_port else 0

                if port_span > 200:
                    rule_detail["analysis"]["large_port_range_exposed"] = {
                        "from": from_port,
                        "to": to_port,
                        "range_size": port_span
                    }
                else:
                    for p in range(from_port, (to_port or from_port) + 1):
                        if p in COMMON_PORTS:
                            critical_ports_exposed.append({
                                "port": p,
                                "service": COMMON_PORTS[p]
                            })

                rule_detail["analysis"]["critical_ports_exposed"] = critical_ports_exposed
                rule_detail["analysis"]["port_range"] = {
                    "from": from_port,
                    "to": to_port
                }

                exposed_rules.append(rule_detail)

            if exposed_rules:
                resources.append({
                    "provider": "AWS",
                    "service": "EC2",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "SecurityGroup",
                    "resource_id": sg_id,
                    "resource_name": sg_name,
                    "analysis": {
                        "public_ingress_rules_detected": True,
                        "total_public_rules": len(exposed_rules),
                        "rules": exposed_rules
                    }
                })

        resultado = {
            "provider": "AWS",
            "service": "EC2",
            "inventory_type": "SECURITY_GROUP_EXPOSURE_ANALYSIS",
            "account_id": account_id,
            "region": region,
            "total_security_groups": len(security_groups),
            "total_exposed_groups": len(resources),
            "resources": resources
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def ec2_public_instances_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        ec2 = session.client("ec2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = ec2.get_paginator("describe_instances")

        findings = []
        instance_count = 0

        # 🔥 Cache de SG para no repetir consultas
        sg_cache = {}

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):

                    instance_count += 1

                    instance_id = instance.get("InstanceId")
                    state = instance.get("State", {}).get("Name")
                    public_ip = instance.get("PublicIpAddress")
                    sg_list = instance.get("SecurityGroups", [])

                    if state != "running" or not public_ip:
                        continue

                    sg_ids = [sg["GroupId"] for sg in sg_list]

                    exposure_reason = "Instance has Public IP"
                    sg_public = False

                    for sg_id in sg_ids:

                        if sg_id not in sg_cache:
                            sg_response = ec2.describe_security_groups(
                                GroupIds=[sg_id]
                            )
                            sg_cache[sg_id] = sg_response["SecurityGroups"][0]

                        sg = sg_cache[sg_id]

                        for rule in sg.get("IpPermissions", []):

                            ipv4_ranges = [
                                r.get("CidrIp") for r in rule.get("IpRanges", [])
                            ]
                            ipv6_ranges = [
                                r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", [])
                            ]

                            if "0.0.0.0/0" in ipv4_ranges or "::/0" in ipv6_ranges:
                                sg_public = True

                    if sg_public:
                        exposure_reason = "Public IP + SG allows 0.0.0.0/0 or ::/0"

                    findings.append({
                        "provider": "AWS",
                        "service": "EC2",
                        "account_id": account_id,
                        "region": region,
                        "resource_type": "EC2Instance",
                        "resource_id": instance_id,
                        "analysis": {
                            "state": state,
                            "public_ip": public_ip,
                            "security_groups": sg_ids,
                            "sg_allows_public_ingress": sg_public,
                            "exposure_reason": exposure_reason
                        }
                    })

        resultado = {
            "provider": "AWS",
            "service": "EC2",
            "inventory_type": "PUBLIC_INSTANCE_ANALYSIS",
            "account_id": account_id,
            "region": region,
            "total_instances_checked": instance_count,
            "total_findings": len(findings),
            "resources": findings
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def ec2_iam_role_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        ec2 = session.client("ec2")
        iam = session.client("iam")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = ec2.get_paginator("describe_instances")

        findings = []
        instance_count = 0

        # 🔥 Cache de roles ya analizados
        role_analysis_cache = {}

        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):

                    instance_count += 1

                    instance_id = instance.get("InstanceId")
                    iam_profile = instance.get("IamInstanceProfile")

                    if not iam_profile:
                        continue

                    profile_name = iam_profile["Arn"].split("/")[-1]

                    profile = iam.get_instance_profile(
                        InstanceProfileName=profile_name
                    )

                    roles = profile["InstanceProfile"]["Roles"]

                    for role in roles:

                        role_name = role["RoleName"]

                        # 🔥 Si ya analizamos el rol, reutilizamos
                        if role_name not in role_analysis_cache:

                            issues = set()

                            # -------- Attached Policies --------
                            attached_policies = iam.list_attached_role_policies(
                                RoleName=role_name
                            )

                            for policy in attached_policies.get("AttachedPolicies", []):

                                policy_name = policy["PolicyName"]
                                policy_arn = policy["PolicyArn"]

                                if policy_name == "AdministratorAccess":
                                    issues.add("AdministratorAccess attached")

                                policy_version = iam.get_policy(
                                    PolicyArn=policy_arn
                                )["Policy"]["DefaultVersionId"]

                                policy_doc = iam.get_policy_version(
                                    PolicyArn=policy_arn,
                                    VersionId=policy_version
                                )["PolicyVersion"]["Document"]

                                for stmt in policy_doc.get("Statement", []):

                                    actions = stmt.get("Action")

                                    if actions == "*" or actions == ["*"]:
                                        issues.add("Wildcard action '*' detected")

                                    elif isinstance(actions, list):
                                        for action in actions:
                                            if action.endswith(":*"):
                                                issues.add(f"Broad permission: {action}")

                                    elif isinstance(actions, str):
                                        if actions.endswith(":*"):
                                            issues.add(f"Broad permission: {actions}")

                            # -------- Inline Policies --------
                            inline_policies = iam.list_role_policies(
                                RoleName=role_name
                            )

                            for policy_name in inline_policies.get("PolicyNames", []):

                                inline_doc = iam.get_role_policy(
                                    RoleName=role_name,
                                    PolicyName=policy_name
                                )["PolicyDocument"]

                                for stmt in inline_doc.get("Statement", []):

                                    actions = stmt.get("Action")

                                    if actions == "*" or actions == ["*"]:
                                        issues.add("Wildcard action '*' detected (inline)")

                                    elif isinstance(actions, list):
                                        for action in actions:
                                            if action.endswith(":*"):
                                                issues.add(f"Broad permission inline: {action}")

                                    elif isinstance(actions, str):
                                        if actions.endswith(":*"):
                                            issues.add(f"Broad permission inline: {actions}")

                            role_analysis_cache[role_name] = list(issues)

                        # 🔥 Si hay issues en ese rol, agregamos finding para esa instancia
                        role_issues = role_analysis_cache.get(role_name)

                        if role_issues:
                            findings.append({
                                "provider": "AWS",
                                "service": "EC2",
                                "account_id": account_id,
                                "region": region,
                                "resource_type": "EC2Instance",
                                "resource_id": instance_id,
                                "analysis": {
                                    "iam_role": role_name,
                                    "issues": role_issues
                                }
                            })

        resultado = {
            "provider": "AWS",
            "service": "EC2",
            "inventory_type": "EC2_IAM_ROLE_ANALYSIS",
            "account_id": account_id,
            "region": region,
            "total_instances_checked": instance_count,
            "total_findings": len(findings),
            "resources": findings
        }

        CloudEjecucion.mark_completed(
            json.dumps(resultado, indent=2),
            ejecucion_id
        )

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

# ===================== Final EC2 ==================== #


# ===================== Inicio Api Gateway ==================== #
def apigateway_public_exposure_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        apigw = session.client("apigateway")
        apigw2 = session.client("apigatewayv2")
        wafv2 = session.client("wafv2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        resources = []
        total_apis_checked = 0

        # ======================================================
        # 🔵 REST APIs (v1)
        # ======================================================

        paginator = apigw.get_paginator("get_rest_apis")

        for page in paginator.paginate():
            for api in page.get("items", []):

                total_apis_checked += 1

                api_id = api["id"]
                api_name = api["name"]

                endpoint_types = api.get("endpointConfiguration", {}).get("types", [])

                policy_public = False
                try:
                    api_full = apigw.get_rest_api(restApiId=api_id)
                    policy = api_full.get("policy")
                    if policy and '"Principal":"*"' in policy:
                        policy_public = True
                except Exception:
                    pass

                stages = []
                stage_paginator = apigw.get_paginator("get_stages")

                for stage_page in stage_paginator.paginate(restApiId=api_id):
                    for stage in stage_page.get("item", []):
                        stages.append({
                            "stage_name": stage.get("stageName"),
                            "cache_enabled": stage.get("cacheClusterEnabled"),
                            "logging_enabled": stage.get("methodSettings", {}),
                            "web_acl_associated": bool(stage.get("webAclArn"))
                        })

                methods_data = []

                resource_paginator = apigw.get_paginator("get_resources")

                for res_page in resource_paginator.paginate(restApiId=api_id):
                    for resource in res_page.get("items", []):

                        if "resourceMethods" not in resource:
                            continue

                        path = resource.get("path", "/")

                        for method_name in resource["resourceMethods"].keys():

                            method = apigw.get_method(
                                restApiId=api_id,
                                resourceId=resource["id"],
                                httpMethod=method_name
                            )

                            methods_data.append({
                                "path": path,
                                "method": method_name,
                                "authorization_type": method.get("authorizationType"),
                                "api_key_required": method.get("apiKeyRequired"),
                                "authorizer_id": method.get("authorizerId")
                            })

                resources.append({
                    "provider": "AWS",
                    "service": "APIGateway",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "REST_API",
                    "resource_id": api_id,
                    "resource_name": api_name,
                    "analysis": {
                        "endpoint_types": endpoint_types,
                        "resource_policy_public": policy_public,
                        "stages": stages,
                        "methods": methods_data
                    }
                })

        # ======================================================
        # 🟢 HTTP / WebSocket APIs (v2)
        # ======================================================

        paginator_v2 = apigw2.get_paginator("get_apis")

        for page in paginator_v2.paginate():
            for api in page.get("Items", []):

                total_apis_checked += 1

                api_id = api["ApiId"]
                api_name = api["Name"]

                cors = api.get("CorsConfiguration")
                endpoint_type = api.get("ProtocolType")

                cors_config = {
                    "allow_origins": cors.get("AllowOrigins") if cors else None,
                    "allow_methods": cors.get("AllowMethods") if cors else None,
                    "allow_headers": cors.get("AllowHeaders") if cors else None
                } if cors else None

                routes_data = []
                routes_paginator = apigw2.get_paginator("get_routes")

                for route_page in routes_paginator.paginate(ApiId=api_id):
                    for route in route_page.get("Items", []):

                        routes_data.append({
                            "route_key": route.get("RouteKey"),
                            "authorization_type": route.get("AuthorizationType"),
                            "api_key_required": route.get("ApiKeyRequired"),
                            "authorizer_id": route.get("AuthorizerId")
                        })

                stages_data = []
                stages_paginator = apigw2.get_paginator("get_stages")

                for stage_page in stages_paginator.paginate(ApiId=api_id):
                    for stage in stage_page.get("Items", []):
                        stages_data.append({
                            "stage_name": stage.get("StageName"),
                            "auto_deploy": stage.get("AutoDeploy"),
                            "access_log_settings": stage.get("AccessLogSettings"),
                            "web_acl_associated": bool(stage.get("WebAclArn"))
                        })

                resources.append({
                    "provider": "AWS",
                    "service": "APIGateway",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "HTTP_API",
                    "resource_id": api_id,
                    "resource_name": api_name,
                    "analysis": {
                        "protocol_type": endpoint_type,
                        "cors_configuration": cors_config,
                        "routes": routes_data,
                        "stages": stages_data
                    }
                })

        # ======================================================

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "APIGateway",
            "account_id": account_id,
            "region": region,
            "inventory_type": "FULL_CONFIGURATION_ANALYSIS",
            "total_apis_checked": total_apis_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)
    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def apigateway_discovery_stages_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        apigw = session.client("apigateway")
        apigw2 = session.client("apigatewayv2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        resources = []
        total_apis_checked = 0

        # ======================================================
        # 🔵 REST APIs (v1)
        # ======================================================

        paginator = apigw.get_paginator("get_rest_apis")

        for page in paginator.paginate():
            for api in page.get("items", []):

                total_apis_checked += 1

                api_id = api["id"]
                api_name = api["name"]

                stage_paginator = apigw.get_paginator("get_stages")

                for stage_page in stage_paginator.paginate(restApiId=api_id):
                    for stage in stage_page.get("item", []):

                        resources.append({
                            "provider": "AWS",
                            "service": "APIGateway",
                            "account_id": account_id,
                            "region": region,
                            "resource_type": "REST_API_STAGE",
                            "resource_id": f"{api_id}:{stage.get('stageName')}",
                            "resource_name": stage.get("stageName"),
                            "analysis": {
                                "api_id": api_id,
                                "api_name": api_name,
                                "tracing_enabled": stage.get("tracingEnabled"),
                                "cache_cluster_enabled": stage.get("cacheClusterEnabled"),
                                "cache_cluster_size": stage.get("cacheClusterSize"),
                                "web_acl_associated": stage.get("webAclArn"),
                                "method_settings": stage.get("methodSettings"),
                                "access_log_settings": stage.get("accessLogSettings"),
                                "variables": stage.get("variables")
                            }
                        })

        # ======================================================
        # 🟢 HTTP / WebSocket APIs (v2)
        # ======================================================

        paginator_v2 = apigw2.get_paginator("get_apis")

        for page in paginator_v2.paginate():
            for api in page.get("Items", []):

                total_apis_checked += 1

                api_id = api["ApiId"]
                api_name = api["Name"]

                stages_paginator = apigw2.get_paginator("get_stages")

                for stage_page in stages_paginator.paginate(ApiId=api_id):
                    for stage in stage_page.get("Items", []):

                        resources.append({
                            "provider": "AWS",
                            "service": "APIGateway",
                            "account_id": account_id,
                            "region": region,
                            "resource_type": "HTTP_API_STAGE",
                            "resource_id": f"{api_id}:{stage.get('StageName')}",
                            "resource_name": stage.get("StageName"),
                            "analysis": {
                                "api_id": api_id,
                                "api_name": api_name,
                                "auto_deploy": stage.get("AutoDeploy"),
                                "default_route_settings": stage.get("DefaultRouteSettings"),
                                "access_log_settings": stage.get("AccessLogSettings"),
                                "web_acl_associated": stage.get("WebAclArn"),
                                "stage_variables": stage.get("StageVariables")
                            }
                        })

        # ======================================================

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "APIGateway",
            "account_id": account_id,
            "region": region,
            "inventory_type": "STAGE_CONFIGURATION_DISCOVERY",
            "total_apis_checked": total_apis_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def apigateway_review_authorizers_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        apigw = session.client("apigateway")
        apigw2 = session.client("apigatewayv2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        resources = []
        total_apis_checked = 0

        # ======================================================
        # 🔵 REST APIs (v1)
        # ======================================================

        paginator = apigw.get_paginator("get_rest_apis")

        for page in paginator.paginate():
            for api in page.get("items", []):

                total_apis_checked += 1

                api_id = api["id"]
                api_name = api["name"]

                # Obtener authorizers definidos en el API
                auth_paginator = apigw.get_paginator("get_authorizers")
                rest_authorizers = []

                for auth_page in auth_paginator.paginate(restApiId=api_id):
                    for auth in auth_page.get("items", []):
                        rest_authorizers.append({
                            "authorizer_id": auth.get("id"),
                            "name": auth.get("name"),
                            "type": auth.get("type"),
                            "identity_source": auth.get("identitySource"),
                            "provider_arns": auth.get("providerARNs"),
                            "authorizer_uri": auth.get("authorizerUri"),
                            "auth_ttl": auth.get("authorizerResultTtlInSeconds")
                        })

                # Methods + autorización asociada
                resource_paginator = apigw.get_paginator("get_resources")
                methods_data = []

                for res_page in resource_paginator.paginate(restApiId=api_id):
                    for resource in res_page.get("items", []):

                        if "resourceMethods" not in resource:
                            continue

                        path = resource.get("path")

                        for method_name in resource["resourceMethods"].keys():

                            method = apigw.get_method(
                                restApiId=api_id,
                                resourceId=resource["id"],
                                httpMethod=method_name
                            )

                            methods_data.append({
                                "path": path,
                                "method": method_name,
                                "authorization_type": method.get("authorizationType"),
                                "authorizer_id": method.get("authorizerId"),
                                "authorization_scopes": method.get("authorizationScopes")
                            })

                resources.append({
                    "provider": "AWS",
                    "service": "APIGateway",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "REST_API_AUTHORIZERS",
                    "resource_id": api_id,
                    "resource_name": api_name,
                    "analysis": {
                        "authorizers_defined": rest_authorizers,
                        "methods_authorization": methods_data
                    }
                })

        # ======================================================
        # 🟢 HTTP / WebSocket APIs (v2)
        # ======================================================

        paginator_v2 = apigw2.get_paginator("get_apis")

        for page in paginator_v2.paginate():
            for api in page.get("Items", []):

                total_apis_checked += 1

                api_id = api["ApiId"]
                api_name = api["Name"]

                # Obtener authorizers v2
                authorizers_data = []
                auth_paginator = apigw2.get_paginator("get_authorizers")

                for auth_page in auth_paginator.paginate(ApiId=api_id):
                    for auth in auth_page.get("Items", []):
                        authorizers_data.append({
                            "authorizer_id": auth.get("AuthorizerId"),
                            "name": auth.get("Name"),
                            "authorizer_type": auth.get("AuthorizerType"),
                            "identity_sources": auth.get("IdentitySource"),
                            "jwt_configuration": auth.get("JwtConfiguration"),
                            "authorizer_uri": auth.get("AuthorizerUri"),
                            "authorizer_payload_format_version": auth.get("AuthorizerPayloadFormatVersion"),
                            "enable_simple_responses": auth.get("EnableSimpleResponses")
                        })

                # Routes + autorización
                routes_data = []
                routes_paginator = apigw2.get_paginator("get_routes")

                for route_page in routes_paginator.paginate(ApiId=api_id):
                    for route in route_page.get("Items", []):

                        routes_data.append({
                            "route_key": route.get("RouteKey"),
                            "authorization_type": route.get("AuthorizationType"),
                            "authorizer_id": route.get("AuthorizerId"),
                            "authorization_scopes": route.get("AuthorizationScopes")
                        })

                resources.append({
                    "provider": "AWS",
                    "service": "APIGateway",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "HTTP_API_AUTHORIZERS",
                    "resource_id": api_id,
                    "resource_name": api_name,
                    "analysis": {
                        "authorizers_defined": authorizers_data,
                        "routes_authorization": routes_data
                    }
                })

        # ======================================================

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "APIGateway",
            "account_id": account_id,
            "region": region,
            "inventory_type": "AUTHORIZER_CONFIGURATION_DISCOVERY",
            "total_apis_checked": total_apis_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def apigateway_security_exposure_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        apigw = session.client("apigateway")
        apigw2 = session.client("apigatewayv2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        resources = []
        total_apis_checked = 0

        # ======================================================
        # 🔵 REST APIs (v1)
        # ======================================================

        paginator = apigw.get_paginator("get_rest_apis")

        for page in paginator.paginate():
            for api in page.get("items", []):

                total_apis_checked += 1
                api_id = api["id"]
                api_name = api["name"]

                methods_data = []

                resource_paginator = apigw.get_paginator("get_resources")

                for res_page in resource_paginator.paginate(restApiId=api_id):
                    for resource in res_page.get("items", []):

                        if "resourceMethods" not in resource:
                            continue

                        path = resource.get("path", "/")

                        for method_name in resource["resourceMethods"].keys():

                            method = apigw.get_method(
                                restApiId=api_id,
                                resourceId=resource["id"],
                                httpMethod=method_name
                            )

                            integration = apigw.get_integration(
                                restApiId=api_id,
                                resourceId=resource["id"],
                                httpMethod=method_name
                            )

                            methods_data.append({
                                "path": path,
                                "method": method_name,
                                "authorization_type": method.get("authorizationType"),
                                "api_key_required": method.get("apiKeyRequired"),
                                "integration_type": integration.get("type"),
                                "integration_uri": integration.get("uri"),
                                "cors_headers": integration.get("integrationResponses")
                            })

                resources.append({
                    "provider": "AWS",
                    "service": "APIGateway",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "REST_API_SECURITY_EXPOSURE",
                    "resource_id": api_id,
                    "resource_name": api_name,
                    "analysis": {
                        "methods": methods_data
                    }
                })

        # ======================================================
        # 🟢 HTTP APIs (v2)
        # ======================================================

        paginator_v2 = apigw2.get_paginator("get_apis")

        for page in paginator_v2.paginate():
            for api in page.get("Items", []):

                total_apis_checked += 1
                api_id = api["ApiId"]
                api_name = api["Name"]

                integrations_map = {}
                integ_paginator = apigw2.get_paginator("get_integrations")

                for integ_page in integ_paginator.paginate(ApiId=api_id):
                    for integ in integ_page.get("Items", []):
                        integrations_map[integ["IntegrationId"]] = {
                            "integration_type": integ.get("IntegrationType"),
                            "integration_uri": integ.get("IntegrationUri"),
                            "connection_type": integ.get("ConnectionType")
                        }

                routes_data = []
                routes_paginator = apigw2.get_paginator("get_routes")

                for route_page in routes_paginator.paginate(ApiId=api_id):
                    for route in route_page.get("Items", []):

                        integration_id = None
                        if route.get("Target"):
                            integration_id = route["Target"].replace("integrations/", "")

                        routes_data.append({
                            "route_key": route.get("RouteKey"),
                            "authorization_type": route.get("AuthorizationType"),
                            "api_key_required": route.get("ApiKeyRequired"),
                            "integration": integrations_map.get(integration_id)
                        })

                resources.append({
                    "provider": "AWS",
                    "service": "APIGateway",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "HTTP_API_SECURITY_EXPOSURE",
                    "resource_id": api_id,
                    "resource_name": api_name,
                    "analysis": {
                        "routes": routes_data
                    }
                })

        # ======================================================

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "APIGateway",
            "account_id": account_id,
            "region": region,
            "inventory_type": "SECURITY_EXPOSURE_DISCOVERY",
            "total_apis_checked": total_apis_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def apigateway_logging_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)
        apigw = session.client("apigateway")
        apigw2 = session.client("apigatewayv2")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        resources = []
        total_apis_checked = 0

        # ======================================================
        # 🔵 REST APIs (v1)
        # ======================================================

        paginator = apigw.get_paginator("get_rest_apis")

        for page in paginator.paginate():
            for api in page.get("items", []):

                total_apis_checked += 1

                api_id = api["id"]
                api_name = api["name"]

                stage_paginator = apigw.get_paginator("get_stages")

                for stage_page in stage_paginator.paginate(restApiId=api_id):
                    for stage in stage_page.get("item", []):

                        resources.append({
                            "provider": "AWS",
                            "service": "APIGateway",
                            "account_id": account_id,
                            "region": region,
                            "resource_type": "REST_API_LOGGING_CONFIG",
                            "resource_id": f"{api_id}:{stage.get('stageName')}",
                            "resource_name": stage.get("stageName"),
                            "analysis": {
                                "api_id": api_id,
                                "api_name": api_name,
                                "tracing_enabled": stage.get("tracingEnabled"),
                                "access_log_settings": stage.get("accessLogSettings"),
                                "method_settings": stage.get("methodSettings"),
                                "cache_cluster_enabled": stage.get("cacheClusterEnabled"),
                                "web_acl_associated": stage.get("webAclArn")
                            }
                        })

        # ======================================================
        # 🟢 HTTP / WebSocket APIs (v2)
        # ======================================================

        paginator_v2 = apigw2.get_paginator("get_apis")

        for page in paginator_v2.paginate():
            for api in page.get("Items", []):

                total_apis_checked += 1

                api_id = api["ApiId"]
                api_name = api["Name"]

                stages_paginator = apigw2.get_paginator("get_stages")

                for stage_page in stages_paginator.paginate(ApiId=api_id):
                    for stage in stage_page.get("Items", []):

                        resources.append({
                            "provider": "AWS",
                            "service": "APIGateway",
                            "account_id": account_id,
                            "region": region,
                            "resource_type": "HTTP_API_LOGGING_CONFIG",
                            "resource_id": f"{api_id}:{stage.get('StageName')}",
                            "resource_name": stage.get("StageName"),
                            "analysis": {
                                "api_id": api_id,
                                "api_name": api_name,
                                "auto_deploy": stage.get("AutoDeploy"),
                                "access_log_settings": stage.get("AccessLogSettings"),
                                "default_route_settings": stage.get("DefaultRouteSettings"),
                                "route_settings": stage.get("RouteSettings"),
                                "web_acl_associated": stage.get("WebAclArn")
                            }
                        })

        # ======================================================

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "APIGateway",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LOGGING_CONFIGURATION_DISCOVERY",
            "total_apis_checked": total_apis_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

# ===================== Final Api Gateway ==================== #


# ===================== Inicio Funciones Lambda ==================== #

# ===================== Inicio Lambda ==================== #
def discovery_functions_job(ejecucion_id, proyecto_id):
    try:
        # 1️⃣ RUNNING
        CloudEjecucion.mark_running(ejecucion_id)

        # 2️⃣ Session centralizada
        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        # 3️⃣ Paginator
        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaFunction",
                    "resource_id": fn.get("FunctionName"),
                    "analysis": {
                        "function_arn": fn.get("FunctionArn"),
                        "runtime": fn.get("Runtime"),
                        "role": fn.get("Role"),
                        "handler": fn.get("Handler"),
                        "timeout": fn.get("Timeout"),
                        "memory_size": fn.get("MemorySize"),
                        "last_modified": fn.get("LastModified"),
                        "package_type": fn.get("PackageType"),
                        "architectures": fn.get("Architectures"),
                        "vpc_configured": bool(fn.get("VpcConfig", {}).get("VpcId")),
                        "subnet_ids": fn.get("VpcConfig", {}).get("SubnetIds"),
                        "security_group_ids": fn.get("VpcConfig", {}).get("SecurityGroupIds"),
                        "tracing_mode": fn.get("TracingConfig", {}).get("Mode"),
                        "dead_letter_config": fn.get("DeadLetterConfig"),
                        "layers": [layer.get("Arn") for layer in fn.get("Layers", [])],
                        # Solo mostramos nombres de variables, nunca valores
                        "environment_variables": list(
                            fn.get("Environment", {}).get("Variables", {}).keys()
                        )
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "FUNCTION_CONFIGURATION_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        # 4️⃣ COMPLETED
        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def discovery_permissions_job(ejecucion_id, proyecto_id):
    try:
        # 1️⃣ RUNNING
        CloudEjecucion.mark_running(ejecucion_id)

        # 2️⃣ Session centralizada
        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1
                function_name = fn.get("FunctionName")

                has_policy = False
                is_public = False
                statements_count = 0
                policy_json = None
                error = None

                try:
                    policy_response = lambda_client.get_policy(
                        FunctionName=function_name
                    )

                    has_policy = True
                    policy_json = json.loads(
                        policy_response.get("Policy", "{}")
                    )

                    statements = policy_json.get("Statement", [])
                    statements_count = len(statements)

                    for stmt in statements:
                        principal = stmt.get("Principal")

                        if principal == "*":
                            is_public = True

                        if isinstance(principal, dict):
                            if principal.get("AWS") == "*":
                                is_public = True
                            if principal.get("Service") == "*":
                                is_public = True

                except lambda_client.exceptions.ResourceNotFoundException:
                    # No tiene policy
                    pass

                except Exception as inner_error:
                    error = str(inner_error)

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaPermissionPolicy",
                    "resource_id": function_name,
                    "analysis": {
                        "has_policy": has_policy,
                        "is_public": is_public,
                        "statements_count": statements_count,
                        # Guardamos policy completa porque es inventory,
                        # no scoring. El análisis real vendrá después.
                        "policy_document": policy_json,
                        "error": error
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_PERMISSION_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def discovery_triggers_job(ejecucion_id, proyecto_id):
    try:
        # 1️⃣ RUNNING
        CloudEjecucion.mark_running(ejecucion_id)

        # 2️⃣ Session centralizada
        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1
                function_name = fn.get("FunctionName")

                event_source_mappings_data = []
                policy_triggers_data = []
                error = None

                # 🔹 1️⃣ Event Source Mappings (SQS, DynamoDB, Kinesis, MSK, etc.)
                try:
                    mappings_paginator = lambda_client.get_paginator("list_event_source_mappings")

                    for m_page in mappings_paginator.paginate(FunctionName=function_name):
                        for mapping in m_page.get("EventSourceMappings", []):
                            event_source_mappings_data.append({
                                "event_source_arn": mapping.get("EventSourceArn"),
                                "state": mapping.get("State"),
                                "batch_size": mapping.get("BatchSize"),
                                "maximum_batching_window": mapping.get("MaximumBatchingWindowInSeconds"),
                                "parallelization_factor": mapping.get("ParallelizationFactor"),
                                "function_response_types": mapping.get("FunctionResponseTypes")
                            })

                except Exception as e:
                    error = f"EventSourceMappingError: {str(e)}"

                # 🔹 2️⃣ Resource-based policy triggers (API Gateway, S3, EventBridge, etc.)
                try:
                    policy_response = lambda_client.get_policy(
                        FunctionName=function_name
                    )

                    policy_json = json.loads(
                        policy_response.get("Policy", "{}")
                    )

                    statements = policy_json.get("Statement", [])

                    for stmt in statements:
                        principal = stmt.get("Principal")
                        condition = stmt.get("Condition")
                        source_arn = None

                        if condition:
                            source_arn = (
                                condition.get("ArnLike", {}).get("AWS:SourceArn")
                                or condition.get("ArnEquals", {}).get("AWS:SourceArn")
                            )

                        policy_triggers_data.append({
                            "principal": principal,
                            "effect": stmt.get("Effect"),
                            "action": stmt.get("Action"),
                            "source_arn": source_arn
                        })

                except lambda_client.exceptions.ResourceNotFoundException:
                    # No resource-based policy
                    pass

                except Exception as e:
                    policy_triggers_data.append({
                        "error": str(e)
                    })

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaTriggerConfiguration",
                    "resource_id": function_name,
                    "analysis": {
                        "event_source_mappings": event_source_mappings_data,
                        "policy_triggers": policy_triggers_data,
                        "error": error
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_TRIGGER_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)
        

def public_exposure_review_job(ejecucion_id, proyecto_id):
    try:
        # 1️⃣ RUNNING
        CloudEjecucion.mark_running(ejecucion_id)

        # 2️⃣ Session centralizada
        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0
        total_exposed_functions = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1
                function_name = fn.get("FunctionName")

                is_public = False
                policy_statements = []
                error = None

                try:
                    policy_response = lambda_client.get_policy(
                        FunctionName=function_name
                    )

                    policy_json = json.loads(
                        policy_response.get("Policy", "{}")
                    )

                    statements = policy_json.get("Statement", [])

                    for stmt in statements:
                        principal = stmt.get("Principal")
                        condition = stmt.get("Condition")
                        action = stmt.get("Action")

                        statement_public = False

                        if principal == "*":
                            statement_public = True

                        elif isinstance(principal, dict):
                            if principal.get("AWS") == "*":
                                statement_public = True
                            if principal.get("Service") == "*":
                                statement_public = True

                        if statement_public:
                            is_public = True

                        policy_statements.append({
                            "principal": principal,
                            "action": action,
                            "condition": condition,
                            "statement_public": statement_public
                        })

                except lambda_client.exceptions.ResourceNotFoundException:
                    pass

                except Exception as inner_error:
                    error = str(inner_error)

                if is_public:
                    total_exposed_functions += 1

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaPublicExposure",
                    "resource_id": function_name,
                    "analysis": {
                        "is_public": is_public,
                        "policy_statements": policy_statements,
                        "error": error
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_PUBLIC_EXPOSURE_ANALYSIS",
            "total_functions_checked": total_functions_checked,
            "total_exposed_functions": total_exposed_functions,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def overprivileged_role_review_job(ejecucion_id, proyecto_id):
    try:
        # 1️⃣ RUNNING
        CloudEjecucion.mark_running(ejecucion_id)

        # 2️⃣ Session centralizada
        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        iam_client = session.client("iam")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1

                function_name = fn.get("FunctionName")
                role_arn = fn.get("Role")

                if not role_arn:
                    continue

                role_name = role_arn.split("/")[-1]

                attached_policies_data = []
                inline_policies_data = []
                error = None

                try:
                    # 🔹 Attached Policies
                    attached_policies = iam_client.list_attached_role_policies(
                        RoleName=role_name
                    ).get("AttachedPolicies", [])

                    for policy in attached_policies:
                        policy_arn = policy.get("PolicyArn")

                        policy_meta = iam_client.get_policy(
                            PolicyArn=policy_arn
                        ).get("Policy", {})

                        version_id = policy_meta.get("DefaultVersionId")

                        policy_doc = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=version_id
                        ).get("PolicyVersion", {}).get("Document", {})

                        attached_policies_data.append({
                            "policy_name": policy.get("PolicyName"),
                            "policy_arn": policy_arn,
                            "policy_document": policy_doc
                        })

                    # 🔹 Inline Policies
                    inline_policies = iam_client.list_role_policies(
                        RoleName=role_name
                    ).get("PolicyNames", [])

                    for policy_name in inline_policies:
                        policy_doc = iam_client.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name
                        ).get("PolicyDocument", {})

                        inline_policies_data.append({
                            "policy_name": policy_name,
                            "policy_document": policy_doc
                        })

                except Exception as e:
                    error = str(e)

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaExecutionRole",
                    "resource_id": role_name,
                    "resource_name": role_name,
                    "analysis": {
                        "function_name": function_name,
                        "role_arn": role_arn,
                        "attached_policies": attached_policies_data,
                        "inline_policies": inline_policies_data,
                        "error": error
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_ROLE_CONFIGURATION_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def analyze_policy(policy_doc):
    statements = policy_doc.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    normalized = []

    for index, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        actions = stmt.get("Action", [])
        not_actions = stmt.get("NotAction", [])
        resources = stmt.get("Resource", [])
        not_resources = stmt.get("NotResource", [])
        effect = stmt.get("Effect")
        condition = stmt.get("Condition")
        principal = stmt.get("Principal")
        not_principal = stmt.get("NotPrincipal")

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        if isinstance(resources, str):
            resources = [resources]
        if isinstance(not_resources, str):
            not_resources = [not_resources]

        normalized.append({
            "statement_index": index,
            "sid": stmt.get("Sid"),
            "effect": effect,
            "actions": actions,
            "not_actions": not_actions,
            "resources": resources,
            "not_resources": not_resources,
            "principal": principal,
            "not_principal": not_principal,
            "condition": condition
        })

    return normalized


def wildcard_permissions_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        iam_client = session.client("iam")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1

                function_name = fn.get("FunctionName")
                role_arn = fn.get("Role")

                if not role_arn:
                    continue

                role_name = role_arn.split("/")[-1]

                attached_policies = []
                inline_policies = []
                error = None

                try:
                    attached = iam_client.get_paginator("list_attached_role_policies")
                    for a_page in attached.paginate(RoleName=role_name):
                        for policy in a_page.get("AttachedPolicies", []):
                            policy_arn = policy.get("PolicyArn")

                            policy_meta = iam_client.get_policy(
                                PolicyArn=policy_arn
                            ).get("Policy", {})

                            version = policy_meta.get("DefaultVersionId")

                            policy_doc = iam_client.get_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=version
                            ).get("PolicyVersion", {}).get("Document", {})

                            attached_policies.append({
                                "policy_name": policy.get("PolicyName"),
                                "policy_arn": policy_arn,
                                "statements": analyze_policy(policy_doc)
                            })

                    inline = iam_client.get_paginator("list_role_policies")
                    for i_page in inline.paginate(RoleName=role_name):
                        for policy_name in i_page.get("PolicyNames", []):
                            policy_doc = iam_client.get_role_policy(
                                RoleName=role_name,
                                PolicyName=policy_name
                            ).get("PolicyDocument", {})

                            inline_policies.append({
                                "policy_name": policy_name,
                                "statements": analyze_policy(policy_doc)
                            })

                except Exception as e:
                    error = str(e)

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaWildcardPermissionDiscovery",
                    "resource_id": role_name,
                    "analysis": {
                        "function_name": function_name,
                        "role_arn": role_arn,
                        "attached_policies": attached_policies,
                        "inline_policies": inline_policies,
                        "error": error
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_WILDCARD_PERMISSION_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

def analyze_wildcards(policy_doc):
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    result = []

    for index, stmt in enumerate(statements):

        if not isinstance(stmt, dict):
            continue

        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        action_wildcard_full = False
        resource_wildcard_full = False
        action_wildcard_partial = []

        if actions and "*" in actions:
            action_wildcard_full = True

        if resources and "*" in resources:
            resource_wildcard_full = True

        for action in actions:
            if isinstance(action, str) and "*" in action and action != "*":
                action_wildcard_partial.append(action)

        result.append({
            "statement_index": index,
            "actions": actions,
            "resources": resources,
            "action_wildcard_full": action_wildcard_full,
            "resource_wildcard_full": resource_wildcard_full,
            "action_wildcard_partial": action_wildcard_partial
        })
    return result

def no_vpc_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")

        resources = []
        total_functions_checked = 0

        for page in paginator.paginate():
            for fn in page.get("Functions", []):

                total_functions_checked += 1

                function_name = fn.get("FunctionName")
                vpc_config = fn.get("VpcConfig", {}) or {}

                vpc_id = vpc_config.get("VpcId")
                subnets = vpc_config.get("SubnetIds", []) or []
                security_groups = vpc_config.get("SecurityGroupIds", []) or []

                resources.append({
                    "provider": "AWS",
                    "service": "Lambda",
                    "account_id": account_id,
                    "region": region,
                    "resource_type": "LambdaVpcConfiguration",
                    "resource_id": function_name,
                    "analysis": {
                        "vpc_id": vpc_id,
                        "subnet_ids": subnets,
                        "security_group_ids": security_groups,
                        "vpc_configured": bool(vpc_id and subnets and security_groups)
                    }
                })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_VPC_CONFIGURATION_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)


def old_runtime_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")
        resources = []
        total_functions_checked = 0

        # Obtiene las versiones obsoletas usando el método de CloudEjecucion
        deprecated_runtimes = CloudEjecucion.versiones_deprecadas(
            tipo_proyecto_id=proyecto_id,
            proveedor="AWS",
            servicio="Lambda",
            categoria="Runtime"
        )

        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                total_functions_checked += 1
                function_name = fn.get("FunctionName")
                runtime = fn.get("Runtime")

                if runtime in deprecated_runtimes:
                    resources.append({
                        "provider": "AWS",
                        "service": "Lambda",
                        "account_id": account_id,
                        "region": region,
                        "resource_type": "LambdaRuntime",
                        "resource_id": function_name,
                        "analysis": {
                            "runtime": runtime,
                            "deprecated": True,
                            "recommendation": "Actualizar a una versión soportada oficialmente por AWS"
                        }
                    })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_RUNTIME_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

def lambda_runtime_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client("lambda")
        sts = session.client("sts")

        account_id = sts.get_caller_identity()["Account"]

        paginator = lambda_client.get_paginator("list_functions")
        resources = []
        total_functions_checked = 0

        deprecated_runtimes = CloudEjecucion.versiones_deprecadas(
            tipo_proyecto_id=proyecto_id,
            proveedor="AWS",
            servicio="Lambda",
            categoria="Runtime"
        )

        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                total_functions_checked += 1
                function_name = fn.get("FunctionName")
                runtime = fn.get("Runtime")

                if runtime in deprecated_runtimes:
                    resources.append({
                        "provider": "AWS",
                        "service": "Lambda",
                        "account_id": account_id,
                        "region": region,
                        "resource_type": "LambdaRuntime",
                        "resource_id": function_name,
                        "analysis": {
                            "runtime": runtime,
                            "deprecated": True,
                            "recommendation": "Actualizar a una versión soportada oficialmente por AWS"
                        }
                    })

        resultado_json = json.dumps({
            "provider": "AWS",
            "service": "Lambda",
            "account_id": account_id,
            "region": region,
            "inventory_type": "LAMBDA_RUNTIME_DISCOVERY",
            "total_functions_checked": total_functions_checked,
            "total_resources": len(resources),
            "resources": resources
        }, indent=2, default=str)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

def env_secrets_review_job(ejecucion_id, proyecto_id): 
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client('lambda')
        paginator = lambda_client.get_paginator('list_functions')

        findings = []

        suspicious_keywords = [
            "password",
            "secret",
            "token",
            "apikey",
            "api_key",
            "access_key",
            "private_key",
            "jwt",
            "db_",
            "database",
        ]

        for page in paginator.paginate():
            for fn in page.get('Functions', []):

                function_name = fn.get("FunctionName")

                env = fn.get("Environment", {})
                variables = env.get("Variables", {})

                for key, value in variables.items():

                    key_lower = key.lower()

                    if any(keyword in key_lower for keyword in suspicious_keywords):

                        findings.append({
                            "FunctionName": function_name,
                            "Issue": "Potential secret stored in environment variable",
                            "VariableName": key,
                            "VariableValue": value,
                            "Recommendation": "Mover secretos a AWS Secrets Manager o Parameter Store"
                        })

                    # Extra: detectar valores tipo clave larga (heurística básica)
                    if isinstance(value, str) and len(value) > 30:
                        if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
                            findings.append({
                                "FunctionName": function_name,
                                "Issue": "Suspicious high-entropy environment variable value",
                                "VariableName": key,
                                "Recommendation": "Revisar si el valor es un secreto en texto plano"
                            })

        resultado_json = json.dumps(findings, indent=2)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)

def logging_review_job(ejecucion_id, proyecto_id):
    try:
        CloudEjecucion.mark_running(ejecucion_id)

        session, region = _get_aws_session(proyecto_id)

        lambda_client = session.client('lambda')
        logs_client = session.client('logs')

        paginator = lambda_client.get_paginator('list_functions')

        findings = []

        for page in paginator.paginate():
            for fn in page.get('Functions', []):

                function_name = fn.get("FunctionName")
                log_group_name = f"/aws/lambda/{function_name}"

                try:
                    response = logs_client.describe_log_groups(
                        logGroupNamePrefix=log_group_name
                    )

                    log_groups = response.get("logGroups", [])

                    if not log_groups:
                        findings.append({
                            "FunctionName": function_name,
                            "Issue": "CloudWatch Log Group not found",
                            "Recommendation": "Verificar que la Lambda tenga permisos para escribir logs"
                        })
                        continue

                    log_group = log_groups[0]
                    retention = log_group.get("retentionInDays")

                    if not retention:
                        findings.append({
                            "FunctionName": function_name,
                            "Issue": "Log retention not configured (Never expire)",
                            "Recommendation": "Configurar retención para evitar almacenamiento indefinido"
                        })

                except Exception as inner_error:
                    findings.append({
                        "FunctionName": function_name,
                        "Issue": "Error reviewing logging",
                        "Error": str(inner_error)
                    })

        resultado_json = json.dumps(findings, indent=2)

        CloudEjecucion.mark_completed(resultado_json, ejecucion_id)

    except Exception as e:
        CloudEjecucion.mark_failed(str(e), ejecucion_id)
        
# ===================== Final Funciones Lambda ==================== #
