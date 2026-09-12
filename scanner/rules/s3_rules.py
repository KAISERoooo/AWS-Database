from models.finding import Finding


def check_public_access(bucket_name, public_access_config):
    """
    Check whether S3 public access protection is properly configured.
    """

    if public_access_config is None:
        return Finding(
            rule_id="S3_PUBLIC_ACCESS",
            service="s3",
            resource_id=bucket_name,
            severity="HIGH",
            status="FAIL",
            message="S3 bucket does not have Public Access Block configured.",
            description=(
                "The S3 bucket does not have Public Access Block "
                "configuration enabled."
            ),
            remediation=(
                "Enable all four S3 Public Access Block settings: "
                "BlockPublicAcls, IgnorePublicAcls, "
                "BlockPublicPolicy, and RestrictPublicBuckets."
            )
        )

    all_blocked = (
        public_access_config.get("BlockPublicAcls", False)
        and public_access_config.get("IgnorePublicAcls", False)
        and public_access_config.get("BlockPublicPolicy", False)
        and public_access_config.get("RestrictPublicBuckets", False)
    )

    if all_blocked:
        return Finding(
            rule_id="S3_PUBLIC_ACCESS",
            service="s3",
            resource_id=bucket_name,
            severity="INFO",
            status="PASS",
            message="S3 bucket has all Public Access Block settings enabled.",
            description=(
                "The S3 bucket has all four Public Access Block "
                "settings enabled."
            ),
            remediation="No remediation required."
        )

    return Finding(
        rule_id="S3_PUBLIC_ACCESS",
        service="s3",
        resource_id=bucket_name,
        severity="HIGH",
        status="FAIL",
        message=(
            "S3 bucket may allow public access because not all "
            "Public Access Block settings are enabled."
        ),
        description=(
            "One or more S3 Public Access Block settings are disabled, "
            "which may allow unintended public access."
        ),
        remediation=(
            "Enable BlockPublicAcls, IgnorePublicAcls, "
            "BlockPublicPolicy, and RestrictPublicBuckets."
        )
    )


def check_versioning(bucket_name, versioning_status):
    """
    Check whether S3 bucket versioning is enabled.
    """

    if versioning_status == "Enabled":
        return Finding(
            rule_id="S3_VERSIONING",
            service="s3",
            resource_id=bucket_name,
            severity="INFO",
            status="PASS",
            message="S3 bucket versioning is enabled.",
            description=(
                "S3 versioning is enabled, allowing previous versions "
                "of objects to be retained."
            ),
            remediation="No remediation required."
        )

    return Finding(
        rule_id="S3_VERSIONING",
        service="s3",
        resource_id=bucket_name,
        severity="MEDIUM",
        status="FAIL",
        message="S3 bucket versioning is not enabled.",
        description=(
            "Without versioning, accidental deletion or overwriting "
            "of objects may result in permanent data loss."
        ),
        remediation="Enable versioning for the S3 bucket."
    )


def check_encryption(bucket_name, encryption_enabled):
    """
    Check whether S3 bucket encryption is enabled.
    """

    if encryption_enabled:
        return Finding(
            rule_id="S3_ENCRYPTION",
            service="s3",
            resource_id=bucket_name,
            severity="INFO",
            status="PASS",
            message="S3 bucket encryption is enabled.",
            description=(
                "The S3 bucket has server-side encryption enabled "
                "for stored objects."
            ),
            remediation="No remediation required."
        )

    return Finding(
        rule_id="S3_ENCRYPTION",
        service="s3",
        resource_id=bucket_name,
        severity="HIGH",
        status="FAIL",
        message="S3 bucket encryption is not enabled.",
        description=(
            "Objects stored in the S3 bucket are not protected "
            "by server-side encryption."
        ),
        remediation="Enable server-side encryption for the S3 bucket."
    )

def check_logging(bucket_name, logging_enabled):
    """
    Check whether S3 bucket access logging is enabled.
    """

    if logging_enabled:
        return Finding(
            rule_id="S3_LOGGING",
            service="s3",
            resource_id=bucket_name,
            severity="INFO",
            status="PASS",
            message="S3 bucket access logging is enabled.",
            description=(
                "S3 access logging is enabled, allowing requests "
                "to the bucket to be recorded for auditing."
            ),
            remediation="No remediation required."
        )

    return Finding(
        rule_id="S3_LOGGING",
        service="s3",
        resource_id=bucket_name,
        severity="MEDIUM",
        status="FAIL",
        message="S3 bucket access logging is not enabled.",
        description=(
            "Access logging is disabled, which can make it harder "
            "to investigate suspicious or unauthorized activity."
        ),
        remediation=(
            "Enable S3 server access logging and configure an "
            "appropriate destination bucket."
        )
    )