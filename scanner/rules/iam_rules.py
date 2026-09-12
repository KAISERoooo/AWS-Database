from models.finding import Finding


def check_mfa(user_name, mfa_enabled):
    """
    Check whether an IAM user has multi-factor authentication enabled.
    """

    if mfa_enabled:
        return Finding(
            rule_id="IAM_MFA",
            service="iam",
            resource_id=user_name,
            severity="INFO",
            status="PASS",
            message="IAM user has MFA enabled.",
            description=(
                "The IAM user is protected with multi-factor authentication, "
                "which adds a second verification factor during sign-in."
            ),
            remediation="No remediation required.",
        )

    return Finding(
        rule_id="IAM_MFA",
        service="iam",
        resource_id=user_name,
        severity="HIGH",
        status="FAIL",
        message="IAM user does not have MFA enabled.",
        description=(
            "The IAM user can sign in without multi-factor authentication, "
            "increasing the risk of account compromise from stolen credentials."
        ),
        remediation=(
            "Enable MFA for this IAM user and require it for all interactive "
            "AWS console sign-ins."
        ),
    )


def check_console_access(user_name, console_access, mfa_enabled):
    """
    Check whether an IAM user has console access without MFA protection.
    """

    if console_access and not mfa_enabled:
        return Finding(
            rule_id="IAM_CONSOLE_MFA",
            service="iam",
            resource_id=user_name,
            severity="HIGH",
            status="FAIL",
            message="IAM user has console access without MFA.",
            description=(
                "The IAM user can sign in to the AWS Management Console "
                "without multi-factor authentication."
            ),
            remediation=(
                "Enable MFA for this user, or remove the login profile if "
                "console access is not required."
            ),
        )

    return Finding(
        rule_id="IAM_CONSOLE_MFA",
        service="iam",
        resource_id=user_name,
        severity="INFO",
        status="PASS",
        message=(
            "IAM user console access is protected by MFA or console access "
            "is disabled."
        ),
        description=(
            "The IAM user either has MFA enabled for console sign-in or does "
            "not have an AWS Management Console login profile."
        ),
        remediation="No remediation required.",
    )


def check_access_keys(user_name, access_keys):
    """
    Check whether an IAM user has active programmatic access keys.
    """

    has_active_access_key = any(
        access_key["status"] == "Active" for access_key in access_keys
    )

    if has_active_access_key:
        return Finding(
            rule_id="IAM_ACCESS_KEY",
            service="iam",
            resource_id=user_name,
            severity="MEDIUM",
            status="FAIL",
            message="IAM user has an active access key.",
            description=(
                "The IAM user has at least one active access key that can be "
                "used for programmatic AWS access."
            ),
            remediation=(
                "Disable or delete unused access keys. Prefer IAM roles and "
                "short-lived credentials where possible."
            ),
        )

    return Finding(
        rule_id="IAM_ACCESS_KEY",
        service="iam",
        resource_id=user_name,
        severity="INFO",
        status="PASS",
        message="IAM user has no active access keys.",
        description=(
            "The IAM user has no active programmatic access keys, reducing "
            "the risk of long-lived credential exposure."
        ),
        remediation="No remediation required.",
    )
