# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Simulated AWS CloudTrail records: a small company's AWS account on a working day.

The background is what CloudTrail records for a team of four developers and an administrator:
developers' command-line tools reading the account with their access keys, console sessions
after a sign-in with MFA (now and then after one mistyped password), a CI pipeline assuming its
deployment role and updating stacks and functions, AWS services acting for the account (sign-ins
of service roles, key use), a developer trying something their policy does not allow, and a
reporting job that is denied the same metric call every few minutes.

Once a day the administrator also does what an administrator does: creates a key for the backup
user (rotation), opens a web security group to everyone on port 443 and SSH to the office, and a
developer replaces a phone (MFA device deactivated and a new one enabled). The key rotation and
the MFA replacement are the known false positives of PRH-AWS-005 and PRH-AWS-004, there on
purpose.

Access key ids are 16 characters (``AKIA`` or ``ASIA`` and 12 more), shorter than real ones, so
nothing here looks like a real key to a secret scanner.
"""

import hashlib
import json
from datetime import datetime
from typing import Any

from prohori.simulate.addresses import AddressPool
from prohori.simulate.background import BROWSERS
from prohori.simulate.model import Attack, Recorder

ACCOUNT = "111122223333"
REGION = "ap-southeast-1"
DEVELOPERS = ("amina", "rafiq", "nusrat", "tanvir")
ADMIN = "it-admin"
REPORTS = "svc-reports"
BACKUP = "svc-backup"
CI_ROLE = "ci-deploy"
TRAIL = "management-events"
#: The GitHub Actions subject the CI pipeline's role trusts.
REPOSITORY = "repo:example/shop:ref:refs/heads/main"
CLI = (
    "aws-cli/2.17.50 md/awscrt#0.21.2 ua/2.0 os/linux#6.8.0-45-generic md/arch#x86_64 "
    "lang/python#3.12.6 md/pyimpl#CPython cfg/retry-mode#standard"
)
SDK = (
    "Boto3/1.35.20 md/Botocore#1.35.20 ua/2.0 os/linux#6.8.0 md/arch#x86_64 "
    "lang/python#3.12.3 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.35.20"
)
CI_AGENT = "aws-sdk-js/3.654.0 ua/2.0 os/linux#6.5.0-1025-azure lang/js md/nodejs#20.17.0"

#: Read-only calls developers make from the command line: (service, event name).
READS = (
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeSecurityGroups"),
    ("s3.amazonaws.com", "ListBuckets"),
    ("logs.amazonaws.com", "DescribeLogGroups"),
    ("logs.amazonaws.com", "FilterLogEvents"),
    ("lambda.amazonaws.com", "ListFunctions20150331"),
    ("cloudformation.amazonaws.com", "DescribeStacks"),
    ("ecr.amazonaws.com", "DescribeRepositories"),
    ("sts.amazonaws.com", "GetCallerIdentity"),
    ("rds.amazonaws.com", "DescribeDBInstances"),
)
#: Calls a developer's policy does not allow.
FORBIDDEN = (
    ("iam.amazonaws.com", "ListRoles"),
    ("secretsmanager.amazonaws.com", "GetSecretValue"),
    ("iam.amazonaws.com", "GetAccountAuthorizationDetails"),
    ("organizations.amazonaws.com", "DescribeOrganization"),
)
#: What the CI pipeline changes when it deploys.
DEPLOYS = (
    ("cloudformation.amazonaws.com", "UpdateStack"),
    ("lambda.amazonaws.com", "UpdateFunctionCode20150331v2"),
    ("ecr.amazonaws.com", "PutImage"),
    ("cloudformation.amazonaws.com", "DescribeStackEvents"),
)
#: Calls AWS services make for the account.
SERVICE_CALLS = (
    ("sts.amazonaws.com", "AssumeRole", "lambda.amazonaws.com"),
    ("kms.amazonaws.com", "Decrypt", "secretsmanager.amazonaws.com"),
    ("ec2.amazonaws.com", "CreateTags", "cloudformation.amazonaws.com"),
    ("sts.amazonaws.com", "AssumeRole", "ecs-tasks.amazonaws.com"),
)
#: What a stolen key is tried on, one service after another.
ENUMERATION = (
    ("iam.amazonaws.com", "ListUsers"),
    ("iam.amazonaws.com", "ListRoles"),
    ("iam.amazonaws.com", "ListPolicies"),
    ("iam.amazonaws.com", "GetAccountAuthorizationDetails"),
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeSnapshots"),
    ("rds.amazonaws.com", "DescribeDBInstances"),
    ("secretsmanager.amazonaws.com", "ListSecrets"),
    ("ssm.amazonaws.com", "DescribeParameters"),
    ("lambda.amazonaws.com", "ListFunctions20150331"),
    ("kms.amazonaws.com", "ListKeys"),
    ("dynamodb.amazonaws.com", "ListTables"),
)
_DENIAL = {
    "ec2.amazonaws.com": "Client.UnauthorizedOperation",
    "kms.amazonaws.com": "AccessDeniedException",
    "dynamodb.amazonaws.com": "AccessDeniedException",
    "ssm.amazonaws.com": "AccessDeniedException",
}


def _key(prefix: str, seed: str) -> str:
    """A 16-character access key id: the prefix and 12 characters derived from ``seed``."""
    return prefix + hashlib.sha256(seed.encode()).hexdigest()[:12].upper()


def _uuid(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def iam_user(name: str, *, console: bool = False, mfa: bool = False) -> dict[str, Any]:
    """An IAM user: with a console session's temporary key, or the user's long-term key."""
    identity: dict[str, Any] = {
        "type": "IAMUser",
        "principalId": "AIDA" + hashlib.sha256(name.encode()).hexdigest()[:17].upper(),
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "accessKeyId": _key("ASIA" if console else "AKIA", f"{name}:{console}"),
        "userName": name,
    }
    if console:
        identity["sessionContext"] = {
            "sessionIssuer": {},
            "webIdFederationData": {},
            "attributes": {"mfaAuthenticated": "true" if mfa else "false"},
        }
    return identity


def role_session(role: str, session: str) -> dict[str, Any]:
    principal = "AROA" + hashlib.sha256(role.encode()).hexdigest()[:17].upper()
    return {
        "type": "AssumedRole",
        "principalId": f"{principal}:{session}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}",
        "accountId": ACCOUNT,
        "accessKeyId": _key("ASIA", f"{role}:{session}"),
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": principal,
                "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                "accountId": ACCOUNT,
                "userName": role,
            },
            "webIdFederationData": {},
            "attributes": {"mfaAuthenticated": "false"},
        },
    }


def service(name: str) -> dict[str, Any]:
    return {"type": "AWSService", "invokedBy": name}


class CloudTrailLog:
    """Writes CloudTrail records (JSON Lines, as CloudWatch Logs or EventBridge deliver them)."""

    def __init__(self, rec: Recorder) -> None:
        self.rec = rec
        self.count = 0

    def call(
        self,
        when: datetime,
        source: str,
        name: str,
        identity: dict[str, Any],
        *,
        ip: str,
        agent: str,
        request: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        denied: bool = False,
        event_type: str = "AwsApiCall",
        additional: dict[str, Any] | None = None,
        error_message: str | None = None,
        attack: Attack | None = None,
    ) -> None:
        self.count += 1
        record: dict[str, Any] = {
            "eventVersion": "1.11",
            "userIdentity": identity,
            "eventTime": f"{when:%Y-%m-%dT%H:%M:%SZ}",
            "eventSource": source,
            "eventName": name,
            "awsRegion": "us-east-1"
            if source in {"iam.amazonaws.com", "signin.amazonaws.com"}
            else REGION,
            "sourceIPAddress": ip,
            "userAgent": agent,
        }
        if denied:
            record["errorCode"] = _DENIAL.get(source, "AccessDenied")
            record["errorMessage"] = (
                f"User: {identity.get('arn', '')} is not authorized to perform: "
                f"{source.split('.')[0]}:{name}"
            )
        elif error_message:
            record["errorMessage"] = error_message
        record["requestParameters"] = request
        record["responseElements"] = response
        if additional:
            record["additionalEventData"] = additional
        seed = f"{self.count}:{record['eventTime']}:{name}"
        record.update(
            {
                "requestID": _uuid("request:" + seed),
                "eventID": _uuid("event:" + seed),
                "readOnly": name.startswith(("Describe", "List", "Get", "Filter")),
                "eventType": event_type,
                "managementEvent": True,
                "recipientAccountId": ACCOUNT,
                "eventCategory": "Management",
            }
        )
        self.rec.add(when, json.dumps(record, separators=(",", ":")), attack)

    def console_login(
        self,
        when: datetime,
        identity: dict[str, Any],
        ip: str,
        agent: str,
        *,
        ok: bool,
        mfa: bool,
        attack: Attack | None = None,
    ) -> None:
        identity = {k: v for k, v in identity.items() if k not in {"accessKeyId", "sessionContext"}}
        self.call(
            when,
            "signin.amazonaws.com",
            "ConsoleLogin",
            identity,
            ip=ip,
            agent=agent,
            response={"ConsoleLogin": "Success" if ok else "Failure"},
            event_type="AwsConsoleSignIn",
            additional={
                "LoginTo": "https://console.aws.amazon.com/console/home",
                "MobileVersion": "No",
                "MFAUsed": "Yes" if mfa else "No",
            },
            error_message=None if ok else "Failed authentication",
            attack=attack,
        )


#: The user name CloudTrail writes for a sign-in with a name that does not exist.
HIDDEN = {
    "type": "IAMUser",
    "accountId": ACCOUNT,
    "accessKeyId": "",
    "userName": "HIDDEN_DUE_TO_SECURITY_REASONS",
}


def account_background(
    rec: Recorder, pool: AddressPool, duration: int, noise: float
) -> CloudTrailLog:
    """A working day in the account; returns the log so the attack keeps counting records."""
    log = CloudTrailLog(rec)
    rng = rec.rng
    homes = {name: pool.household() for name in (*DEVELOPERS, ADMIN)}
    agents = {name: rng.choice(BROWSERS[:3]) for name in homes}
    ci = pool.internet_host()
    reports = pool.internet_host()  # the reporting job runs on a server outside AWS
    # Everyone signs in to the console once in the morning, with MFA.
    for name in homes:
        minute = rng.uniform(0, 30)
        if rng.random() < 0.25:  # a mistyped password first
            log.console_login(
                rec.at(minute - 0.3), iam_user(name), homes[name], agents[name], ok=False, mfa=False
            )
        log.console_login(
            rec.at(minute), iam_user(name), homes[name], agents[name], ok=True, mfa=True
        )
    run = 0
    for _ in range(round(duration * noise)):
        minute = rng.uniform(0, duration)
        when = rec.at(minute)
        roll = rng.random()
        name = rng.choice(DEVELOPERS)
        if roll < 0.35:  # a developer's command-line tool reads the account
            source, call = rng.choice(READS)
            log.call(when, source, call, iam_user(name), ip=homes[name], agent=CLI)
        elif roll < 0.5:  # a console session
            source, call = rng.choice(READS[:7])
            log.call(
                when,
                source,
                call,
                iam_user(name, console=True, mfa=True),
                ip=homes[name],
                agent=agents[name],
            )
        elif roll < 0.6:  # the CI pipeline deploys
            run += 1
            session = f"gh-actions-{9100 + run}"
            log.call(
                when,
                "sts.amazonaws.com",
                "AssumeRoleWithWebIdentity",
                {
                    "type": "WebIdentityUser",
                    "principalId": f"token.actions.githubusercontent.com:{REPOSITORY}",
                    "userName": REPOSITORY,
                    "identityProvider": "token.actions.githubusercontent.com",
                },
                ip=ci,
                agent=CI_AGENT,
                request={
                    "roleArn": f"arn:aws:iam::{ACCOUNT}:role/{CI_ROLE}",
                    "roleSessionName": session,
                },
            )
            for step, (source, call) in enumerate(DEPLOYS):
                log.call(
                    rec.at(minute + 0.2 + step * 0.3),
                    source,
                    call,
                    role_session(CI_ROLE, session),
                    ip=ci,
                    agent=CI_AGENT,
                )
        elif roll < 0.8:  # AWS services act for the account
            source, call, by = rng.choice(SERVICE_CALLS)
            log.call(when, source, call, service(by), ip=by, agent=by)
        elif roll < 0.85:  # a developer tries something their policy does not allow
            source, call = rng.choice(FORBIDDEN)
            log.call(
                when,
                source,
                call,
                iam_user(name, console=True, mfa=True),
                ip=homes[name],
                agent=agents[name],
                denied=True,
            )
        else:  # the reporting job is denied the same metric call it has been denied for weeks
            log.call(
                when,
                "monitoring.amazonaws.com",
                "GetMetricData",
                iam_user(REPORTS),
                ip=reports,
                agent=SDK,
                denied=True,
            )
    admin = iam_user(ADMIN, console=True, mfa=True)
    home, agent = homes[ADMIN], agents[ADMIN]
    # The administrator rotates the backup user's key (a known false positive of PRH-AWS-005).
    minute = rng.uniform(40, duration - 20)
    log.call(
        rec.at(minute),
        "iam.amazonaws.com",
        "CreateAccessKey",
        admin,
        ip=home,
        agent=agent,
        request={"userName": BACKUP},
        response={
            "accessKey": {
                "accessKeyId": _key("AKIA", "backup-new"),
                "status": "Active",
                "userName": BACKUP,
            }
        },
    )
    log.call(
        rec.at(minute + 5),
        "iam.amazonaws.com",
        "UpdateAccessKey",
        admin,
        ip=home,
        agent=agent,
        request={
            "userName": BACKUP,
            "accessKeyId": _key("AKIA", "backup-old"),
            "status": "Inactive",
        },
    )
    # ... opens the shop's load balancer to everyone on 443 and SSH to the office only.
    minute = rng.uniform(40, duration - 20)
    log.call(
        rec.at(minute),
        "ec2.amazonaws.com",
        "AuthorizeSecurityGroupIngress",
        admin,
        ip=home,
        agent=agent,
        request=ingress("sg-0c4f1e2d3b5a69780", [("tcp", 443, ["0.0.0.0/0"], ["::/0"])]),
        response={"_return": True},
    )
    log.call(
        rec.at(minute + 1),
        "ec2.amazonaws.com",
        "AuthorizeSecurityGroupIngress",
        admin,
        ip=home,
        agent=agent,
        request=ingress("sg-0c4f1e2d3b5a69781", [("tcp", 22, [f"{home}/32"], [])]),
        response={"_return": True},
    )
    # A developer replaces a phone (a known false positive of PRH-AWS-004).
    name = rng.choice(DEVELOPERS)
    minute = rng.uniform(40, duration - 20)
    serial = f"arn:aws:iam::{ACCOUNT}:mfa/{name}-phone"
    user = iam_user(name, console=True, mfa=True)
    log.call(
        rec.at(minute),
        "iam.amazonaws.com",
        "DeactivateMFADevice",
        user,
        ip=homes[name],
        agent=agents[name],
        request={"userName": name, "serialNumber": serial},
    )
    log.call(
        rec.at(minute + 2),
        "iam.amazonaws.com",
        "EnableMFADevice",
        user,
        ip=homes[name],
        agent=agents[name],
        request={"userName": name, "serialNumber": serial + "-2"},
    )
    # A developer creates a key for themselves (not an alert).
    name = rng.choice(DEVELOPERS)
    log.call(
        rec.at(rng.uniform(40, duration - 20)),
        "iam.amazonaws.com",
        "CreateAccessKey",
        iam_user(name, console=True, mfa=True),
        ip=homes[name],
        agent=agents[name],
        response={
            "accessKey": {
                "accessKeyId": _key("AKIA", f"{name}-new"),
                "status": "Active",
                "userName": name,
            }
        },
    )
    return log


def ingress(
    group: str, rules: list[tuple[str, int | None, list[str], list[str]]]
) -> dict[str, Any]:
    """``requestParameters`` of AuthorizeSecurityGroupIngress: (protocol, port, IPv4, IPv6)."""
    items = []
    for protocol, port, v4, v6 in rules:
        item: dict[str, Any] = {"ipProtocol": protocol if port is not None else "-1"}
        if port is not None:
            item["fromPort"] = item["toPort"] = port
        item["groups"] = {}
        item["ipRanges"] = {"items": [{"cidrIp": c} for c in v4]} if v4 else {}
        item["ipv6Ranges"] = {"items": [{"cidrIpv6": c} for c in v6]} if v6 else {}
        item["prefixListIds"] = {}
        items.append(item)
    return {"groupId": group, "ipPermissions": {"items": items}}
