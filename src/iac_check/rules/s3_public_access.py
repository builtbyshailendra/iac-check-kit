"""Rule: every S3 bucket blocks public access.

A bucket is covered when all four public access settings are on. They can come
from a bucket-level aws_s3_bucket_public_access_block, an account-level
aws_s3_account_public_access_block, or a mix of both: AWS applies whichever is
stricter, so a setting counts as on if either level turns it on.

A setting that is left out defaults to false in the AWS provider, so a missing
setting counts as off.
"""
from __future__ import annotations

from iac_check.parse import Module, Ref, Resource, Unknown
from iac_check.rules import FAIL, PASS, UNKNOWN, Finding, Rule

RULE_ID = "s3-public-access-block"
SETTINGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)

ON, OFF, CANT_TELL = "on", "off", "can't tell"


def _setting(module: Module, block: Resource, name: str) -> str:
    value = module.resolve(block.attrs.get(name, False))
    if value is True:
        return ON
    if value is False:
        return OFF
    return CANT_TELL


def _targets(module: Module, block: Resource, bucket: Resource) -> bool | None:
    """Does this public access block point at this bucket? None means can't tell."""
    target = module.resolve(block.attrs.get("bucket"))
    if isinstance(target, Ref):
        return target.address == bucket.address
    if isinstance(target, str):
        name = module.resolve(bucket.attrs.get("bucket"))
        return isinstance(name, str) and target == name
    return None


def _combine(values: list[str]) -> str:
    if ON in values:
        return ON
    if CANT_TELL in values:
        return CANT_TELL
    return OFF


def _join(words: list[str]) -> str:
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


def check(module: Module) -> list[Finding]:
    findings = []
    account_blocks = module.of_type("aws_s3_account_public_access_block")
    bucket_blocks = module.of_type("aws_s3_bucket_public_access_block")

    for bucket in module.of_type("aws_s3_bucket"):
        mine = [b for b in bucket_blocks if _targets(module, b, bucket)]
        unclear = [b for b in bucket_blocks if _targets(module, b, bucket) is None]
        sources = mine + account_blocks

        if not sources:
            if unclear:
                reason = (
                    "No public access block clearly points at this bucket. "
                    f"Can't tell where {unclear[0].address} points"
                )
                findings.append(Finding.for_resource(RULE_ID, bucket, UNKNOWN, reason))
            else:
                reason = "No public access block for this bucket, and none at account level"
                findings.append(Finding.for_resource(RULE_ID, bucket, FAIL, reason))
            continue

        state = {s: _combine([_setting(module, b, s) for b in sources]) for s in SETTINGS}
        off = [s for s in SETTINGS if state[s] == OFF]
        unsure = [s for s in SETTINGS if state[s] == CANT_TELL]
        via = _join([b.address for b in sources])

        if off:
            verb = "is" if len(off) == 1 else "are"
            reason = f"{_join(off)} {verb} off ({via})"
            findings.append(Finding.for_resource(RULE_ID, bucket, FAIL, reason))
        elif unsure:
            reason = f"Can't tell if {_join(unsure)} {'is' if len(unsure) == 1 else 'are'} on ({via})"
            findings.append(Finding.for_resource(RULE_ID, bucket, UNKNOWN, reason))
        else:
            reason = f"All four settings are on ({via})"
            findings.append(Finding.for_resource(RULE_ID, bucket, PASS, reason))

    return findings


RULE = Rule(RULE_ID, "S3 buckets block public access", check)
