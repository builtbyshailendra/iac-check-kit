# iac-check-kit

**Small Python checks that grade Terraform for common mistakes, and explain the result in plain words.**

> Personal learning project. Every bucket, CIDR and account here is made up.

## Why

When Terraform is written quickly, by a person or by a model, two mistakes turn up again and again: a bucket that can be made public, and SSH open to the whole internet. This kit reads the `.tf` files, checks those rules, and writes a report that says what it checked, what passed, what failed and why.

## Samples

| Folder | What it is |
|---|---|
| `samples/good` | A log bucket with public access blocked, SSH only from the office CIDR |
| `samples/flawed_public_bucket` | One bucket with no public access block, one with only half the settings on |
| `samples/flawed_open_ssh` | SSH from `0.0.0.0/0`, once directly and once by opening every port |

Every sample passes `terraform validate`. The flawed ones are valid Terraform; they're just not safe.

## Build log

### Step 1: samples

**Built:** three small stacks, one good and two flawed, each a valid root module pinned to the AWS provider 6.x.

### Step 2: read the Terraform

**Built:** a loader that reads every `.tf` file in a folder with `python-hcl2`, plus a `list` command.

**Learned:** python-hcl2 version 8 keeps the quotes around strings by default, so a bucket name comes back as `"\"demo-app-logs\""`. One serialization option strips them. References like `var.office_cidr` come back as text such as `${var.office_cidr}`, so the loader follows variable defaults and locals itself, and marks anything it can't follow without running Terraform as unknown instead of guessing.

### Step 3: rule 1, buckets block public access

**Built:** a small rule framework (each rule returns one finding per resource: pass, fail or unknown, with a reason) and the first rule. A bucket passes when all four public access settings are on. They can come from the bucket's own block, an account-level block, or both, because AWS applies whichever is stricter. A setting that's left out counts as off, since that's the provider default.

**What broke:** findings pointed one line above the resource. The line search used `^\s*resource`, and `\s*` also matches a newline, so it started on the blank line before the block. Changing it to `^[ \t]*` fixed it, and a test now checks the line.

### Step 4: rule 2, no SSH open to the whole internet

**Built:** the second rule. It reads all three ways the AWS provider lets you write ingress: `ingress` blocks inside a security group, `aws_security_group_rule`, and `aws_vpc_security_group_ingress_rule`. A rule fails when it allows TCP (or every protocol) on a port range that includes 22, from a CIDR with a `/0` prefix, so both `0.0.0.0/0` and `::/0` count.

**Learned:** the easy version only looks for `from_port = 22` and `"0.0.0.0/0"` side by side. That misses protocol `-1` (every port), a range like 20-25, TCP written as `"6"`, IPv6, and an open CIDR hidden behind a variable. Each of those now has its own test.

### Step 5: JSON report and command line

**Built:** `python -m iac_check check <folder>` runs every rule and prints a short report. `--json FILE` also writes the same result as JSON, with pass, fail and "can't tell" counts per rule. The exit code is 1 when anything fails, so CI can gate on it. `--strict` makes "can't tell" fail too.

**What broke:** a test expected the bastion finding on line 31. I had copied that number from the output before the line fix in Step 3. The file shows it on line 32, so the test was wrong, not the code.
