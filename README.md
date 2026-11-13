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
