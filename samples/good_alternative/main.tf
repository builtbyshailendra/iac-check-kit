# The same safe setup as samples/good, written a different way.
# A fair check has to pass this too:
#   - public access is blocked once for the whole account, not per bucket
#   - SSH comes from a /32 held in a local, through separate rule resources
#   - SSH also comes from the office over IPv6, on a port range that includes 22

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

variable "jump_host_ip" {
  description = "The one machine allowed to SSH in"
  type        = string
  default     = "198.51.100.10/32"
}

locals {
  ssh_sources = [var.jump_host_ip]
}

resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "demo-app-logs-alt"
}

resource "aws_s3_bucket" "backups" {
  bucket = "demo-app-backups-alt"
}

resource "aws_security_group" "web" {
  name        = "demo-web-alt"
  description = "Rules live in separate resources below"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.web.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_security_group_rule" "ssh_from_jump_host" {
  type              = "ingress"
  security_group_id = aws_security_group.web.id
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = local.ssh_sources
}

resource "aws_vpc_security_group_ingress_rule" "admin_from_office_v6" {
  security_group_id = aws_security_group.web.id
  cidr_ipv6         = "2001:db8:1234::/48"
  ip_protocol       = "tcp"
  from_port         = 20
  to_port           = 25
}
