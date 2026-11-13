# SSH open to the whole internet, in two different ways.
# "bastion" lists 0.0.0.0/0 on port 22 directly.
# "admin" opens every port on every protocol, which includes 22.

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

resource "aws_s3_bucket" "logs" {
  bucket = "demo-app-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "bastion" {
  name = "demo-bastion"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "admin" {
  name = "demo-admin"
}

resource "aws_vpc_security_group_ingress_rule" "admin_all" {
  security_group_id = aws_security_group.admin.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
