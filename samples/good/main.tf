# A small web app stack written the way the checks expect:
# the log bucket blocks public access, and SSH is only open to the office.

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

variable "office_cidr" {
  description = "Where SSH is allowed from"
  type        = string
  default     = "203.0.113.0/24"
}

resource "aws_s3_bucket" "logs" {
  bucket = "demo-app-logs"

  tags = {
    Name = "demo-app-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "web" {
  name        = "demo-web"
  description = "HTTPS from anywhere, SSH from the office"

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from the office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
