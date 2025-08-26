# Cloud Security Misconfiguration Scanner

## Overview
This project scans AWS cloud resources to detect common security misconfigurations such as:
- Publicly accessible S3 buckets
- Overly permissive IAM policies
- Security groups open to the internet

## Setup Instructions

1. Install Python 3.x.
2. Install dependencies:
3. Configure AWS credentials:
- Use `aws configure` command from AWS CLI (recommended).
- Or set environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`.
4. Adjust `AWS_REGION` in `config.py` if needed.

## Running the Scanner

Run this command in your terminal:
