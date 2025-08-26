from aws_scanner import (
    find_public_s3_buckets,
    find_over_permissive_iam_policies,
    find_open_security_groups
)
from report_generator import print_report, generate_pdf_report

def main():
    print("Starting Cloud Security Misconfiguration Scanner...\n")

    public_buckets = find_public_s3_buckets()
    permissive_policies = find_over_permissive_iam_policies()
    open_security_groups = find_open_security_groups()

    print_report(public_buckets, permissive_policies, open_security_groups)
    generate_pdf_report(public_buckets, permissive_policies, open_security_groups)

if __name__ == "__main__":
    main()
