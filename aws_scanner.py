import boto3
import json

def find_public_s3_buckets_by_acl():
    s3 = boto3.client('s3')
    bucket_list = s3.list_buckets()
    public_buckets_acl = []
    for bucket in bucket_list['Buckets']:
        bucket_name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                # Check if bucket is public via 'AllUsers' or 'AuthenticatedUsers'
                if grantee.get('URI') in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    public_buckets_acl.append(bucket_name)
                    break
        except Exception:
            # Could be permission error or no access - skip silently
            continue
    return public_buckets_acl

def find_public_s3_buckets_by_policy():
    s3 = boto3.client('s3')
    bucket_list = s3.list_buckets()
    public_buckets_policy = []
    for bucket in bucket_list['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_dict = json.loads(policy['Policy'])
            for statement in policy_dict.get('Statement', []):
                if statement.get('Effect') == 'Allow' and (statement.get('Principal') == "*" or statement.get('Principal', {}).get('AWS') == "*"):
                    actions = statement.get('Action', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    resources = statement.get('Resource', [])
                    if not isinstance(resources, list):
                        resources = [resources]
                    if "s3:GetObject" in actions or "s3:*" in actions:
                        for resource in resources:
                            if resource.endswith("/*") and bucket_name in resource:
                                public_buckets_policy.append(bucket_name)
                                break
        except s3.exceptions.NoSuchBucketPolicy:
            # No bucket policy, skip
            continue
        except Exception:
            # Any other exception ignore
            continue
    return public_buckets_policy

def find_public_s3_buckets():
    # Combine buckets found by ACL and policy checks without duplicates
    acl_buckets = find_public_s3_buckets_by_acl()
    policy_buckets = find_public_s3_buckets_by_policy()
    combined = list(set(acl_buckets + policy_buckets))
    return combined

def find_over_permissive_iam_policies():
    iam = boto3.client('iam')
    over_permissive_policies = []

    paginator = iam.get_paginator('list_policies')
    for page in paginator.paginate(Scope='Local'):
        for policy in page['Policies']:
            policy_arn = policy['Arn']
            versions = iam.list_policy_versions(PolicyArn=policy_arn)
            default_version = next((v for v in versions['Versions'] if v['IsDefaultVersion']), None)
            if default_version:
                version_info = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version['VersionId']
                )
                document = version_info['PolicyVersion']['Document']
                statements = document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for stmt in statements:
                    actions = stmt.get('Action', [])
                    resources = stmt.get('Resource', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]
                    if '*' in actions or '*' in resources:
                        over_permissive_policies.append(policy['PolicyName'])
                        break
    return over_permissive_policies

def find_open_security_groups():
    ec2 = boto3.client('ec2')
    open_groups = []
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        for perm in sg.get('IpPermissions', []):
            for ip_range in perm.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    open_groups.append(sg['GroupName'])
                    break
    return open_groups
