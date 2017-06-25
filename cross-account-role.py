""" This script requires you to have IAM permissions in the trusted and trusting account.  It assumes that your
AWS CLI default profile is for the trusting account and that you have a secondary profile for the trusted account. 
For information about creating AWS CLI profiles, see http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html """

import boto3
import re
from botocore.exceptions import ClientError

iam_client = boto3.client('iam')


def get_user_input():
    account_number = raw_input('Enter the account number of the trusting account: ')
    if not is_valid_account(account_number):
        exit()
    role_name = raw_input('Enter the name of the role you want to create: ')
    policy_arn = raw_input('Enter the policy arn of the policy you want to assign to this role: ')
    aws_profile = raw_input('Enter the name of the AWS profile of the trusted account: ')
    policy_name = raw_input('Enter the name for the assume-role policy that you wish to create in the trusted account: ')
    # construct the trust policy document
    iam_policy_document = '{ \
      "Version": "2012-10-17", \
      "Statement": [ \
        { \
          "Effect": "Allow", \
          "Principal": { \
            "AWS": "arn:aws:iam::' + account_number + ':root" \
          }, \
          "Action": "sts:AssumeRole" \
        } \
      ] \
    }'
    return role_name, iam_policy_document, policy_arn, aws_profile, policy_name


def is_valid_account(account_number):
    # account_number = account_number[0:12]
    if (re.search('[0-9]{12}', account_number)) and (len(account_number) == 12):
        return 1
    else:
        print 'You entered an invalid account number.'
        return 0


def create_iam_role(iam_policy_document, role_name):
    # creates role in the trusting account
    try:
        role = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=iam_policy_document,
            Description='Dummy role created by cross-account-role.py'
        )
    except ClientError as err:
        print err
    # capture the arn of the role that was created
    role_arn = role['Role']['Arn']

    # attach a policy to the role in the trusting account
    # this can be a managed policy, e.g. ReadOnly, or a custom policy
    try:
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
    except ClientError as err:
        print err

    return role_arn


def create_assume_role_policy(role_arn, aws_profile, policy_name):
    # switch profiles and create the assume role policy in the trusted account
    session = boto3.Session(profile_name=aws_profile)
    iam_client = session.client('iam')
    assume_role_policy = '{ \
      "Version": "2012-10-17", \
      "Statement": { \
        "Effect": "Allow", \
        "Action": "sts:AssumeRole", \
        "Resource": "' + role_arn + '" \
      } \
    }'
    try:
        iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=assume_role_policy,
            Description='This policy allows you to assume a role in another account'
        )
    except ClientError as err:
        print err


role_name, iam_policy_document, policy_arn, aws_profile, policy_name = get_user_input()
role_arn = create_iam_role(iam_policy_document, role_name)
create_assume_role_policy(role_arn, aws_profile, policy_name)
aws_account_numer = boto3.client('sts').get_caller_identity().get('Account')
print "After assigning the AssumeRolePolicy to an IAM principle in the trusted account, browse to\nhttps://signin.aws.amazon.com/switchrole?account=" + aws_account_numer + "&roleName=" + role_name
