provider "aws" {
  region  = "us-gov-west-1"
}

resource "aws_organizations_policy" "ScpPolicy1" {
  name = "scp_root_account"
  description = "This SCP prevents restricts the root user in an AWS account from taking any action, either directly as a command or through the console. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "*",
      "Resource": "*",
      "Effect": "Deny",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:root"
          ]
        }
      }
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy2" {
  name = "scp_cloudtrail"
  description = "This SCP prevents users or roles in any affected account from disabling a CloudTrail log, either directly as a command or through the console. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy3" {
  name = "scp_config"
  description = "This SCP prevents users or roles in any affected account from running AWS Config operations that could disable AWS Config or alter its rules or triggers. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "config:DeleteConfigRule",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy4" {
  name = "scp_guardduty"
  description = "This SCP prevents users or roles in any affected account from disabling or modifying Amazon GuardDuty settings, either directly as a command or through the console. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:DeleteInvitations",
        "guardduty:DeleteIPSet",
        "guardduty:DeleteMembers",
        "guardduty:DeleteThreatIntelSet",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:UpdateDetector"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy5" {
  name = "scp_securityhub"
  description = "This SCP prevents users or roles in any affected account from disabling AWS Security Hub, deleting member accounts or disassociating an account from a master Security Hub account."
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "securityhub:DeleteInvitations",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromMasterAccount",
        "securityhub:DeleteMembers",
        "securityhub:DisassociateMembers"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy6" {
  name = "scp_organizations"
  description = "This SCP prevents users or roles in any affected account from leaving AWS Organizations, either directly as a command or through the console. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "organizations:LeaveOrganization"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy7" {
  name = "scp_account_billing"
  description = "This SCP prevents users or roles in any affected account from modifying the account and billing settings, either directly as a command or through the console."
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "aws-portal:ModifyAccount",
        "aws-portal:ModifyBilling",
        "aws-portal:ModifyPaymentMethods"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy8" {
  name = "scp_deny_iam_user_creation"
  description = "This SCP restricts IAM principals from creating new IAM users or IAM Access Keys in an AWS account."
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey"
      ],
      "Resource": [
        "*"
      ],
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy9" {
  name = "scp_s3_block_public_access"
  description = "This SCP prevents users or roles in any affected account from modifying the S3 Block Public Access Account Level Settings"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy10" {
  name = "scp_s3_encryption"
  description = "This SCP requires that all Amazon S3 buckets use AES256 encryption in an AWS Account. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "*",
      "Effect": "Deny",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    },
    {
      "Action": [
        "s3:PutObject"
      ],
      "Resource": "*",
      "Effect": "Deny",
      "Condition": {
        "Bool": {
          "s3:x-amz-server-side-encryption": false
        }
      }
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy11" {
  name = "scp_s3"
  description = "This SCP prevents users or roles in any affected account from deleting any S3 bucket or objects. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:DeleteBucket",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy12" {
  name = "scp_kms_delete_keys"
  description = "This SCP prevents users or roles in any affected account from deleting KMS keys, either directly as a command or through the console. "
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "kms:ScheduleKeyDeletion",
        "kms:Delete*"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}

resource "aws_organizations_policy" "ScpPolicy13" {
  name = "scp_s3"
  description = "This SCP prevents users or roles in any affected account from deleting any S3 Glacier vaults or archives"
  content = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "glacier:DeleteArchive",
        "glacier:DeleteVault"
      ],
      "Resource": "*",
      "Effect": "Deny"
    }
  ]
}
POLICY

}