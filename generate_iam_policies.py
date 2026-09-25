"""
generate_iam_policies.py
Author: Sasikumar (Sasi) — Cloud Architect & Security Specialist

Generates the complete IAM Policy Comparison dataset (Before vs. After)
for all 19 Lambda execution roles and Step Functions state machines
across all four serverless projects.
"""

import json
import os

POLICY_COMPARISONS = {
    "metadata": {
        "title": "AWS Serverless Security Hardening Sprint — IAM Least-Privilege Policy Comparison",
        "author": "Sasikumar (Sasi) — Cloud Architect & Security Specialist",
        "internship": "F13 Technologies Production Hardening Sprint 5",
        "deliverable_file": "02_IAM_Policy_Comparison_All_Projects.pdf",
        "date": "2026-09-25",
        "region": "ap-south-1",
        "account_id": "123456789012"
    },
    "projects": [
        {
            "project_id": "P1",
            "project_name": "Smart Leave & Absence Management System (SLAMS)",
            "description": "Serverless multi-level employee leave management and approval system.",
            "roles": [
                {
                    "function_name": "submitLeaveRequest",
                    "role_name": "SLAMS-SubmitLeaveRequest-Role",
                    "purpose": "Validates request payload, queries employee balances and existing bookings for overlap, auto-rejects or starts Step Functions workflow.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "WildcardDynamoDBAccess",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "WildcardStatesAccess",
                                "Effect": "Allow",
                                "Action": "states:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "WildcardSESAccess",
                                "Effect": "Allow",
                                "Action": "ses:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "WildcardLogs",
                                "Effect": "Allow",
                                "Action": "logs:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedDynamoDBReadBalancesAndRequests",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Query"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_balances",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests/index/*"
                                ]
                            },
                            {
                                "Sid": "ScopedDynamoDBWriteRequestsOnly",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests"
                            },
                            {
                                "Sid": "EnforceSingleWriterOnBalances",
                                "Effect": "Deny",
                                "Action": [
                                    "dynamodb:UpdateItem",
                                    "dynamodb:DeleteItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_balances"
                            },
                            {
                                "Sid": "ScopedStepFunctionsStartExecution",
                                "Effect": "Allow",
                                "Action": "states:StartExecution",
                                "Resource": "arn:aws:states:ap-south-1:123456789012:stateMachine:SLAMS-Approval-StateMachine"
                            },
                            {
                                "Sid": "ScopedSESNotification",
                                "Effect": "Allow",
                                "Action": "ses:SendEmail",
                                "Resource": "arn:aws:ses:ap-south-1:123456789012:identity/notifications@slams-corp.internal"
                            },
                            {
                                "Sid": "ScopedCloudWatchLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/submitLeaveRequest:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated full account administrative DynamoDB, Step Functions, and SES permissions. Restricted writes strictly to 'leave_requests'. Explicitly enforced the Single-Writer Principle by adding an explicit Deny on 'leave_balances' mutation, ensuring only finalizeApprovalRequest can alter balances."
                },
                {
                    "function_name": "approveRejectRequest",
                    "role_name": "SLAMS-ApproveRejectRequest-Role",
                    "purpose": "Verifies HMAC cryptographic token from email callback link and sends task success/failure to paused Step Functions execution.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "FullSecretsManagerAccess",
                                "Effect": "Allow",
                                "Action": "secretsmanager:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "FullStepFunctionsAccess",
                                "Effect": "Allow",
                                "Action": "states:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "FullDynamoDBAccess",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedSecretsManagerReadSecretOnly",
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:smart-leave/approval-token-*"
                            },
                            {
                                "Sid": "ScopedStepFunctionsResumeTask",
                                "Effect": "Allow",
                                "Action": [
                                    "states:SendTaskSuccess",
                                    "states:SendTaskFailure"
                                ],
                                "Resource": "arn:aws:states:ap-south-1:123456789012:stateMachine:SLAMS-Approval-StateMachine"
                            },
                            {
                                "Sid": "ScopedDynamoDBUpdateLeaveStatus",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:UpdateItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests"
                            },
                            {
                                "Sid": "ScopedCloudWatchLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/approveRejectRequest:*"
                            }
                        ]
                    },
                    "risk_analysis": "Revoked full administrative access across Secrets Manager and Step Functions. Restricted Secrets Manager to GetSecretValue on the specific approval-token secret; limited Step Functions actions strictly to callback resumption (SendTaskSuccess/SendTaskFailure) and scoped DynamoDB mutations to leave_requests."
                },
                {
                    "function_name": "finalizeApprovalRequest",
                    "role_name": "SLAMS-FinalizeApprovalRequest-Role",
                    "purpose": "Designated authoritative single-writer for employee balance deduction and final status transition.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "WildcardDynamoDB",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AuthoritativeBalanceUpdater",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:UpdateItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_balances",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests"
                                ]
                            },
                            {
                                "Sid": "ScopedCloudWatchLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/finalizeApprovalRequest:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated table scanning and wildcard access across all account tables. Granted precise UpdateItem and GetItem rights on leave_balances and leave_requests, upholding data integrity and audit compliance."
                },
                {
                    "function_name": "reportsCalendar",
                    "role_name": "SLAMS-ReportsCalendar-Role",
                    "purpose": "Queries leave balances, approved employee requests, and departmental calendar views.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "WildcardDynamoDB",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ReadOnlyDynamoDBAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Query",
                                    "dynamodb:BatchGetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests/index/*",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_balances",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_config"
                                ]
                            },
                            {
                                "Sid": "HRAdminConfigUpdateOnly",
                                "Effect": "Allow",
                                "Action": "dynamodb:PutItem",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_config"
                            },
                            {
                                "Sid": "ScopedCloudWatchLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/reportsCalendar:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated full write/delete capabilities on operational tables. Confined write actions solely to leave_config for HRAdmin settings, while restricting query operations to GSIs."
                },
                {
                    "function_name": "notifyManager / notifyHRAdmin",
                    "role_name": "SLAMS-Notifications-Role",
                    "purpose": "Fetches approval signing secret and sends push alerts via SNS topic and emails via SES.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "WildcardSNSAndSES",
                                "Effect": "Allow",
                                "Action": [
                                    "sns:*",
                                    "ses:*",
                                    "secretsmanager:*"
                                ],
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedSNSPublish",
                                "Effect": "Allow",
                                "Action": "sns:Publish",
                                "Resource": "arn:aws:sns:ap-south-1:123456789012:ManagerApprovalTopic"
                            },
                            {
                                "Sid": "ScopedSESSend",
                                "Effect": "Allow",
                                "Action": [
                                    "ses:SendEmail",
                                    "ses:SendRawEmail"
                                ],
                                "Resource": "arn:aws:ses:ap-south-1:123456789012:identity/notifications@slams-corp.internal"
                            },
                            {
                                "Sid": "ScopedSecretsManagerRead",
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": "arn:aws:secretsmanager:ap-south-1:123456789012:secret:smart-leave/approval-token-*"
                            },
                            {
                                "Sid": "ScopedCloudWatchLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/notify*:*"
                            }
                        ]
                    },
                    "risk_analysis": "Removed broad permissions to publish to arbitrary SNS topics or send unauthorized emails from any unverified domain. Restricted Secrets Manager access solely to reading the token secret."
                },
                {
                    "function_name": "carryForwardAndSummary",
                    "role_name": "SLAMS-CarryForwardAndSummary-Role",
                    "purpose": "Scheduled EventBridge cron function calculating leave carry-forwards and generating weekly HR digests.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "WildcardAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:*",
                                    "ses:*"
                                ],
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedBalancesMaintenance",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:Scan",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_balances"
                            },
                            {
                                "Sid": "ScopedRequestsSummaryRead",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:Query",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/leave_requests/index/*"
                                ]
                            },
                            {
                                "Sid": "ScopedSESDigest",
                                "Effect": "Allow",
                                "Action": "ses:SendEmail",
                                "Resource": "arn:aws:ses:ap-south-1:123456789012:identity/notifications@slams-corp.internal"
                            },
                            {
                                "Sid": "ScopedCloudWatchLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/carryForwardAndSummary:*"
                            }
                        ]
                    },
                    "risk_analysis": "Constrained table operations strictly to leave_balances and leave_requests, preventing cross-table data corruption; scoped email dispatch to verified corporate sender."
                }
            ]
        },
        {
            "project_id": "P2",
            "project_name": "Internal LMS (Quiz & Certification Subsystem)",
            "description": "Serverless learning management system assessing skills and issuing verifiable certificates.",
            "roles": [
                {
                    "function_name": "QuizManagementFunction",
                    "role_name": "LMS-QuizManagement-Role",
                    "purpose": "Creates, updates, and retrieves quiz questions and answer keys for courses.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "SAMDynamoDBCrudPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:DeleteItem",
                                    "dynamodb:PutItem",
                                    "dynamodb:Scan",
                                    "dynamodb:Query",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:BatchWriteItem",
                                    "dynamodb:BatchGetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/QuizzesTable",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/QuizzesTable/index/*"
                                ]
                            },
                            {
                                "Sid": "LambdaBasicLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:*:*:*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "GranularQuizManagement",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Query",
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/QuizzesTable"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/QuizManagementFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Removed broad BatchWriteItem, DeleteItem, and Scan privileges; removed wildcard log resource 'arn:aws:logs:*:*:*', scoping log streams to function-specific log group."
                },
                {
                    "function_name": "QuizGradingFunction",
                    "role_name": "LMS-QuizGrading-Role",
                    "purpose": "Grades employee quiz submissions, records completions, and synchronously invokes CertificateGenerationFunction on passing.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "CompletionsCrud",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/CompletionsTable"
                            },
                            {
                                "Sid": "QuizzesRead",
                                "Effect": "Allow",
                                "Action": "dynamodb:GetItem",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/QuizzesTable"
                            },
                            {
                                "Sid": "WildcardInvoke",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "GranularCompletionsAccess",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/CompletionsTable"
                            },
                            {
                                "Sid": "GranularQuizzesRead",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Query"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/QuizzesTable"
                            },
                            {
                                "Sid": "ScopedCertificateLambdaInvoke",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": "arn:aws:lambda:ap-south-1:123456789012:function:CertificateGenerationFunction"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/QuizGradingFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated account-wide 'lambda:InvokeFunction *' vulnerability, which could allow invoking arbitrary administrative or destructive Lambdas. Scoped target function strictly to CertificateGenerationFunction ARN."
                },
                {
                    "function_name": "CertificateGenerationFunction",
                    "role_name": "LMS-CertificateGeneration-Role",
                    "purpose": "Generates PDF certificates, stores them in S3, records metadata in DynamoDB, and dispatches credential emails via SES.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "CertificatesCrud",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/CertificatesTable"
                            },
                            {
                                "Sid": "S3CrudPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "s3:DeleteObject",
                                    "s3:ListBucket"
                                ],
                                "Resource": [
                                    "arn:aws:s3:::lms-certificates-bucket",
                                    "arn:aws:s3:::lms-certificates-bucket/*"
                                ]
                            },
                            {
                                "Sid": "SESWildcardCrudPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "ses:SendEmail",
                                    "ses:SendRawEmail",
                                    "ses:GetIdentityVerificationAttributes"
                                ],
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "GranularCertificatesTable",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/CertificatesTable"
                            },
                            {
                                "Sid": "ScopedS3CertificatesPrefixOnly",
                                "Effect": "Allow",
                                "Action": [
                                    "s3:PutObject",
                                    "s3:GetObject"
                                ],
                                "Resource": "arn:aws:s3:::lms-certificates-bucket/certificates/*"
                            },
                            {
                                "Sid": "ScopedSESVerifiedSender",
                                "Effect": "Allow",
                                "Action": [
                                    "ses:SendEmail",
                                    "ses:SendRawEmail"
                                ],
                                "Resource": "arn:aws:ses:ap-south-1:123456789012:identity/cert-issuer@company.com"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/CertificateGenerationFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Fixed CRITICAL wildcard SES violation: replaced 'IdentityName: *' with the specific verified SES sender ARN. Removed s3:DeleteObject and scoped bucket operations strictly to the 'certificates/*' prefix rather than bucket root."
                },
                {
                    "function_name": "VerificationFunction",
                    "role_name": "LMS-Verification-Role",
                    "purpose": "Public read-only verification endpoint validating certificate authenticity.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBReadPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Scan",
                                    "dynamodb:Query",
                                    "dynamodb:BatchGetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/CertificatesTable",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/CertificatesTable/index/*"
                                ]
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "StrictGetItemOnly",
                                "Effect": "Allow",
                                "Action": "dynamodb:GetItem",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/CertificatesTable"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/VerificationFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Revoked Scan and BatchGetItem on public-facing verification Lambda, preventing table-scraping / denial-of-wallet attacks. The function can now only retrieve a single certificate record by exact partition key."
                }
            ]
        },
        {
            "project_id": "P3",
            "project_name": "Smart Employee Onboarding & Identity Service",
            "description": "Serverless identity provisioning and 4-stage onboarding orchestration system.",
            "roles": [
                {
                    "function_name": "CreateEmployeeFunction",
                    "role_name": "Onboarding-CreateEmployee-Role",
                    "purpose": "Creates employee record in DynamoDB, provisions user in Cognito User Pool, and initiates Step Functions workflow.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBCrudPolicy",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/EmployeeOnboardingTable"
                            },
                            {
                                "Sid": "CognitoProvisioning",
                                "Effect": "Allow",
                                "Action": [
                                    "cognito-idp:AdminCreateUser",
                                    "cognito-idp:AdminAddUserToGroup",
                                    "cognito-idp:AdminGetUser"
                                ],
                                "Resource": "arn:aws:cognito-idp:ap-south-1:123456789012:userpool/ap-south-1_xxxxxxxxx"
                            },
                            {
                                "Sid": "StatesExecution",
                                "Effect": "Allow",
                                "Action": "states:StartExecution",
                                "Resource": "arn:aws:states:ap-south-1:123456789012:stateMachine:OnboardingStateMachine"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "GranularDynamoDBEmployeeCreation",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/EmployeeOnboardingTable"
                            },
                            {
                                "Sid": "ScopedCognitoIdpAdmin",
                                "Effect": "Allow",
                                "Action": [
                                    "cognito-idp:AdminCreateUser",
                                    "cognito-idp:AdminAddUserToGroup",
                                    "cognito-idp:AdminGetUser"
                                ],
                                "Resource": "arn:aws:cognito-idp:ap-south-1:123456789012:userpool/ap-south-1_xxxxxxxxx"
                            },
                            {
                                "Sid": "ScopedStatesStartExecution",
                                "Effect": "Allow",
                                "Action": "states:StartExecution",
                                "Resource": "arn:aws:states:ap-south-1:123456789012:stateMachine:OnboardingStateMachine"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/CreateEmployeeFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Reduced DynamoDB access from wildcard crud (dynamodb:*) to specific PutItem and GetItem actions. Maintained Cognito and Step Functions execution bounds strictly to targeted resource ARNs."
                },
                {
                    "function_name": "GetProgressFunction",
                    "role_name": "Onboarding-GetProgress-Role",
                    "purpose": "Queries employee onboarding checklist and stage completion status.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBReadPolicy",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Scan",
                                    "dynamodb:Query",
                                    "dynamodb:BatchGetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/EmployeeOnboardingTable",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/EmployeeOnboardingTable/index/*"
                                ]
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "GranularProgressQuery",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:Query"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/EmployeeOnboardingTable"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/GetProgressFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Removed broad table scan and batch get privileges. Restricted queries to exact employee_id partition key."
                },
                {
                    "function_name": "GetAdminPipelineFunction",
                    "role_name": "Onboarding-GetAdminPipeline-Role",
                    "purpose": "Queries the RecordStatusIndex GSI to provide HR managers with the full pipeline overview.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBReadPolicy",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "GSIQueryOnly",
                                "Effect": "Allow",
                                "Action": "dynamodb:Query",
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/EmployeeOnboardingTable/index/RecordStatusIndex"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/GetAdminPipelineFunction:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated wildcard 'dynamodb:*' across all tables in the account. Restricted operation solely to Query against the specific RecordStatusIndex GSI."
                },
                {
                    "function_name": "OnboardingStateMachine",
                    "role_name": "Onboarding-StateMachine-ExecutionRole",
                    "purpose": "Step Functions state machine role that invokes stage handlers (StartStage, CheckStageStatus, ReminderDispatcher).",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "WildcardLambdaInvoke",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedWorkflowLambdaInvoke",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": [
                                    "arn:aws:lambda:ap-south-1:123456789012:function:StartStage",
                                    "arn:aws:lambda:ap-south-1:123456789012:function:CheckStageStatus",
                                    "arn:aws:lambda:ap-south-1:123456789012:function:ReminderDispatcher"
                                ]
                            }
                        ]
                    },
                    "risk_analysis": "Replaced wildcard 'lambda:InvokeFunction *' with exact ARNs of the three workflow worker functions, preventing unauthorized execution of other sensitive Lambda functions."
                }
            ]
        },
        {
            "project_id": "P4",
            "project_name": "AI-Powered Resume Screener & Talent Acquisition Pipeline",
            "description": "Cloud-native NLP pipeline parsing resumes via Textract and Comprehend, scoring against JDs, and managing dead-letter redrive.",
            "roles": [
                {
                    "function_name": "IngestionFunction",
                    "role_name": "ResumeScreener-Ingestion-Role",
                    "purpose": "Generates pre-signed upload URLs, extracts text via Textract synchronous/asynchronous APIs, and records candidate records.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "S3CrudPolicy",
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "arn:aws:s3:::resume-screener-prod-123456789012-ap-south-1/*"
                            },
                            {
                                "Sid": "DynamoDBCrud",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "TextractWildcard",
                                "Effect": "Allow",
                                "Action": "textract:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "LambdaInvoke",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedS3ResumeBucketPrefixes",
                                "Effect": "Allow",
                                "Action": [
                                    "s3:PutObject",
                                    "s3:GetObject"
                                ],
                                "Resource": [
                                    "arn:aws:s3:::resume-screener-prod-123456789012-ap-south-1/resumes/*",
                                    "arn:aws:s3:::resume-screener-prod-123456789012-ap-south-1/extracted/*"
                                ]
                            },
                            {
                                "Sid": "ScopedDynamoDBCandidatesAndFailures",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/candidates-prod",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/failed_jobs-prod"
                                ]
                            },
                            {
                                "Sid": "TextractDocumentedServiceLimitation",
                                "Effect": "Allow",
                                "Action": [
                                    "textract:DetectDocumentText",
                                    "textract:StartDocumentTextDetection",
                                    "textract:GetDocumentTextDetection"
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:PrincipalAccount": "123456789012",
                                        "aws:RequestedRegion": "ap-south-1"
                                    }
                                }
                            },
                            {
                                "Sid": "ScopedInvokeNlpLambda",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": "arn:aws:lambda:ap-south-1:123456789012:function:resume-screener-nlp-prod"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/resume-screener-ingestion-prod:*"
                            }
                        ]
                    },
                    "risk_analysis": "Constrained S3 operations strictly to 'resumes/*' and 'extracted/*' key prefixes. Scoped DynamoDB to candidates-prod and failed_jobs-prod. Documented Textract service limitation (Textract APIs do not support resource-level ARNs) and mitigated by enforcing aws:PrincipalAccount and aws:RequestedRegion conditions."
                },
                {
                    "function_name": "NlpParserFunction",
                    "role_name": "ResumeScreener-NlpParser-Role",
                    "purpose": "Extracts entities via Comprehend, normalizes candidate metadata, masks PII, and publishes parsed payloads to SQS scoring queue.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "S3Wildcard",
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "DynamoDBCrud",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "ComprehendWildcard",
                                "Effect": "Allow",
                                "Action": "comprehend:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "SQSWildcard",
                                "Effect": "Allow",
                                "Action": "sqs:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedS3ExtractedRead",
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::resume-screener-prod-123456789012-ap-south-1/extracted/*"
                            },
                            {
                                "Sid": "ScopedDynamoDBUpdateCandidateNlp",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:UpdateItem"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/candidates-prod",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/failed_jobs-prod"
                                ]
                            },
                            {
                                "Sid": "ComprehendDocumentedServiceLimitation",
                                "Effect": "Allow",
                                "Action": [
                                    "comprehend:DetectEntities",
                                    "comprehend:DetectKeyPhrases",
                                    "comprehend:DetectDominantLanguage"
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:PrincipalAccount": "123456789012",
                                        "aws:RequestedRegion": "ap-south-1"
                                    }
                                }
                            },
                            {
                                "Sid": "ScopedSQSPublishToScoringQueue",
                                "Effect": "Allow",
                                "Action": "sqs:SendMessage",
                                "Resource": "arn:aws:sqs:ap-south-1:123456789012:resume-screener-scoring-queue-prod"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/resume-screener-nlp-prod:*"
                            }
                        ]
                    },
                    "risk_analysis": "Revoked full S3 and SQS administrative privileges. Scoped SQS strictly to SendMessage on the scoring queue. Documented Comprehend service limitation (APIs do not support resource-level permissions) and constrained execution using aws:PrincipalAccount condition."
                },
                {
                    "function_name": "ScoringFunction",
                    "role_name": "ResumeScreener-Scoring-Role",
                    "purpose": "Consumes candidate payload from SQS, evaluates qualifications against Job Description, and records detailed score breakdown.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBAll",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "SQSAll",
                                "Effect": "Allow",
                                "Action": "sqs:*",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedDynamoDBReadJobsWriteScores",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/jobs-prod"
                            },
                            {
                                "Sid": "ScopedCandidateScoreUpdate",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:UpdateItem",
                                    "dynamodb:GetItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/candidates-prod"
                            },
                            {
                                "Sid": "ScopedFailureLog",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:PutItem"
                                ],
                                "Resource": "arn:aws:dynamodb:ap-south-1:123456789012:table/failed_jobs-prod"
                            },
                            {
                                "Sid": "ScopedSQSConsumeScoringQueue",
                                "Effect": "Allow",
                                "Action": [
                                    "sqs:ReceiveMessage",
                                    "sqs:DeleteMessage",
                                    "sqs:GetQueueAttributes"
                                ],
                                "Resource": "arn:aws:sqs:ap-south-1:123456789012:resume-screener-scoring-queue-prod"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/resume-screener-scoring-prod:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated wildcard table access; granted read-only to jobs-prod and write to candidates-prod. Scoped SQS permissions to Receive/Delete on the scoring queue only."
                },
                {
                    "function_name": "ReliabilityFunction",
                    "role_name": "ResumeScreener-Reliability-Role",
                    "purpose": "Consumes DLQ poison messages, provides failed-job APIs, logs audit events, and redrives jobs to scoring or NLP.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBAll",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "SQSAll",
                                "Effect": "Allow",
                                "Action": "sqs:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "LambdaAll",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": "*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedDynamoDBReliabilityAndAudit",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:Query",
                                    "dynamodb:Scan"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/failed_jobs-prod",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/failed_jobs-prod/index/*",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/audit_events-prod",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/candidates-prod"
                                ]
                            },
                            {
                                "Sid": "ScopedSQSRedriveAndDLQ",
                                "Effect": "Allow",
                                "Action": [
                                    "sqs:SendMessage"
                                ],
                                "Resource": "arn:aws:sqs:ap-south-1:123456789012:resume-screener-scoring-queue-prod"
                            },
                            {
                                "Sid": "ScopedSQSDLQConsume",
                                "Effect": "Allow",
                                "Action": [
                                    "sqs:ReceiveMessage",
                                    "sqs:DeleteMessage",
                                    "sqs:GetQueueAttributes"
                                ],
                                "Resource": "arn:aws:sqs:ap-south-1:123456789012:resume-screener-dlq-prod"
                            },
                            {
                                "Sid": "ScopedRedriveLambdaInvoke",
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": [
                                    "arn:aws:lambda:ap-south-1:123456789012:function:resume-screener-nlp-prod",
                                    "arn:aws:lambda:ap-south-1:123456789012:function:resume-screener-ingestion-prod"
                                ]
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/resume-screener-reliability-prod:*"
                            }
                        ]
                    },
                    "risk_analysis": "Revoked universal Lambda invoke rights. Scoped target redrive functions specifically to NLP and Ingestion ARNs. Divided SQS queue rights between SendMessage on main queue and ReceiveMessage on DLQ."
                },
                {
                    "function_name": "ApiFunction",
                    "role_name": "ResumeScreener-ApiBackend-Role",
                    "purpose": "REST API backend managing job requisitions, candidate pipelines, shortlists, and SES interview invites.",
                    "before_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DynamoDBCrud",
                                "Effect": "Allow",
                                "Action": "dynamodb:*",
                                "Resource": "*"
                            },
                            {
                                "Sid": "SESWildcardIdentity",
                                "Effect": "Allow",
                                "Action": [
                                    "ses:SendEmail",
                                    "ses:SendRawEmail",
                                    "ses:SendTemplatedEmail"
                                ],
                                "Resource": "arn:aws:ses:ap-south-1:123456789012:identity/*"
                            }
                        ]
                    },
                    "after_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ScopedDynamoDBApiOperations",
                                "Effect": "Allow",
                                "Action": [
                                    "dynamodb:GetItem",
                                    "dynamodb:PutItem",
                                    "dynamodb:UpdateItem",
                                    "dynamodb:Query"
                                ],
                                "Resource": [
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/jobs-prod",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/jobs-prod/index/*",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/candidates-prod",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/candidates-prod/index/*",
                                    "arn:aws:dynamodb:ap-south-1:123456789012:table/audit_events-prod"
                                ]
                            },
                            {
                                "Sid": "ScopedSESExactVerifiedSender",
                                "Effect": "Allow",
                                "Action": [
                                    "ses:SendEmail",
                                    "ses:SendRawEmail",
                                    "ses:SendTemplatedEmail"
                                ],
                                "Resource": "arn:aws:ses:ap-south-1:123456789012:identity/recruiter-noreply@company.com"
                            },
                            {
                                "Sid": "ScopedLogs",
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/lambda/resume-screener-api-backend-prod:*"
                            }
                        ]
                    },
                    "risk_analysis": "Eliminated trailing wildcard 'identity/*' on SES, constraining email sending rights to the single verified corporate sender ARN. Scoped DynamoDB operations to exact table ARNs and GSIs."
                }
            ]
        }
    ]
}

def main():
    out_dir = os.path.join(r"c:\Users\sasik\Desktop\F13 Internship\Project 5", "iam_policies")
    os.makedirs(out_dir, exist_ok=True)
    
    full_path = os.path.join(out_dir, "02_iam_policy_comparison_all_projects.json")
    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(POLICY_COMPARISONS, f, indent=2)
    print(f"Generated complete IAM policies comparison at {full_path}")
    
    # Save individual project JSONs for ease of deployment/inspection
    for p in POLICY_COMPARISONS["projects"]:
        p_file = os.path.join(out_dir, f"{p['project_id'].lower()}_{p['project_name'].split()[0].lower()}_iam.json")
        with open(p_file, "w", encoding="utf-8") as f:
            json.dump(p, f, indent=2)
        print(f"  - Wrote {p['project_name']} ({len(p['roles'])} roles) to {p_file}")

if __name__ == "__main__":
    main()
