# AWS Production Hardening Sprint — Security Hardening Audit

[![Security Hardened](https://img.shields.io/badge/Security-Production%20Hardened-brightgreen.svg)](#)
[![AWS Serverless](https://img.shields.io/badge/AWS-Serverless%20Architecture-orange.svg)](#)
[![IAM Least Privilege](https://img.shields.io/badge/IAM-Least%20Privilege%20Enforced-blue.svg)](#)
[![Cognito Authorizer](https://img.shields.io/badge/API%20Gateway-Cognito%20Secured-purple.svg)](#)
[![Trusted Advisor](https://img.shields.io/badge/Trusted%20Advisor-100%25%20Compliant-success.svg)](#)

**Repository:** `AWS-Production-Hardening-Sprint-`  
**Workstream Owner:** **Sasikumar (Sasi)** — Cloud Architect & Security Specialist  
**Sprint Focus:** Workstream 4: Sasi – Security Hardening Audit (Production Hardening Sprint 5)  
**Organization / Program:** F13 Technologies Final Technical Submission  
**AWS Region & Account:** `ap-south-1` (Asia Pacific - Mumbai) | Account ID: `123456789012`  

---

## 📌 Primary Deliverables & Artifacts

| Deliverable Name | Format | Description / Purpose | File Link |
| :--- | :---: | :--- | :--- |
| **02_IAM_Policy_Comparison_All_Projects.pdf** | **PDF** | **Primary 17-page publication-grade PDF deliverable** containing all 19 Lambda execution roles before/after diffs, storage audit tables, 24 API routes authorization matrix, and Trusted Advisor findings. | [📄 View PDF](02_IAM_Policy_Comparison_All_Projects.pdf) |
| **02_Security_Hardening_Audit_Report.docx** | **Word** | Full technical audit document matching sprint specifications and typography. | [📝 View DOCX](02_Security_Hardening_Audit_Report.docx) |
| **02_IAM_Policy_Comparison_All_Projects.md** | **Markdown** | Comprehensive GitHub markdown report (592 lines, 67,000+ characters). | [📖 View Markdown](02_IAM_Policy_Comparison_All_Projects.md) |
| **iam_policies/** | **JSON** | Standalone machine-readable JSON policies Before & After hardening for all 19 roles across all 4 projects. | [📂 Browse Directory](iam_policies/) |
| **hardened_iac/** | **IaC / Code** | Production-hardened SAM/CloudFormation templates and Node.js deployment scripts. | [📂 Browse Directory](hardened_iac/) |
| **audit_all_projects_security.py** | **Python** | Automated multi-project security verification and audit execution script. | [🐍 View Script](audit_all_projects_security.py) |

---

## 🚀 Workstream 4 Task Execution Matrix

| Requirement | Targets / Scope | Status | Evidence / Artifact |
| :--- | :--- | :---: | :--- |
| **1. Review Lambda IAM Roles** | 19 execution roles across Projects 1–4 | **100% COMPLETE** | Section 1 & `iam_policies/` JSONs |
| **2. Remove Wildcard Permissions** | Eliminated `dynamodb:*`, `s3:*`, `ses:*`, `Resource: *` | **100% COMPLETE** | Side-by-side JSON diffs |
| **3. Document IAM Before/After** | Full side-by-side comparison & risk rationale | **100% COMPLETE** | `02_IAM_Policy_Comparison_All_Projects.pdf` |
| **4. Verify S3 & DynamoDB Encryption** | 10 DynamoDB tables (PITR + SSE) & 5 S3 buckets (TLS) | **100% COMPLETE** | Storage Audit Tables below |
| **5. Verify Cognito API Auth** | 24 API Gateway REST and HTTP endpoints | **100% COMPLETE** | Route Authorization Matrix below |
| **6. Run Trusted Advisor Checks** | Security & Fault Tolerance pillars (9 checks) | **100% COMPLETE** | Trusted Advisor Matrix below |
| **7. Document Findings & Fixes** | Complete issue diagnosis & code fixes | **100% COMPLETE** | Hardened IaC templates in `hardened_iac/` |

---

## 🔒 Projects in Scope & Hardening Overview

1. **Project 1: Smart Leave & Absence Management System (SLAMS)**
   - **Compute:** 6 Lambdas (`submitLeaveRequest`, `approveRejectRequest`, `finalizeApprovalRequest`, `reportsCalendar`, `notifyManager`, `carryForwardAndSummary`).
   - **Security Controls:** Replaced wildcard managed policies with scoped ARNs. Enforced **Single-Writer Principle** (only `finalizeApprovalRequest` is authorized to mutate `leave_balances.used`). Configured Cognito JWT Authorizer on protected HTTP API routes while documenting the `GET /approve` HMAC cryptographic webhook exception. Enabled KMS SSE and PITR on DynamoDB tables.

2. **Project 2: Internal LMS (Quiz & Certification Subsystem)**
   - **Compute:** 4 Lambdas (`QuizManagementFunction`, `QuizGradingFunction`, `CertificateGenerationFunction`, `VerificationFunction`).
   - **Security Controls:** Fixed critical wildcard finding on `CertificateGenerationFunction` (`SESCrudPolicy: IdentityName: "*"` -> scoped to verified email ARN). Scoped S3 operations strictly to `certificates/*` prefix. Enabled KMS SSE and PITR on `QuizzesTable`, `CompletionsTable`, and `CertificatesTable`. Enforced Cognito Authorizer on quiz endpoints while preserving public verification on `/verify/{cert_id}`.

3. **Project 3: Smart Employee Onboarding & Identity Service**
   - **Compute:** 6 Lambdas (`CreateEmployeeFunction`, `GetProgressFunction`, `GetAdminPipelineFunction`, workflow stage handlers).
   - **Security Controls:** Configured Cognito Authorizer on `/submit` (restricted to `HRAdmins`), `/admin/pipeline` (`HRAdmins`), and `/progress/{employee_id}`. Enabled KMS SSE and PITR on `EmployeeOnboardingTable`. Scoped Step Functions execution role to explicit task Lambdas.

4. **Project 4: AI-Powered Resume Screener & Talent Acquisition Pipeline**
   - **Compute:** 5 Lambdas (`IngestionFunction`, `NlpParserFunction`, `ScoringFunction`, `ReliabilityFunction`, `ApiFunction`).
   - **Security Controls:** Scoped S3 operations to `resumes/*` and `extracted/*`. Scoped SES permissions to verified recruiter email ARN. Documented AWS service limitations for Amazon Textract OCR and Amazon Comprehend NLP, applying `aws:PrincipalAccount` and `aws:RequestedRegion` condition keys. Verified automated PII masking in CloudWatch logs and DynamoDB audit trails.

---

## 📊 Summary of Storage Encryption & Fault Tolerance (10 Tables & 5 Buckets)

### DynamoDB Encryption & Disaster Recovery
- **100% Tables KMS Encrypted:** All 10 operational tables use AWS KMS Server-Side Encryption (`SSEEnabled: true`).
- **100% PITR Coverage:** Continuous backups enabled across all tables, providing point-in-time recovery for disaster resiliency.
- **Single-Writer Architecture:** Enforced via IAM to prevent race conditions or unauthorized balance updates.

### S3 Storage Security
- **Block Public Access:** All 4 flags (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`) enforced on all 5 buckets.
- **Default Server-Side Encryption:** Enforced AES256 encryption on all stored objects.
- **In-Transit TLS Enforcement:** Bucket policies configured with explicit `Deny` on non-TLS requests (`aws:SecureTransport: false`).
- **S3 Bucket Versioning:** Enabled with 30-day non-current version expiration lifecycle rules.

---

## 🛡️ API Gateway & Cognito Authorization Matrix (24 Endpoints)

- **21 Protected Endpoints:** Protected by Amazon Cognito JWT Authorizers with strict role-group mapping (`Employee`, `Manager`, `HRAdmin` / `HRAdmins`, `Recruiters`).
- **3 Documented Intentional Public Exemptions:**
  1. `GET /approve` (P1 SLAMS): Email one-click approval webhook authenticated via tamper-proof HMAC-SHA256 cryptographic token from AWS Secrets Manager, 48h expiration, and single-use nonce check.
  2. `GET /verify/{cert_id}` (P2 Internal LMS): Public credential registry for employers to verify certificate authenticity without login.
  3. `GET /health` (P4 Resume Screener): Synthetic uptime monitoring and health check probe.

---

## 📈 AWS Trusted Advisor Findings & Remediation

| Pillar | Check Name | Initial Status | Remediation & Code Resolution | Final Status |
| :--- | :--- | :---: | :--- | :---: |
| **Security** | S3 Bucket Permissions | **GREEN** | Verified all 4 BPA flags active across all buckets | **GREEN (OK)** |
| **Security** | Security Groups (Ports) | **GREEN** | Pure serverless architecture; zero open security groups | **GREEN (OK)** |
| **Security** | IAM Least Privilege | **YELLOW** | Eliminated wildcards; scoped ARNs & condition keys | **GREEN (RESOLVED)** |
| **Security** | MFA on Root Account | **GREEN** | Hardware/virtual TOTP MFA active on root | **GREEN (OK)** |
| **Security** | Secrets Manager Rotation | **YELLOW** | Added 90-day automatic rotation Lambda hook for signing secret | **GREEN (RESOLVED)** |
| **Fault Tol.** | DynamoDB PITR | **RED** | Hardened IaC templates and enabled continuous backups on all tables | **GREEN (RESOLVED)** |
| **Fault Tol.** | S3 Bucket Versioning | **YELLOW** | Enabled S3 Versioning & 30-day lifecycle rule | **GREEN (RESOLVED)** |
| **Fault Tol.** | Lambda DLQs & Resilience | **GREEN** | Configured `ResumeScoringDLQ` with maxReceiveCount: 3 and redrive | **GREEN (OK)** |
| **Fault Tol.** | Step Functions Retries | **GREEN** | Configured exponential backoff retries & timeout catch handlers | **GREEN (OK)** |

---

## 🧪 Automated Testing & Verification

Run the automated security verification tool to validate the configuration across all four projects:

```bash
# Run multi-project security audit
python audit_all_projects_security.py

# Run unit tests verifying S3 BPA, KMS SSE, DynamoDB PITR, and PII masking
cd "c:/Users/sasik/Desktop/F13 Internship/project 4"
python -m unittest tests/test_security_audit.py
```

**Verification Results:**
```text
Ran 8 tests in 0.001s - OK
  ✓ test_s3_buckets_block_public_access (PASSED)
  ✓ test_s3_buckets_enforce_server_side_encryption (PASSED)
  ✓ test_dynamodb_point_in_time_recovery (PASSED)
  ✓ test_iam_least_privilege_no_wildcard_admin (PASSED)
  ✓ test_pii_masking_email (PASSED)
  ✓ test_pii_masking_phone (PASSED)
  ✓ test_sanitized_error_handling (PASSED)
  ✓ test_cors_and_security_headers (PASSED)
```

---

## 👥 Authors & Acknowledgments

- **Sasikumar (Sasi)** — Cloud Architect & Security Specialist (Author of Workstream 4)
- **Team F13 Internship** — Production Hardening Sprint 5