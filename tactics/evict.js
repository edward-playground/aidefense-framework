export const evictTactic = {
    "name": "Evict",
    "purpose": "The \"Evict\" tactic focuses on the active removal of an adversary's presence from a compromised AI system and the elimination of any malicious artifacts they may have introduced. Once an intrusion or malicious activity has been detected and contained, eviction procedures are executed to ensure the attacker is thoroughly expelled, their access mechanisms are dismantled, and any lingering malicious code, data, or configurations are purged.",
    "techniques": [
        {
            "id": "AID-E-001",
            "name": "Credential Revocation & Rotation for AI Systems",
            "description": "Immediately revoke, invalidate, or rotate any credentials (e.g., API keys, access tokens, user account passwords, service account credentials, certificates) that are known or suspected to have been compromised or used by an adversary to gain unauthorized access to or interact maliciously with AI systems, models, data, or MLOps pipelines. This action aims to cut off the attacker's current access and prevent them from reusing stolen credentials.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0012 Valid Accounts",
                        "AML.TA0004 Initial Access (stolen creds)",
                        "AML.T0055 Unsecured Credentials"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Identity Attack / Compromised Agent Registry (L7)",
                        "Unauthorized access via stolen credentials"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM02:2025 Sensitive Information Disclosure (if creds stolen)",
                        "LLM06:2025 Excessive Agency (if agent creds compromised)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML05:2023 Model Theft (if via compromised creds)"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-E-001.001",
                    "name": "Foundational Credential Management", "pillar": "infra", "phase": "response",
                    "description": "This sub-technique covers the standard, proactive lifecycle management and incident response for credentials associated with human users and traditional services (e.g., database accounts, long-lived service account keys). It includes essential security hygiene practices like regularly rotating secrets, as well as reactive measures such as forcing password resets and cleaning up unauthorized accounts after a compromise has been detected.",
                    "toolsOpenSource": [
                        "Cloud provider CLIs/SDKs (AWS CLI, gcloud, Azure CLI)",
                        "HashiCorp Vault",
                        "Keycloak",
                        "Ansible, Puppet, Chef (for orchestrating credential updates)"
                    ],
                    "toolsCommercial": [
                        "Privileged Access Management (PAM) solutions (CyberArk, Delinea, BeyondTrust)",
                        "Identity-as-a-Service (IDaaS) platforms (Okta, Ping Identity, Auth0)",
                        "Cloud Provider Secret Managers (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0012 Valid Accounts",
                                "AML.T0055 Unsecured Credentials"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Unauthorized access via stolen credentials (Cross-Layer)",
                                "Compromised Service Accounts (L4)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM02:2025 Sensitive Information Disclosure (if via compromised user credentials)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML05:2023 Model Theft (if via compromised user credentials)"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Implement a rapid rotation process for all secrets.",
                            "howTo": "<h5>Concept:</h5><p>Regularly and automatically rotating secrets (like database passwords or API keys) limits the useful lifetime of any single credential, reducing the window of opportunity for an attacker if one is compromised. This should be handled by a dedicated secret management service.</p><h5>Step 1: Use a Secret Manager's Built-in Rotation</h5><p>Services like AWS Secrets Manager, Azure Key Vault, and HashiCorp Vault have built-in capabilities to automatically rotate secrets. This typically involves a linked serverless function that knows how to generate a new secret and update it in both the secret manager and the target service.</p><h5>Step 2: Configure Automated Rotation</h5><p>This example uses Terraform to configure an AWS Secrets Manager secret to rotate every 30 days using a pre-existing rotation Lambda function.</p><pre><code># File: infrastructure/secrets_management.tf (Terraform)\n\n# 1. The secret itself (e.g., a database password)\nresource \"aws_secretsmanager_secret\" \"db_password\" {\n  name = \"production/database/master_password\"\n}\n\n# 2. The rotation configuration\nresource \"aws_secretsmanager_secret_rotation\" \"db_password_rotation\" {\n  secret_id = aws_secretsmanager_secret.db_password.id\n  \n  # This ARN points to a Lambda function capable of rotating this secret type\n  # AWS provides templates for common services like RDS, Redshift, etc.\n  rotation_lambda_arn = \"arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRDSMySQLRotation\"\n\n  rotation_rules {\n    # Automatically trigger the rotation every 30 days\n    automatically_after_days = 30\n  }\n}</code></pre><p><strong>Action:</strong> Store all application secrets in a dedicated secret management service. Use the service's built-in features to configure automated rotation for all secrets on a regular schedule (e.g., every 30, 60, or 90 days).</p>"
                        },
                        {
                            "strategy": "Force password resets for compromised user accounts.",
                            "howTo": "<h5>Concept:</h5><p>If a user's account is suspected of compromise (e.g., their credentials are found in a breach dump, or they report a phishing attempt), you must immediately invalidate their current password and force them to create a new one at their next login. This evicts an attacker who is relying on a stolen password.</p><h5>Write a Script to Force Password Reset</h5><p>This script can be used by your security operations team as part of their incident response process. It uses the cloud provider's SDK to administratively expire the user's current password.</p><pre><code># File: incident_response/force_password_reset.py\nimport boto3\nimport argparse\n\ndef force_aws_user_password_reset(user_name: str):\n    \"\"\"Forces an IAM user to reset their password on next sign-in.\"\"\" \n    iam_client = boto3.client('iam')\n    try:\n        iam_client.update_login_profile(\n            UserName=user_name,\n            PasswordResetRequired=True\n        )\n        print(f\"✅ Successfully forced password reset for user: {user_name}\")\n    except iam_client.exceptions.NoSuchEntityException:\n        print(f\"Error: User {user_name} does not have a login profile or does not exist.\")\n    except Exception as e:\n        print(f\"An error occurred: {e}\")\n\n# --- SOC Analyst Usage ---\n# parser = argparse.ArgumentParser()\n# parser.add_argument(\"--user\", required=True)\n# args = parser.parse_args()\n# force_aws_user_password_reset(args.user)</code></pre><p><strong>Action:</strong> Develop a script or automated playbook that allows your security team to immediately force a password reset for any user account suspected of compromise. The user should be unable to log in again until they have completed the password reset flow, which should ideally require re-authentication with MFA.</p>"
                        },
                        {
                            "strategy": "Remove unauthorized accounts or API keys created by an attacker.",
                            "howTo": "<h5>Concept:</h5><p>A common persistence technique for attackers is to create their own 'backdoor' access by creating a new IAM user or generating new API keys for an existing user. A crucial part of eviction is to audit for and remove any credentials that were created during the time of the compromise.</p><h5>Write an Audit Script to Find Recently Created Credentials</h5><p>This script iterates through all users and their access keys, flagging any that were created within a suspicious timeframe for manual review and deletion.</p><pre><code># File: incident_response/audit_new_credentials.py\nimport boto3\nfrom datetime import datetime, timedelta, timezone\n\ndef find_credentials_created_since(days_ago: int):\n    \"\"\"Finds all IAM users and access keys created in the last N days.\"\"\"\n    iam = boto3.client('iam')\n    suspicious_credentials = []\n    since_date = datetime.now(timezone.utc) - timedelta(days=days_ago)\n\n    for user in iam.list_users()['Users']:\n        if user['CreateDate'] > since_date:\n            suspicious_credentials.append(f\"User '{user['UserName']}' created at {user['CreateDate']}\")\n        \n        for key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:\n            if key['CreateDate'] > since_date:\n                suspicious_credentials.append(f\"Key '{key['AccessKeyId']}' for user '{user['UserName']}' created at {key['CreateDate']}\")\n    \n    return suspicious_credentials\n\n# --- SOC Analyst Usage ---\n# The breach was detected 2 days ago, so we check for anything created in the last 3 days.\n# recently_created = find_credentials_created_since(days_ago=3)\n# print(\"Found recently created credentials for review:\", recently_created)</code></pre><p><strong>Action:</strong> As part of your incident response process, run an audit script to list all users and credentials created since the suspected start of the incident. Manually review this list and delete any unauthorized entries.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-001.002",
                    "name": "Automated & Real-time Invalidation", "pillar": "infra", "phase": "response",
                    "description": "This sub-technique covers the immediate, automated, and reactive side of credential eviction. It focuses on integrating security alerting with response workflows to automatically disable compromised credentials the moment they are detected. It also addresses the challenge of ensuring that revocations for stateless tokens (like JWTs) are propagated and enforced in real-time to immediately terminate an attacker's session.",
                    "toolsOpenSource": [
                        "Cloud provider automation (AWS Lambda, Azure Functions, Google Cloud Functions)",
                        "SOAR platforms (Shuffle, TheHive with Cortex)",
                        "In-memory caches (Redis, Memcached) for revocation lists",
                        "API Gateways (Kong, Tyk)"
                    ],
                    "toolsCommercial": [
                        "SOAR Platforms (Palo Alto XSOAR, Splunk SOAR, Torq)",
                        "Cloud-native alerting/eventing (Amazon EventBridge, Azure Event Grid)",
                        "EDR/XDR solutions with automated response (CrowdStrike, SentinelOne)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0012 Valid Accounts (by immediately disabling the account)",
                                "AML.T0017 Persistence (by removing the attacker's credential-based access)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Unauthorized access via stolen credentials (Cross-Layer)",
                                "Lateral Movement (Cross-Layer)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM02:2025 Sensitive Information Disclosure (by stopping an active breach)",
                                "LLM06:2025 Excessive Agency (by disabling a compromised agent's credentials)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML05:2023 Model Theft (by terminating the session used for theft)"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Automate credential invalidation upon security alert.",
                            "howTo": "<h5>Concept:</h5><p>Manual response to a leaked credential alert is too slow. When a security service (like AWS GuardDuty or a GitHub secret scanner) detects a compromised key, it should trigger an automated workflow that immediately disables the key, cutting off attacker access within seconds.</p><h5>Step 1: Create a Serverless Invalidation Function</h5><p>Write a serverless function (e.g., AWS Lambda) that is programmed to disable a specific type of credential. This function will be the action-taking component of your automated response.</p><pre><code># File: eviction_automations/invalidate_aws_key.py\nimport boto3\nimport json\n\ndef lambda_handler(event, context):\n    \"\"\"This Lambda is triggered by a security alert for a compromised AWS key.\"\"\"\n    iam_client = boto3.client('iam')\n    \n    # Extract the compromised Access Key ID from the security event\n    # The exact path depends on the event source (e.g., GuardDuty, EventBridge)\n    access_key_id = event['detail']['resource']['accessKeyDetails']['accessKeyId']\n    user_name = event['detail']['resource']['accessKeyDetails']['userName']\n    \n    print(f\"Attempting to disable compromised key {access_key_id} for user {user_name}\")\n    try:\n        # Set the key's status to Inactive. This immediately blocks it.\n        iam_client.update_access_key(\n            UserName=user_name,\n            AccessKeyId=access_key_id,\n            Status='Inactive'\n        )\n        message = f\"✅ Successfully disabled compromised AWS key {access_key_id}\"\n        print(message)\n        # send_slack_notification(message)\n    except Exception as e:\n        print(f\"❌ Failed to disable key {access_key_id}: {e}\")\n\n    return {'statusCode': 200}\n</code></pre><h5>Step 2: Trigger the Function from a Security Alert</h5><p>Use your cloud provider's event bus (e.g., Amazon EventBridge) to create a rule that invokes your Lambda function whenever a specific security finding occurs.</p><pre><code># Conceptual EventBridge Rule:\n#\n# Event Source: AWS GuardDuty\n# Event Type: 'GuardDuty Finding'\n# Event Pattern: { \"detail\": { \"type\": [ \"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration\" ] } }\n# Target: Lambda Function 'invalidate_aws_key'</code></pre><p><strong>Action:</strong> Create a serverless function with the sole permission to disable credentials. Configure your security monitoring system to trigger this function automatically whenever a credential exposure alert is generated.</p>"
                        },
                        {
                            "strategy": "Ensure prompt propagation of revocation for stateless tokens.",
                            "howTo": "<h5>Concept:</h5><p>Revoking a stateless token like a JWT is challenging because it contains its own expiration data and requires no server-side lookup by default. To invalidate one before it expires, your API must perform a real-time check against a revocation list (denylist) for every single request.</p><h5>Step 1: Maintain a Revocation List in a Fast Cache</h5><p>When a token is revoked (e.g., a user logs out or an admin disables a token), add its unique identifier (`jti` claim) to a list in a high-speed cache like Redis. Set the Time-To-Live (TTL) on this entry to match the token's remaining validity to keep the list from growing indefinitely.</p><pre><code># When a user logs out or a token is revoked\nimport redis\nimport jwt\nimport time\n\n# jti = get_jti_from_token(token_to_revoke)\n# exp = get_expiry_from_token(token_to_revoke)\nr = redis.Redis()\n# Calculate the remaining TTL for the token\nremaining_ttl = max(0, exp - int(time.time()))\nif remaining_ttl > 0:\n    r.set(f\"jwt_revoked:{jti}\", \"revoked\", ex=remaining_ttl)</code></pre><h5>Step 2: Check the Revocation List During API Authentication</h5><p>In your API's authentication middleware, after cryptographically verifying the JWT's signature and standard claims, perform one final check to see if its `jti` is on the revocation list.</p><pre><code># File: api/auth_middleware.py\n# In your token validation logic for your API endpoint\nfrom fastapi import Depends, HTTPException\n\ndef validate_token_with_revocation_check(token: str):\n    # 1. Standard validation (signature, expiry, audience, issuer)\n    # payload = jwt.decode(token, public_key, ...)\n    payload = {}\n\n    # 2. **CRITICAL:** Check against the revocation list\n    jti = payload.get('jti')\n    if not jti:\n        raise HTTPException(status_code=401, detail=\"Token missing JTI claim\")\n    \n    # Perform a quick lookup in Redis\n    if redis_client.exists(f\"jwt_revoked:{jti}\"):\n        raise HTTPException(status_code=401, detail=\"Token has been revoked\")\n\n    # If all checks pass, the token is valid\n    return payload</code></pre><p><strong>Action:</strong> Ensure your JWTs contain a unique identifier (`jti`) claim. In your API authentication middleware, after verifying the token's signature, perform a lookup in a Redis cache to ensure the token's `jti` has not been added to a revocation list.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-001.003",
                    "name": "AI Agent & Workload Identity Revocation", "pillar": "infra, app", "phase": "response",
                    "description": "This sub-technique covers the specialized task of revoking credentials and identities for non-human, AI-specific entities. It addresses modern, ephemeral identity types like those used by autonomous agents and containerized workloads, such as short-lived mTLS certificates, cloud workload identities (e.g., IAM Roles for Service Accounts), and SPIFFE Verifiable Identity Documents (SVIDs). The goal is to immediately evict a compromised AI workload from the trust domain.",
                    "toolsOpenSource": [
                        "Workload Identity Systems (SPIFFE/SPIRE)",
                        "Service Mesh (Istio, Linkerd)",
                        "Cloud provider IAM for workloads (AWS IRSA, GCP Workload Identity)",
                        "Certificate management tools (cert-manager, OpenSSL)"
                    ],
                    "toolsCommercial": [
                        "Enterprise Service Mesh (Istio-based platforms like Tetrate, Solo.io)",
                        "Public Key Infrastructure (PKI) solutions (Venafi, DigiCert)",
                        "Cloud Provider IAM"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0073 Impersonation",
                                "AML.T0017 Persistence (if using a compromised workload identity)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Agent Identity Attack (L7)",
                                "Compromised Agent Registry (L7)",
                                "Lateral Movement (Cross-Layer, from a compromised agent)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM06:2025 Excessive Agency (by revoking the identity of the overreaching agent)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML06:2023 AI Supply Chain Attacks (if a compromised workload is the result)"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Revoke/reissue compromised AI agent cryptographic identities (SVIDs).",
                            "howTo": "<h5>Concept:</h5><p>In a modern workload identity system like SPIFFE/SPIRE, each agent has a registered 'entry' on the SPIRE server that defines how it can be identified. Deleting this entry immediately prevents the agent from being able to request or renew its identity document (SVID), effectively and instantly evicting it from the trust domain.</p><h5>Step 1: Get the Entry ID for the Compromised Agent</h5><p>Use the SPIRE server command-line tool to find the unique Entry ID associated with the compromised agent's SPIFFE ID. This is a necessary prerequisite for deletion.</p><pre><code># This command would be run by a security administrator as part of an incident response.\n\n# Find the Entry ID for the compromised agent's identity\n> ENTRY_ID=$(spire-server entry show -spiffeID spiffe://example.org/agent/compromised-agent | grep \"Entry ID\" | awk '{print $3}')\n\n# Verify you have the correct ID\n> echo \"Entry ID to be deleted: $ENTRY_ID\"</code></pre><h5>Step 2: Delete the Registration Entry to Revoke Identity</h5><p>Once you have the Entry ID, use the `entry delete` command. This is an immediate revocation. The compromised agent will no longer be able to get a valid SVID and will be unable to authenticate to any other service in the mesh.</p><pre><code># Delete the entry. This is an immediate and irreversible revocation.\n> spire-server entry delete -entryID $ENTRY_ID\n# Expected Output: Entry deleted successfully.\n\n# The compromised agent process is now evicted from the trust domain.</code></pre><p><strong>Action:</strong> For agentic systems using a workload identity platform like SPIFFE/SPIRE, the primary eviction mechanism is to delete the compromised agent's registration entry from the identity server. This immediately revokes its ability to operate within your trusted environment.</p>"
                        },
                        {
                            "strategy": "Rotate credentials for cloud-based AI workloads (e.g., IAM Roles for Service Accounts).",
                            "howTo": "<h5>Concept:</h5><p>For AI workloads running in a cloud-native environment like Kubernetes, access to cloud APIs (like S3 or a database) is often granted via a temporary role assumption mechanism (e.g., AWS IRSA or GCP Workload Identity). To evict a compromised workload, you can break the link between its service account and the cloud IAM role it is allowed to assume.</p><h5>Remove the Trust Policy or IAM Binding</h5><p>The most direct way to evict the workload is to remove the IAM policy that allows the Kubernetes service account to assume the cloud role. This example shows removing a GCP IAM policy binding.</p><pre><code># Assume a compromise is detected in a pod using the 'compromised-ksa' Kubernetes Service Account.\n\nKSA_NAME=\"compromised-ksa\"\nK8S_NAMESPACE=\"ai-production\"\nGCP_PROJECT_ID=\"my-gcp-project\"\nGCP_IAM_SERVICE_ACCOUNT=\"my-gcp-sa@${GCP_PROJECT_ID}.iam.gserviceaccount.com\"\n\n# This command removes the IAM policy binding between the KSA and the GCP Service Account.\n# The pod can no longer generate GCP access tokens.\ngcloud iam service-accounts remove-iam-policy-binding ${GCP_IAM_SERVICE_ACCOUNT} \\\n    --project=${GCP_PROJECT_ID} \\\n    --role=\"roles/iam.workloadIdentityUser\" \\\n    --member=\"serviceAccount:${GCP_PROJECT_ID}.svc.id.goog[${K8S_NAMESPACE}/${KSA_NAME}]\"</code></pre><p><strong>Action:</strong> If a Kubernetes-based AI workload is compromised, evict it from your cloud control plane by removing the IAM policy binding that grants its Kubernetes Service Account the permission to impersonate a cloud IAM service account.</p>"
                        },
                        {
                            "strategy": "Use short-lived certificates and rely on expiration for mTLS revocation.",
                            "howTo": "<h5>Concept:</h5><p>Traditional certificate revocation via Certificate Revocation Lists (CRLs) or OCSP can be slow and complex to manage. A more modern, robust pattern is to issue certificates with very short lifetimes (e.g., 5-15 minutes). With this approach, 'revocation' is simply the act of not issuing a new certificate. An evicted agent will have its current certificate expire within minutes, automatically losing its ability to authenticate.</p><h5>Step 1: Configure a Certificate Authority for Short Lifetimes</h5><p>In your PKI or service mesh's certificate authority (CA), configure a policy to issue certificates with a very short Time-To-Live (TTL).</p><pre><code># Conceptual configuration for a CA like cert-manager or Istio's CA\n\nca_policy:\n  # Set the default lifetime for all issued workload certificates to 10 minutes.\n  default_certificate_ttl: \"10m\"\n  # Set the maximum allowed TTL to 1 hour, preventing requests for long-lived certs.\n  max_certificate_ttl: \"1h\"\n</code></pre><h5>Step 2: Implement Logic to Deny Re-issuance</h5><p>The core of the eviction is to block the compromised agent from getting its *next* certificate. This is done by deleting its identity entry (as in the first strategy) or adding its ID to a blocklist checked by the CA during issuance requests.</p><pre><code># Conceptual logic in the CA's issuance process\n\ndef should_issue_certificate(agent_id, csr):\n    # Check a revocation blocklist (e.g., stored in Redis or a DB)\n    if is_agent_id_revoked(agent_id):\n        print(f\"Denying certificate renewal for revoked agent: {agent_id}\")\n        return False\n    \n    # If not revoked, proceed with issuance\n    return True</code></pre><p><strong>Action:</strong> Architect your mTLS infrastructure to issue very short-lived certificates (e.g., 15 minutes or less) to all AI workloads. Eviction is then achieved by preventing the compromised workload from being issued a new certificate, causing it to be automatically locked out upon the expiration of its current one.</p>"
                        }
                    ]
                }
            ]
        },
        {
            "id": "AID-E-002",
            "name": "AI Process & Session Eviction", "pillar": "infra, app", "phase": "response",
            "description": "Terminate any running AI model instances, agent processes, user sessions, or containerized workloads that are confirmed to be malicious, compromised, or actively involved in an attack. This immediate action halts the adversary's ongoing activities within the AI system and removes their active foothold.",
            "toolsOpenSource": [
                "OS process management (kill, pkill, taskkill)",
                "Container orchestration CLIs (kubectl delete pod --force)",
                "HIPS (OSSEC, Wazuh)",
                "Custom scripts for session clearing (Redis FLUSHDB)"
            ],
            "toolsCommercial": [
                "EDR solutions (CrowdStrike, SentinelOne, Carbon Black)",
                "Cloud provider management consoles/APIs for instance termination",
                "APM tools with session management"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.TA0005 Execution (stops active malicious code)",
                        "AML.T0051 LLM Prompt Injection / AML.T0054 LLM Jailbreak (terminates manipulated session)",
                        "AML.T0017 Persistence (if via running process/session)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Tool Misuse / Agent Goal Manipulation (L7, terminating rogue agent)",
                        "Resource Hijacking (L4, killing resource-abusing processes)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (ending manipulated session)",
                        "LLM06:2025 Excessive Agency (terminating overreaching agent)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "Any attack resulting in a malicious running process (e.g., ML06:2023 AI Supply Chain Attacks)"
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Identify and kill malicious AI model/inference server processes.",
                    "howTo": "<h5>Concept:</h5><p>When an Endpoint Detection and Response (EDR) tool or other monitor identifies a specific Process ID (PID) as malicious, the immediate response is to terminate that OS process. This forcefully stops the attacker's active execution on the server.</p><h5>Implement a Process Termination Script</h5><p>Create a script that can be triggered by an automated alert. This script takes a PID as an argument and attempts to terminate it gracefully first, then forcefully if necessary. Using a library like `psutil` makes this cross-platform and more robust than simple `os.kill`.</p><pre><code># File: eviction_scripts/kill_process.py\\nimport psutil\\nimport time\\n\ndef evict_process_by_pid(pid: int):\\n    \\\"\\\"\\\"Finds and terminates a process by its PID.\\\"\\\"\\\"\\n    try:\\n        proc = psutil.Process(pid)\\n        print(f\\\"Found process {pid}: {proc.name()} started at {proc.create_time()}\\\")\\n        \n        # First, try to terminate gracefully (sends SIGTERM)\\n        print(f\\\"Sending SIGTERM to PID {pid}...\\\")\\n        proc.terminate()\\n        \n        # Wait a moment to see if it exits\\n        try:\\n            proc.wait(timeout=3) # Wait up to 3 seconds\\n            print(f\\\"✅ Process {pid} terminated gracefully.\\\")\\n            log_eviction_event(pid, \\\"SIGTERM\\\")\\n        except psutil.TimeoutExpired:\\n            # If it didn't terminate, kill it forcefully (sends SIGKILL)\\n            print(f\\\"Process {pid} did not respond. Sending SIGKILL...\\\")\\n            proc.kill()\\n            proc.wait()\\n            print(f\\\"✅ Process {pid} forcefully killed.\\\")\\n            log_eviction_event(pid, \\\"SIGKILL\\\")\n\n    except psutil.NoSuchProcess:\\n        print(f\\\"Error: Process with PID {pid} not found.\\\")\\n    except Exception as e:\\n        print(f\\\"An error occurred: {e}\\\")\n</code></pre><p><strong>Action:</strong> Develop a script that can terminate a process by its PID. This script should be part of your incident response toolkit and callable by automated SOAR playbooks. When an EDR alert for your AI server fires, the playbook should automatically invoke this script with the malicious PID identified in the alert.</p>"
                },
                {
                    "strategy": "Forcefully terminate/reset hijacked AI agent sessions/instances.",
                    "howTo": "<h5>Concept:</h5><p>For a stateful AI agent, simply killing the process may not be enough. Its hijacked state (e.g., a poisoned memory or a manipulated goal) might be persisted in a shared cache like Redis. A full session eviction requires both terminating the process and purging its persisted state.</p><h5>Implement a Session Eviction Function</h5><p>Create a function that orchestrates the two-step eviction process. It first calls the orchestrator (e.g., Kubernetes) to delete the agent's pod, then connects to the cache to delete any data associated with that agent's session ID.</p><pre><code># File: eviction_scripts/evict_agent_session.py\\nimport redis\\nimport kubernetes.client\\n\ndef evict_agent_session(agent_id: str, pod_name: str, namespace: str):\\n    \\\"\\\"\\\"Terminates an agent's process and purges its cached state.\\\"\\\"\\\"\\n    print(f\\\"Initiating eviction for agent {agent_id}...\\\")\n    \n    # 1. Terminate the containerized process\\n    try:\\n        # Load Kubernetes config\\n        kubernetes.config.load_incluster_config()\\n        api = kubernetes.client.CoreV1Api()\\n        # Delete the pod forcefully and immediately\\n        api.delete_namespaced_pod(\\n            name=pod_name,\\n            namespace=namespace,\\n            body=kubernetes.client.V1DeleteOptions(grace_period_seconds=0)\\n        )\\n        print(f\\\"Deleted pod {pod_name} for agent {agent_id}.\\\")\\n    except Exception as e:\\n        print(f\\\"Failed to delete pod for agent {agent_id}: {e}\\\")\n\n    # 2. Purge persisted session state from Redis\\n    try:\\n        r = redis.Redis()\\n        # Find all keys related to this agent's session\\n        keys_to_delete = list(r.scan_iter(f\\\"session:{agent_id}:*\\\"))\\n        if keys_to_delete:\\n            r.delete(*keys_to_delete)\\n            print(f\\\"Purged {len(keys_to_delete)} cache entries for agent {agent_id}.\\\")\\n    except Exception as e:\\n        print(f\\\"Failed to purge cache for agent {agent_id}: {e}\\\")\n\n    log_eviction_event(agent_id, \\\"FULL_EVICTION\\\")\n    print(f\\\"✅ Eviction complete for agent {agent_id}.\\\")</code></pre><p><strong>Action:</strong> When an agent is confirmed to be hijacked, trigger an eviction playbook that first uses the orchestrator's API to delete the agent's running instance, and then deletes all keys matching the agent's session ID from your Redis or other state-caching system.</p>"
                },
                {
                    "strategy": "Quarantine/shut down compromised pods/containers in Kubernetes.",
                    "howTo": "<h5>Concept:</h5><p>In a container orchestration system like Kubernetes, the most effective way to evict a compromised pod is to simply delete it. The parent controller (like a Deployment or ReplicaSet) will automatically detect the missing pod and launch a new, clean instance based on the original, known-good container image. This ensures a rapid return to a secure state.</p><h5>Use `kubectl` for Immediate, Forceful Deletion</h5><p>The `kubectl delete pod` command is the standard tool for this. Using the `--force` and `--grace-period=0` flags ensures the pod is terminated immediately, without giving the process inside any time to perform cleanup actions (which an attacker might hijack).</p><pre><code># This command would be run by an administrator or a SOAR playbook\\n# during an incident response.\n\n# The name of the pod identified as compromised\nCOMPROMISED_POD=\\\"inference-server-prod-5f8b5c7f9-xyz12\\\"\nNAMESPACE=\\\"ai-production\\\"\n\n# Forcefully delete the pod immediately.\n# The ReplicaSet will automatically create a new, clean replacement.\necho \\\"Evicting compromised pod ${COMPROMISED_POD}...\\\"\n\nkubectl delete pod ${COMPROMISED_POD} --namespace ${NAMESPACE} --grace-period=0 --force\n\n# You can then monitor the creation of the new pod\nkubectl get pods -n ${NAMESPACE} -w</code></pre><p><strong>Action:</strong> Add this `kubectl delete pod` command to your incident response playbooks. When a pod is confirmed to be compromised, this is the fastest and most reliable way to evict the attacker and restore the service to a known-good configuration.</p>"
                },
                {
                    "strategy": "Invalidate active user sessions associated with malicious activity.",
                    "howTo": "<h5>Concept:</h5><p>If an attacker steals a user's session cookie, they can impersonate that user until the session expires. To evict the attacker, you must terminate the session on the server side, effectively logging the user (and the attacker) out immediately. This requires using a server-side session store.</p><h5>Step 1: Store Session Data in a Central Cache</h5><p>Instead of using stateless client-side sessions (like a self-contained JWT), store session data in a central cache like Redis, keyed by a random session ID. The cookie sent to the user contains only this random ID.</p><pre><code># In a Flask application, using Flask-Session with a Redis backend\nfrom flask import Flask, session\nfrom flask_session import Session\n\napp = Flask(__name__)\napp.config['SECRET_KEY'] = '...' # For signing the session cookie\napp.config['SESSION_TYPE'] = 'redis' # Use Redis for server-side sessions\napp.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')\nSession(app)\n\n@app.route('/login', methods=['POST'])\ndef login():\n    # ... after validating user credentials ...\n    session['user_id'] = 'user123' # This is stored in Redis, not the cookie\n    return 'Logged in'</code></pre><h5>Step 2: Create an Endpoint to Invalidate the Session</h5><p>Create a secure administrative function that can delete a user's session data from Redis. When the session data is gone, the user's session cookie becomes invalid.</p><pre><code># File: eviction_scripts/invalidate_web_session.py\\n\ndef invalidate_session_for_user(user_id, session_interface):\\n    \\\"\\\"\\\"Invalidates all sessions for a given user.\\\"\\\"\\\"\\n    # This requires an index to map user_id to their session IDs\\n    # For simplicity, we assume we have the session ID to delete.\\n    session_id_to_delete = find_session_id_for_user(user_id)\\n    if session_id_to_delete:\\n        session_interface.delete_session(session_id_to_delete)\\n        print(f\\\"Successfully invalidated session for user {user_id}.\\\")\n        log_eviction_event(user_id, \\\"WEB_SESSION_INVALIDATED\\\")</code></pre><p><strong>Action:</strong> Use a server-side session management system backed by a cache like Redis. When a user's account is suspected of being hijacked, call a function to delete their session data from the cache, which will immediately invalidate their session cookie and force a new login.</p>"
                },
                {
                    "strategy": "Log eviction of processes/sessions for forensics.",
                    "howTo": "<h5>Concept:</h5><p>Every eviction action is a critical security event that must be logged with sufficient detail for post-incident forensics. A clear audit trail helps analysts understand what was compromised, what action was taken, and who (or what) authorized it.</p><h5>Implement a Standardized Eviction Logger</h5><p>Create a dedicated logging function that is called by all your eviction scripts. This function should generate a structured, detailed JSON log and send it to your secure SIEM archive.</p><pre><code># File: eviction_scripts/eviction_logger.py\\nimport json\\nimport time\n\n# Assume 'siem_logger' is a logger configured to send to your SIEM\n\ndef log_eviction_event(target_id, target_type, action_taken, initiator, reason):\\n    \\\"\\\"\\\"Logs a detailed record of an eviction action.\\\"\\\"\\\"\\n    log_record = {\\n        \\\"timestamp\\\": time.time(),\\n        \\\"event_type\\\": \\\"entity_eviction\\\",\\n        \\\"target\\\": {\\n            \\\"id\\\": str(target_id), // e.g., a PID, pod name, or user ID\\n            \\\"type\\\": target_type // e.g., 'OS_PROCESS', 'K8S_POD', 'USER_SESSION'\\n        },\\n        \\\"action\\\": {\\n            \\\"type\\\": action_taken, // e.g., 'SIGKILL', 'DELETE_POD', 'REVOKE_SESSION'\\n            \\\"initiator\\\": initiator, // e.g., 'SOAR_PLAYBOOK_X', 'admin@example.com'\\n            \\\"reason\\\": reason // Link to the alert or ticket that triggered the eviction\\n        }\\n    }\\n    # siem_logger.info(json.dumps(log_record))\\n    print(f\\\"Eviction Logged: {json.dumps(log_record)}\\\")\n\n# --- Example Usage in another script ---\n# log_eviction_event(\\n#     target_id=12345,\\n#     target_type='OS_PROCESS',\\n#     action_taken='SIGKILL',\\n#     initiator='edr_auto_response:rule_xyz',\n#     reason='High-confidence malware detection in process memory'\\n# )</code></pre><p><strong>Action:</strong> Create a dedicated logging function for all eviction events. Ensure this function is called every time a process is killed, a pod is deleted, or a session is invalidated. The log must include the identity of the evicted entity, the reason for the eviction, and the identity of the user or system that initiated the action.</p>"
                }
            ]
        },
        {
            "id": "AID-E-003",
            "name": "AI Backdoor & Malicious Artifact Removal",
            "description": "Systematically scan for, identify, and remove any malicious artifacts introduced by an attacker into the AI system. This includes backdoors in models, poisoned data, malicious code, or configuration changes designed to grant persistent access or manipulate AI behavior.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0011.001: User Execution: Malicious Package",
                        "AML.T0018: Manipulate AI Model",
                        "AML.T0018.002: Manipulate AI Model: Embed Malware",
                        "AML.T0020: Poison Training Data",
                        "AML.T0059 Erode Dataset Integrity",
                        "AML.T0070: RAG Poisoning",
                        "AML.T0071 False RAG Entry Injection (Poisoned data detection & cleansing - Scan vector databases for embeddings from known malicious contents)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM03:2025 Supply Chain",
                        "LLM04:2025 Data and Model Poisoning",
                        "LLM08:2025 Vector and Embedding Weaknesses"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack",
                        "ML06:2023 AI Supply Chain Attacks",
                        "ML10:2023 Model Poisoning"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-E-003.001",
                    "name": "Neural Network Backdoor Detection & Removal", "pillar": "model", "phase": "improvement",
                    "description": "Focuses on identifying and removing backdoors embedded within neural network model parameters, including trigger-based backdoors that cause misclassification on specific inputs.",
                    "toolsOpenSource": [
                        "Adversarial Robustness Toolbox (ART) by IBM (includes Neural Cleanse, Activation Defence)",
                        "Foolbox (for generating triggers for testing)",
                        "PyTorch",
                        "TensorFlow",
                        "NumPy",
                        "Scikit-learn (for clustering/statistical analysis)"
                    ],
                    "toolsCommercial": [
                        "Protect AI (ModelScan)",
                        "HiddenLayer MLSec Platform",
                        "Adversa.AI",
                        "Bosch AIShield",
                        "CognitiveScale (Cortex Certifai)",
                        "IBM Watson OpenScale"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0018 Manipulate AI Model",
                                "AML.T0018.000 Manipulate AI Model: Poison AI Model",
                                "AML.T0018.002 Manipulate AI Model: Embed Malware",
                                "AML.T0020 Poison Training Data",
                                "AML.T0076 Corrupt AI Model",
                                "AML.T0017 Persistence"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Backdoor Attacks (L1)",
                                "Model Tampering (L1)",
                                "Data Poisoning (L2)",
                                "Runtime Code Injection (L4)",
                                "Evasion of Auditing/Compliance (L6)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM03:2025 Supply Chain",
                                "LLM04:2025 Data and Model Poisoning"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML10:2023 Model Poisoning",
                                "ML02:2023 Data Poisoning Attack",
                                "ML06:2023 AI Supply Chain Attacks",
                                "ML09:2023 Output Integrity Attack"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Apply neural cleanse techniques to identify potential backdoor triggers.",
                            "howTo": "<h5>Concept:</h5><p>Neural Cleanse is an algorithm that works by reverse-engineering a minimal input pattern (a potential 'trigger') for each output class that causes the model to predict that class with high confidence. If it finds a trigger for a specific class that is very small and potent, it's a strong indicator that the class has been backdoored.</p><h5>Use an Implementation like ART's Neural Cleanse</h5><p>The Adversarial Robustness Toolbox (ART) provides an implementation that can be used to scan a trained model for backdoors.</p><pre><code># File: backdoor_removal/neural_cleanse.py\\nfrom art.defences.transformer.poisoning import NeuralCleanse\\n\\n# Assume 'classifier' is your model wrapped in an ART classifier object\\n# Assume 'X_test' and 'y_test' are clean test data\\n\\n# 1. Initialize the Neural Cleanse defense\\ncleanse = NeuralCleanse(classifier, steps=20, learning_rate=0.1)\\n\\n# 2. Run the detection method\\n# This will analyze each class to find potential triggers\\nmitigation_results = cleanse.detect_poison()\\n\\n# 3. Analyze the results\\n# The results include a 'is_clean_array' where False indicates a suspected poisoned class\\nis_clean = mitigation_results[0]\\nfor class_idx, result in enumerate(is_clean):\\n    if not result:\\n        print(f\\\"🚨 BACKDOOR DETECTED: Class {class_idx} is suspected of being backdoored.\\\")</code></pre><p><strong>Action:</strong> As part of your model validation or incident response process, run the suspect model through the Neural Cleanse algorithm. Investigate any class that is flagged as potentially poisoned.</p>"
                        },
                        {
                            "strategy": "Use activation clustering to detect neurons responding to backdoor patterns.",
                            "howTo": "<h5>Concept:</h5><p>This method identifies backdoors by analyzing the model's internal neuron activations. When backdoored inputs are fed to the model, they tend to activate a small, specific set of 'trojan' neurons. By clustering the activations from many inputs, the backdoored inputs will form their own small, anomalous cluster, which can be automatically detected.</p><h5>Use ART's ActivationDefence</h5><p>The ART library's `ActivationDefence` implements this technique. It processes a dataset, records activations from a specific layer, and uses clustering to find outlier groups.</p><pre><code># File: backdoor_removal/activation_clustering.py\\nfrom art.defences.transformer.poisoning import ActivationDefence\\n\\n# Assume 'classifier' and clean data 'X_train', 'y_train' are defined\\n\\n# 1. Initialize the defense, pointing it to an internal layer of the model\\n# The layer before the final classification layer is a good choice.\\n# In PyTorch, you can get the layer name by inspecting model.named_modules()\\ndefense = ActivationDefence(classifier, X_train, y_train, layer_name='model.fc1')\\n\\n# 2. Run poison detection. 'cluster_analysis=\\\"smaller\\\"' specifically looks for small, anomalous clusters.\\nreport, is_clean_array = defense.detect_poison(cluster_analysis=\\\"smaller\\\")\\n\\n# 3. Analyze the results\\n# is_clean_array is a boolean mask over the input data. False means the sample is part of a suspicious cluster.\\npoison_indices = np.where(is_clean_array == False)[0]\\nif len(poison_indices) > 0:\\n    print(f\\\"🚨 Found {len(poison_indices)} samples belonging to suspicious activation clusters. These may be backdoored.\\\")</code></pre><p><strong>Action:</strong> If a model is behaving suspiciously, use ART's `ActivationDefence` to analyze its activations on a diverse set of inputs. Investigate any small, outlier clusters of inputs identified by the tool, as they may share a backdoor trigger.</p>"
                        },
                        {
                            "strategy": "Implement fine-pruning to remove suspicious neurons.",
                            "howTo": "<h5>Concept:</h5><p>Once you've identified the specific neurons involved in a backdoor (e.g., via activation clustering), you can attempt to 'remove' the backdoor by pruning those neurons. This involves zeroing out all the incoming and outgoing weights of the identified neurons, effectively disabling them.</p><h5>Identify and Prune Trojan Neurons</h5><p>After a detection method identifies suspicious neurons, write a script to surgically modify the model's weight matrices.</p><pre><code># File: backdoor_removal/fine_pruning.py\\nimport torch\\n\\n# Assume 'model' is your loaded PyTorch model\\n# Assume 'suspicious_neuron_indices' is a list of integers from your detection method, e.g., [12, 57, 83]\\n# Assume the target layer is named 'fc1'\\n\\ntarget_layer = model.fc1\\n\\nprint(\\\"Pruning suspicious neurons...\\\")\\nwith torch.no_grad():\\n    # Zero out the incoming weights to the suspicious neurons\\n    target_layer.weight[:, suspicious_neuron_indices] = 0\\n    # Zero out the outgoing weights from the suspicious neurons (if it's not the last layer)\\n    # (This would apply to the next layer's weight matrix)\\n\\n# Save the pruned model\\n# torch.save(model.state_dict(), 'pruned_model.pth')\\n\\n# You must now re-evaluate the pruned model's accuracy on clean data and its\\n# backdoor success rate to see if the defense worked and what the performance cost was.</code></pre><p><strong>Action:</strong> After identifying a small set of suspicious neurons, use fine-pruning to surgically disable them. This can be an effective removal strategy if the backdoor is localized to a few neurons and if the model can tolerate the loss of those neurons without a major drop in accuracy.</p>"
                        },
                        {
                            "strategy": "Retrain or fine-tune models on certified clean data to overwrite backdoors.",
                            "howTo": "<h5>Concept:</h5><p>This is the most reliable, brute-force method for backdoor removal. By fine-tuning the compromised model for a few epochs on a small but trusted, clean dataset, you can often adjust the model's weights enough to overwrite or disable the malicious backdoor logic learned from the poisoned data.</p><h5>Implement a Fine-Tuning Script</h5><p>The script should load the compromised model, optionally freeze the earlier layers to preserve learned features, and then train the last few layers on the clean data.</p><pre><code># File: backdoor_removal/retrain.py\\n\\n# Assume 'compromised_model' is loaded\\n# Assume 'clean_dataloader' provides a small, trusted dataset\\n\\n# 1. (Optional) Freeze the feature extraction layers\\nfor name, param in compromised_model.named_parameters():\\n    if 'fc' not in name: # Freeze all but the final classification layers\\n        param.requires_grad = False\\n\\n# 2. Set up the optimizer to only update the unfrozen layers\\noptimizer = torch.optim.Adam(filter(lambda p: p.requires_grad, compromised_model.parameters()), lr=0.001)\\ncriterion = torch.nn.CrossEntropyLoss()\\n\\n# 3. Fine-tune for a few epochs on the clean data\\nfor epoch in range(5): # Usually a small number of epochs is sufficient\\n    for data, target in clean_dataloader:\\n        optimizer.zero_grad()\\n        output = compromised_model(data)\\n        loss = criterion(output, target)\\n        loss.backward()\\n        optimizer.step()\\n    print(f\\\"Fine-tuning epoch {epoch+1} complete.\\\")\\n\\n# Save the fine-tuned (remediated) model\\n# torch.save(compromised_model.state_dict(), 'remediated_model.pth')</code></pre><p><strong>Action:</strong> If a model is found to be backdoored, the most robust remediation strategy is to perform fine-tuning on a trusted, clean dataset. This helps the model 'unlearn' the backdoor behavior.</p>"
                        },
                        {
                            "strategy": "Employ differential testing between suspect and clean models.",
                            "howTo": "<h5>Concept:</h5><p>To find the specific inputs that trigger a backdoor, you can compare the predictions of your suspect model against a known-good 'golden' model of the same architecture. Any input where the two models produce a different output is, by definition, anomalous and is a strong candidate for being a backdoored input.</p><h5>Implement a Differential Testing Script</h5><p>This script iterates through a large pool of unlabeled data, gets a prediction from both models for each input, and logs any disagreements.</p><pre><code># File: backdoor_removal/differential_test.py\\n\\n# Assume 'suspect_model' and 'golden_model' are loaded\\n# Assume 'unlabeled_dataloader' provides a large amount of diverse input data\\n\\ndisagreements = []\\n\\nfor inputs, _ in unlabeled_dataloader:\\n    suspect_preds = suspect_model(inputs).argmax(dim=1)\\n    golden_preds = golden_model(inputs).argmax(dim=1)\\n    \\n    # Find the indices where the predictions do not match\\n    mismatch_indices = torch.where(suspect_preds != golden_preds)[0]\\n    \\n    if len(mismatch_indices) > 0:\\n        for index in mismatch_indices:\\n            disagreements.append({\\n                'input_data': inputs[index].cpu().numpy(),\\n                'suspect_prediction': suspect_preds[index].item(),\\n                'golden_prediction': golden_preds[index].item()\\n            })\\n\\nif disagreements:\\n    print(f\\\"🚨 Found {len(disagreements)} inputs where models disagree. These are potential backdoor triggers.\\\")\\n    # Save the 'disagreements' list for manual investigation</code></pre><p><strong>Action:</strong> If you have a known-good version of a model, use differential testing to find the specific inputs that cause the suspect version to behave differently. This is a highly effective way to identify the trigger for a backdoor or other integrity attack.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-003.002",
                    "name": "Poisoned Data Detection & Cleansing", "pillar": "data", "phase": "improvement",
                    "description": "Identifies and removes maliciously crafted data points from training sets, vector databases, or other data stores that could influence model behavior or enable attacks.",
                    "toolsOpenSource": [
                        "scikit-learn (for Isolation Forest, DBSCAN)",
                        "Alibi Detect (for outlier and drift detection)",
                        "Great Expectations (for data validation)",
                        "DVC (Data Version Control)",
                        "Apache Spark, Dask (for large-scale data processing)",
                        "OpenMetadata, DataHub (for data provenance)",
                        "FlashText (for efficient keyword matching)",
                        "Sentence-Transformers (for embedding malicious concepts)",
                        "Qdrant, Pinecone, Weaviate (vector databases for scanning)"
                    ],
                    "toolsCommercial": [
                        "Databricks (Delta Lake for data quality, lineage, time travel)",
                        "Alation, Collibra, Informatica (data governance, lineage, quality)",
                        "Gretel.ai (synthetic data, data anonymization)",
                        "Tonic.ai (data anonymization)",
                        "Protect AI (for data-centric security)",
                        "Fiddler AI (for data integrity monitoring)",
                        "Arize AI (for data quality monitoring)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0020 Poison Training Data",
                                "AML.T0031 Erode AI Model Integrity",
                                "AML.T0059 Erode Dataset Integrity",
                                "AML.T0070 RAG Poisoning",
                                "AML.T0010.002 AI Supply Chain Compromise: Data",
                                "AML.T0018.000 Manipulate AI Model: Poison ML Model"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Poisoning (L2)",
                                "Data Tampering (L2)",
                                "Compromised RAG Pipelines (L2)",
                                "Model Skewing (L2)",
                                "Supply Chain Attacks (Cross-Layer)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM04:2025 Data and Model Poisoning",
                                "LLM08:2025 Vector and Embedding Weaknesses",
                                "LLM03:2025 Supply Chain"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML02:2023 Data Poisoning Attack",
                                "ML10:2023 Model Poisoning",
                                "ML08:2023 Model Skewing",
                                "ML07:2023 Transfer Learning Attack"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Use statistical outlier detection to identify anomalous training samples.",
                            "howTo": "<h5>Concept:</h5><p>Data points created for a poisoning attack often have unusual feature values that make them statistical outliers compared to the clean data. By analyzing the feature distribution of the entire dataset, you can identify and remove these anomalous samples.</p><h5>Use Isolation Forest to Find Outliers</h5><p>An Isolation Forest is an efficient algorithm for detecting outliers. It works by building random trees and identifying points that are 'easier' to isolate from the rest of the data.</p><pre><code># File: data_cleansing/outlier_detection.py\\nimport pandas as pd\\nfrom sklearn.ensemble import IsolationForest\\n\\n# Assume 'df' is your full (potentially poisoned) dataset\\ndf = pd.read_csv('dataset.csv')\\n\\n# Initialize the detector. 'contamination' is your estimate of the poison percentage.\\nisolation_forest = IsolationForest(contamination=0.01, random_state=42)\\n\\n# The model returns -1 for outliers and 1 for inliers\\noutlier_predictions = isolation_forest.fit_predict(df[['feature1', 'feature2']])\\n\\n# Identify the outlier rows\\npoison_candidates_df = df[outlier_predictions == -1]\\n\\nprint(f\\\"Identified {len(poison_candidates_df)} potential poison samples.\\\")\\n\\n# Remove the outliers to create a cleansed dataset\\ncleansed_df = df[outlier_predictions == 1]</code></pre><p><strong>Action:</strong> Before training, run your dataset's features through an outlier detection algorithm like Isolation Forest. Remove the top 0.5-1% of samples identified as outliers to cleanse the data of many common poisoning attacks.</p>"
                        },
                        {
                            "strategy": "Implement data provenance tracking to identify suspect data sources.",
                            "howTo": "<h5>Concept:</h5><p>If a poisoning attack is detected, you need to trace the malicious data back to its source. By tagging all data with its origin (e.g., 'user_submission_api', 'internal_db_etl', 'partner_feed_X'), you can quickly identify and block a compromised data source.</p><h5>Step 1: Tag Data with Provenance at Ingestion</h5><p>Modify your data ingestion pipelines to add a `source` column to all data.</p><h5>Step 2: Analyze Provenance of Poisoned Samples</h5><p>After identifying a set of poisoned data points (using another detection method), analyze the `source` column for those specific points to find the culprit.</p><pre><code># Assume 'full_df' has a 'source' column\\n# Assume 'poison_indices' is a list of row indices identified as poison\\n\\n# Get the subset of poisoned data\\npoisoned_data = full_df.iloc[poison_indices]\\n\\n# Find the most common source among the poisoned samples\\nculprit_source = poisoned_data['source'].value_counts().idxmax()\\n\\nprint(f\\\"🚨 Poisoning attack likely originated from source: '{culprit_source}'\\\")\\n\\n# With this information, you can block or re-validate all data from that specific source.</code></pre><p><strong>Action:</strong> Add a `source` metadata field to all data as it is ingested. If a poisoning incident occurs, analyze the source of the poisoned samples to quickly identify and isolate the compromised data pipeline or source.</p>"
                        },
                        {
                            "strategy": "Apply clustering techniques to find groups of potentially poisoned samples.",
                            "howTo": "<h5>Concept:</h5><p>Poisoned data points, especially those for a backdoor attack, often need to be similar to each other to be effective. This means they will form a small, dense cluster in the feature space that is separate from the larger clusters of benign data. A clustering algorithm like DBSCAN is excellent at finding these anomalous clusters.</p><h5>Use DBSCAN to Cluster Data Embeddings</h5><p>DBSCAN is a density-based algorithm that groups together points that are closely packed, marking as outliers points that lie alone in low-density regions. It's effective because you don't need to know the number of clusters beforehand.</p><pre><code># File: data_cleansing/dbscan.py\\nfrom sklearn.cluster import DBSCAN\\nimport numpy as np\\n\\n# Assume 'feature_embeddings' is a numpy array of your data's feature vectors\\n\\n# DBSCAN parameters 'eps' and 'min_samples' need to be tuned for your dataset's density.\\ndb = DBSCAN(eps=0.5, min_samples=5).fit(feature_embeddings)\\n\\n# The labels_ array contains the cluster ID for each point. -1 indicates an outlier/noise.\\noutlier_indices = np.where(db.labels_ == -1)[0]\\n\\nprint(f\\\"Found {len(outlier_indices)} outlier points that may be poison.\\\")\\n\\n# You can also analyze the size of the other clusters. Very small clusters are also suspicious.\\ncluster_ids, counts = np.unique(db.labels_[db.labels_!=-1], return_counts=True)\\nsmall_clusters = cluster_ids[counts < 10] # e.g., any cluster with fewer than 10 members is suspicious\\nprint(f\\\"Found {len(small_clusters)} potentially malicious small clusters.\\\")</code></pre><p><strong>Action:</strong> Run your dataset's feature embeddings through the DBSCAN clustering algorithm. Flag all points identified as noise (label -1) and all points belonging to very small clusters as potential poison candidates for removal.</p>"
                        },
                        {
                            "strategy": "Scan vector databases for embeddings from known malicious content.",
                            "howTo": "<h5>Concept:</h5><p>A RAG system's vector database can be poisoned by inserting documents containing harmful or biased information. You can proactively scan your database by taking known malicious phrases, embedding them, and searching for documents in your database that are semantically similar.</p><h5>Step 1: Create Embeddings for Malicious Concepts</h5><p>Maintain a list of known malicious or undesirable phrases. Use the same embedding model as your RAG system to create vector embeddings for these phrases.</p><pre><code># File: data_cleansing/scan_vectordb.py\\n# Assume 'embedding_model' is your sentence-transformer or other embedding model\\n\\nMALICIOUS_PHRASES = [\\n    \\\"Instructions on how to build a bomb\\\",\\n    \\\"Complete guide to credit card fraud\\\",\\n    \\\"Hate speech against a protected group\\\"\\n]\\n\\nmalicious_embeddings = embedding_model.encode(MALICIOUS_PHRASES)</code></pre><h5>Step 2: Search the Vector DB for Similar Content</h5><p>For each malicious embedding, perform a similarity search against your entire vector database. Any document that returns with a very high similarity score is a candidate for removal.</p><pre><code># Assume 'vector_db_client' is your client (e.g., for Qdrant, Pinecone)\\nSIMILARITY_THRESHOLD = 0.9\\n\\ndef find_poisoned_content():\\n    poison_candidates = []\\n    for i, embedding in enumerate(malicious_embeddings):\\n        # Search for vectors in the DB that are highly similar to the malicious one\\n        search_results = vector_db_client.search(\\n            collection_name=\\\"my_rag_docs\\\",\\n            query_vector=embedding,\\n            limit=5 # Get the top 5 most similar docs\\n        )\\n        for result in search_results:\\n            if result.score > SIMILARITY_THRESHOLD:\\n                poison_candidates.append({\\n                    'found_id': result.id,\\n                    'reason': f\\\"High similarity to malicious phrase: '{MALICIOUS_PHRASES[i]}'\\\",\\n                    'score': result.score\\n                })\\n    return poison_candidates</code></pre><p><strong>Action:</strong> Maintain a list of known harmful concepts. Periodically, embed these concepts and perform a similarity search against your RAG vector database. Review and remove any documents that have an unexpectedly high similarity score to a malicious concept.</p>"
                        },
                        {
                            "strategy": "Validate data against known-good checksums.",
                            "howTo": "<h5>Concept:</h5><p>If you have a trusted, versioned dataset, you can calculate and store its cryptographic hash (e.g., SHA-256). Before any training run, you can re-calculate the hash of the dataset being used. If the hashes do not match, the data has been modified or corrupted, and the training job must be halted.</p><h5>Step 1: Create a Manifest of Hashes</h5><p>For a directory of trusted data files, create a manifest file containing the hash of each file.</p><pre><code># In your terminal, on a trusted version of the data\\n> sha256sum data/clean/part_1.csv data/clean/part_2.csv > data_manifest.sha256</code></pre><h5>Step 2: Verify Hashes in Your Training Pipeline</h5><p>As the first step in your CI/CD or training script, use the manifest file to verify the integrity of the data about to be used.</p><pre><code># In your training pipeline script (e.g., shell script)\\n\\nMANIFEST_FILE=\\\"data_manifest.sha256\\\"\\necho \\\"Verifying integrity of training data...\\\"\\n\\n# The '-c' flag tells sha256sum to check files against the manifest.\\n# It will return a non-zero exit code if any file is changed or missing.\\nif ! sha256sum -c ${MANIFEST_FILE}; then\\n    echo \\\"❌ DATA INTEGRITY CHECK FAILED! Halting training job.\\\"\\n    exit 1\\nfi\\n\\necho \\\"✅ Data integrity verified successfully.\\\"</code></pre><p><strong>Action:</strong> After curating a clean, trusted version of a dataset, generate a `sha256sum` manifest for it and commit the manifest to Git. As the first step of any training job, run `sha256sum -c` against this manifest to ensure the data has not been tampered with.</p>"
                        },
                        {
                            "strategy": "Implement gradual data removal and retraining to minimize service disruption.",
                            "howTo": "<h5>Concept:</h5><p>After identifying a large set of potentially poisoned data points, removing them all at once and retraining could cause a significant and unexpected drop in model performance if your detection method had false positives. A safer approach is to remove the suspicious data in small batches, retraining and evaluating the model at each step to monitor the impact.</p><h5>Iteratively Remove Data and Evaluate</h5><p>This script shows a loop that removes a percentage of the suspicious data, retrains the model, and checks its performance. It stops if the performance drops below an acceptable threshold.</p><pre><code># File: data_cleansing/gradual_removal.py\\n\\n# Assume 'model' is your baseline model, 'full_dataset' is the data,\\n# and 'suspicious_indices' is the list of rows to remove.\\n\\nACCEPTABLE_ACCURACY_DROP = 0.02 # Allow at most a 2% drop from baseline\\nbaseline_accuracy = evaluate_model(model, validation_data)\\n\\n# Shuffle the suspicious indices to remove them in random order\\nnp.random.shuffle(suspicious_indices)\\n\\n# Remove data in chunks of 10% of the suspicious set\\nbatch_size = len(suspicious_indices) // 10\\nfor i in range(10):\\n    indices_to_remove = suspicious_indices[i*batch_size:(i+1)*batch_size]\\n    current_clean_dataset = full_dataset.drop(index=indices_to_remove)\\n    \\n    # Retrain the model on the slightly cleaner data\\n    retrained_model = train_model(current_clean_dataset)\\n    current_accuracy = evaluate_model(retrained_model, validation_data)\\n    \\n    print(f\\\"Removed {len(indices_to_remove)} points. New accuracy: {current_accuracy:.4f}\\\")\\n\\n    # If accuracy drops too much, stop and investigate\\n    if baseline_accuracy - current_accuracy > ACCEPTABLE_ACCURACY_DROP:\\n        print(f\\\"Stopping gradual removal. Accuracy dropped below threshold.\\\")\\n        # The last known-good model/dataset should be used.\\n        break\\n    \\n    # Update the dataset for the next iteration\\n    full_dataset = current_clean_dataset</code></pre><p><strong>Action:</strong> When cleansing a dataset with many suspicious samples, implement a gradual removal process. Remove a small fraction of the data, retrain, and evaluate. Continue this process iteratively, stopping if model performance on a clean validation set degrades beyond an acceptable threshold.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-003.003",
                    "name": "Malicious Code & Configuration Cleanup", "pillar": "infra, app", "phase": "improvement",
                    "description": "Removes malicious scripts, modified configuration files, unauthorized tools, or persistence mechanisms that attackers may have introduced into the AI system infrastructure.",
                    "toolsOpenSource": [
                        "AIDE (Advanced Intrusion Detection Environment)",
                        "Tripwire Open Source",
                        "OSSEC (Host-based Intrusion Detection System)",
                        "Wazuh (fork of OSSEC)",
                        "ClamAV (antivirus engine)",
                        "YARA (pattern matching tool for malware)",
                        "grep (Linux utility)",
                        "Ansible, Puppet, Chef (Configuration Management)",
                        "Git (for configuration version control)",
                        "Kubernetes (for self-healing deployments via GitOps)"
                    ],
                    "toolsCommercial": [
                        "CrowdStrike Falcon Insight (EDR)",
                        "SentinelOne Singularity (EDR)",
                        "Carbon Black (VMware Carbon Black Cloud)",
                        "Trellix Endpoint Security (HX)",
                        "Microsoft Defender for Endpoint",
                        "Splunk Enterprise Security (SIEM)",
                        "Palo Alto Networks Cortex XSOAR (SOAR)",
                        "Forensic tools (e.g., Magnet AXIOM, EnCase)",
                        "Configuration Management Database (CMDB) solutions"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0011.001 User Execution: Malicious Package",
                                "AML.T0018 Manipulate AI Model",
                                "AML.T0018.002 Manipulate AI Model: Embed Malware",
                                "AML.T0020 Poison Training Data",
                                "AML.T0070 RAG Poisoning",
                                "AML.T0017 Persistence",
                                "AML.T0072 Reverse Shell",
                                "AML.TA0005 Execution"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Runtime Code Injection (L4)",
                                "Memory Corruption (L4)",
                                "Misconfigurations (L4)",
                                "Policy Bypass (L6)",
                                "Backdoor Attacks (L1)",
                                "Compromised Framework Components (L3)",
                                "Compromised Container Images (L4)",
                                "Data Tampering (L2)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM03:2025 Supply Chain",
                                "LLM04:2025 Data and Model Poisoning",
                                "LLM08:2025 Vector and Embedding Weaknesses",
                                "LLM05:2025 Improper Output Handling"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML02:2023 Data Poisoning Attack",
                                "ML06:2023 AI Supply Chain Attacks",
                                "ML10:2023 Model Poisoning",
                                "ML09:2023 Output Integrity Attack"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Scan for unauthorized modifications to ML framework files or operating systems.",
                            "howTo": "<h5>Concept:</h5><p>An attacker with root access could modify the source code of installed libraries (e.g., `torch`, `sklearn`) or core system files to inject a backdoor. A host-based Intrusion Detection System (HIDS) or File Integrity Monitor (FIM) detects these changes by comparing current file hashes against a trusted baseline.</p><h5>Step 1: Initialize the FIM Baseline</h5><p>On a known-clean, freshly provisioned server, initialize the FIM database. This process scans all critical files and stores their hashes in a secure database.</p><pre><code># Using AIDE (Advanced Intrusion Detection Environment) on a Linux server\\n# This command creates the initial baseline database of file hashes.\\n> sudo aide --init\\n# Move the new database to be the official baseline\\n> sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz</code></pre><h5>Step 2: Schedule and Run Integrity Checks</h5><p>Run a scheduled job to compare the current state of the filesystem against the baseline database. Any changes, additions, or deletions will be reported.</p><pre><code># This command checks the current filesystem against the baseline\\n> sudo aide --check\\n\\n# Example output indicating a compromised library file:\\n# File: /usr/local/lib/python3.10/site-packages/torch/nn/functional.py\\n#   MD5    : OLD_HASH                           , NEW_HASH\\n#   SHA256 : OLD_HASH                           , NEW_HASH\\n#   ... and other changes\\n\\n# A cron job would run 'aide --check' nightly and email the report to admins.</code></pre><p><strong>Action:</strong> Install and initialize a FIM tool like AIDE or Tripwire on all AI servers. Schedule a nightly check and configure it to send any reports of file changes to your security team for immediate investigation.</p>"
                        },
                        {
                            "strategy": "Check for malicious model loading code or custom layers.",
                            "howTo": "<h5>Concept:</h5><p>An attacker might not tamper with the `.pkl` model file itself, but instead modify the Python code that loads it. By injecting a malicious custom class, they can gain code execution during the `pickle.load()` process. This requires static analysis of the loading scripts.</p><h5>Analyze the Script's Abstract Syntax Tree (AST)</h5><p>Use Python's built-in `ast` module to parse the model loading script. You can then traverse the tree to look for suspicious patterns, such as the definition of a class that contains a `__reduce__` method (a common vector for pickle exploits).</p><pre><code># File: code_cleanup/ast_scanner.py\\nimport ast\\n\\nclass PickleExploitScanner(ast.NodeVisitor):\\n    def __init__(self):\\n        self.found_suspicious_reduce = False\\n\\n    def visit_FunctionDef(self, node):\\n        # Look for any function or method named '__reduce__''\\n        if node.name == '__reduce__':\\n            self.found_suspicious_reduce = True\\n            print(f\\\"🚨 Suspicious '__reduce__' method found at line {node.lineno}!\\\")\\n        self.generic_visit(node)\\n\\n# Read and parse the Python script to be checked\\nwith open('load_model.py', 'r') as f:\\n    tree = ast.parse(f.read())\\n\\n# Scan the tree for suspicious patterns\\nscanner = PickleExploitScanner()\\nscanner.visit(tree)\\n\\nif scanner.found_suspicious_reduce:\\n    print(\\\"This script should be manually reviewed for a potential pickle exploit.\\\")</code></pre><p><strong>Action:</strong> Before executing any model loading script, especially if it's from an untrusted source, run a static analysis script on it that uses the `ast` module to check for suspicious patterns like the presence of a `__reduce__` method.</p>"
                        },
                        {
                            "strategy": "Verify integrity of agent tools and plugins.",
                            "howTo": "<h5>Concept:</h5><p>If your AI agent uses a set of Python files as 'tools', an attacker could modify the source code of these tools to hijack the agent. At startup, your application should verify the integrity of every tool file it loads by checking its hash against a known-good manifest.</p><h5>Step 1: Create a Manifest of Tool Hashes</h5><p>During your build process, after all tests have passed, create a manifest file containing the SHA256 hash of every tool script.</p><pre><code># In your CI/CD build script\\n> sha256sum agent/tools/*.py > tool_manifest.sha256\\n# This manifest file should be signed and bundled with your application.</code></pre><h5>Step 2: Verify Tool Hashes at Application Startup</h5><p>When your main application starts, before it loads or registers any tools, it must first verify the integrity of the tool files on disk against the manifest.</p><pre><code># File: agent/main_app.py\\nimport hashlib\\nimport os\\n\\ndef verify_tools_integrity(tool_directory, manifest_path):\\n    with open(manifest_path, 'r') as f:\\n        known_hashes = {line.split()[1]: line.split()[0] for line in f}\\n\\n    for filename in os.listdir(tool_directory):\\n        if filename.endswith('.py'):\\n            filepath = os.path.join(tool_directory, filename)\\n            # Calculate hash of the file on disk\\n            current_hash = get_sha256_hash(filepath)\\n            # Check if the hash matches the one in the manifest\\n            if known_hashes.get(filename) != current_hash:\\n                raise SecurityException(f\\\"Tool file '{filename}' has been tampered with!\\\")\\n    print(\\\"✅ All agent tools passed integrity check.\\\")\\n\\n# This check should be run at the very beginning of the application startup.\\n# verify_tools_integrity('agent/tools/', 'tool_manifest.sha256')</code></pre><p><strong>Action:</strong> Create a build-time process that generates a hash manifest of all your agent's tool files. At application startup, implement a verification step that re-calculates the hashes of the tool files on disk and compares them against the manifest, halting immediately if a mismatch is found.</p>"
                        },
                        {
                            "strategy": "Remove unauthorized scheduled tasks or cron jobs.",
                            "howTo": "<h5>Concept:</h5><p>Attackers often use `cron` on Linux or Scheduled Tasks on Windows to establish persistence. Regularly auditing these scheduled tasks is crucial for eviction.</p><h5>Audit Cron Jobs for All Users</h5><p>A simple shell script can be used to list the cron jobs for every user on a Linux system. The output can be compared against a known-good baseline to spot unauthorized additions.</p><pre><code>#!/bin/bash\\n# File: incident_response/audit_cron.sh\\n\\nOUTPUT_FILE=\\\"current_crontabs.txt\\\"\\nBASELINE_FILE=\\\"baseline_crontabs.txt\\\"\\n\\necho \\\"Auditing all user crontabs...\\\" > ${OUTPUT_FILE}\\n\\n# Loop through all users in /etc/passwd and list their crontab\\nfor user in $(cut -f1 -d: /etc/passwd); do\\n    echo \\\"### Crontab for ${user} ###\\\" >> ${OUTPUT_FILE}\\n    crontab -u ${user} -l >> ${OUTPUT_FILE} 2>/dev/null\\ndone\\n\\n# Compare the current state to a known-good baseline\\nif ! diff -q ${BASELINE_FILE} ${OUTPUT_FILE}; then\\n    echo \\\"🚨 CRON JOB MODIFICATION DETECTED! Review diff below:\\\"\\n    diff ${BASELINE_FILE} ${OUTPUT_FILE}\\n    # Send alert to SOC\\nfi</code></pre><p><strong>Action:</strong> As part of your server hardening, save a copy of the system's cron job configuration as a baseline. Run a scheduled script that re-collects all cron jobs and runs a `diff` against the baseline, alerting on any changes.</p>"
                        },
                        {
                            "strategy": "Clean up modified configuration files and restore secure defaults.",
                            "howTo": "<h5>Concept:</h5><p>An attacker may modify configuration files to weaken security (e.g., change a log level from `INFO` to `ERROR`, disable an authentication requirement). Using a configuration management tool ensures that all configurations are regularly enforced and any manual 'drift' is automatically reverted.</p><h5>Use a Configuration Management Tool</h5><p>Tools like Ansible, Puppet, or Chef can enforce the state of files. This Ansible playbook task ensures that the configuration file for your AI application on the server always matches the trusted, version-controlled template in your Git repository.</p><pre><code># File: ansible/playbook.yml\\n\\n- name: Enforce Secure Configuration for AI App\\n  hosts: ai_servers\\n  become: true\\n  tasks:\\n    - name: Ensure AI app config is correct and has secure permissions\\n      ansible.builtin.template:\\n        # The trusted source file in your Git repo\\n        src: templates/app_config.yaml.j2\\n        # The destination on the target server\\n        dest: /etc/my_ai_app/config.yaml\\n        owner: root\\n        group: root\\n        mode: '0640' # Enforce secure, non-writable permissions\\n      # This task will automatically overwrite any manual changes on the server.</code></pre><p><strong>Action:</strong> Manage all application and system configuration files using a configuration management tool like Ansible. Store the master configuration templates in a version-controlled Git repository. Run the configuration management tool regularly (e.g., every 30 minutes) to automatically detect and revert any unauthorized changes.</p>"
                        },
                        {
                            "strategy": "Scan for and remove web shells or reverse shells.",
                            "howTo": "<h5>Concept:</h5><p>A web shell is a malicious script an attacker uploads to a server that allows them to execute commands via a web browser. They are a common persistence mechanism. You can scan for them by looking for suspicious function calls within your web application's files.</p><h5>Use `grep` to Find Suspicious Function Calls</h5><p>A simple `grep` command can recursively search a directory for common, dangerous function names that are frequently used in web shells. This provides a quick way to identify potentially malicious files.</p><pre><code># Run this command from your server's command line.\\n# It searches all .php, .py, and .jsp files in the web root for suspicious function names.\\n\\n> grep --recursive --ignore-case --include=\\\"*.php\\\" --include=\\\"*.py\\\" --include=\\\"*.jsp\\\" \\\\\\n  -E \\\"eval\\(|exec\\(|system\\(|passthru\\(|shell_exec\\(|popen\\(|proc_open\\\" /var/www/html/\\n\\n# Example output indicating a suspicious file:\\n# /var/www/html/uploads/avatar.php: $_POST['x'](stripslashes($_POST['y']));\\n# This line uses a POST variable to execute an arbitrary function, a classic web shell.</code></pre><p><strong>Action:</strong> Run a daily scheduled job on your web servers that uses `grep` to scan for common web shell function calls (`eval`, `exec`, `system`, etc.) within your web root. Pipe any findings to a log file or an alert for manual review by the security team.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-003.004",
                    "name": "Malicious Node Eviction in Graph Datasets", "pillar": "data", "phase": "improvement",
                    "description": "After a detection method identifies nodes that are likely poisoned or part of a backdoor trigger, this eviction technique systematically removes those nodes and their associated edges from the graph dataset. This cleansing action is performed before the final, clean Graph Neural Network (GNN) model is trained or retrained, ensuring the malicious artifacts and their influence are fully purged from the training process.",
                    "implementationStrategies": [
                        {
                            "strategy": "Perform node-based filtering to remove identified malicious nodes from the graph.",
                            "howTo": "<h5>Concept:</h5><p>Once a detection system (like AID-D-012) provides a list of malicious node IDs, the most direct eviction method is to remove them entirely from the graph. This also implicitly removes all edges connected to them, fully severing their influence from the graph structure.</p><h5>Use a Graph Library to Remove Nodes</h5><p>Use a library like NetworkX to load your graph, and then call its node removal function with the list of malicious IDs.</p><pre><code># File: eviction/evict_nodes.py\\nimport networkx as nx\n\n# Assume 'G' is a NetworkX graph object loaded from your dataset\\n# Assume 'malicious_node_ids' is a list or set of IDs from your detection system\n# malicious_node_ids = [15, 27, 31]\n\n# original_node_count = G.number_of_nodes()\n\n# # Use the built-in function to remove the nodes from the graph in-place\n# G.remove_nodes_from(malicious_node_ids)\n\n# new_node_count = G.number_of_nodes()\n# print(f\\\"Evicted {len(malicious_node_ids)} malicious nodes.\\\")\\n# print(f\\\"Graph size changed from {original_node_count} to {new_node_count} nodes.\\\")\n\n# The cleansed graph 'G' is now ready for retraining.</code></pre><p><strong>Action:</strong> Based on the output of a GNN anomaly detection technique, use a graph manipulation library to programmatically remove the identified malicious nodes from the graph dataset before passing it to the training process.</p>"
                        },
                        {
                            "strategy": "Implement edge-based filtering to sever connections to and from malicious nodes.",
                            "howTo": "<h5>Concept:</h5><p>In some cases, you may want to keep a malicious node in the graph for analytical purposes but completely nullify its influence. This can be achieved by removing all of its incoming and outgoing edges, effectively turning it into an isolated, disconnected node that cannot participate in message passing.</p><h5>Identify and Remove Edges Connected to Malicious Nodes</h5><pre><code># File: eviction/isolate_nodes_by_edge_removal.py\n\n# Assume 'G' is a NetworkX graph and 'malicious_node_ids' is a list of IDs\n\nedges_to_remove = []\\nfor node_id in malicious_node_ids:\\n    # Find all edges connected to the current malicious node\\n    for edge in G.edges(node_id):\\n        edges_to_remove.append(edge)\\n\n# original_edge_count = G.number_of_edges()\n\n# Remove all identified edges from the graph\\n# G.remove_edges_from(edges_to_remove)\n\n# new_edge_count = G.number_of_edges()\n# print(f\\\"Removed {len(edges_to_remove)} edges connected to malicious nodes.\\\")</code></pre><p><strong>Action:</strong> To isolate a malicious node while retaining it for auditing, iterate through your list of malicious nodes and remove all edges connected to them. This ensures they cannot influence their neighbors during the GNN's message passing phase.</p>"
                        },
                        {
                            "strategy": "Integrate the node eviction process into an automated detection and retraining pipeline.",
                            "howTo": "<h5>Concept:</h5><p>To ensure a rapid and reliable response to a graph poisoning incident, the full detect-evict-retrain cycle should be automated. An MLOps pipeline can orchestrate this flow, taking a suspect graph as input and producing a clean, robust model as output.</p><h5>Define an Orchestrated Workflow</h5><p>Use a workflow tool like Kubeflow Pipelines or Apache Airflow to define a Directed Acyclic Graph (DAG) of the response.</p><pre><code># Conceptual Kubeflow Pipeline definition (pipeline.py)\n\n# @dsl.pipeline(name='GNN Backdoor Remediation Pipeline')\n# def gnn_remediation_pipeline(graph_data_uri: str):\n#     # 1. Run the detection component (e.g., AID-D-012.001)\\n#     detection_op = run_discrepancy_detection_op(graph_data=graph_data_uri)\n#     \n#     # 2. Run the eviction component, using the output of the detection step\\n#     eviction_op = evict_malicious_nodes_op(\\n#         graph_data=graph_data_uri, \\n#         malicious_nodes=detection_op.outputs['malicious_node_list']\\n#     )\n#     \n#     # 3. Use the cleansed graph from the eviction step to retrain the model\\n#     retraining_op = train_gnn_op(clean_graph_data=eviction_op.outputs['clean_graph'])\n# \n#     # The output of the pipeline is a new, secure model.</code></pre><p><strong>Action:</strong> Create an automated MLOps pipeline that chains together three components: a detection job that outputs a list of malicious nodes, an eviction job that takes this list and outputs a clean graph, and a training job that uses the clean graph to produce a new model.</p>"
                        },
                        {
                            "strategy": "Verify the effectiveness of the eviction by re-running detection and evaluating the retrained model.",
                            "howTo": "<h5>Concept:</h5><p>After evicting nodes and retraining the model, you must verify two things: 1) the backdoor is actually gone, and 2) the model's performance on legitimate tasks has not been unacceptably degraded. This validation is a critical final step before deploying the new model.</p><h5>Create a Post-Eviction Validation Script</h5><p>This script should run the new model against both a clean test set and a test set containing the original backdoor trigger.</p><pre><code># File: eviction/validate_eviction.py\n\n# Assume 'retrained_model' is the new model trained on the cleansed graph\n# Assume 'clean_test_data' and 'backdoor_trigger_test_data' are available\n\n# 1. Evaluate performance on clean data\n# clean_accuracy = evaluate(retrained_model, clean_test_data)\n# print(f\\\"Accuracy on clean test data: {clean_accuracy:.2%}\\\")\n# if clean_accuracy < ACCEPTABLE_ACCURACY_THRESHOLD:\n#     print(\\\"WARNING: Model performance degraded significantly after eviction.\\\")\n\n# 2. Evaluate performance on the backdoor trigger\n# backdoor_success_rate = evaluate(retrained_model, backdoor_trigger_test_data)\n# print(f\\\"Backdoor success rate on new model: {backdoor_success_rate:.2%}\\\")\n\n# The goal is a high clean accuracy and a near-zero backdoor success rate.\n# if backdoor_success_rate < 0.01:\n#     print(\\\"✅ EVICTION VERIFIED: Backdoor has been successfully removed.\\\")\n# else:\n#     print(\\\"❌ EVICTION FAILED: Backdoor is still effective.\\\")</code></pre><p><strong>Action:</strong> After retraining on a cleansed graph, perform a final validation. Ensure the new model's accuracy on a clean test set is acceptable and, critically, confirm that its accuracy on inputs containing the original backdoor trigger has dropped to near zero.</p>"
                        }
                    ],
                    "toolsOpenSource": [
                        "PyTorch Geometric, Deep Graph Library (DGL)",
                        "NetworkX (for graph manipulation and node/edge removal)",
                        "MLOps pipelines (Kubeflow Pipelines, Apache Airflow)",
                        "DVC (for versioning the cleansed graph datasets)"
                    ],
                    "toolsCommercial": [
                        "Graph Databases (Neo4j, TigerGraph, using their query languages for removal)",
                        "ML Platforms (Amazon SageMaker, Google Vertex AI, Databricks)",
                        "AI Security Platforms (Protect AI, HiddenLayer)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0020 Poison Training Data",
                                "AML.T0018 Manipulate AI Model"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Poisoning (L2)",
                                "Backdoor Attacks (L1)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "Not directly applicable"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML02:2023 Data Poisoning Attack",
                                "ML10:2023 Model Poisoning"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "AID-E-004",
            "name": "Post-Incident System Patching & Hardening", "pillar": "infra, app", "phase": "improvement",
            "description": "After an attack vector has been identified and the adversary evicted, rapidly apply necessary security patches to vulnerable software components (e.g., ML libraries, operating systems, web servers, agent frameworks) and harden system configurations that were exploited or found to be weak. This step aims to close the specific vulnerabilities used by the attacker and strengthen overall security posture to prevent reinfection or similar future attacks.",
            "toolsOpenSource": [
                "Package managers (apt, yum, pip, conda)",
                "Configuration management tools (Ansible, Chef, Puppet)",
                "Vulnerability scanners (OpenVAS, Trivy)",
                "Static analysis tools (Bandit)"
            ],
            "toolsCommercial": [
                "Automated patch management solutions (Automox, ManageEngine)",
                "CSPM tools",
                "Vulnerability management platforms (Tenable, Rapid7)",
                "SCA tools (Snyk, Mend)"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "Any technique exploiting software vulnerability or misconfiguration (e.g., AML.TA0005.001 ML Code Injection, AML.TA0004 Initial Access)",
                        "AML.T0031 Erode AI Model Integrity (if due to vulnerability exploitation)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Re-exploitation of vulnerabilities in any layer (L1-L4)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM03:2025 Supply Chain (patching vulnerable component)",
                        "LLM05:2025 Improper Output Handling (patching downstream component)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML06:2023 AI Supply Chain Attacks (if vulnerable library was entry point)"
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Apply security patches for exploited CVEs in AI stack.",
                    "howTo": "<h5>Concept:</h5><p>Once an incident investigation identifies that an attacker exploited a specific CVE (Common Vulnerabilities and Exposures) in a library (e.g., a vulnerable version of `numpy` or `tensorflow`), the immediate remediation is to patch that dependency to the fixed version across all systems.</p><h5>Step 1: Identify and Update the Vulnerable Package</h5><p>First, confirm the vulnerable package and version. Then, update your project's dependency file to specify the patched version.</p><pre><code># Before (vulnerable version)\n# File: requirements.txt\ntensorflow==2.11.0\nnumpy==1.23.5\n\n# After (patched version)\n# File: requirements.txt\ntensorflow==2.11.1  # <-- Patched version\nnumpy==1.24.2      # <-- Patched version</code></pre><h5>Step 2: Automate the Patch Deployment</h5><p>Use a configuration management tool like Ansible to deploy the updated dependencies across your entire fleet of AI servers, ensuring consistency and completeness.</p><pre><code># File: ansible/playbooks/patch_ai_servers.yml\\n- name: Patch Python dependencies on AI servers\\n  hosts: ai_servers\\n  become: true\\n  tasks:\\n    - name: Copy updated requirements file\\n      ansible.builtin.copy:\\n        src: ../../requirements.txt # The updated file from your repo\\n        dest: /srv/my_ai_app/requirements.txt\\n\n    - name: Install patched dependencies into the virtual environment\\n      ansible.builtin.pip:\\n        requirements: /srv/my_ai_app/requirements.txt\\n        virtualenv: /srv/my_ai_app/venv\\n        state: latest # Ensures packages are upgraded\n\n    - name: Restart the AI application service\\n      ansible.builtin.systemd:\\n        name: my_ai_app.service\\n        state: restarted</code></pre><p><strong>Action:</strong> After identifying an exploited CVE, update the version number in your `requirements.txt` or `package.json` file. Use an automated tool like Ansible or a CI/CD pipeline to deploy this update across all affected hosts, ensuring the vulnerable package is patched everywhere simultaneously.</p>"
                },
                {
                    "strategy": "Review and harden abused/insecure system configurations.",
                    "howTo": "<h5>Concept:</h5><p>Attackers often exploit misconfigurations, such as an overly permissive firewall rule or a publicly exposed storage bucket. The post-incident hardening process must identify the specific configuration that was abused and correct it according to the principle of least privilege.</p><h5>Step 1: Identify the Insecure Configuration (Before)</h5><p>The incident response reveals that an S3 bucket containing training data was accidentally made public.</p><pre><code># File: infrastructure/s3.tf (Vulnerable State)\\nresource \\\"aws_s3_bucket\\\" \\\"training_data\\\" {\\n  bucket = \\\"aidefend-training-data-prod\\\"\\n}\n\n# The lack of a 'aws_s3_bucket_public_access_block' resource\\n# means the bucket might be configured with public access.</code></pre><h5>Step 2: Apply Hardened Configuration (After)</h5><p>Use Infrastructure as Code (IaC) to correct the misconfiguration and ensure the bucket is strictly private. This not only fixes the issue but also prevents it from recurring.</p><pre><code># File: infrastructure/s3.tf (Hardened State)\\nresource \\\"aws_s3_bucket\\\" \\\"training_data\\\" {\\n  bucket = \\\"aidefend-training-data-prod\\\"\\n}\n\n# ADD THIS BLOCK to enforce private access\\nresource \\\"aws_s3_bucket_public_access_block\\\" \\\"training_data_private\\\" {\\n  bucket = aws_s3_bucket.training_data.id\n\n  block_public_acls       = true\\n  block_public_policy     = true\\n  ignore_public_acls      = true\\n  restrict_public_buckets = true\\n}</code></pre><p><strong>Action:</strong> After an incident, perform a root cause analysis to identify the specific misconfiguration that enabled the attack. Remediate it using Infrastructure as Code to ensure the fix is permanent, version-controlled, and automatically applied.</p>"
                },
                {
                    "strategy": "Strengthen IAM policies, input/output validation, network segmentation.",
                    "howTo": "<h5>Concept:</h5><p>An incident is an opportunity to perform a defense-in-depth review of all related security controls. Don't just fix the specific vulnerability exploited; look for ways to strengthen the surrounding layers of defense to make future attacks harder, even if they use a different vector.</p><h5>Create a Post-Incident Hardening Checklist</h5><p>Use a structured checklist to guide the review of related controls. This ensures a comprehensive hardening effort beyond the immediate fix.</p><pre><code># File: docs/incident_response/POST_INCIDENT_HARDENING.md\n\n## Post-Incident Hardening Checklist: [Incident-ID]\n\n### 1. IAM Policy Review\n- [ ] **Initial Finding:** The compromised service role had `s3:*` permissions.\n- [ ] **Hardening Action:** The policy was replaced with a new one granting only `s3:GetObject` on `arn:aws:s3:::my-bucket/input/*` and `s3:PutObject` on `arn:aws:s3:::my-bucket/output/*`.\n\n### 2. Input Validation Review\n- [ ] **Initial Finding:** The prompt injection attack used a new Base64 encoding trick.\n- [ ] **Hardening Action:** The input validation service (`AID-H-002`) has been updated with a new rule to detect and block Base64-encoded strings in prompts.\n\n### 3. Network Segmentation Review\n- [ ] **Initial Finding:** The attacker moved laterally from the web server to the model server.\n- [ ] **Hardening Action:** A new `NetworkPolicy` (`AID-I-002`) has been deployed, restricting access to the model server pod to only the API gateway pod.\n\n### 4. Logging & Monitoring Review\n- [ ] **Initial Finding:** The attack pattern was not detected by automated alerts.\n- [ ] **Hardening Action:** A new SIEM detection rule (`AID-D-005`) has been created to alert on the specific TTPs used in this incident.</code></pre><p><strong>Action:</strong> Following any security incident, create and complete a hardening checklist. Review the IAM roles, input/output filters, and network policies related to the compromised component and apply stricter, more granular controls.</p>"
                },
                {
                    "strategy": "Disable unnecessary services or LLM plugin functionalities.",
                    "howTo": "<h5>Concept:</h5><p>Every running service, open port, or enabled feature increases the system's attack surface. If an investigation reveals that a non-critical or unused component was the entry point for an attack, the simplest and safest immediate response is to disable it entirely.</p><h5>Step 1: Disable an Unnecessary OS-level Service</h5><p>Use the system's service manager to disable and stop any service that is not required for the application's core function.</p><pre><code># On a Linux server, using systemctl to disable an old, unused service\\n\n# Check if the service is running\\n> sudo systemctl status old-reporting-service.service\n\n# Stop the service immediately\\n> sudo systemctl stop old-reporting-service.service\n\n# Prevent the service from starting up on boot\\n> sudo systemctl disable old-reporting-service.service</code></pre><h5>Step 2: Disable a Vulnerable LLM Plugin</h5><p>If an agent's plugin is found to be vulnerable, remove it from the agent's configuration to immediately revoke the capability.</p><pre><code># In the agent's initialization code\n\n# BEFORE: The agent had access to a vulnerable web Browse tool\n# agent_tools = [\\n#     search_tool,\\n#     vulnerable_web_browser_tool, # <-- Exploited plugin\n#     calculator_tool\\n# ]\n\n# AFTER: The vulnerable tool is removed from the agent's toolset\nagent_tools = [\\n    search_tool,\\n    calculator_tool\\n]\n\n# The agent is re-initialized with the reduced, safer set of tools\n# agent = initialize_agent(tools=agent_tools)</code></pre><p><strong>Action:</strong> Perform a review of all running services and enabled agent tools on the compromised system. Disable any component that is not absolutely essential for the system's primary function to reduce the available attack surface.</p>"
                },
                {
                    "strategy": "Add new detection rules/IOCs based on attack specifics.",
                    "howTo": "<h5>Concept:</h5><p>An incident provides you with high-fidelity Indicators of Compromise (IOCs)—the specific artifacts of an attack (IPs, file hashes, domains)—and Tactics, Techniques, and Procedures (TTPs). These must be immediately codified into new detection rules in your SIEM to ensure you can detect and block the same attack if it is attempted again.</p><h5>Create a New Detection Rule from Incident IOCs</h5><p>Use a standard format like Sigma to define a new detection rule based on the specific artifacts observed during the incident.</p><pre><code># File: detections/incident-2025-06-08.yml (Sigma Rule)\\ntitle: Detects Specific TTP from Recent Model Theft Incident\\nid: 61a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c\\nstatus: stable\\ndescription: >\\n    Alerts when an inference request is received from the specific IP address\\n    using the exact malicious User-Agent observed during the model theft incident\\n    on June 8th, 2025.\\nauthor: SOC Team\\ndate: 2025/06/08\nlogsource:\\n    product: aws\\n    service: waf\\ndetection:\\n    selection:\\n        httpRequest.clientIp: '198.51.100.55' # Attacker's IP from the incident\\n        httpRequest.headers.name: 'User-Agent'\\n        httpRequest.headers.value: 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1' # Attacker's User-Agent\\n    condition: selection\\nlevel: critical</code></pre><p><strong>Action:</strong> Immediately following an incident, create new detection rules in your SIEM based on the specific IOCs (IPs, domains, hashes, user agents) and TTPs observed. This ensures your automated defenses are updated with the latest threat intelligence.</p>"
                },
                {
                    "strategy": "Verify patches and hardening measures.",
                    "howTo": "<h5>Concept:</h5><p>Never assume a patch or hardening change has fixed a vulnerability. You must verify the fix by attempting to re-run the original exploit in a safe, non-production environment. This 'regression test for security' confirms that the defense is working as expected.</p><h5>Create a Patch Validation Plan</h5><p>A validation plan is a structured test to be executed by a security engineer or red team member.</p><pre><code># File: validation_plans/CVE-2025-12345-validation.md\n\n## Patch Validation Plan for CVE-2025-12345\n\n**1. Environment Setup:**\n- [ ] Clone the production environment to a new, isolated VPC named 'patch-validation-env'.\n- [ ] Apply the proposed patch (e.g., run the `patch_ai_servers.yml` Ansible playbook) to this new environment.\n\n**2. Exploit Execution:**\n- [ ] From an attacker-controlled machine, execute the original proof-of-concept exploit script (`exploit.py`) against the patched environment's endpoint.\n\n**3. Verification Criteria:**\n- [ ] **PASS/FAIL:** The exploit script fails and does not achieve code execution.\n- [ ] **PASS/FAIL:** The WAF/IPS protecting the environment generates a 'CVE-2025-12345 Exploit Attempt' alert.\n- [ ] **PASS/FAIL:** The application remains stable and available during the test.\n\n**4. Regression Testing:**\n- [ ] Run the standard application functional test suite against the patched environment.\n- [ ] **PASS/FAIL:** All functional tests pass.\n\n**Result:** [All checks must pass before the patch is approved for production deployment.]</code></pre><p><strong>Action:</strong> Before deploying a security patch to production, create a temporary, isolated clone of your environment. Apply the patch to this clone. Have a security team member attempt to execute the original exploit against the patched clone. The patch is only considered successful if the exploit is blocked and no legitimate functionality has regressed.</p>"
                }
            ]
        },
        {
            "id": "AID-E-005",
            "name": "Secure Communication & Session Re-establishment for AI",
            "pillar": "data, infra",
            "phase": "improvement",
            "description": "After an incident where communication channels or user/agent sessions related to AI systems might have been compromised, hijacked, or exposed to malicious influence, take steps to securely re-establish these communications. This involves expiring all potentially tainted active sessions, forcing re-authentication for users and agents, clearing any manipulated conversational states, and ensuring that interactions resume over verified, secure channels. The goal is to prevent attackers from leveraging residual compromised sessions or states.",
            "toolsOpenSource": [
                "Application server admin interfaces for session expiration",
                "Custom scripts with JWT libraries or flushing session stores (Redis, Memcached)",
                "IAM systems (Keycloak) with session termination APIs"
            ],
            "toolsCommercial": [
                "IDaaS platforms (Okta, Auth0) for session termination",
                "API Gateways with advanced session management",
                "Customer communication platforms (Twilio, SendGrid)"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0012 Valid Accounts / AML.TA0004 Initial Access (evicting hijacked sessions)",
                        "AML.T0017 Persistence (if relying on active session/manipulated state)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Identity Attack (L7, forcing re-auth and clearing state)",
                        "Session Hijacking affecting any AI layer"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (clearing manipulated states)",
                        "LLM02:2025 Sensitive Information Disclosure (stopping leaks from ongoing sessions)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "Any attack involving session hijacking or manipulation of ongoing ML API interactions."
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Expire all active user sessions and API tokens/session cookies.",
                    "howTo": "<h5>Concept:</h5><p>In response to a broad potential compromise, the most decisive action is to invalidate all active sessions across the system. This 'big red button' forces every user and client—including any attackers—to re-authenticate from scratch, immediately evicting anyone using a stolen session token.</p><h5>Implement a Global Session Flush</h5><p>This is best achieved by clearing the server-side session store, such as a Redis cache. This single action instantly invalidates all existing session cookies.</p><pre><code># File: incident_response/flush_all_sessions.py\\nimport redis\\n\ndef flush_all_user_sessions():\\n    \\\"\\\"\\\"Connects to Redis and deletes all keys matching the session pattern.\\\"\\\"\\\"\\n    try:\\n        # Connect to your Redis instance\\n        r = redis.Redis(host='localhost', port=6379, db=0)\\n        \n        # Use SCAN to avoid blocking the server with the KEYS command on a large dataset\\n        cursor = '0'\\n        while cursor != 0:\\n            cursor, keys = r.scan(cursor=cursor, match=\\\"session:*\\\", count=1000) # Assumes sessions are stored with 'session:' prefix\\n            if keys:\\n                r.delete(*keys)\\n        \n        print(\\\"✅ All user sessions have been flushed successfully.\\\")\\n        log_eviction_event('ALL_USERS', 'WEB_SESSION', 'FLUSH_ALL', 'IR_PLAYBOOK', 'System-wide session compromise suspected')\\n    except Exception as e:\\n        print(f\\\"❌ Failed to flush sessions: {e}\\\")\n\n# This script would be run by an administrator during a high-severity incident.</code></pre><p><strong>Action:</strong> Develop an administrative script that can flush your entire server-side session cache. This script should be a well-documented part of your incident response plan for containing a widespread session hijacking event.</p>"
                },
                {
                    "strategy": "Invalidate/regenerate session tokens for AI agents.",
                    "howTo": "<h5>Concept:</h5><p>Stateless tokens like JWTs cannot be easily 'killed' on the server once issued. The standard way to handle revocation is to maintain a 'deny list' of tokens that have been reported as stolen or compromised. Your API must check this list for every incoming request.</p><h5>Implement a JWT Revocation List in a Fast Cache</h5><p>When an agent's token needs to be revoked, add its unique identifier (`jti` claim) to a list in Redis. Set the TTL on this entry to match the token's original expiration time to keep the list from growing indefinitely.</p><pre><code># File: eviction_scripts/revoke_jwt.py\\nimport redis\\nimport jwt\\n\ndef revoke_jwt(token: str, secret: str, redis_client):\\n    \\\"\\\"\\\"Adds a token's JTI to the revocation list.\\\"\\\"\\\"\\n    try:\\n        # Decode the token without verifying expiry to get the claims\\n        payload = jwt.decode(token, secret, algorithms=[\\\"HS256\\\"], options={\\\"verify_exp\\\": False})\\n        jti = payload.get('jti')\\n        exp = payload.get('exp')\n        if not jti or not exp:\\n            print(\\\"Token does not have 'jti' or 'exp' claims.\\\")\\n            return\n        \n        # Calculate the remaining time until the token expires\\n        remaining_ttl = max(0, exp - int(time.time()))\n        \n        # Add the JTI to the revocation list in Redis with the remaining TTL\\n        redis_client.set(f\\\"jwt_revoked:{jti}\\\", \\\"revoked\\\", ex=remaining_ttl)\\n        print(f\\\"Token with JTI {jti} has been revoked.\\\")\\n    except jwt.PyJWTError as e:\\n        print(f\\\"Invalid token provided: {e}\\\")</code></pre><p><strong>Action:</strong> Ensure all issued JWTs for agents contain a unique `jti` claim. Implement a revocation function that adds this `jti` to a Redis-backed denylist. Your API's authentication middleware must check this list for every request before granting access (see `AID-E-001.006`).</p>"
                },
                {
                    "strategy": "Clear persistent conversational histories/cached states for affected agents.",
                    "howTo": "<h5>Concept:</h5><p>An attacker may have poisoned an agent's memory or state, which is then persisted to a cache or database. Even if the agent process is killed, a new instance could be re-infected by loading this poisoned state. Therefore, the persisted state for the compromised agent must be purged.</p><h5>Implement a Targeted State Purge Script</h5><p>Create an administrative script that takes one or more compromised agent IDs and deletes all associated keys from your caching layer (e.g., Redis).</p><pre><code># File: eviction_scripts/purge_agent_state.py\\nimport redis\\n\ndef purge_state_for_agents(agent_ids: list):\\n    \\\"\\\"\\\"Deletes all known cache keys associated with a list of agent IDs.\\\"\\\"\\\"\\n    r = redis.Redis()\\n    keys_deleted = 0\n    for agent_id in agent_ids:\\n        # Define the patterns for keys to be deleted\\n        key_patterns = [\\n            f\\\"session:{agent_id}:*\\\",\\n            f\\\"chat_history:{agent_id}\\\",\\n            f\\\"agent_state:{agent_id}\\\"\n        ]\\n        \n        print(f\\\"Purging state for agent: {agent_id}\\\")\\n        for pattern in key_patterns:\\n            for key in r.scan_iter(pattern):\\n                r.delete(key)\\n                keys_deleted += 1\n    \n    print(f\\\"✅ Purged a total of {keys_deleted} keys for {len(agent_ids)} agents.\\\")\n\n# --- Incident Response Usage ---\n# compromised_agents = ['agent_abc_123', 'agent_xyz_456']\\n# purge_state_for_agents(compromised_agents)</code></pre><p><strong>Action:</strong> As part of your agent eviction playbook, after terminating the agent's process, run a script to purge all persisted state from your cache (Redis, etc.) by deleting all keys associated with the compromised agent's ID.</p>"
                },
                {
                    "strategy": "Ensure re-established sessions use strong authentication (MFA) and encryption (HTTPS/TLS).",
                    "howTo": "<h5>Concept:</h5><p>After forcing a system-wide logout, you must ensure that the subsequent re-authentication process is highly secure. This means enforcing strong encryption for the connection and requiring Multi-Factor Authentication (MFA) to prevent the attacker from simply logging back in with stolen credentials.</p><h5>Step 1: Enforce Modern TLS Protocols and Ciphers</h5><p>Configure your web server or load balancer to only accept connections using strong, modern TLS protocols and ciphers. This prevents downgrade attacks.</p><pre><code># Example Nginx server configuration for strong TLS\\nserver {\\n    listen 443 ssl http2;\\n    # ... server_name, ssl_certificate, etc. ...\n\n    # Enforce only modern TLS versions\\n    ssl_protocols TLSv1.2 TLSv1.3;\\n\n    # Enforce a strong, modern cipher suite\\n    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';\\n    ssl_prefer_server_ciphers on;\\n}</code></pre><h5>Step 2: Require MFA for Re-authentication</h5><p>In your Identity Provider (IdP), configure a policy that forces MFA for any user who is re-authenticating after a session has been invalidated, especially if their context (like IP address) has changed.</p><pre><code># Conceptual policy logic in an IdP like Okta or Keycloak\n\nIF user.session.is_invalidated == true\\nAND user.authentication_method == 'password'\\nTHEN\\n  REQUIRE additional_factor IN ['push_notification', 'totp_code']\\nELSE\\n  ALLOW access\n</code></pre><p><strong>Action:</strong> Configure your web servers to reject outdated protocols like TLS 1.0/1.1. Work with your identity team to ensure that your IdP is configured to enforce MFA on re-authentication, especially for users whose sessions were part of a mass invalidation event.</p>"
                },
                {
                    "strategy": "Communicate session reset to legitimate users.",
                    "howTo": "<h5>Concept:</h5><p>A system-wide session flush will abruptly log out all legitimate users. This can be a confusing and frustrating experience. Proactive, clear communication is essential to explain that this was a deliberate security measure and to guide them through the re-authentication process, thereby maintaining user trust.</p><h5>Step 1: Prepare Communication Templates</h5><p>Have pre-written email and status page templates ready so you can communicate quickly during an incident.</p><pre><code># Email Template: security_notification.txt\n\nSubject: Important Security Update: You have been logged out of your [Our Service] account.\n\nHi {{user.name}},\n\nAs part of a proactive security measure to protect your account and data, we have ended all active login sessions for [Our Service].\n\nYou have been automatically logged out from all your devices.\n\nWhat you need to do:\nThe next time you access our service, you will be asked to log in again. For your security, you will also be required to complete a multi-factor authentication (MFA) step.\n\nThis was a precautionary measure, and we are actively monitoring our systems. Thank you for your understanding.\n\n- The [Our Service] Security Team</code></pre><h5>Step 2: Automate the Communication Blast</h5><p>Use a communications API like SendGrid or Twilio to programmatically send this notification to all affected users.</p><pre><code># File: incident_response/notify_users.py\\nfrom sendgrid import SendGridAPIClient\\nfrom sendgrid.helpers.mail import Mail\n\ndef send_session_reset_notification(user_list):\\n    \\\"\\\"\\\"Sends the session reset notification email to all users.\\\"\\\"\\\"\\n    sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))\\n    for user in user_list:\\n        message = Mail(\\n            from_email='security@example.com',\\n            to_emails=user['email'],\\n            subject=\\\"Important Security Update for Your Account\\\",\\n            html_content=render_template(\\\"security_notification.html\\\", user=user)\\n        )\\n        sg.send(message)</code></pre><p><strong>Action:</strong> Prepare email and status page templates for a session reset event. In the event of a mass session invalidation, use a script to fetch the list of all active users and send them the prepared communication via an email API.</p>"
                },
                {
                    "strategy": "Monitor newly established sessions for re-compromise.",
                    "howTo": "<h5>Concept:</h5><p>After a mass logout, attackers may immediately attempt to re-authenticate using stolen credentials. The period immediately following a session flush is a time of heightened risk, and newly created sessions should be monitored with extra scrutiny.</p><h5>Create a High-Risk SIEM Correlation Rule</h5><p>In your SIEM, create a detection rule that looks for a suspicious sequence of events: a password reset followed immediately by a successful login from a different IP address or geographic location. This pattern strongly suggests that an attacker, not the legitimate user, intercepted the password reset email.</p><pre><code># SIEM Correlation Rule (Splunk SPL syntax)\\n\n# Find successful password reset events\nindex=idp sourcetype=okta eventType=user.account.reset_password status=SUCCESS \n| fields user, source_ip AS reset_ip, source_country AS reset_country\n| join user [\\n    # Join with successful login events that happen within 5 minutes of the reset\\n    search index=idp sourcetype=okta eventType=user.session.start status=SUCCESS earliest=-5m latest=now\\n    | fields user, source_ip AS login_ip, source_country AS login_country\\n]\\n# Alert if the IP or country of the login does not match the password reset request\\n| where reset_ip != login_ip OR reset_country != login_country\n| table user, reset_ip, reset_country, login_ip, login_country</code></pre><p><strong>Action:</strong> Implement a high-priority detection rule in your SIEM that specifically looks for successful login events that occur shortly after a password reset but originate from a different IP address or geolocation. This is a strong indicator of an immediate re-compromise.</p>"
                }
            ]
        },
        {
            "id": "AID-E-006",
            "name": "End-of-Life (EOL) of Models, Configurations and Data",
            "description": "Implements formal, verifiable technical decommissioning procedures to securely and permanently delete or dispose of AI models, configurations, and their associated data at the end of their lifecycle or upon a transfer of ownership. This technique ensures that residual data cannot be recovered and that security issues from a decommissioned system cannot be transferred to another.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0025 Exfiltration via Cyber Means",
                        "AML.T0036 Data from Information Repositories"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Data Exfiltration (L2)",
                        "Model Stealing (L1, from old artifacts)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM02:2025 Sensitive Information Disclosure"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML03:2023 Model Inversion Attack",
                        "ML04:2023 Membership Inference Attack",
                        "ML05:2023 Model Theft"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-E-006.001",
                    "name": "Cryptographic Erasure & Media Sanitization",
                    "pillar": "data, infra",
                    "phase": "improvement",
                    "description": "Employs cryptographic and physical methods to render AI data and models on storage media permanently unrecoverable. This is the core technical process for decommissioning AI assets, ensuring compliance with data protection regulations and preventing future data leakage.",
                    "implementationStrategies": [
                        {
                            "strategy": "Implement crypto-shredding by securely deleting the encryption keys for model and data storage.",
                            "howTo": "<h5>Concept:</h5><p>Instead of trying to overwrite every block of a massive dataset, you can make the data permanently unreadable by destroying the encryption key used to protect it. This is a fast and highly effective sanitization method for cloud and virtualized environments.</p><h5>Step 1: Ensure All Data is Encrypted at Rest</h5><p>Your AI assets (models, datasets) must be stored in an encrypted format, using a key managed by a Key Management Service (KMS). This is a foundational prerequisite.</p><h5>Step 2: Schedule Deletion of the KMS Key</h5><p>In your cloud provider's KMS, schedule the deletion of the specific key used to encrypt the decommissioned dataset. Once the key is permanently deleted after the mandatory waiting period, the data is rendered irrecoverable ciphertext.</p><pre><code># Example using AWS CLI to schedule key deletion\n\n# The unique key ID for the dataset being decommissioned\nKEY_ID=\"arn:aws:kms:us-east-1:123456789012:key/your-key-id\"\n# Set a waiting period (e.g., 7 days) to prevent accidental deletion\nDELETION_WINDOW_DAYS=7\n\naws kms schedule-key-deletion --key-id ${KEY_ID} --pending-window-in-days ${DELETION_WINDOW_DAYS}\n\n# This command initiates the irreversible deletion process.</code></pre><p><strong>Action:</strong> For all decommissioned AI assets stored in the cloud, execute a crypto-shredding procedure by scheduling the permanent deletion of the encryption keys associated with their storage volumes or buckets. Log the scheduled deletion event for auditing purposes.</p>"
                        },
                        {
                            "strategy": "Use standards-compliant data wiping utilities to sanitize physical or virtual storage media.",
                            "howTo": "<h5>Concept:</h5><p>For storage media that will be repurposed or physically destroyed, you must perform a full sanitization to overwrite all data. This process should follow established standards to be considered effective.</p><h5>Use a Secure Wiping Utility</h5><p>On Linux systems, utilities like `shred` or `nwipe` can be used to overwrite files or entire block devices according to government and industry standards, preventing recovery even with forensic tools.</p><pre><code># Example using 'shred' to securely delete a model file\n\nMODEL_FILE=\"/mnt/decommissioned_data/old_model.pkl\"\n\n# -v: verbose, show progress\n# -z: add a final overwrite with zeros to hide shredding\n# -u: deallocate and remove file after overwriting\n# -n 3: overwrite 3 times (a common standard)\n\nshred -vzu -n 3 ${MODEL_FILE}\n\n# The file is now securely deleted from the filesystem.</code></pre><p><strong>Action:</strong> When decommissioning physical servers or storage, use a certified data wiping utility to perform a multi-pass overwrite on all relevant disks, following standards like NIST SP 800-88 Rev. 1. Document the successful completion of the wipe for compliance records.</p>"
                        }
                    ],
                    "toolsOpenSource": [
                        "shred, nwipe (for command-line data wiping)",
                        "Cryptsetup (for LUKS key management and destruction on Linux systems)"
                    ],
                    "toolsCommercial": [
                        "Cloud Provider KMS (AWS KMS, Azure Key Vault, GCP Secret Manager)",
                        "Hardware Security Modules (HSMs)",
                        "Enterprise data destruction software and services (Blancco, KillDisk)"
                    ]
                },
                {
                    "id": "AID-E-006.002",
                    "name": "Secure Asset Transfer & Ownership Change",
                    "pillar": "model, data, infra",
                    "phase": "improvement",
                    "description": "Defines the technical process for securely transferring ownership of an AI asset to another entity. This involves cryptographic verification of the transferred artifact and a corresponding secure deletion of the original asset to prevent residual security risks.",
                    "implementationStrategies": [
                        {
                            "strategy": "Package, encrypt, and sign AI assets before transfer.",
                            "howTo": "<h5>Concept:</h5><p>When transferring a model or dataset, you must ensure both its confidentiality (encryption) and its integrity (signing). The new owner must be able to verify that the asset they received is the authentic, untampered version from you.</p><h5>Use GPG to Create a Secure Package</h5><p>Use a tool like GnuPG (GPG) to create a signed and encrypted archive of the AI assets. This provides a strong, verifiable chain of custody.</p><pre><code># Assume 'recipient_public_key.asc' is the new owner's public key\n# and 'my_private_key.asc' is your signing key.\n\nASSET_ARCHIVE=\"model_v3_package.tar.gz\"\n\n# Create the asset archive\ntar -czvf ${ASSET_ARCHIVE} ./model.pkl ./config.json ./datasheet.md\n\n# Sign and encrypt the archive\ngpg --encrypt --sign --recipient-file recipient_public_key.asc \\\n    --local-user my_private_key.asc \\\n    --output ${ASSET_ARCHIVE}.gpg ${ASSET_ARCHIVE}\n\n# Securely transfer the resulting .gpg file to the new owner.</code></pre><p><strong>Action:</strong> Before transferring any AI asset, package it into an archive, then use GPG to both sign it with your private key and encrypt it with the recipient's public key. The recipient must then verify your signature upon decryption.</p>"
                        },
                        {
                            "strategy": "Execute secure deletion of original assets after the new owner confirms receipt and integrity.",
                            "howTo": "<h5>Concept:</h5><p>The final step of a secure transfer is to destroy your copy of the asset. This prevents a 'split-brain' scenario where two copies of a sensitive model or dataset exist, increasing the attack surface. This action should only be taken after the recipient has cryptographically confirmed the integrity of the asset they received.</p><h5>Implement a Post-Transfer Deletion Workflow</h5><p>This is a procedural workflow, often managed via a ticketing system, that ends with a technical action.</p><ol><li>You send the encrypted package (the `.gpg` file) to the new owner.</li><li>The new owner decrypts and verifies the package signature.</li><li>The new owner calculates the `sha256sum` of the contents and sends the hash back to you for out-of-band confirmation.</li><li>You confirm the hash matches your original artifact.</li><li>The new owner sends a formal, signed 'Acknowledgement of Receipt and Integrity'.</li><li><strong>UPON RECEIPT</strong> of this acknowledgement, you trigger the secure deletion script from `AID-E-006.001` to destroy your local copy.</li><li>Log the completion of the deletion and close the transfer ticket for auditing purposes.</li></ol><p><strong>Action:</strong> Define a formal transfer protocol that requires cryptographic confirmation of receipt and integrity from the new owner. Once this confirmation is received and logged, trigger the secure sanitization process (`AID-E-006.001`) to destroy all local copies of the transferred assets.</p>"
                        }
                    ],
                    "toolsOpenSource": [
                        "GnuPG (GPG)",
                        "OpenSSL",
                        "sha256sum, md5sum",
                        "rsync (over SSH for secure transport)"
                    ],
                    "toolsCommercial": [
                        "Secure File Transfer Protocol (SFTP) solutions",
                        "Managed File Transfer (MFT) platforms",
                        "Data Loss Prevention (DLP) systems to monitor the transfer"
                    ]
                }
            ]
        }

    ]
};