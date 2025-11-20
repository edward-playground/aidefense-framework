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
                        "AML.T0055 Unsecured Credentials"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Identity Attack (L7)",
                        "Compromised Agent Registry (L7)"
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
                    "name": "Foundational Credential Management", "pillar": ["infra"], "phase": ["response"],
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
                                "Lateral Movement (Cross-Layer)",
                                "Resource Hijacking (L4)"
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
                    "name": "Automated & Real-time Invalidation", "pillar": ["infra"], "phase": ["response"],
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
                                "AML.T0012 Valid Accounts (by immediately disabling the account)"
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
                    "name": "AI Agent & Workload Identity Revocation", "pillar": ["infra", "app"], "phase": ["response"],
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
                                "AML.T0073 Impersonation"
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
                                "ML06:2023 ML Supply Chain Attacks (if a compromised workload is the result)"
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
            "name": "AI Process & Session Eviction", "pillar": ["infra", "app"], "phase": ["response"],
            "description": "Terminate any running AI model instances, agent processes, user sessions, or containerized workloads that are confirmed to be malicious, compromised, or actively involved in an attack. This immediate action halts the adversary's ongoing activities within the AI system and removes their active foothold.",
            "toolsOpenSource": [
                "OS process management (kill, pkill, taskkill)",
                "Container orchestration CLIs (kubectl delete pod --force)",
                "HIPS (OSSEC, Wazuh)",
                "Custom eviction scripts for targeted session invalidation (Redis key purge by prefix)"
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
                        "AML.T0051 LLM Prompt Injection",
                        "AML.T0054 LLM Jailbreak (terminates manipulated session)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Tool Misuse (L7)",
                        "Agent Goal Manipulation (L7, terminating rogue agent)",
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
                        "ML06:2023 ML Supply Chain Attacks (a malicious container image introduced via the ML supply chain)"
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Identify and terminate malicious AI model or inference server processes.",
                    "howTo": "<h5>Concept:</h5><p>When your EDR/XDR or runtime monitor flags a specific OS process ID (PID) as malicious (for example, an unauthorized inference server, a rogue fine-tuning loop, or a crypto-mining workload abusing your GPUs), the fastest containment step is to kill that process. This immediately stops the attacker's active execution path.</p><h5>Operational Guidance:</h5><p>Ideally, before killing, capture minimal forensic context (command line, hashes, open sockets) if policy requires it. After termination, log the eviction event for auditability.</p><h5>Example: Process Termination Script</h5><pre><code># File: eviction_scripts/kill_process.py\nimport psutil\nimport time\n\ndef log_eviction_event(target_id, action_taken, reason):\n    # Placeholder: send structured JSON to SIEM / incident log\n    print({\n        \"event_type\": \"process_eviction\",\n        \"target_pid\": target_id,\n        \"action\": action_taken,\n        \"reason\": reason,\n        \"timestamp\": time.time()\n    })\n\ndef evict_process_by_pid(pid: int, reason: str = \"malicious_activity_detected\"):\n    \"\"\"Locate and terminate a process by PID. Graceful first, then force kill if needed.\"\"\"\n    try:\n        proc = psutil.Process(pid)\n        print(f\"[Evict] Found process {pid}: {proc.name()} (started {proc.create_time()})\")\n\n        # Attempt graceful shutdown first (SIGTERM)\n        print(f\"[Evict] Sending SIGTERM to PID {pid}...\")\n        proc.terminate()\n        try:\n            proc.wait(timeout=3)\n            print(f\"[Evict] Process {pid} terminated gracefully.\")\n            log_eviction_event(pid, \"SIGTERM\", reason)\n        except psutil.TimeoutExpired:\n            # Escalate to force kill (SIGKILL)\n            print(f\"[Evict] PID {pid} did not exit. Sending SIGKILL...\")\n            proc.kill()\n            proc.wait()\n            print(f\"[Evict] Process {pid} forcefully killed.\")\n            log_eviction_event(pid, \"SIGKILL\", reason)\n\n    except psutil.NoSuchProcess:\n        print(f\"[Evict] PID {pid} no longer exists.\")\n    except Exception as e:\n        print(f\"[Evict][Error] Failed to evict PID {pid}: {e}\")\n</code></pre><p><strong>Action:</strong> Add a privileged but tightly controlled script (like the one above) to your IR toolkit. Your SOAR playbooks or SOC analysts should be able to call it automatically when an alert tags a PID as hostile, ensuring rapid containment.</p>"
                },
                {
                    "strategy": "Evict hijacked AI agent sessions and purge poisoned runtime state.",
                    "howTo": "<h5>Concept:</h5><p>LLM/agent compromise (prompt injection, tool misuse, goal hijacking) is often stateful. The malicious 'intent' can persist in agent memory, Redis-backed context, tool queues, or long-running inference loops. Eviction here means two steps: (1) kill the running agent instance (e.g. delete its pod), and (2) wipe its associated in-memory/session state so it cannot resume in that compromised mindset.</p><h5>Operational Guidance:</h5><p>Only trigger this for high-confidence compromise, because this is destructive. Always log the eviction and link it to the detection event so that post-incident review can reconstruct why it happened.</p><h5>Example: Agent Session Eviction Orchestrator</h5><pre><code># File: eviction_scripts/evict_agent_session.py\nimport time\nimport redis\nfrom kubernetes import client, config\n\ndef log_eviction_event(agent_id, action_taken, reason):\n    print({\n        \"event_type\": \"agent_session_eviction\",\n        \"agent_id\": agent_id,\n        \"action\": action_taken,\n        \"reason\": reason,\n        \"timestamp\": time.time()\n    })\n\ndef evict_agent_session(agent_id: str, pod_name: str, namespace: str, reason: str = \"agent_compromise_detected\"):\n    \"\"\"Terminate a rogue agent's container and purge its cached session state.\"\"\"\n    print(f\"[Evict] Initiating eviction for agent {agent_id}...\")\n\n    # 1. Terminate the containerized agent process immediately\n    try:\n        config.load_incluster_config()  # or load_kube_config() if running externally\n        v1 = client.CoreV1Api()\n        v1.delete_namespaced_pod(\n            name=pod_name,\n            namespace=namespace,\n            body=client.V1DeleteOptions(grace_period_seconds=0)\n        )\n        print(f\"[Evict] Deleted pod {pod_name} for agent {agent_id}.\")\n    except Exception as e:\n        print(f\"[Evict][Error] Failed to delete pod {pod_name}: {e}\")\n\n    # 2. Purge any persisted agent session state from Redis (targeted keys only)\n    try:\n        r = redis.Redis()\n        pattern = f\"session:{agent_id}:*\"\n        keys_to_delete = list(r.scan_iter(pattern))\n        if keys_to_delete:\n            r.delete(*keys_to_delete)\n            print(f\"[Evict] Purged {len(keys_to_delete)} cache entries for agent {agent_id}.\")\n    except Exception as e:\n        print(f\"[Evict][Error] Failed to purge cached state for agent {agent_id}: {e}\")\n\n    log_eviction_event(agent_id, \"FULL_AGENT_EVICTION\", reason)\n    print(f\"[Evict] ✅ Eviction complete for agent {agent_id}.\")\n</code></pre><p><strong>Action:</strong> Build a callable eviction function that your SOC or automated watcher can trigger. It should (a) delete the pod of the compromised agent instance, and (b) purge only that agent's session keys from Redis (never a full FLUSHDB). This guarantees the compromised behavior cannot silently respawn with poisoned memory.</p>"
                },
                {
                    "strategy": "Forcefully delete or quarantine compromised Kubernetes pods/containers.",
                    "howTo": "<h5>Concept:</h5><p>In Kubernetes, the fastest, safest eviction is often to delete the compromised pod right now. The Deployment/ReplicaSet/Job controller will recreate a clean pod from the known-good image. This instantly cuts off malicious execution and halts resource hijacking (GPU abuse, secret scraping, exfil loops).</p><h5>Operational Guidance:</h5><p>Before or immediately after deletion, record minimal forensics (image digest, pod labels, node, suspicious commands) to support later investigation. Always log who/what initiated the deletion and why.</p><h5>Example: Emergency Pod Eviction via kubectl</h5><pre><code># Administrator or SOAR playbook usage during incident response\nCOMPROMISED_POD=\"inference-server-prod-5f8b5c7f9-xyz12\"\nNAMESPACE=\"ai-production\"\n\necho \"[Evict] Evicting compromised pod ${COMPROMISED_POD}...\"\n# Immediate, no-grace shutdown to prevent attacker cleanup hooks\nkubectl delete pod ${COMPROMISED_POD} \\\n    --namespace ${NAMESPACE} \\\n    --grace-period=0 \\\n    --force\n\n# Optional: watch cluster recover a clean replacement pod\nkubectl get pods -n ${NAMESPACE} -w\n</code></pre><p><strong>Action:</strong> Add this forced pod eviction procedure to your incident response runbooks. Make sure platform SREs and SOC both know who is allowed to run it, and that every forced deletion is logged with pod name, namespace, initiator, and root-cause alert ID.</p>"
                },
                {
                    "strategy": "Invalidate active user sessions involved in malicious or hijacked activity.",
                    "howTo": "<h5>Concept:</h5><p>If an attacker steals a user's session cookie or bearer session token, they can impersonate that user indefinitely (until expiry). You must be able to server-side revoke that session immediately. The safest pattern is a central, server-side session store (e.g. Redis) where you can delete a session ID on demand.</p><h5>Operational Guidance:</h5><p>This invalidation endpoint/function must be tightly access-controlled (SOC-only / SOAR-only / admin with MFA). It is effectively a 'kick this user out now' button and should be audited.</p><h5>Example: Server-Side Session Storage and Invalidation</h5><pre><code># Snippet: Flask-style server-side session with Redis\nfrom flask import Flask, session\nfrom flask_session import Session\nimport redis\n\napp = Flask(__name__)\napp.config[\"SECRET_KEY\"] = \"REDACTED_FOR_PROD\"\napp.config[\"SESSION_TYPE\"] = \"redis\"\napp.config[\"SESSION_REDIS\"] = redis.from_url(\"redis://localhost:6379\")\nSession(app)\n\n@app.route(\"/login\", methods=[\"POST\"])\ndef login():\n    # ... after validating credentials ...\n    session[\"user_id\"] = \"user123\"  # stored server-side in Redis, not in the cookie\n    return \"Logged in\"\n\n# Eviction helper (conceptual): delete that user's session keys\n\ndef log_eviction_event(user_id, action_taken, reason):\n    import time\n    print({\n        \"event_type\": \"user_session_eviction\",\n        \"user_id\": user_id,\n        \"action\": action_taken,\n        \"reason\": reason,\n        \"timestamp\": time.time()\n    })\n\ndef invalidate_user_session(user_id: str, reason: str = \"account_compromise_suspected\"):\n    \"\"\"Invalidate all active sessions for a given user by removing their server-side session data.\"\"\"\n    # In production you'd maintain an index user_id -> session_ids.\n    session_ids = find_session_ids_for_user(user_id)  # implement this mapping\n    for sid in session_ids:\n        delete_session_id_from_redis(sid)  # implement this to remove that SID's data\n    log_eviction_event(user_id, \"SESSION_INVALIDATED\", reason)\n    print(f\"[Evict] ✅ Invalidated sessions for user {user_id}.\")\n</code></pre><p><strong>Action:</strong> Require that all privileged or high-value sessions (admin dashboards, model management consoles, agent control panels) be revocable in real time. Build an internal function or SOAR action that deletes those sessions server-side and records who initiated the forced logout.</p>"
                },
                {
                    "strategy": "Record every eviction action in a structured, tamper-resistant audit log.",
                    "howTo": "<h5>Concept:</h5><p>Eviction is a high-impact, high-risk action. If you kill an inference pod or invalidate an executive's session, you must be able to prove why you did it, what you touched, and who authorized it. A standardized eviction logger creates incident-grade forensics and enables compliance review.</p><h5>Operational Guidance:</h5><p>All eviction helpers (process kill, pod delete, agent session purge, user session invalidation) must call a shared logging function. The log should include: timestamp, target identity, action taken (SIGKILL, DELETE_POD, SESSION_INVALIDATED), initiator (SOAR playbook, analyst ID), and the triggering alert/ticket reference.</p><h5>Example: Centralized Eviction Logger</h5><pre><code># File: eviction_scripts/eviction_logger.py\nimport json\nimport time\n\ndef log_eviction_event(target_id, target_type, action_taken, initiator, reason):\n    \"\"\"Emit a structured, immutable-ish audit log for incident forensics.\"\"\"\n    record = {\n        \"timestamp\": time.time(),\n        \"event_type\": \"entity_eviction\",\n        \"target\": {\n            \"id\": str(target_id),          # e.g. PID, pod name, user ID, agent_id\n            \"type\": target_type            # e.g. OS_PROCESS, K8S_POD, USER_SESSION, AGENT_INSTANCE\n        },\n        \"action\": {\n            \"type\": action_taken,          # e.g. SIGKILL, DELETE_POD, SESSION_INVALIDATED\n            \"initiator\": initiator,        # e.g. SOAR_PLAYBOOK_X, soc-analyst@company\n            \"reason\": reason               # link to alert ID / incident ticket\n        }\n    }\n\n    # In production, send to SIEM or append-only log store with write-once retention\n    print(f\"[Evict][Audit] {json.dumps(record)}\")\n</code></pre><p><strong>Action:</strong> Enforce that every eviction path calls a common logging function like <code>log_eviction_event</code> before/after the kill. Store these logs in a central SIEM or write-once bucket for later incident analysis, regulatory reporting, and lessons-learned review.</p>"
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
                        "AML.T0011.001 User Execution: Malicious Package",
                        "AML.T0018 Manipulate AI Model",
                        "AML.T0018.002 Manipulate AI Model: Embed Malware",
                        "AML.T0020 Poison Training Data",
                        "AML.T0059 Erode Dataset Integrity",
                        "AML.T0070 RAG Poisoning",
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
                        "ML06:2023 ML Supply Chain Attacks",
                        "ML10:2023 Model Poisoning"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-E-003.001",
                    "name": "Neural Network Backdoor Detection & Removal", "pillar": ["model"], "phase": ["improvement"],
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
                                "AML.T0076 Corrupt AI Model"
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
                            "strategy": "Apply neural cleanse (reverse-engineer minimal triggers) to detect backdoor classes.",
                            "howTo": "<h5>Concept:</h5><p>Neural Cleanse attempts to synthesize the smallest possible trigger that forces the model to predict each class with high confidence. If one class can be hijacked by an extremely small trigger, that class is likely backdoored. This is used during incident analysis or pre-deployment validation.</p><h5>Use ART's Neural Cleanse</h5><p>The Adversarial Robustness Toolbox (ART) provides an implementation that scans a trained classifier for hidden triggers. Always archive the suspect model before scanning so forensics can review the untouched artifact later.</p><pre><code># File: backdoor_removal/neural_cleanse.py\nfrom art.defences.transformer.poisoning import NeuralCleanse\n\n# 'classifier' is the model wrapped as an ART classifier\n# 'X_test', 'y_test' are held-out clean validation data\n\ncleanse = NeuralCleanse(classifier, steps=20, learning_rate=0.1)\nresults = cleanse.detect_poison()\n\nis_clean_array = results[0]\nfor class_idx, is_clean in enumerate(is_clean_array):\n    if not is_clean:\n        print(f\"🚨 BACKDOOR SUSPECTED in class {class_idx}\")\n</code></pre><p><strong>Action:</strong> Run Neural Cleanse on any model that behaves suspiciously. Flag classes that exhibit tiny/highly effective triggers. Treat those classes as compromised until validated or remediated.</p>"
                        },
                        {
                            "strategy": "Use activation clustering to isolate trojan neurons and poisoned samples.",
                            "howTo": "<h5>Concept:</h5><p>Backdoored inputs often light up a tight cluster of 'trojan' neurons. By capturing internal activations and clustering them, you can locate anomalous groups of samples that share the same hidden trigger. This is useful for identifying which training samples (and which neurons) are corrupted.</p><h5>Use ART's ActivationDefence</h5><p>ActivationDefence extracts layer activations, clusters them, and reports which samples are outliers. Those samples can then be investigated or removed from the training set.</p><pre><code># File: backdoor_removal/activation_clustering.py\nimport numpy as np\nfrom art.defences.transformer.poisoning import ActivationDefence\n\n# 'classifier' is an ART-wrapped model\n# 'X_train', 'y_train' are training samples (may include poison)\n# 'layer_name' should point to a penultimate layer\n\ndefence = ActivationDefence(\n    classifier,\n    X_train,\n    y_train,\n    layer_name='model.fc1'  # adjust to your model\n)\n\nreport, is_clean_array = defence.detect_poison(cluster_analysis=\"smaller\")\npoison_indices = np.where(is_clean_array == False)[0]\n\nif len(poison_indices) > 0:\n    print(f\"🚨 {len(poison_indices)} suspicious samples found via activation clustering.\")\n</code></pre><p><strong>Action:</strong> Run activation clustering when you suspect a model backdoor. Treat outlier clusters as likely poisoned samples and record them for removal and legal/forensic traceability.</p>"
                        },
                        {
                            "strategy": "Perform fine-pruning to disable malicious neurons.",
                            "howTo": "<h5>Concept:</h5><p>After you identify specific neurons strongly associated with the backdoor trigger, you can surgically 'turn them off' by zeroing their weights. This is called fine-pruning. It often kills the backdoor while preserving most accuracy.</p><h5>Prune Trojan Neurons</h5><p>Always checkpoint the original model first. After pruning, re-evaluate on clean data and on known backdoor-trigger inputs, and log both results to your SIEM/IR case record.</p><pre><code># File: backdoor_removal/fine_pruning.py\nimport torch\n\n# 'model' is a loaded PyTorch model under investigation\n# 'suspicious_neuron_indices' is a list like [12, 57, 83]\n# 'model.fc1' is an example layer suspected of holding the trojan logic\n\ndef prune_neurons(model, layer_name, suspicious_neuron_indices):\n    target_layer = getattr(model, layer_name)\n    with torch.no_grad():\n        # Zero incoming weights for suspicious neurons\n        target_layer.weight[:, suspicious_neuron_indices] = 0\n        # Optionally zero outgoing weights in downstream layers as well\n    return model\n\n# pruned_model = prune_neurons(model, 'fc1', suspicious_neuron_indices)\n# torch.save(pruned_model.state_dict(), 'pruned_model_after_fineprune.pth')\n</code></pre><p><strong>Action:</strong> Use fine-pruning to neutralize the neurons most correlated with a suspected backdoor. After pruning, confirm: (1) clean accuracy is acceptable, and (2) backdoor trigger success rate drops toward zero.</p>"
                        },
                        {
                            "strategy": "Retrain / fine-tune on trusted clean data to overwrite hidden backdoors.",
                            "howTo": "<h5>Concept:</h5><p>A reliable (though more expensive) remediation is to fine-tune the compromised model for a few epochs on a strictly vetted clean dataset. This 're-teaches' the model normal behavior and weakens the backdoor trigger.</p><h5>Targeted Remediation Fine-Tune</h5><p>Freeze earlier layers to preserve general capabilities, retrain only the final layers. Afterward, store the remediated model as a new signed artifact and mark the old model as <code>quarantined</code> for forensics, not for production use.</p><pre><code># File: backdoor_removal/retrain.py\nimport torch\n\n# 'compromised_model' is loaded\n# 'clean_dataloader' yields trusted examples only\n\n# 1. Freeze most layers\nfor name, param in compromised_model.named_parameters():\n    if 'fc' not in name:  # keep final layers trainable, freeze the rest\n        param.requires_grad = False\n\noptimizer = torch.optim.Adam(\n    filter(lambda p: p.requires_grad, compromised_model.parameters()),\n    lr=0.001\n)\ncriterion = torch.nn.CrossEntropyLoss()\n\nfor epoch in range(5):\n    for data, target in clean_dataloader:\n        optimizer.zero_grad()\n        output = compromised_model(data)\n        loss = criterion(output, target)\n        loss.backward()\n        optimizer.step()\n    print(f\"Fine-tune epoch {epoch+1} done.\")\n\n# torch.save(compromised_model.state_dict(), 'remediated_model.pth')\n</code></pre><p><strong>Action:</strong> When a model is confirmed backdoored, run a short fine-tune on verified-clean data. Version and sign the remediated model artifact. Never silently overwrite the original; keep the original for evidence.</p>"
                        },
                        {
                            "strategy": "Differential testing between a suspect model and a known-good baseline model.",
                            "howTo": "<h5>Concept:</h5><p>If you have a previous 'golden' (trusted) model, compare it with the suspect model on a wide pool of inputs. Any input where the two models disagree is suspicious, and may reveal a hidden trigger or backdoor pathway.</p><h5>Side-by-side Behavioral Diff</h5><p>Log all disagreements with enough context (input features, suspect vs golden output) so investigators can reproduce the issue. This log should be retained with your incident ticket for audit.</p><pre><code># File: backdoor_removal/differential_test.py\nimport torch\n\ndisagreements = []\n\n# 'suspect_model' and 'golden_model' are loaded\n# 'unlabeled_dataloader' yields diverse samples\n\nfor inputs, _ in unlabeled_dataloader:\n    suspect_preds = suspect_model(inputs).argmax(dim=1)\n    golden_preds = golden_model(inputs).argmax(dim=1)\n\n    mismatch_indices = torch.where(suspect_preds != golden_preds)[0]\n    for idx in mismatch_indices:\n        disagreements.append({\n            'input_data': inputs[idx].cpu().numpy().tolist(),\n            'suspect_prediction': int(suspect_preds[idx]),\n            'golden_prediction': int(golden_preds[idx])\n        })\n\nif disagreements:\n    print(f\"🚨 {len(disagreements)} anomalous inputs found (suspect != golden). Potential triggers logged.\")\n</code></pre><p><strong>Action:</strong> Maintain at least one signed, known-good 'golden' model. Whenever a production model shows signs of compromise, run differential testing to surface suspicious triggers for deeper analysis and cleanup.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-003.002",
                    "name": "Poisoned Data Detection & Cleansing", "pillar": ["data"], "phase": ["improvement"],
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
                            "strategy": "Detect statistically anomalous (poisoned) samples with outlier detection.",
                            "howTo": "<h5>Concept:</h5><p>Poisoned samples often look statistically weird: extreme feature values, unnatural distributions, or adversarial trigger tokens. Isolation Forest and similar outlier detectors can identify these anomalies at scale before training.</p><h5>Isolation Forest for Poison Candidate Discovery</h5><p>Always snapshot the pre-clean dataset with DVC/Delta Lake so you can roll back, and so you have evidence for audit.</p><pre><code># File: data_cleansing/outlier_detection.py\nimport pandas as pd\nfrom sklearn.ensemble import IsolationForest\n\ndf = pd.read_csv('dataset.csv')  # potentially poisoned\n\nisolation_forest = IsolationForest(\n    contamination=0.01,\n    random_state=42\n)\n\npred = isolation_forest.fit_predict(df[['feature1', 'feature2']])\npoison_candidates = df[pred == -1]\nprint(f\"Identified {len(poison_candidates)} potential poison samples.\")\n\ncleansed_df = df[pred == 1]\n</code></pre><p><strong>Action:</strong> Run Isolation Forest (or similar) on high-risk training sets. Remove the top ~1% most anomalous rows as poison candidates. Keep hashes/IDs of removed rows in a secure log for later forensics.</p>"
                        },
                        {
                            "strategy": "Track provenance and block compromised data sources.",
                            "howTo": "<h5>Concept:</h5><p>When you catch poisoning, you must know where the bad data came from (e.g. user upload API, partner feed, compromised ETL). Tag every row of data with a <code>source</code> field at ingestion, and analyze which source produced the suspicious rows.</p><h5>Source Attribution</h5><p>Once you identify a malicious source, quarantine that pipeline/feed. Version-control all ingestion manifests for audit.</p><pre><code># 'full_df' includes a 'source' column for lineage\n# 'poison_indices' are the row indices flagged as poisoned\n\npoisoned_rows = full_df.iloc[poison_indices]\nculprit_source = poisoned_rows['source'].value_counts().idxmax()\nprint(f\"🚨 Likely malicious source: {culprit_source}\")\n</code></pre><p><strong>Action:</strong> Enforce a mandatory <code>source</code> (origin tag) on all ingested data. When poison is found, immediately block or review that source, and record the decision in the IR ticket.</p>"
                        },
                        {
                            "strategy": "Cluster embeddings (DBSCAN / density methods) to locate dense poison clusters and tiny trigger clusters.",
                            "howTo": "<h5>Concept:</h5><p>Backdoor-trigger samples tend to look very similar to each other so the trigger is consistent. They often form tiny, dense clusters separate from the main data. DBSCAN can surface those suspicious 'micro-clusters' and outliers.</p><h5>DBSCAN for Cluster-Based Poison Discovery</h5><p>Flag very small clusters (e.g. &lt;10 points) and outliers (label -1). Store these IDs separately before removal so you can prove why data was discarded.</p><pre><code># File: data_cleansing/dbscan.py\nimport numpy as np\nfrom sklearn.cluster import DBSCAN\n\n# 'feature_embeddings' is an array of embedding vectors for each sample\n\ndb = DBSCAN(eps=0.5, min_samples=5).fit(feature_embeddings)\nlabels = db.labels_\n\noutlier_indices = np.where(labels == -1)[0]\nprint(f\"Found {len(outlier_indices)} anomalous points (label -1).\")\n\ncluster_ids, counts = np.unique(labels[labels != -1], return_counts=True)\nsmall_clusters = cluster_ids[counts < 10]\nprint(f\"Small suspicious clusters: {small_clusters}\")\n</code></pre><p><strong>Action:</strong> Use DBSCAN (or similar) to find tiny, high-risk clusters. Review/remove samples from those clusters as suspected poison. Keep a signed record of what was removed and why.</p>"
                        },
                        {
                            "strategy": "Continuously scan your RAG vector database for semantically malicious content.",
                            "howTo": "<h5>Concept:</h5><p>Attackers can poison a RAG system by inserting embeddings of harmful content into your vector DB. Mitigation: maintain a list of known malicious phrases/patterns, embed them with the same model you use in production, and perform similarity search. Anything with extremely high similarity should be reviewed or purged.</p><h5>High-Similarity Screening</h5><p>Do this on a schedule (e.g., hourly/daily) and log any removals. Use versioned snapshots of the vector DB (or export) before deletion for evidence.</p><pre><code># File: data_cleansing/scan_vectordb.py\nMALICIOUS_PHRASES = [\n    \"Instructions on how to build a bomb\",\n    \"Full credit card fraud tutorial\",\n    \"Hate speech against a protected group\"\n]\n\n# 'embedding_model' is your production embedding model\nmalicious_embeds = embedding_model.encode(MALICIOUS_PHRASES)\n\nSIMILARITY_THRESHOLD = 0.9\npoison_candidates = []\n\nfor phrase_idx, vec in enumerate(malicious_embeds):\n    results = vector_db_client.search(\n        collection_name=\"rag_docs\",\n        query_vector=vec,\n        limit=5\n    )\n    for r in results:\n        if r.score > SIMILARITY_THRESHOLD:\n            poison_candidates.append({\n                \"doc_id\": r.id,\n                \"reason\": f\"High semantic match to phrase '{MALICIOUS_PHRASES[phrase_idx]}'\",\n                \"score\": r.score\n            })\n\nprint(poison_candidates)\n</code></pre><p><strong>Action:</strong> Maintain a curated list of banned / toxic / policy-violating concepts. On a recurring schedule, embed them and query your vector DB. Remove or quarantine any entries above a similarity threshold, and record the decision trail.</p>"
                        },
                        {
                            "strategy": "Verify dataset integrity against known-good cryptographic hashes before training.",
                            "howTo": "<h5>Concept:</h5><p>For high-value training runs, treat the dataset like production code: hash it, sign it, and verify it before every job. If anything has changed unexpectedly, abort. This prevents silently training on tampered data.</p><h5>Hash Manifest Enforcement</h5><p>Generate a SHA-256 manifest from a trusted snapshot and store that manifest in Git or another write-once store. Your pipeline must verify hashes before training begins.</p><pre><code># Generate the baseline manifest on a trusted machine\n# (run once after data is approved)\nsha256sum data/clean/*.csv > data_manifest.sha256\n\n# In the training pipeline (shell script)\necho \"Verifying training data integrity...\"\nif ! sha256sum -c data_manifest.sha256; then\n    echo \"❌ DATA INTEGRITY CHECK FAILED. Halting training.\" >&2\n    exit 1\nfi\n\necho \"✅ Data integrity verified.\"\n</code></pre><p><strong>Action:</strong> Treat training data like signed artifacts: create a hash manifest for clean data, and block any training job whose input data fails verification. Keep failed verification logs for compliance and incident review.</p>"
                        },
                        {
                            "strategy": "Remove suspicious data in controlled batches and retrain incrementally to avoid catastrophic accuracy loss.",
                            "howTo": "<h5>Concept:</h5><p>If you mass-delete everything that looks suspicious, you may crater model quality because of false positives. Safer pattern: remove in small batches, retrain, evaluate, stop if performance drops too far. Record each batch removal and resulting metrics for audit/MLOps traceability.</p><h5>Progressive Eviction Loop</h5><p>Use an iterative loop that: (1) removes 5-10% of the flagged samples at a time, (2) retrains or fine-tunes, (3) measures accuracy vs a clean validation set, and (4) stops if drop &gt; threshold.</p><pre><code># File: data_cleansing/gradual_removal.py\nimport numpy as np\n\nACCEPTABLE_DROP = 0.02  # max 2% absolute accuracy loss allowed\nbaseline_acc = evaluate_model(model, validation_data)\n\nnp.random.shuffle(suspicious_indices)\nbatch_size = max(1, len(suspicious_indices) // 10)\n\nfor i in range(0, len(suspicious_indices), batch_size):\n    to_remove = suspicious_indices[i:i+batch_size]\n    current_clean = full_dataset.drop(index=to_remove)\n\n    retrained_model = train_model(current_clean)\n    current_acc = evaluate_model(retrained_model, validation_data)\n    print(f\"Removed {len(to_remove)} samples. New accuracy: {current_acc:.4f}\")\n\n    if (baseline_acc - current_acc) > ACCEPTABLE_DROP:\n        print(\"Stopping removal: accuracy drop too high. Investigate manually.\")\n        break\n\n    # Commit the new dataset snapshot to DVC / Delta Lake here\n    full_dataset = current_clean\n</code></pre><p><strong>Action:</strong> Automate a staged data-cleansing loop. After each batch removal, checkpoint both the dataset (via DVC/Delta Lake) and resulting model. This gives you rollback capability and an auditable trail that explains why data was removed and what impact it had.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-003.003",
                    "name": "Malicious Code & Configuration Cleanup", "pillar": ["infra", "app"], "phase": ["improvement", "response"],
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
                                "AML.T0072 Reverse Shell"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Runtime Code Injection (L4)",
                                "Memory Corruption (L4)",
                                "Misconfigurations (L4)",
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
                                "LLM08:2025 Vector and Embedding Weaknesses"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML06:2023 AI Supply Chain Attacks",
                                "ML09:2023 Output Integrity Attack"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Detect unauthorized changes to ML frameworks, system binaries, and configs using File Integrity Monitoring (FIM).",
                            "howTo": "<h5>Concept:</h5><p>Attackers may modify core libraries (e.g. torch, sklearn), inject hostile hooks, or disable security logging. A File Integrity Monitoring (FIM) / Host IDS baseline lets you spot any drift. This is immediate incident response (who tampered with this host?) and ongoing hardening.</p><h5>Initialize a Trusted Baseline</h5><p>On a freshly provisioned, trusted host, generate a baseline DB of hashes. Store that baseline in a secure, write-once location so attackers cannot silently update it.</p><pre><code># Create baseline with AIDE on a clean host\nsudo aide --init\nsudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz\n</code></pre><h5>Schedule Integrity Checks</h5><p>Run a cron job or SOAR action that periodically executes <code>aide --check</code> (or Tripwire/Wazuh equivalent). Alert on any unexpected differences, and log them to SIEM with timestamp, hostname, and file paths for forensics.</p><pre><code># Nightly check example\nsudo aide --check\n# Output differences: changed hashes in sensitive libs or config files\n</code></pre><p><strong>Action:</strong> Deploy FIM (AIDE/Tripwire/Wazuh) on all AI inference/training nodes. Baseline once on a golden image, then continuously diff. Treat any unauthorized drift as an incident and record it alongside the alert ID.</p>"
                        },
                        {
                            "strategy": "Statically analyze model loading code for malicious deserialization or custom loader hooks.",
                            "howTo": "<h5>Concept:</h5><p>Attackers often weaponize model loading code instead of the model file itself (e.g., custom <code>__reduce__</code> methods that run arbitrary code during <code>pickle.load()</code>). You must scan loader scripts before allowing them in production.</p><h5>AST-Based Scanner</h5><p>Use Python's <code>ast</code> module to look for suspicious constructs (like <code>__reduce__</code>, arbitrary <code>exec()</code>, or <code>os.system()</code>) in loader scripts. Block deployment if flagged. Never auto-run unreviewed loaders.</p><pre><code># File: code_cleanup/ast_scanner.py\nimport ast\n\nSUSPICIOUS_NAMES = {\"__reduce__\", \"exec\", \"eval\", \"os.system\", \"subprocess.Popen\"}\n\nclass LoaderScanner(ast.NodeVisitor):\n    def __init__(self):\n        self.findings = []\n    def visit_FunctionDef(self, node):\n        if node.name in SUSPICIOUS_NAMES:\n            self.findings.append((node.name, node.lineno))\n        self.generic_visit(node)\n    def visit_Call(self, node):\n        # catch exec()/eval()/os.system()/subprocess.Popen calls\n        if hasattr(node.func, 'id') and node.func.id in {\"exec\", \"eval\"}:\n            self.findings.append((node.func.id, node.lineno))\n        self.generic_visit(node)\n\nwith open('load_model.py', 'r') as f:\n    tree = ast.parse(f.read())\n\nscanner = LoaderScanner()\nscanner.visit(tree)\n\nif scanner.findings:\n    print(\"🚨 Suspicious loader patterns detected:\")\n    for name, line in scanner.findings:\n        print(f\" - {name} at line {line}\")\n</code></pre><p><strong>Action:</strong> Before promoting any new model loader / agent bootstrap code, run a static AST scan to flag risky constructs. Block anything that triggers until a security engineer signs off. Log the review decision.</p>"
                        },
                        {
                            "strategy": "Verify integrity of AI agent tools/plugins against a signed hash manifest at startup.",
                            "howTo": "<h5>Concept:</h5><p>Agentic systems often load 'tools' (Python scripts, plugins) dynamically. An attacker can slip a backdoored tool file into that directory. Mitigation: at build time, generate a signed manifest of SHA-256 hashes; at runtime, verify each tool file matches its expected hash. Abort startup if anything is tampered.</p><h5>Hash Manifest + Runtime Enforcement</h5><p>Store the manifest in code-signed form (e.g. signed by CI), not writable by the runtime service account. Any mismatch should be logged to SIEM and treated as an active compromise.</p><pre><code># File: agent/verify_tools.py\nimport hashlib, os, json, time\n\nclass IntegrityError(Exception):\n    pass\n\ndef sha256_file(path):\n    h = hashlib.sha256()\n    with open(path, 'rb') as f:\n        for chunk in iter(lambda: f.read(8192), b''):\n            h.update(chunk)\n    return h.hexdigest()\n\ndef verify_tools_integrity(tool_dir, manifest_path):\n    with open(manifest_path, 'r') as mf:\n        known = {line.split()[1]: line.split()[0] for line in mf}\n    for fname in os.listdir(tool_dir):\n        if fname.endswith('.py'):\n            fullpath = os.path.join(tool_dir, fname)\n            current = sha256_file(fullpath)\n            if known.get(fname) != current:\n                record = {\n                    \"timestamp\": time.time(),\n                    \"event\": \"tool_integrity_violation\",\n                    \"file\": fname\n                }\n                print(f\"🚨 Tampering detected in {fname}: {json.dumps(record)}\")\n                raise IntegrityError(f\"Tool {fname} hash mismatch\")\n    print(\"✅ All agent tools passed integrity check.\")\n\n# verify_tools_integrity('agent/tools/', 'tool_manifest.sha256')\n</code></pre><p><strong>Action:</strong> Add a startup gate that refuses to launch the agent service if any tool/plugin hash does not match the signed manifest. This prevents silently running attacker-modified helper code. Log failures with timestamp, filename, and initiator.</p>"
                        },
                        {
                            "strategy": "Audit and remove unauthorized cron jobs / scheduled tasks used for persistence.",
                            "howTo": "<h5>Concept:</h5><p>Attackers love persistence via cron (Linux) or Scheduled Tasks (Windows). You should diff the current scheduled tasks against a known-good baseline stored in a protected location. Any drift is suspicious.</p><h5>Baseline vs Current Diff</h5><p>Export all crontabs for every user, diff them against a baseline snapshot. Alert on differences, then remove or disable unauthorized entries. Keep both the diff and original crontab snapshot for forensics.</p><pre><code># File: incident_response/audit_cron.sh\nOUTPUT_FILE=\"current_crontabs.txt\"\nBASELINE_FILE=\"baseline_crontabs.txt\"  # stored read-only in a secure repo\n\necho \"Auditing all user crontabs...\" > ${OUTPUT_FILE}\n\nfor user in $(cut -f1 -d: /etc/passwd); do\n    echo \"### Crontab for ${user} ###\" >> ${OUTPUT_FILE}\n    crontab -u ${user} -l >> ${OUTPUT_FILE} 2>/dev/null\ndone\n\ndiff -q ${BASELINE_FILE} ${OUTPUT_FILE} || {\n    echo \"🚨 CRON DRIFT DETECTED. Review unauthorized scheduled tasks.\";\n    diff ${BASELINE_FILE} ${OUTPUT_FILE};\n}\n</code></pre><p><strong>Action:</strong> Nightly (or on incident trigger), diff all cron jobs against a read-only baseline. Remove/disable anything unexpected and log who approved the cleanup. This evicts attacker persistence like reverse shells or data exfil scripts.</p>"
                        },
                        {
                            "strategy": "Continuously enforce golden configuration via config management / GitOps.",
                            "howTo": "<h5>Concept:</h5><p>Attackers often weaken logging, disable auth, or change inference service flags. Use configuration management (Ansible/Puppet/Chef/GitOps) to overwrite drift automatically with a trusted template from version control. Treat any diff as an incident.</p><h5>Automated Reconciliation</h5><p>Run Ansible or a GitOps controller every 15–30 minutes (or immediately on alert) to force the server config back to the approved template and lock down permissions. Send drift events to SIEM so SOC can investigate who changed what and why.</p><pre><code># File: ansible/playbook.yml\n- name: Enforce Secure Configuration for AI App\n  hosts: ai_servers\n  become: true\n  tasks:\n    - name: Ensure AI app config is correct and locked down\n      ansible.builtin.template:\n        src: templates/app_config.yaml.j2   # trusted in Git\n        dest: /etc/my_ai_app/config.yaml\n        owner: root\n        group: root\n        mode: '0640'\n      # Any unauthorized change on the host gets overwritten here.\n</code></pre><p><strong>Action:</strong> Treat config files for AI inference/training services as immutable infrastructure. Automatically revert any drift and alert. This both evicts attacker persistence and documents the remediation for audit.</p>"
                        },
                        {
                            "strategy": "Scan for and remove web shells / reverse shells in agent surfaces and API-facing code.",
                            "howTo": "<h5>Concept:</h5><p>Attackers may drop a web shell (PHP/Python/etc.) or inject reverse-shell logic into agent helper scripts, letting them execute arbitrary OS commands later. You should regularly grep for dangerous calls (eval/exec/system/subprocess) in web roots and agent tool directories.</p><h5>Pattern-Based Shell Hunting</h5><p>Run this scan on a schedule or immediately after an incident alert. Anything suspicious gets quarantined, hashed, and archived for forensics, then removed from production.</p><pre><code># Example shell-hunting command on a Linux host\n# Scan .php/.py/.jsp for dangerous execution primitives\n\ngrep --recursive --ignore-case \\\n  --include=\"*.php\" --include=\"*.py\" --include=\"*.jsp\" \\\n  -E \"eval\\(|exec\\(|system\\(|passthru\\(|shell_exec\\(|popen\\(|proc_open\\(|subprocess\\.Popen\" \\\n  /var/www/html/\n\n# Suspicious hits should be reviewed and removed immediately.\n</code></pre><p><strong>Action:</strong> Add automated reverse shell / web shell scanning to your IR checklist and scheduled security jobs. When found, quarantine and delete. Log filename, path, hash, and who approved the cleanup.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-E-003.004",
                    "name": "Malicious Node Eviction in Graph Datasets", "pillar": ["data"], "phase": ["improvement"],
                    "description": "After a detection method identifies nodes that are likely poisoned or part of a backdoor trigger, this eviction technique systematically removes those nodes and their associated edges from the graph dataset. This cleansing action is performed before the final, clean Graph Neural Network (GNN) model is trained or retrained, ensuring the malicious artifacts and their influence are fully purged from the training process.",
                    "implementationStrategies": [
                        {
                            "strategy": "Remove confirmed malicious nodes entirely from the graph dataset before retraining.",
                            "howTo": "<h5>Concept:</h5><p>In graph poisoning/backdoor attacks (on Graph Neural Networks), attackers insert specific malicious nodes or subgraphs that steer predictions. Once detection logic flags certain node IDs as malicious, the safest eviction is to delete those nodes and all their edges from the training graph so they cannot influence message passing.</p><h5>Programmatic Node Eviction</h5><p>Take a snapshot of the original graph first (DVC / versioned artifact). Then remove all malicious node IDs and persist the cleansed graph as a new version for retraining and audit.</p><pre><code># File: eviction/evict_nodes.py\nimport networkx as nx\n\ndef evict_nodes(G, malicious_node_ids):\n    original_node_count = G.number_of_nodes()\n    G.remove_nodes_from(malicious_node_ids)\n    new_node_count = G.number_of_nodes()\n    print(f\"Evicted {len(malicious_node_ids)} malicious nodes.\")\n    print(f\"Graph size: {original_node_count} -> {new_node_count} nodes.\")\n    return G\n</code></pre><p><strong>Action:</strong> When your anomaly detector (e.g. AID-D-* series) outputs a malicious node list, run an eviction step that removes those nodes and stores the resulting graph as a distinct, signed artifact for retraining.</p>"
                        },
                        {
                            "strategy": "Isolate (but keep) malicious nodes by removing all their edges.",
                            "howTo": "<h5>Concept:</h5><p>Sometimes legal/compliance or forensics requires you to preserve the node object itself as evidence. In that case, instead of deleting the node, strip all of its inbound/outbound edges. This renders it inert for GNN message passing but keeps it in the dataset for audit.</p><h5>Edge Cut Isolation</h5><p>Log which edges were cut, and keep that diff alongside your incident record so you can prove why those connections disappeared.</p><pre><code># File: eviction/isolate_nodes_by_edge_removal.py\n\ndef isolate_nodes(G, malicious_node_ids):\n    edges_to_remove = []\n    for nid in malicious_node_ids:\n        for edge in list(G.edges(nid)):\n            edges_to_remove.append(edge)\n    original_edge_count = G.number_of_edges()\n    G.remove_edges_from(edges_to_remove)\n    new_edge_count = G.number_of_edges()\n    print(f\"Removed {len(edges_to_remove)} edges linked to malicious nodes.\")\n    print(f\"Edges: {original_edge_count} -> {new_edge_count}\")\n    return G\n</code></pre><p><strong>Action:</strong> For high-scrutiny environments, instead of deleting nodes outright, sever all their edges. This preserves audit evidence while preventing further graph influence. Store the pre/post edge diff in version control (DVC / Git LFS).</p>"
                        },
                        {
                            "strategy": "Automate the detect → evict → retrain loop as an MLOps pipeline.",
                            "howTo": "<h5>Concept:</h5><p>Graph poisoning response should be automated: run detection, produce a malicious node list, evict them (or cut their edges), retrain on the cleansed graph, then register the new model. This should emit artifacts (clean graph snapshot, retrained model, validation report) for audit.</p><h5>Pipeline Orchestration</h5><p>Use Kubeflow Pipelines, Airflow, or similar to chain these steps. Each stage should version its outputs and push metadata (timestamp, who approved) to your security log.</p><pre><code># Pseudocode for a Kubeflow-style pipeline\n# 1. detect_malicious_nodes_op -> outputs malicious_node_list\n# 2. evict_nodes_op -> outputs clean_graph\n# 3. retrain_gnn_op(clean_graph) -> outputs new_model\n# 4. validate_op(new_model, clean_graph) -> outputs validation report\n</code></pre><p><strong>Action:</strong> Stand up a dedicated remediation pipeline for graph-based models. Require security sign-off before promoting the newly retrained model to production, and archive every artifact for traceability.</p>"
                        },
                        {
                            "strategy": "Validate eviction effectiveness before redeploying the retrained GNN.",
                            "howTo": "<h5>Concept:</h5><p>After node/edge eviction and retraining, you must show two things: (1) normal task accuracy is still acceptable, and (2) the backdoor trigger attack no longer works. This mirrors traditional model backdoor remediation but in a GNN context.</p><h5>Post-Eviction Validation</h5><p>Run evaluation both on a clean validation set and on the known backdoor-trigger patterns or poisoned subgraphs. Store the report (accuracy, backdoor success rate) as part of the IR ticket and deployment approval log.</p><pre><code># File: eviction/validate_eviction.py\n# Pseudocode outline:\n# clean_acc = evaluate(gnn_model, clean_validation_graph)\n# trigger_success = evaluate_trigger_success(gnn_model, known_trigger_subgraphs)\n# print(f\"Clean accuracy: {clean_acc:.2%}\")\n# print(f\"Backdoor success rate: {trigger_success:.2%}\")\n# Require: high clean accuracy AND near-zero trigger_success before prod rollout.\n</code></pre><p><strong>Action:</strong> Gate production rollout on a signed validation report that documents clean accuracy and post-eviction backdoor success rate. This becomes part of your compliance and audit trail for AI integrity.</p>"
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
            "name": "Post-Eviction System Patching & Hardening", "pillar": ["infra", "app"], "phase": ["improvement"],
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
                        "ML06:2023 ML Supply Chain Attacks (if vulnerable library was entry point)"
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Apply security patches for exploited CVEs in AI stack.",
                    "howTo": "<h5>Concept:</h5><p>After an incident, if investigation shows the attacker used a known vulnerability in a library (e.g., TensorFlow, NumPy, FastAPI plugin, vector DB client), the first task is to patch that component everywhere. This stops immediate re-exploitation of the exact same vulnerability.</p><h5>Step 1: Update the Vulnerable Dependency</h5><p>Pin the fixed version in your dependency manifest so future builds always use the patched release.</p><pre><code># Before (vulnerable version)\n# File: requirements.txt\ntensorflow==2.11.0\nnumpy==1.23.5\n\n# After (patched version)\n# File: requirements.txt\ntensorflow==2.11.1  # <-- patched\nnumpy==1.24.2      # <-- patched\n</code></pre><h5>Step 2: Roll Out the Patch Fleet-Wide</h5><p>Use Ansible/Chef/Puppet (or commercial patch mgmt like Automox) to roll out the updated dependencies consistently across all AI-serving hosts and inference nodes.</p><pre><code># File: ansible/playbooks/patch_ai_servers.yml\n- name: Patch Python dependencies on AI servers\n  hosts: ai_servers\n  become: true\n  tasks:\n    - name: Copy updated requirements file\n      ansible.builtin.copy:\n        src: ../../requirements.txt\n        dest: /srv/my_ai_app/requirements.txt\n\n    - name: Install patched dependencies\n      ansible.builtin.pip:\n        requirements: /srv/my_ai_app/requirements.txt\n        virtualenv: /srv/my_ai_app/venv\n        state: latest\n\n    - name: Restart the AI application service\n      ansible.builtin.systemd:\n        name: my_ai_app.service\n        state: restarted\n</code></pre><p><strong>Action:</strong> Immediately pin and deploy the patched version of any exploited dependency. Treat this patch rollout as an emergency change and confirm it lands on every affected host, container image, and serverless function that runs the vulnerable code.</p>"
                },
                {
                    "strategy": "Review and harden abused or insecure system configurations.",
                    "howTo": "<h5>Concept:</h5><p>Most real intrusions are not pure 0-days. They are misconfigurations: overly permissive IAM roles, public S3 buckets, debug endpoints left exposed, etc. After eviction, you must fix the exact misconfig that let the attacker in and enforce that fix as the new baseline using Infrastructure as Code (IaC). That prevents drift back to the unsafe state.</p><h5>Step 1: Identify the Weak Config (Before)</h5><p>Example: A training-data S3 bucket was world-readable.</p><pre><code># File: infrastructure/s3.tf (vulnerable)\nresource \"aws_s3_bucket\" \"training_data\" {\n  bucket = \"aidefend-training-data-prod\"\n}\n# Missing 'aws_s3_bucket_public_access_block' means it could be made public.\n</code></pre><h5>Step 2: Enforce Least-Privilege via IaC (After)</h5><p>Harden and codify the secure config so it is version-controlled, reviewed, and automatically re-applied if someone tries to relax it later.</p><pre><code># File: infrastructure/s3.tf (hardened)\nresource \"aws_s3_bucket\" \"training_data\" {\n  bucket = \"aidefend-training-data-prod\"\n}\n\nresource \"aws_s3_bucket_public_access_block\" \"training_data_private\" {\n  bucket = aws_s3_bucket.training_data.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n</code></pre><p><strong>Action:</strong> Perform root cause analysis, fix the exact misconfiguration, and then freeze that fix into Terraform/Ansible/Puppet so it cannot silently drift back. Treat IaC as the enforcement mechanism for long-term hardening.</p>"
                },
                {
                    "strategy": "Strengthen IAM policies, I/O validation, and network segmentation around the compromised component.",
                    "howTo": "<h5>Concept:</h5><p>Do not only fix the single hole. Assume the attacker will try again laterally. After an incident, tighten identity and access management (IAM), input/output validation for agent tools, and east-west network policies so that even a different exploit will have less blast radius.</p><h5>Step 1: Document the Hardening Deltas in a Checklist</h5><p>Maintain a post-incident hardening checklist in version control. Capture what was too permissive and what the corrected state is.</p><pre><code># File: docs/incident_response/POST_INCIDENT_HARDENING.md\n## Post-Incident Hardening Checklist: [Incident-ID]\n\n### 1. IAM Policy Review\n- [ ] Initial Finding: The compromised service role had \"s3:*\" permissions.\n- [ ] Hardening Action: Replace with a policy allowing only s3:GetObject on '.../input/*' and s3:PutObject on '.../output/*'.\n\n### 2. Input / Output Validation Review\n- [ ] Initial Finding: Prompt injection used Base64-wrapped tool commands to trigger unintended actions.\n- [ ] Hardening Action: Update the I/O validation layer (e.g. AID-H-002 or safe tool dispatcher) to detect and block those patterns before they reach sensitive tools.\n\n### 3. Network Segmentation Review\n- [ ] Initial Finding: Attacker laterally reached the model-serving pod from a generic web pod.\n- [ ] Hardening Action: Apply a NetworkPolicy (e.g. AID-I-002 style) so only the API gateway namespace can talk to the model-serving namespace.\n\n### 4. Logging & Detection Review\n- [ ] Initial Finding: No alert triggered on that lateral hop.\n- [ ] Hardening Action: Add a SIEM detection rule (see AID-D-005) for unexpected cross-namespace calls.\n</code></pre><p><strong>Action:</strong> After every incident, produce and execute a concrete hardening checklist across IAM, input/output validation, and internal network policies. Store this checklist in Git and track it like code review, not tribal memory.</p>"
                },
                {
                    "strategy": "Disable unnecessary or vulnerable services, plugins, and agent tool capabilities.",
                    "howTo": "<h5>Concept:</h5><p>Attack surface area = risk. If the attacker got in through an optional legacy service or an LLM plugin that nobody truly needs, the safest mitigation is to remove that surface entirely. Hardening is not just 'patch'; sometimes hardening is 'turn it off'.</p><h5>Step 1: Disable Unused OS-Level Services</h5><p>Stop and disable any service that should not be running in production.</p><pre><code># On Linux using systemd\nsudo systemctl status old-reporting-service.service\nsudo systemctl stop old-reporting-service.service\nsudo systemctl disable old-reporting-service.service\n</code></pre><h5>Step 2: Remove a High-Risk Agent Tool / LLM Plugin</h5><p>If an LLM agent was exploited via an overly-powerful tool, remove that tool from its allowed toolset and redeploy the agent with reduced capabilities.</p><pre><code># BEFORE: tool list included a dangerous web_browser_tool\nagent_tools = [\n    search_tool,\n    vulnerable_web_browser_tool,\n    calculator_tool\n]\n\n# AFTER: remove the vulnerable capability so it cannot be abused again\nagent_tools = [\n    search_tool,\n    calculator_tool\n]\n# agent = initialize_agent(tools=agent_tools)\n</code></pre><p><strong>Action:</strong> Enumerate every service, port, plugin, and agent tool capability that was active on the compromised node. If it's not business-critical, shut it down or remove it from the allowed toolset. Less surface = less chance of reinfection.</p>"
                },
                {
                    "strategy": "Codify new IOCs and TTP-based detections into SIEM/SOAR.",
                    "howTo": "<h5>Concept:</h5><p>An incident gives you high-fidelity Indicators of Compromise (IOCs): attacker IPs, malicious User-Agent strings, hashes of uploaded malware, suspicious API call patterns. You must immediately operationalize these into detection rules so the exact same attacker behavior will page you (or auto-block) next time.</p><h5>Create and Commit a Detection Rule</h5><p>Use Sigma or your SIEM's native rule format. Keep these detection rules in version control; treat them as product code, not ad-hoc SOC notes.</p><pre><code># File: detections/incident-2025-06-08.yml\n\ntitle: Detect Specific TTP from Recent Model Theft Incident\nid: 61a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c\nstatus: stable\ndescription: >\n    Alerts when an inference request is received from the attacker IP\n    using the malicious User-Agent observed during the June 8, 2025 incident.\nauthor: SOC Team\ndate: 2025/06/08\nlogsource:\n    product: aws\n    service: waf\ndetection:\n    selection:\n        httpRequest.clientIp: '198.51.100.55'\n        httpRequest.headers.name: 'User-Agent'\n        httpRequest.headers.value: 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'\n    condition: selection\nlevel: critical\n</code></pre><p><strong>Action:</strong> For every serious incident, create (or update) a SIEM/SOAR detection rule capturing the attacker’s observable behavior. This is part of hardening: you are not only closing the hole, you are also teaching your monitoring stack to scream instantly if that TTP shows up again.</p>"
                },
                {
                    "strategy": "Security regression testing: verify patches and hardening measures actually block the original exploit.",
                    "howTo": "<h5>Concept:</h5><p>Never assume \"we patched it\" means \"we are safe\". You must recreate the attack in an isolated clone of production and prove it no longer works. Treat this like CI for security. Only after this passes should you promote the patch to production.</p><h5>Step 1: Spin Up a Validation Environment</h5><p>Clone prod (or the affected micro-environment) into an isolated VPC / namespace. Apply the new patch, hardened IAM, network policies, and disabled plugins.</p><h5>Step 2: Re-Run the Original Exploit Safely</h5><p>Fire the same PoC exploit or prompt-injection chain that the attacker used. Observe: does it still get code execution / lateral movement / privileged data access?</p><pre><code># File: validation_plans/CVE-2025-12345-validation.md\n\n## Patch Validation Plan for CVE-2025-12345\n\n1. Environment Setup:\n   - Clone production workload into an isolated 'patch-validation-env'.\n   - Apply the Ansible playbook that rolled out patched dependencies and hardened configs.\n\n2. Exploit Execution:\n   - From a test attacker box, run the original exploit (exploit.py) against the patched target.\n\n3. Verification Criteria:\n   - PASS: exploit no longer yields code execution or model exfiltration.\n   - PASS: WAF / SIEM now logs and alerts on the attempt.\n   - PASS: The service stays stable under test.\n\n4. Regression Check:\n   - Run the normal functional test suite to ensure business logic still works.\n\nResult: Only promote the patch to actual production if all checks PASS.\n</code></pre><p><strong>Action:</strong> Bake \"security regression tests\" into your incident closure process. Every high-severity incident should end with a validated patch + hardening bundle, plus a proof (kept in Git / ticket) that the original exploit path is now blocked.</p>"
                }
            ]
        },
        {
            "id": "AID-E-005",
            "name": "Compromised Session Termination & State Purging",
            "pillar": ["infra", "app"],
            "phase": ["response"],
            "description": "When communication channels or user/agent sessions are suspected or confirmed compromised, immediately expel the adversary and dismantle all footholds. This includes terminating active sessions, revoking tokens, purging tainted conversational memory, and disabling malicious execution paths like unknown webhooks or queued jobs. The goal is to prevent any residual access so the attacker cannot continue or instantly re-enter.",
            "toolsOpenSource": [
                "Application server admin interfaces for session expiration",
                "Custom scripts using JWT libraries or flushing session stores (Redis, Memcached)",
                "IAM systems (Keycloak) with session termination APIs"
            ],
            "toolsCommercial": [
                "IDaaS platforms (Okta, Auth0, Ping Identity) with global session termination features",
                "API Gateways with advanced session management",
                "SIEM/SOAR platforms for orchestrating automated eviction actions (Splunk SOAR, Palo Alto XSOAR)"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0012 Valid Accounts (evicting hijacked sessions)",
                        "AML.TA0006 Persistence (dismantling live footholds / manipulated state)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Identity Attack (L7, cutting compromised sessions/tokens)",
                        "Session Hijacking affecting any AI layer"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (purging poisoned states)",
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
                    "strategy": "Expire or mass-invalidate active sessions / cookies / API tokens linked to the compromise.",
                    "howTo": "<h5>Concept:</h5><p>When you confirm a session hijack or identity takeover, you cannot assume you know exactly which tokens the attacker has. The safest immediate containment move is to revoke every active session and token associated with the affected user / tenant / agent identity. In high-severity cases, you may force-logout <em>all</em> sessions across an environment (org-wide kill switch) to cut off attacker access in bulk.</p><h5>Targeted or Global Session Flush</h5><p>If you use server-side state (Redis, Memcached) for sessions, you can enumerate and delete keys that match a pattern (e.g. <code>session:user123:*</code> for targeted, or <code>session:*</code> for global). This immediately invalidates cookies and bearer tokens that depend on that server-side state.</p><pre><code># File: incident_response/flush_sessions.py\nimport redis\n\ndef flush_sessions(prefix: str = \"session:*\"):\n    \"\"\"Delete server-side session keys that match a pattern.\\n    Use a specific prefix (e.g. session:user123:*) for scoped eviction,\\n    or session:* as an emergency kill switch.\"\"\"\n    r = redis.Redis(host=\"localhost\", port=6379, db=0)\n    cursor = 0\n    total_deleted = 0\n    while True:\n        cursor, keys = r.scan(cursor=cursor, match=prefix, count=1000)\n        if keys:\n            total_deleted += r.delete(*keys)\n        if cursor == 0:\n            break\n    print(f\"✅ Deleted {total_deleted} session keys for pattern {prefix}.\")\n</code></pre><p><strong>Action:</strong> Maintain a tested admin/IR playbook that can 1) scope-evict sessions for a single account, team, or agent service, and 2) run an emergency global eviction if blast radius is unclear. This playbook should be callable from SOAR.</p>"
                },
                {
                    "strategy": "Revoke stateless tokens (JWT, API tokens) and rotate signing keys.",
                    "howTo": "<h5>Concept:</h5><p>Attackers often steal bearer tokens or JWTs. Unlike server-side sessions, JWTs remain valid until they expire unless you actively revoke them. You must introduce a denylist (revocation list) and force all verifiers to check it. For high-severity incidents, rotate the signing key so <em>all</em> previously issued tokens become invalid at once.</p><h5>Implement a JWT Revocation List</h5><pre><code># File: eviction_scripts/revoke_jwt.py\nimport time\nimport redis\nimport jwt\n\ndef revoke_jwt(token: str, secret: str, redis_client):\n    \"\"\"Extract jti/exp from the token and store its jti in a denylist\\n    with a TTL that matches the token's remaining lifetime.\"\"\"\n    try:\n        payload = jwt.decode(token, secret, algorithms=[\"HS256\"], options={\"verify_exp\": False})\n        jti = payload.get(\"jti\")\n        exp = payload.get(\"exp\")\n        if not jti or not exp:\n            return\n        remaining_ttl = max(0, exp - int(time.time()))\n        if remaining_ttl > 0:\n            redis_client.set(f\"jwt_revoked:{jti}\", \"revoked\", ex=remaining_ttl)\n            print(f\"🚫 Revoked token jti={jti} for {remaining_ttl}s\")\n    except jwt.PyJWTError as e:\n        print(f\"Invalid token: {e}\")\n</code></pre><p><strong>Critical Requirements:</strong> (1) All services that validate JWTs must also check <code>jwt_revoked:{jti}</code> before accepting the token. (2) Your IR runbook must include \"rotate JWT signing key now\" for P1/P0 incidents; key rotation immediately invalidates every stolen-but-not-yet-used token.</p>"
                },
                {
                    "strategy": "Purge tainted conversational memory / agent state so the attacker’s injected goals cannot respawn.",
                    "howTo": "<h5>Concept:</h5><p>Agentic systems and LLM-powered services often persist memory: conversation history, tool authorization context, scratchpads, chain-of-thought summaries, etc. If an attacker poisoned that memory (prompt injection, internal goal override, hidden tool calls), simply killing the running process (AID-E-002) is not enough. You must delete that persisted state so the next agent instance does not auto-load the compromised intent.</p><h5>Targeted State Purge</h5><pre><code># File: eviction_scripts/purge_agent_state.py\nimport redis\n\ndef purge_state_for_agents(agent_ids: list):\n    \"\"\"Delete cached state for specific agent IDs (chat history,\\n    working memory, tool auth context, etc.).\"\"\"\n    r = redis.Redis()\n    total_deleted = 0\n    for agent_id in agent_ids:\n        patterns = [\n            f\"session:{agent_id}:*\",\n            f\"chat_history:{agent_id}\",\n            f\"agent_state:{agent_id}\"\n        ]\n        for pattern in patterns:\n            for key in r.scan_iter(pattern):\n                total_deleted += r.delete(key)\n    print(f\"✅ Purged {total_deleted} keys across {len(agent_ids)} agents.\")\n</code></pre><p><strong>Action:</strong> As soon as you terminate a compromised agent session, run a purge against all state tied to that agent identity. This directly mitigates ongoing Prompt Injection (OWASP LLM01:2025) and prevents continued Sensitive Information Disclosure (LLM02:2025) through an already-hijacked memory channel.</p>"
                },
                {
                    "strategy": "Dismantle runtime footholds: malicious webhooks, rogue tool registrations, queued jobs, or background workers.",
                    "howTo": "<h5>Concept:</h5><p>Attackers often create persistence that survives a simple logout. Examples: (a) registering a webhook that forwards future model outputs or secrets to an attacker-controlled URL, (b) silently adding a privileged \"tool\" or plugin to an agent, (c) enqueueing high-privilege jobs (e.g. data export) in a background worker queue. Full eviction means ripping out those footholds immediately.</p><h5>Recommended Playbook Steps:</h5><ol><li>Quarantine or cordon any compromised agent runtime / pod / VM as described in AID-E-002 so it cannot keep executing callbacks.</li><li>Enumerate recent webhook registrations, tool/plugin registrations, and queued jobs created by (or on behalf of) the compromised identity or IP. Disable or delete anything unrecognized or outside approved allowlists.</li><li>Temporarily suspend elevated permissions for the affected agent/service account until post-incident review completes (tie-in with hardening in AID-E-004).</li></ol><p><strong>Action:</strong> Include in your IR/SOAR runbook a \"foothold teardown\" step: list and remove any newly added webhook endpoints, tool definitions, scheduled background jobs, or async tasks that were not part of baseline. This directly addresses persistence (MITRE ATLAS AML.T0017) and cuts off exfiltration channels mid-incident.</p>"
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
                        "AML.T0036 Data from Information Repositories",
                        "AML.T0048.004 External Harms: AI Intellectual Property Theft"
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
                    "pillar": ["data", "infra"],
                    "phase": ["improvement"],
                    "description": "Employs cryptographic and physical methods to render AI data and models on storage media permanently unrecoverable. This is the core technical process for decommissioning AI assets, ensuring compliance with data protection regulations and preventing future data leakage.",
                    "implementationStrategies": [
                        {
                            "strategy": "Perform crypto-shredding by destroying the encryption keys for model/data storage at end-of-life.",
                            "howTo": "<h5>Concept:</h5><p>Instead of trying to overwrite massive datasets or model checkpoints block-by-block, you can make them permanently unreadable by destroying the encryption key that protects them. This is fast, automatable, and aligns with modern sanitization guidance for cloud and virtualized storage.</p><h5>Precondition:</h5><p>Each high-sensitivity AI asset (model weights, fine-tuning dataset, RAG index shards, training logs, inference transcripts, configuration secrets) must be stored encrypted at rest under a <em>dedicated</em> KMS-managed key. Assets that share a key are destroyed as a group. This design decision must be enforced during onboarding, not improvised at retirement time.</p><h5>Schedule KMS Key Deletion</h5><p>Most cloud KMS systems let you schedule a key for deletion after a mandatory waiting period. Once deleted, every volume/object encrypted with that key becomes unrecoverable ciphertext.</p><pre><code># Example using AWS KMS to schedule crypto-shred of a retired asset\nKEY_ID=\"arn:aws:kms:us-east-1:123456789012:key/your-key-id\"\nDELETION_WINDOW_DAYS=7  # grace period for human review / audit\n\naws kms schedule-key-deletion \\\n    --key-id ${KEY_ID} \\\n    --pending-window-in-days ${DELETION_WINDOW_DAYS}\n\n# After the window, the key is permanently destroyed.\n# All data encrypted solely with this key becomes cryptographically unrecoverable.</code></pre><p><strong>Action:</strong> For each AI asset marked end-of-life, record the associated KMS key(s), schedule those keys for deletion, and log the key-deletion request (key ARN, timestamp, approver) as an auditable destruction event. This log is your proof of sanitization for compliance and legal chain-of-custody.</p>"
                        },
                        {
                            "strategy": "Sanitize or physically destroy storage media using standards-compliant wiping.",
                            "howTo": "<h5>Concept:</h5><p>When retiring physical servers, on-prem SAN/NAS, or local SSD/NVMe volumes, you must ensure that AI model weights, embeddings, and sensitive training data cannot be later recovered with forensic tools. This requires secure media sanitization that follows an accepted standard (e.g. NIST SP 800-88 Rev.1).</p><h5>Use Secure Wipe Utilities (for traditional block devices):</h5><pre><code># Securely overwrite and remove an on-disk model checkpoint\nMODEL_FILE=\"/mnt/decommissioned_data/old_model.pkl\"\n\n# -n 3 : overwrite 3 passes\n# -z   : final pass with zeros to mask shredding pattern\n# -u   : truncate/remove file after overwrite\n# -v   : verbose progress output\n\nshred -vzu -n 3 ${MODEL_FILE}\n\n# After completion, the file is considered logically unrecoverable\n# on spinning disks and many block devices.</code></pre><p><strong>Important:</strong> On SSD/NVMe or cloud-managed block storage, wear leveling and virtualization may prevent guaranteed multi-pass overwrite of every physical block. In those cases, you must either (1) rely on crypto-shredding (key destruction as above), (2) invoke the provider's secure erase / sanitize API, or (3) physically destroy the media and obtain a destruction certificate.</p><p><strong>Action:</strong> For every decommissioned server or volume that held AI models, datasets, RAG indexes, or inference logs, run an approved wipe procedure or crypto erase, then capture an auditable record (timestamp, operator, method used, volume ID, NIST SP 800-88 classification) as the \"sanitization certificate.\" This supports regulatory proof that sensitive AI data is no longer recoverable.</p>"
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
                    "pillar": ["model", "data", "infra"],
                    "phase": ["improvement"],
                    "description": "Defines the technical process for securely transferring ownership of an AI asset to another entity. This involves cryptographic verification of the transferred artifact and a corresponding secure deletion of the original asset to prevent residual security risks.",
                    "implementationStrategies": [
                        {
                            "strategy": "Package, encrypt, sign, and attest AI assets before transfer to a new owner.",
                            "howTo": "<h5>Concept:</h5><p>When handing off a model or dataset to another organization (M&A, vendor transition, regulated data escrow, etc.), you must: (1) keep it confidential in transit, (2) prove integrity / authenticity, and (3) document usage and security constraints. This creates a verifiable chain-of-custody.</p><h5>Step 1: Bundle the Asset and Metadata</h5><p>Create a tarball that includes the model weights, configuration files, model card / SBOM / tuning history, security notes (e.g. known restrictions or redlines), and any usage/rights/licensing statements.</p><pre><code>ASSET_ARCHIVE=\"model_v3_package.tar.gz\"\n\ntar -czvf ${ASSET_ARCHIVE} \\\n    ./model.pkl \\\n    ./config.json \\\n    ./model_card.md \\\n    ./security_notes.md \\\n    ./licensing_terms.md\n</code></pre><h5>Step 2: Encrypt and Sign with GPG</h5><p>Import the recipient's public key (for confidentiality) and use your signing key (for authenticity). The recipient will later verify your signature and confirm the archive hasn't been tampered with.</p><pre><code># Import keys into your keyring first\n# gpg --import recipient_public_key.asc\n# gpg --import my_signing_key.asc\n\nRECIPIENT_KEY_ID=\"recipient@example.com\"\nMY_SIGNING_KEY_ID=\"me@example.com\"\n\n# Encrypt + sign the archive for the recipient\ngpg --encrypt --sign \\\n    --recipient ${RECIPIENT_KEY_ID} \\\n    --local-user ${MY_SIGNING_KEY_ID} \\\n    --output ${ASSET_ARCHIVE}.gpg \\\n    ${ASSET_ARCHIVE}\n\n# Optionally generate a SHA-256 hash for out-of-band integrity verification\nsha256sum ${ASSET_ARCHIVE}.gpg > ${ASSET_ARCHIVE}.gpg.sha256\n</code></pre><p><strong>Action:</strong> Deliver only the <code>.gpg</code> (and separately the hash) over a secured transfer channel (SFTP / MFT / encrypted tunnel). Require the recipient to verify: (a) your signature is valid, (b) the SHA-256 matches, and (c) the included security_notes.md and licensing_terms.md are accepted. This establishes a provable, tamper-evident handoff.</p>"
                        },
                        {
                            "strategy": "After confirmed receipt, eradicate all original copies (including backups) and revoke original access paths.",
                            "howTo": "<h5>Concept:</h5><p>Secure transfer is not complete until <em>you</em> can no longer access or leak the asset. Keeping a stale copy or leaving IAM roles alive creates dual custody, legal ambiguity, and continued breach risk. The final step is: destroy residual data, kill access, and log evidence.</p><h5>Standard Post-Transfer Decommission Workflow:</h5><ol><li><strong>Recipient Confirmation:</strong> The new owner decrypts the package, verifies your digital signature, and returns a signed \"Acknowledgement of Receipt and Integrity\" plus the SHA-256 they computed. This proves they got the correct asset intact.</li><li><strong>Access Deprovisioning:</strong> Immediately revoke any IAM roles / API keys / service accounts / agent tool permissions that were specific to this asset. Remove this asset from any active inference endpoints, RAG indexes, or internal model registries so it is no longer callable by your production or test systems.</li><li><strong>Backup / DR Cleanup:</strong> Identify all backups, DR replicas, cold storage copies, staging mirrors, and offline exports that include this asset. For each, perform crypto-shred (destroy the per-asset KMS key) or certified wipe as defined in AID-E-006.001. Record each wipe in an auditable log.</li><li><strong>Final Sanitization Proof:</strong> Once all known copies are wiped or crypto-erased, record: timestamp, operator, asset ID/version, locations sanitized, KMS key IDs destroyed, and reference to the recipient's receipt. Store this record in your compliance / security evidence repository.</li></ol><p><strong>Action:</strong> Treat asset transfer as a controlled ownership <em>hand-off</em>, not \"copy and paste.\" Enforce (1) cryptographic integrity confirmation from the new owner, (2) immediate sanitization of your local and backup copies via AID-E-006.001, and (3) revocation of any credentials or tooling that could still reach or regenerate that asset. This closes the door on model theft (OWASP ML05:2023) and prevents future sensitive disclosure (LLM02:2025) through stale artifacts you forgot to retire.</p>"
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