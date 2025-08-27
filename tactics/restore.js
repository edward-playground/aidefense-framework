export const restoreTactic = {
    "name": "Restore",
    "purpose": "The \"Restore\" tactic focuses on recovering normal AI system operations and data integrity following an attack and subsequent eviction of the adversary. This phase involves safely bringing AI models and applications back online, restoring any corrupted or lost data from trusted backups, and, crucially, learning from the incident to reinforce defenses and improve future resilience.",
    "techniques": [
        {
            "id": "AID-R-001",
            "name": "Secure AI Model Restoration & Retraining",
            "description": "After an incident that may have compromised AI model integrity (e.g., through data poisoning, model poisoning, backdoor insertion, or unauthorized modification), securely restore affected models to a known-good state. This may involve deploying models from trusted, verified backups taken prior to the incident, or, if necessary, retraining or fine-tuning models on clean, validated datasets to eliminate any malicious influence or corruption.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0018 Manipulate AI Model / AML.T0019 Publish Poisoned Datasets",
                        "AML.T0020 Poison Training Data",
                        "AML.T0031 Erode AI Model Integrity"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Backdoor Attacks (L1)",
                        "Data Poisoning (L2, retraining)",
                        "Model Skewing (L2, restoring/retraining)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM04:2025 Data and Model Poisoning"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML10:2023 Model Poisoning",
                        "ML02:2023 Data Poisoning Attack"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-R-001.001",
                    "name": "Versioned Model Rollback & Restoration", "pillar": "model", "phase": "improvement",
                    "description": "Restores a compromised AI model to a known-good state by deploying a trusted, previously saved version from a secure artifact repository or model registry. This technique is the primary recovery method when a deployed model artifact has been tampered with post-deployment or when an incident requires reverting to the last known-secure version. It relies on maintaining immutable, versioned, and verifiable backups of all production models.",
                    "implementationStrategies": [
                        {
                            "strategy": "Maintain versioned, immutable backups of all production model artifacts.",
                            "howTo": "<h5>Concept:</h5><p>You cannot restore what you do not have. Every model artifact promoted to production must be treated as a critical asset. It should be stored in a secure, versioned backup location (e.g., an S3 bucket with Object Versioning enabled) with its cryptographic hash recorded to ensure it can be restored without fear of tampering.</p><h5>Configure a Versioned Backup Store</h5><p>Use Infrastructure as Code to create a dedicated, version-enabled storage bucket for model backups.</p><pre><code># File: infrastructure/model_backups.tf (Terraform)\\n\\nresource \\\"aws_s3_bucket\\\" \\\"model_backups\\\" {\\n  bucket = \\\"aidefend-prod-model-backups\\\"\\n}\\n\\n# Enable versioning to keep a full history of all objects\\nresource \\\"aws_s3_bucket_versioning\\\" \\\"model_backups_versioning\\\" {\\n  bucket = aws_s3_bucket.model_backups.id\\n  versioning_configuration {\\n    status = \\\"Enabled\\\"\\n  }\\n}</code></pre><p><strong>Action:</strong> Create a dedicated, version-enabled storage location for production model artifacts. As the final step of your build pipeline, upload the approved model artifact to this location.</p>"
                        },
                        {
                            "strategy": "Identify the last known-good model version from a model registry or deployment logs.",
                            "howTo": "<h5>Concept:</h5><p>During an incident, the first step of recovery is to identify the last model version that was confirmed to be secure and operating correctly before the incident began. This requires having a clear, timestamped audit trail of model deployments and promotions.</p><h5>Use the Model Registry to Find the Target Version</h5><p>Query your model registry (like MLflow) to find the version that was tagged as 'Production' just before the incident's start time.</p><pre><code># File: restore/find_good_version.py\\nfrom mlflow.tracking import MlflowClient\n\n# INCIDENT_START_TIMESTAMP = ... // The time the incident was discovered or started\n# client = MlflowClient()\\n# all_versions = client.search_model_versions(\\\"name='My-Production-Model'\\\")\n# \n# known_good_version = None\\n# for version in sorted(all_versions, key=lambda v: v.creation_timestamp, reverse=True):\\n#     # Find the most recent version created BEFORE the incident\\n#     if version.creation_timestamp < INCIDENT_START_TIMESTAMP:\\n#         known_good_version = version\\n#         break\n# \n# if known_good_version:\\n#     print(f\\\"Identified last known-good version: {known_good_version.version}\\\")\n# else:\\n#     print(\\\"No known-good version found before the incident!\\\")</code></pre><p><strong>Action:</strong> Maintain a timestamped and versioned model registry. Your incident response plan should include a step to query this registry to identify the last known-good model version based on the incident timeline.</p>"
                        },
                        {
                            "strategy": "Verify the integrity of the backup artifact using a checksum or digital signature before deploying.",
                            "howTo": "<h5>Concept:</h5><p>Never trust a backup file without verifying its integrity. Before deploying a restored model, you must re-calculate its cryptographic hash and compare it against the trusted hash that was recorded in your model registry when the model was originally built. This prevents the deployment of a corrupted or tampered-with backup.</p><h5>Implement an Integrity Check in Your Rollback Script</h5><pre><code># File: restore/verify_and_restore.py\n\n# Assume 'known_good_version' is the MLflow version object from the previous step\n# Assume 'get_sha256_hash' is a utility function\n\n# 1. Get the trusted hash from the registry tag\\n# authorized_hash = known_good_version.tags.get('sha256_hash')\n\n# 2. Download the backup artifact\\n# local_path = client.download_artifacts(f\\\"models:/{known_good_version.name}/{known_good_version.version}\\\", \\\".\\\")\n\n# 3. Re-calculate the hash of the downloaded file\\n# actual_hash = get_sha256_hash(local_path + \\\"/model.pkl\\\")\n\n# 4. Compare hashes and halt if they do not match\n# if actual_hash != authorized_hash:\\n#     raise SecurityException(\\\"CRITICAL: Backup artifact hash mismatch! Restore aborted.\\\")\n# else:\\n#     print(\\\"✅ Backup integrity verified. Proceeding with rollback deployment.\\\")\n#     # trigger_deployment(local_path)</code></pre><p><strong>Action:</strong> Your model rollback playbook must include a mandatory step to verify the hash of the backup artifact against the trusted hash stored in your model registry. The rollback must fail if the hashes do not match.</p>"
                        },
                        {
                            "strategy": "Use an automated pipeline to deploy the verified, known-good model version.",
                            "howTo": "<h5>Concept:</h5><p>Manual deployments are error-prone, especially during a high-stress incident. Use a CI/CD pipeline or a GitOps workflow to reliably deploy the restored model. This ensures the deployment process itself is secure, repeatable, and audited.</p><h5>Trigger a Rollback Deployment Pipeline</h5><p>A dedicated pipeline can be triggered with the specific version number that needs to be restored.</p><pre><code># Conceptual GitHub Actions workflow for rollback\n\n# name: Rollback Production Model\n# on: \n#   workflow_dispatch:\n#     inputs:\n#       model_name:\n#         description: 'Name of the model to roll back'\n#         required: true\n#       version_to_restore:\n#         description: 'The known-good version number to deploy'\n#         required: true\n\n# jobs:\n#   rollback:\n#     runs-on: ubuntu-latest\n#     steps:\n#       - name: Restore and Verify Model\n#         run: python restore/verify_and_restore.py --model ${{ github.event.inputs.model_name }} --version ${{ github.event.inputs.version_to_restore }}\n#       - name: Deploy to Production\n#         run: | # ... (commands to deploy the verified artifact to production)</code></pre><p><strong>Action:</strong> Create a parameterized deployment pipeline that can be triggered to perform a rollback. The pipeline should take a model name and version as input, perform the integrity check, and then handle the deployment to the production environment.</p>"
                        }
                    ],
                    "toolsOpenSource": [
                        "MLflow Model Registry, DVC",
                        "Cloud provider CLIs/SDKs (for S3, GCS, Azure Blob Storage)",
                        "CI/CD systems (GitHub Actions, GitLab CI, Jenkins)",
                        "Cryptographic tools (sha256sum, GnuPG)"
                    ],
                    "toolsCommercial": [
                        "Enterprise MLOps platforms (Databricks, Amazon SageMaker, Google Vertex AI)",
                        "Enterprise artifact repositories (JFrog Artifactory)",
                        "Backup and recovery solutions (Veeam, Rubrik, Cohesity)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0018 Manipulate AI Model",
                                "AML.T0076 Corrupt AI Model"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Model Tampering (L1)",
                                "Compromised Container Images (L4)"
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
                                "ML06:2023 AI Supply Chain Attacks",
                                "ML10:2023 Model Poisoning"
                            ]
                        }
                    ]
                },
                {
                    "id": "AID-R-001.002",
                    "name": "Model Retraining for Remediation", "pillar": "model", "phase": "improvement",
                    "description": "This sub-technique covers the restoration workflow for when a model's integrity has been compromised by its training data (e.g., via data poisoning or backdoor attacks). It involves a multi-stage process: first, identifying and removing the malicious data or client influence; second, retraining a new model from scratch using only the resulting sanitized dataset; and third, validating that the new model is both secure and performant. This approach is more comprehensive than a simple rollback and is necessary when no trusted model backup exists.",
                    "toolsOpenSource": [
                        "MLOps platforms (MLflow, Kubeflow Pipelines, DVC)",
                        "Federated Learning frameworks (TensorFlow Federated, Flower, PySyft)",
                        "Graph ML libraries (PyTorch Geometric, DGL)",
                        "Data cleansing/validation tools (Great Expectations, Pandas)",
                        "Deep learning frameworks (PyTorch, TensorFlow)"
                    ],
                    "toolsCommercial": [
                        "Enterprise MLOps platforms (Databricks, Amazon SageMaker, Google Vertex AI, Azure ML)",
                        "Data quality and governance platforms (Alation, Collibra)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0020 Poison Training Data",
                                "AML.T0018 Manipulate AI Model",
                                "AML.T0019 Publish Poisoned Datasets",
                                "AML.T0059 Erode Dataset Integrity"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Poisoning (L2)",
                                "Backdoor Attacks (L1)",
                                "Model Skewing (L2)",
                                "Attacks on Decentralized Learning (Cross-Layer)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM04:2025 Data and Model Poisoning"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML02:2023 Data Poisoning Attack",
                                "ML10:2023 Model Poisoning"
                            ]
                        }
                    ],
                    "implementationStrategies": [
                        {
                            "strategy": "Identify and evict malicious data or participant influence.",
                            "howTo": "<h5>Concept:</h5><p>The first step in any retraining-based remediation is to cleanse the source data. This involves using a detection method to identify the specific poisoned data points, malicious graph nodes, or compromised federated learning clients, and then filtering them out to create a new, trusted dataset.</p><h5>Isolate and Remove Malicious Artifacts</h5><p>Use the output of a detection technique (e.g., from `AID-D-012` for graphs or `AID-I-006` for federated learning) to programmatically create the sanitized dataset.</p><pre><code># File: remediation/cleanse_data.py\n\n# Assume 'compromised_dataset' is a pandas DataFrame or similar data structure\n# Assume 'malicious_indices' is a list of row indices identified by a detection system\n\ndef create_clean_dataset(full_dataset, malicious_indices):\n    \"\"\"Removes rows identified as malicious to create a clean dataset.\"\"\"\n    print(f\"Original dataset size: {len(full_dataset)}\")\n    clean_dataset = full_dataset.drop(index=malicious_indices)\n    print(f\"Removed {len(malicious_indices)} malicious data points.\")\n    print(f\"Cleansed dataset size: {len(clean_dataset)}\")\n    return clean_dataset\n\n# This cleansed dataset is the input for the next step.\n# In a GNN context, this would involve removing nodes/edges.\n# In a Federated Learning context, this would involve filtering out all data from a specific client_id.</code></pre><p><strong>Action:</strong> Implement a data cleansing script as the first step in your remediation playbook. This script must take a list of identified malicious artifacts (data points, node IDs, client IDs) and produce a new, sanitized dataset with those artifacts removed.</p>"
                        },
                        {
                            "strategy": "Initiate a secure retraining job from scratch using the cleansed data.",
                            "howTo": "<h5>Concept:</h5><p>To ensure the complete removal of a backdoor or poisoned influence, a new model must be trained from a clean slate. Fine-tuning the compromised model is risky, as it may not fully overwrite the malicious behavior. Training from scratch on the now-sanitized data is the most robust approach.</p><h5>Trigger a Secure and Auditable Training Pipeline</h5><p>The retraining job should adhere to the principles of `AID-H-007`. It must run in an isolated environment, use version-controlled code and data, and log all parameters for auditability.</p><pre><code># This is an orchestration step, often in a CI/CD or MLOps pipeline\n\n# 1. Version the cleansed dataset (e.g., using DVC)\n# > dvc add data/cleansed_dataset_v2.csv\n# > git commit -m \"feat: Add cleansed dataset for model remediation\"\n\n# 2. Trigger the training pipeline, passing the path to the clean data\n# > trigger_training_pipeline.sh --dataset_uri s3://.../cleansed_dataset_v2.csv \\\n#                              --model_name \"my-model-remediated-v1\"\n\n# The training function itself must initialize a new model, not load the old one:\ndef train_new_model(clean_data):\n    # CRITICAL: Always instantiate a new model object to ensure fresh weights.\n    model = MyModelArchitecture(...)\n    optimizer = Adam(model.parameters())\n    # ... proceed with training loop on clean_data ...\n    return model</code></pre><p><strong>Action:</strong> Your remediation playbook must trigger a full, secure retraining job using the sanitized dataset. Ensure the training script initializes a new model with random weights rather than fine-tuning the compromised one.</p>"
                        },
                        {
                            "strategy": "Use approximate unlearning methods for efficient remediation in Federated Learning.",
                            "howTo": "<h5>Concept:</h5><p>For Federated Learning, retraining the entire global model from scratch can be extremely slow and expensive. Approximate unlearning methods offer a more efficient alternative by attempting to surgically 'un-train' or reverse the influence of the malicious clients' updates on the existing compromised model.</p><h5>Apply 'Negative Gradient' Updates</h5><p>This technique involves calculating the updates that the malicious clients contributed and then applying those updates in the opposite direction to the global model's parameters, effectively trying to cancel them out.</p><pre><code># Conceptual code for approximate unlearning\n\n# Assume 'global_model' is the compromised model\n# Assume 'malicious_updates' is a list of update vectors from the bad clients\n\n# 1. Aggregate the malicious updates\n# total_malicious_update = np.sum(malicious_updates, axis=0)\n\n# 2. Apply an update to the model's parameters in the OPPOSITE direction\n# with torch.no_grad():\n#     for param, malicious_grad in zip(global_model.parameters(), total_malicious_update):\n#         # Subtract the aggregated malicious gradient instead of adding it\n#         param.data -= learning_rate * malicious_grad\n\n# print(\"Applied negative updates to approximately unlearn malicious influence.\")\n# The model is now remediated and can be further fine-tuned on clean data.</code></pre><p><strong>Action:</strong> For Federated Learning remediation, implement an approximate unlearning function. This function should aggregate the updates from identified malicious clients and apply a corrective update to the global model in the opposite direction.</p>"
                        },
                        {
                            "strategy": "Validate the final remediated model for both performance and security.",
                            "howTo": "<h5>Concept:</h5><p>Before deploying the newly retrained model, you must verify two things: 1) that the original attack vector has been neutralized, and 2) that the model's performance on legitimate tasks has not been unacceptably degraded by the data removal.</p><h5>Create a Post-Remediation Validation Suite</h5><p>This script evaluates the new model against both a clean test set and a test set containing the original backdoor trigger or poisoned data.</p><pre><code># File: remediation/validate_retraining.py\n\n# Assume 'remediated_model' is the newly trained model\n# Assume 'clean_test_data' and 'original_attack_data' are available\n\n# 1. Evaluate performance on clean data to check for regressions\n# clean_accuracy = evaluate(remediated_model, clean_test_data)\n# if clean_accuracy < ACCEPTABLE_ACCURACY_THRESHOLD:\n#     print(f\"WARNING: Remediation significantly degraded model performance.\")\n\n# 2. Evaluate performance on the original attack data\n# This measures how often the model is still fooled by the attack\n# attack_success_rate = evaluate_attack_success(remediated_model, original_attack_data)\n\n# The goal is a high clean accuracy and a near-zero attack success rate.\n# if attack_success_rate < 0.05:\n#     print(\"✅ REMEDIATION VERIFIED: Attack vector has been successfully removed.\")\n# else:\n#     print(f\"❌ REMEDIATION FAILED: Model is still susceptible to the original attack.\")</code></pre><p><strong>Action:</strong> As the final step before deploying a remediated model, run a validation suite to confirm both its performance on legitimate data and its resilience to the specific attack that was just removed. The model should only be promoted if both checks pass.</p>"
                        }
                    ]
                }

            ]
        },
        {
            "id": "AID-R-002",
            "name": "Data Integrity Recovery for AI Systems", "pillar": "data", "phase": "improvement",
            "description": "Restore the integrity of any datasets used by or generated by AI systems that were corrupted, tampered with, or maliciously altered during a security incident. This includes training data, validation data, vector databases for RAG, embeddings stores, configuration data, or logs of AI outputs. Recovery typically involves reverting to known-good backups, using data validation tools to identify and correct inconsistencies, or, in some cases, reconstructing data if backups are insufficient or also compromised.",
            "toolsOpenSource": [
                "Database backup/restore utilities (pg_dump, mysqldump)",
                "Cloud provider snapshot/backup services (S3 versioning, Azure Blob snapshots)",
                "Great Expectations",
                "Filesystem backup tools (rsync, Bacula)",
                "Vector DB export/import utilities"
            ],
            "toolsCommercial": [
                "Enterprise backup/recovery solutions (Rubrik, Cohesity, Veeam)",
                "Data quality/integration platforms (Informatica, Talend)",
                "Cloud provider managed backup services (AWS Backup, Azure Backup)"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0020 Poison Training Data (restoring clean dataset)",
                        "AML.T0031 Erode AI Model Integrity (restoring corrupted data stores)",
                        "AML.T0059 Erode Dataset Integrity"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Data Poisoning / Data Tampering (L2)",
                        "Compromised RAG Pipelines (L2, restoring vector DBs)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM04:2025 Data and Model Poisoning (restoring dataset integrity)",
                        "LLM08:2025 Vector and Embedding Weaknesses (if vector DBs corrupted)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack (restoring clean training data)"
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Identify all affected data stores.",
                    "howTo": "<h5>Concept:</h5><p>Before you can restore, you must understand the full 'blast radius' of the data corruption. This involves using your data lineage tools to trace the flow of the compromised data from its point of origin to all downstream systems, including other datasets, feature stores, and trained models that consumed it.</p><h5>Use a Lineage Tool to Trace Downstream Dependencies</h5><p>Starting with the URI of the known-compromised dataset, query your data lineage graph to find all assets that depend on it.</p><pre><code># File: recovery/identify_blast_radius.py\\n# This script conceptually queries a data lineage tool's API (e.g., DataHub, OpenMetadata)\n\n# Assume 'lineage_client' is the client for your data lineage service\n\ndef find_downstream_assets(asset_uri: str):\\n    \\\"\\\"\\\"Recursively finds all downstream assets affected by a compromised asset.\\\"\\\"\\\"\\n    affected_assets = {asset_uri}\\n    queue = [asset_uri]\\n    \n    while queue:\\n        current_asset = queue.pop(0)\\n        # Query the lineage service for assets that are downstream of the current asset\\n        downstream = lineage_client.get_downstream_lineage(current_asset)\\n        \n        for asset in downstream:\\n            if asset.uri not in affected_assets:\\n                affected_assets.add(asset.uri)\\n                queue.append(asset.uri)\\n                \n    return list(affected_assets)\n\n# --- Incident Response Usage ---\n# The incident starts by identifying the initial point of corruption\n# compromised_dataset = \\\"s3://aidefend-datasets/raw/user_uploads/batch_123.csv\\\"\\n# all_affected = find_downstream_assets(compromised_dataset)\n# print(\\\"CRITICAL: The following assets are potentially compromised and must be investigated/restored:\\\")\\n# for asset in all_affected:\\n#     print(f\\\"- {asset}\\\")</code></pre><p><strong>Action:</strong> During an incident, use your data lineage tool, starting with the initially compromised dataset, to generate a complete list of all affected downstream data stores, feature tables, and AI models. This list becomes the scope for your restoration efforts.</p>"
                },
                {
                    "strategy": "Restore data from most recent, verified backups.",
                    "howTo": "<h5>Concept:</h5><p>This is the primary data recovery method. It relies on having pre-existing, versioned backups. The process involves identifying the timestamp just before the corruption event and restoring the database or storage bucket to that specific point in time.</p><h5>Perform a Point-in-Time Recovery (PITR)</h5><p>Use your database or cloud provider's built-in PITR functionality. This example shows how to restore an AWS S3 object to a previous version before it was tampered with.</p><pre><code># File: recovery/restore_s3_object.sh (Shell Script)\\n\nBUCKET_NAME=\\\"aidefend-prod-training-data\\\"\\nOBJECT_KEY=\\\"critical_dataset.csv\\\"\n\n# 1. First, list the object versions to find the version ID of the last known-good state.\\n# This would be done by looking at timestamps from before the incident started.\\naws s3api list-object-versions --bucket ${BUCKET_NAME} --prefix ${OBJECT_KEY}\n\n# Let's assume we identified the correct version ID from the output above\nGOOD_VERSION_ID=\\\"a1b2c3d4e5f6g7h8\\\"\n\n# 2. 'Restore' the object by copying the specific good version over the (corrupted) latest version.\\n# This makes the old version the new, current version.\\necho \\\"Restoring ${OBJECT_KEY} to version ${GOOD_VERSION_ID}...\\\"\naws s3api copy-object --bucket ${BUCKET_NAME} \\ \n    --copy-source \\\"${BUCKET_NAME}/${OBJECT_KEY}?versionId=${GOOD_VERSION_ID}\\\" \\ \n    --key ${OBJECT_KEY}\n\necho \\\"✅ Restore complete.\\\"</code></pre><p><strong>Action:</strong> For critical data stores, ensure that point-in-time backup capabilities are enabled (e.g., S3 Object Versioning, database PITR). Your incident response plan should include the specific CLI commands or console steps required to restore a given data asset to a specific timestamp.</p>"
                },
                {
                    "strategy": "If backups unavailable, attempt reconstruction/repair (data validation tools, log analysis).",
                    "howTo": "<h5>Concept:</h5><p>In a worst-case scenario where no clean backup exists, you must attempt to repair the corrupted data in place. This involves writing a custom script that uses a set of heuristic rules to identify and remove the 'bad' data points, leaving a smaller but hopefully clean dataset.</p><h5>Write a Data Repair Script</h5><p>This script loads the corrupted dataset and applies a series of aggressive filtering steps based on what you know about the corruption. This example assumes the corruption involved invalid values and numerical outliers.</p><pre><code># File: recovery/repair_data.py\\nimport pandas as pd\\nimport great_expectations as gx\\n\n# Load the corrupted dataset\\ndf = pd.read_csv(\\\"data/corrupted_dataset.csv\\\")\noriginal_rows = len(df)\\n\n# Rule 1: Remove rows with missing critical values\\ndf.dropna(subset=['user_id', 'transaction_amount'], inplace=True)\\n\n# Rule 2: Remove rows that fail basic schema validation (using Great Expectations)\\nvalidator = gx.from_pandas(df)\\nvalid_rows_mask = validator.expect_column_values_to_be_between(\\n    'transaction_amount', min_value=0, max_value=100000\\n).success\ndf = df[valid_rows_mask]\n\n# Rule 3: Remove statistical outliers\\n# (Using an outlier detection method from AID-E-003.002)\n# outlier_mask = find_outliers(df['feature_x'])\\n# df = df[~outlier_mask]\n\nprint(f\\\"Repair complete. Removed {original_rows - len(df)} corrupted rows.\\\")\\n# df.to_csv(\\\"data/repaired_dataset.csv\\\", index=False)</code></pre><p><strong>Action:</strong> If a clean backup is unavailable, work with data scientists to define a set of heuristic rules to identify and filter out the corrupted data. Use a data validation library to programmatically apply these rules and generate a smaller, repaired dataset.</p>"
                },
                {
                    "strategy": "Re-validate integrity and consistency of recovered data.",
                    "howTo": "<h5>Concept:</h5><p>After restoring or repairing a dataset, you must prove that it is now in a known-good state before it is used for retraining a model. This involves running it through the same battery of integrity and quality checks that you would apply to any new, incoming data.</p><h5>Create a Post-Restoration Validation Pipeline</h5><p>This script orchestrates multiple validation steps and only succeeds if all checks pass.</p><pre><code># File: recovery/validate_restored_data.py\\n\n# Assume these functions are defined elsewhere\\n# from my_utils import get_sha256_hash, run_great_expectations_checkpoint, generate_data_profile\n\n# Known-good hash from the original backup manifest\\nKNOWN_GOOD_HASH = \\\"a1b2c3d4e5f6...\\\"\nRESTORED_FILE_PATH = \\\"data/restored_dataset.csv\\\"\n\n# 1. Verify cryptographic integrity\\nprint(\\\"Checking SHA256 hash...\\\")\\nactual_hash = get_sha256_hash(RESTORED_FILE_PATH)\\nif actual_hash != KNOWN_GOOD_HASH:\\n    raise SecurityException(\\\"Hash mismatch on restored data!\\\")\\n\n# 2. Verify schema and data quality constraints\\nprint(\\\"Running Great Expectations checkpoint...\\\")\\nvalidation_result = run_great_expectations_checkpoint(RESTORED_FILE_PATH, \\\"my_checkpoint\\\")\\nif not validation_result[\\\"success\\\"]:\\n    raise DataQualityException(\\\"Restored data failed validation checks!\\\")\n\n# 3. Verify statistical distribution\\nprint(\\\"Generating new data profile for comparison...\\\")\\n# profile = generate_data_profile(RESTORED_FILE_PATH)\\n# Compare 'profile' against the original baseline profile to check for unexpected shifts\n\nprint(\\\"✅ All validation checks passed. Restored data is verified.\\\")</code></pre><p><strong>Action:</strong> After any data restoration, run a full validation pipeline on the restored data. This must include a hash check against the backup manifest, a schema and constraint validation against your Great Expectations suite, and a statistical profile comparison against the original baseline.</p>"
                },
                {
                    "strategy": "Update data ingestion/processing pipelines to prevent recurrence.",
                    "howTo": "<h5>Concept:</h5><p>Recovery is not complete until you have closed the vulnerability that allowed the data corruption to happen in the first place. This usually involves adding the specific validation checks that would have caught the bad data to your main data ingestion pipeline.</p><h5>Harden the Ingestion Pipeline</h5><p>Analyze the root cause of the data corruption and add a specific, permanent validation step to the ingestion pipeline to prevent that type of bad data from ever entering your system again.</p><pre><code># --- BEFORE: A simple, vulnerable ingestion pipeline ---\ndef vulnerable_ingestion(source_file):\\n    df = pd.read_csv(source_file)\\n    df.to_sql('my_table', con=db_engine, if_exists='append')\n\n# --- AFTER: A hardened ingestion pipeline ---\ndef hardened_ingestion(source_file):\\n    # The corruption was due to malformed user IDs.\\n    # We add a new, permanent validation step to the pipeline.\n    df = pd.read_csv(source_file)\\n    \n    # NEW VALIDATION STEP\\n    # Ensure all user_ids are integers and positive\n    if not pd.to_numeric(df['user_id'], errors='coerce').notna().all() or not (df['user_id'] > 0).all():\\n        raise ValueError(\\\"Data ingestion failed: Found invalid user IDs.\\\")\n\n    # Only if validation passes, proceed to load data\\n    df.to_sql('my_table', con=db_engine, if_exists='append')</code></pre><p><strong>Action:</strong> After every data corruption incident, perform a root cause analysis. Add a new, specific validation or sanitization step to your data ingestion pipeline that would have prevented the initial corruption. This turns the incident into a permanent improvement in your system's data quality defenses.</p>"
                }
            ]
        },
        {
            "id": "AID-R-003",
            "name": "Secure Session & Identity Re-establishment",
            "pillar": "infra, app",
            "phase": "improvement",
            "description": "After an eviction (AID-E-005) is complete, this technique re-establishes clean, trusted interactions for users and AI agents. It focuses on hardening the recovery process by enforcing strong re-authentication (MFA/step-up), ensuring modern TLS, restoring clean conversational context from trusted snapshots, and progressively re-enabling capabilities. This includes clear communication with legitimate users and maintaining heightened monitoring to detect and prevent immediate re-compromise.",
            "toolsOpenSource": [
                "IAM systems (Keycloak, FreeIPA) for MFA policy enforcement",
                "Customer communication scripting libraries (for notifications)",
                "SIEM/log analytics platforms (ELK Stack, OpenSearch, Grafana Loki) for monitoring"
            ],
            "toolsCommercial": [
                "IDaaS platforms (Okta, Auth0, Ping Identity) for MFA policies",
                "Customer communication platforms (Twilio, SendGrid)",
                "SIEM/SOAR platforms for monitoring and correlation (Splunk, Microsoft Sentinel, Datadog)"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0017 Persistence (by establishing a clean state and preventing re-entry)",
                        "AML.T0012 Valid Accounts (by hardening the re-authentication of a previously hijacked account)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Identity Attack (L7, by forcing re-authentication and restoring trusted state)",
                        "Evasion of Auditing/Compliance (L6, by ensuring communication and monitoring)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (restoring clean context)",
                        "LLM02:2025 Sensitive Information Disclosure (by preventing re-compromise)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "Helps prevent re-exploitation of attacks that rely on credential theft."
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Ensure re-established sessions use strong authentication (MFA) and encryption (HTTPS/TLS).",
                    "howTo": "<h5>Concept:</h5><p>After a mass logout, you must require strong proof of identity and secure the channel to rebuild trust and prevent an attacker from simply logging back in with stolen credentials.</p><h5>Step 1: Enforce Modern TLS Protocols</h5><pre><code># Example Nginx server configuration for strong TLS\nserver {\n    listen 443 ssl http2;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';\n    ssl_prefer_server_ciphers on;\n    # ... rest of config ...\n}</code></pre><h5>Step 2: Require Step-Up or Multi-Factor Authentication</h5><pre><code># Conceptual IdP policy (Okta/Keycloak)\nIF user.session.is_invalidated == true\nAND user.authentication_method == 'password'\nTHEN\n  REQUIRE additional_factor IN ['push_notification', 'totp_code']\nELSE\n  ALLOW access</code></pre><p><strong>Action:</strong> Enforce TLS 1.2+ only across your infrastructure. Configure your identity provider to require MFA for the first login after a global session eviction event.</p>"
                },
                {
                    "strategy": "Restore clean conversational state and progressively re-enable capabilities.",
                    "howTo": "<h5>Concept:</h5><p>After purging potentially poisoned state during eviction, safely rehydrate the agent's context. Start by loading a minimal, known-good state, such as from the last trusted snapshot or a clean baseline. Cautiously re-enable external tool access, perhaps starting with read-only tools before re-granting write or execution permissions, while monitoring for any signs of residual compromise.</p><p><strong>Action:</strong> As part of the recovery plan, define the source for trusted state restoration (e.g., the last successful backup before the incident). Re-enable agent capabilities in a staged manner, starting with the least privileged tools, and monitor closely at each stage before restoring full functionality.</p>"
                },
                {
                    "strategy": "Communicate the session reset clearly to legitimate users.",
                    "howTo": "<h5>Concept:</h5><p>A global session flush is a disruptive but necessary security action. Proactive communication explains the 'why' to users, guides them through the (now more secure) re-authentication process, and helps maintain their trust in the service.</p><h5>Automate User Notification</h5><pre><code># File: incident_response/notify_users.py\nfrom sendgrid import SendGridAPIClient\nfrom sendgrid.helpers.mail import Mail\n\ndef send_session_reset_notification(user_list, template):\n    \"\"\"Sends a pre-approved session reset notification email to all users.\"\"\"\n    # ... (Logic to iterate through users and send email via API) ...</code></pre><p><strong>Action:</strong> Maintain pre-approved communication templates for security incidents. Have a tested script ready to send these notifications to all affected users via a bulk email or messaging API.</p>"
                },
                {
                    "strategy": "Monitor newly established sessions for re-compromise.",
                    "howTo": "<h5>Concept:</h5><p>The period immediately following a restore is critical. Attackers may try to reuse stolen credentials. Heightened, specific monitoring during this window is required to detect these attempts quickly.</p><h5>Create a High-Risk SIEM Correlation Rule</h5><pre><code># SIEM Correlation Rule (Splunk SPL syntax)\n# Find successful password reset events\nindex=idp sourcetype=okta eventType=user.account.reset_password status=SUCCESS \n| fields user, source_ip AS reset_ip, source_country AS reset_country\n| join user [\n    # Join with successful login events that happen within 5 minutes of the reset\n    search index=idp sourcetype=okta eventType=user.session.start status=SUCCESS earliest=-5m latest=now\n    | fields user, source_ip AS login_ip, source_country AS login_country\n]\n# Alert if the IP or country of the login does not match the password reset request\n| where reset_ip != login_ip OR reset_country != login_country\n| table user, reset_ip, reset_country, login_ip, login_country</code></pre><p><strong>Action:</strong> Activate a specific set of high-sensitivity SIEM rules during the restoration window. Focus on detecting rapid password reset and login sequences from different geolocations, token generation anomalies, and unusual spikes in tool authorization requests.</p>"
                }
            ]
        },

        {
            "id": "AID-R-004",
            "name": "Post-Incident Review, Hardening & Communication", "pillar": "data, infra, model, app", "phase": "improvement",
            "description": "Following recovery from a security incident, conduct a thorough, blameless review of the attack to identify the root cause. Based on these lessons learned, reinforce security controls, update threat models, perform targeted testing to validate fixes, and communicate the incident details to relevant internal and external stakeholders. This comprehensive process ensures that vulnerabilities are addressed, system resilience is improved, and knowledge is shared to prevent recurrence and improve collective defense.",
            "toolsOpenSource": [
                "MITRE ATLAS Navigator",
                "OWASP AI Security & Privacy Guide, OWASP LLM/ML Top 10s",
                "AI red teaming frameworks (Counterfit, Garak, vigil-llm)",
                "Vulnerability scanners (OpenVAS, Trivy)",
                "Incident response plan templates (SANS, NIST)",
                "Security community mailing lists/forums (FIRST.org, OWASP)",
                "MISP (Malware Information Sharing Platform)"
            ],
            "toolsCommercial": [
                "AI red teaming services",
                "Breach and Attack Simulation (BAS) platforms",
                "Commercial penetration testing services",
                "GRC platforms for incident reporting/notifications",
                "Threat intelligence sharing platforms",
                "Public relations/crisis communication services"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "Recurrence of same/similar attack techniques by closing gaps. Improves resilience against all ATLAS tactics.",
                        "Indirectly defends against future attacks by community knowledge sharing. Helps manage 'Impact' phase (reputational, legal)."
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Future attacks exploiting similar vulnerabilities across any MAESTRO layer.",
                        "Improves ecosystem resilience if learnings shared. Addresses L6: Security & Compliance."
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "Helps prevent re-exploitation of any LLM Top 10 vulnerabilities.",
                        "Facilitates better community understanding and defense against LLM Top 10 risks."
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "Helps prevent re-exploitation of any ML Top 10 vulnerabilities.",
                        "Improves collective defense against ML-specific risks."
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Conduct detailed post-incident review (PIR) / root cause analysis (RCA).",
                    "howTo": "<h5>Concept:</h5><p>A Post-Incident Review (PIR) is a formal, blameless process to understand an incident's full scope. The goal is not to assign blame, but to identify the root causes (both technical and procedural) that allowed the incident to occur and to generate concrete action items to prevent recurrence.</p><h5>Use a Standardized PIR Template</h5><p>Conduct a meeting with all involved parties within a few days of the incident. Use a standard template to guide the discussion and document the findings.</p><pre><code># File: post_mortems/2025-06-08-Prompt-Injection.md\\n\n## Post-Incident Review: Prompt Injection leading to PII Leakage\n\n- **Incident ID:** INC-2025-021\n- **Date:** 2025-06-08\n- **Lead:** @security_lead\n\n### 1. Timeline of Events\n- **10:00 UTC:** Alert fires for anomalous output from customer support bot.\n- **10:05 UTC:** On-call engineer acknowledges the alert.\n- **10:15 UTC:** PII leakage confirmed; kill-switch (`AID-I-005`) activated.\n- **10:30 UTC:** Root cause identified as a prompt injection vulnerability.\n- **11:00 UTC:** Patch to input validation (`AID-H-002`) deployed.\n- **11:30 UTC:** Service restored after validation (`AID-R-001`).\n\n### 2. Root Cause Analysis (The 5 Whys)\n1.  **Why did the bot leak PII?** Because it was manipulated by a prompt injection attack.\n2.  **Why was the injection successful?** Because the input sanitization only blocked basic keywords.\n3.  **Why was the sanitization insufficient?** Because it did not check for obfuscated inputs (Base64).\n4.  **Why did the output filter not catch the leak?** Because PII scanning (`AID-D-003`) was not yet implemented on this endpoint.\n5.  **Why was PII scanning not implemented?** It was on the backlog but not prioritized.\n\n### 3. Action Items (Tracked in JIRA)\n- **[AISEC-123]** Enhance input sanitizer to decode and check Base64 payloads. (Owner: @ml_infra)\n- **[AISEC-124]** Implement and deploy PII output scanning on the support bot. (Owner: @ml_infra)\n- **[AISEC-125]** Update threat model to increase likelihood of obfuscated injection. (Owner: @security_lead)</code></pre><p><strong>Action:</strong> For every security incident related to an AI system, conduct a formal, blameless Post-Incident Review. Use the '5 Whys' technique to identify the root cause and generate a list of concrete, assigned action items to address the underlying issues.</p>"
                },
                {
                    "strategy": "Develop communication plan for AI security incidents.",
                    "howTo": "<h5>Concept:</h5><p>During a crisis, you don't want to be deciding who to tell and what to say. A pre-approved communication plan defines stakeholder tiers, communication channels, and responsibilities, ensuring a fast, consistent, and calm response.</p><h5>Create a Communication Plan Template</h5><p>Create a version-controlled document that maps incident severity to communication actions.</p><pre><code># File: docs/incident_response/AI_COMMS_PLAN.md\\n\n## AI Incident Communication Plan\n\n### Stakeholder Tiers\n- **T1 (Core Incident Team):** CISO, AI Sec Lead, On-call Engineer, Legal Counsel, PR Lead\n- **T2 (Internal Leadership):** Head of Engineering, Head of Product, CEO's office\n- **T3 (All Employees):** All internal staff\\n- **T4 (Affected Customers):** Specific users whose data or service was impacted\\n- **T5 (All Customers & Public):** General user base, public via status page/social media\n\n### Communication Triggers & Channels\n| Severity | T1 (Core) | T2 (Leadership) | T3 (Employees) | T4/T5 (Public) |\\n|---|---|---|---|---|\\n| **SEV-1 (Critical)** | Immediate Page | Immediate Email | Within 1 hr (Slack) | Within 4 hrs (Status Page) |\\n| **SEV-2 (High)** | Immediate Page | Within 1 hr (Email) | EOD Summary | Monitor, No public comms unless escalated |\\n| **SEV-3 (Medium)** | Slack Alert   | Daily Digest    | None           | None           |\n\n### Responsible Parties\n- **Drafting Internal Comms:** On-Call Incident Commander\n- **Drafting External Comms:** Public Relations Lead\n- **Final Approval for External Comms:** Legal Counsel AND CISO</code></pre><p><strong>Action:</strong> Create a formal AI Incident Communication Plan. Define the stakeholder groups, the severity levels that trigger communication, and the channels to be used. Get pre-approval on this plan from Legal, PR, and Executive leadership.</p>"
                },
                {
                    "strategy": "Provide factual post-mortem report to internal teams; summary for external stakeholders.",
                    "howTo": "<h5>Concept:</h5><p>Internal transparency builds trust and enables learning. A detailed, blameless post-mortem should be shared widely with internal teams. For external stakeholders, a high-level, non-technical summary can provide reassurance without revealing sensitive operational details.</p><h5>Step 1: Write a Detailed Internal Post-Mortem</h5><p>Use the PIR template described in this technique (`AID-R-004`), focusing on the technical root cause and detailed action items. This document is for internal consumption only.</p><h5>Step 2: Write a High-Level External Summary</h5><p>Create a separate, public-facing summary that focuses on user impact and reassurance. It should not contain technical jargon, assign blame, or describe the exploit in detail.</p><pre><code># Public Status Page Update Template\\n\n**Title:** Service Disruption on [Date]\n\n**Date:** 2025-06-08\\n\n**Summary:**\\nOn June 8, 2025, between 10:00 and 11:30 UTC, our AI Customer Support Bot service experienced a disruption. Our automated monitoring systems detected the issue immediately, and our engineering teams took action to restore full functionality.\n\n**Impact:**\\nDuring this period, some users may have received erroneous responses from the bot. Our investigation has confirmed that no customer data was accessed or compromised as a result of this issue.\n\n**Root Cause & Resolution:**\\nThe disruption was caused by a vulnerability in our input processing system. We have deployed a security enhancement to correct the issue and have implemented additional monitoring to prevent recurrence.\n\nWe apologize for any inconvenience this may have caused.</code></pre><p><strong>Action:</strong> After an incident, write two reports: a detailed internal post-mortem for your engineering and security teams, and a high-level, factual summary for your public status page or customer communications.</p>"
                },
                {
                    "strategy": "Follow legal/compliance requirements for notification (data breach, regulations).",
                    "howTo": "<h5>Concept:</h5><p>If an AI security incident involves a data breach of Personally Identifiable Information (PII), you may be legally required to notify regulatory bodies and affected individuals within a strict timeframe (e.g., 72 hours under GDPR). Your incident response plan must integrate these legal obligations.</p><h5>Create a Data Breach Triage Checklist</h5><p>The incident commander should use this checklist immediately upon suspicion of a data breach to ensure legal and compliance teams are engaged correctly.</p><pre><code># Checklist: Potential Data Breach Triage\n\n- [ ] **1. Incident Declared:** An incident has been formally declared.\n- [ ] **2. Engage Legal:** The on-call Legal Counsel has been paged and added to the incident channel.\n- [ ] **3. Assess Data Type:** Confirm with engineering if the affected system processes or stores any PII, PHI, or other regulated data. (`Result: ...`)\n- [ ] **4. Determine Jurisdiction:** Identify the geographic location(s) of potentially affected users (e.g., EU, California, etc.). (`Result: ...`)\n- [ ] **5. Consult Notification Matrix:** Based on data type and jurisdiction, consult the company's 'Data Breach Notification Requirements Matrix' to identify which regulations apply (e.g., GDPR, CCPA).\n- [ ] **6. Start Notification Clock:** Document the exact time the breach was confirmed. This starts the clock for regulatory deadlines (e.g., 72-hour GDPR clock).\n- [ ] **7. Draft Notification:** Legal team begins drafting the required notifications using pre-approved templates.</code></pre><p><strong>Action:</strong> Work with your legal and compliance teams to create a 'Data Breach Notification Matrix' that maps data types and user jurisdictions to specific regulatory requirements. Integrate this into your incident response plan and train incident commanders to engage the legal team immediately upon suspicion of a PII breach.</p>"
                },
                {
                    "strategy": "Update AI threat models to reflect new intelligence.",
                    "howTo": "<h5>Concept:</h5><p>A security incident is a real-world validation of a threat that was previously theoretical. Your threat model (from `AID-M-004`) must be updated to reflect this new information. An attack that was considered 'unlikely' is now a proven, practical threat, and its risk score should be increased accordingly.</p><h5>Update the Living Threat Model Document</h5><p>In your version-controlled threat model, find the threat that corresponds to the incident. Update its likelihood and impact scores, and add a reference to the incident's PIR document. This creates an evidence-based feedback loop for your risk assessments.</p><pre><code># File: docs/THREAT_MODEL.md (Diff after an incident)\\n\n ### Component: User Prompt API Endpoint\\n \n * **T**ampering: An attacker uses prompt injection to bypass system instructions.\\n-    * *Likelihood:* Medium\\n+    * *Likelihood:* High\\n     * *Mitigation:* Implement input sanitization and guardrail models (`AID-H-002`).\n+    * *Incident History:* This threat was actualized in INC-2025-021. Attacker used a Base64-encoded payload to bypass keyword filters. See PIR for details.</code></pre><p><strong>Action:</strong> As a mandatory step in the PIR process, update your system's `THREAT_MODEL.md` file (from `AID-M-004`). Increase the likelihood score for the threat that was exploited and add a brief description of the incident with a link to the full PIR document.</p>"
                },
                {
                    "strategy": "Implement/enhance defensive techniques based on PIR findings.",
                    "howTo": "<h5>Concept:</h5><p>The action items generated by the Post-Incident Review must be converted into trackable engineering work and implemented promptly. This is the core of the 'learn and improve' cycle, turning the lessons from an incident into stronger, more resilient defenses.</p><h5>Create Engineering Tickets from Action Items</h5><p>For each action item identified in the PIR, create a ticket in your project management system (e.g., Jira, GitHub Issues). The ticket should be detailed, actionable, and linked back to the original incident.</p><pre><code># Example GitHub Issue\n\n**Title:** Implement PII Output Scanning on Support Bot (Ref: INC-2025-021)\n\n**Labels:** `security`, `bug`, `aidefend:AID-D-003`\n\n**Description:**\nAs per the Post-Incident Review for **INC-2025-021**, our output filtering was insufficient to prevent PII leakage. We need to add a PII detection and redaction step to the customer support bot's response pipeline.\n\n**Acceptance Criteria:**\n- [ ] The Presidio library (`AID-D-003.002`) is integrated into the API response flow.\n- [ ] All bot-generated text is scanned for PII (names, emails, phone numbers) before being sent to the user.\n- [ ] Detected PII is replaced with placeholders (e.g., `<PERSON>`).\n- [ ] A new detection rule is created to alert on any PII found in the pre-redacted output, for monitoring purposes.</code></pre><p><strong>Action:</strong> Ensure that every action item from a PIR is converted into a well-defined, assigned, and prioritized ticket in your engineering backlog. Track these tickets to completion to ensure the identified security gaps are closed.</p>"
                },
                {
                    "strategy": "Perform targeted security testing (pen testing, AI red teaming) to validate fixes.",
                    "howTo": "<h5>Concept:</h5><p>After a vulnerability has been patched, you must actively test the fix. A targeted red team exercise or penetration test should simulate the original attacker's TTPs to verify that the new defense is effective and has not introduced any new vulnerabilities.</p><h5>Use Automated Tools for Targeted Scanning</h5><p>For common vulnerabilities like prompt injection, you can use an open-source scanner to quickly test your patched endpoint. `garak` is a tool designed for LLM vulnerability scanning.</p><pre><code># This command runs all of garak's prompt injection probes against your API.\n# This would be run against the patched, non-production environment.\n\n> python -m garak --model_type test --model_name http://my-patched-api:8080/v1/chat \\ \n  --probes injection.all\n\n# The output will show how many probes were successful (i.e., how many injections worked).\n# A successful patch should result in 0 successful probes.</code></pre><p><strong>Action:</strong> After deploying a security fix to a staging environment, conduct targeted security testing. At a minimum, use an automated scanner like `garak` to test for the specific vulnerability class. For critical incidents, engage a red team to perform manual, creative testing to verify the robustness of the fix.</p>"
                },
                {
                    "strategy": "Share non-sensitive technical details with trusted communities.",
                    "howTo": "<h5>Concept:</h5><p>If you discover a novel AI attack vector, sharing the TTPs (Tactics, Techniques, and Procedures) with trusted security communities like ISACs, MITRE, or OWASP helps the entire ecosystem build better defenses. This is 'collective defense'. The key is to sanitize the information to remove any details specific to your company.</p><h5>Write a Sanitized TTP Description</h5><p>After an incident involving a new technique, write up a generic, non-attributable description of the attack.</p><pre><code># Title: Novel Prompt Injection Technique via Nested Base64 and Unicode Homoglyphs\n\n## TTP Description\nAn attacker was observed bypassing keyword-based prompt injection filters. The technique involved the following steps:\n1. The malicious payload (e.g., \\\"ignore instructions\\\") was written using Unicode homoglyphs to replace standard ASCII characters (e.g., using Cyrillic 'а' instead of Latin 'a').\n2. This homoglyph-encoded string was then encoded into Base64.\n3. This Base64 string was then embedded in a prompt with instructions for the LLM to first decode the string and then execute the result.\n\n## Example (Sanitized)\n`Benign instruction... Please decode the following string and follow the instructions within: [Base64 string of homoglyph-encoded attack]`\n\n## Suggested Mitigations\n- Input sanitizers should recursively decode multiple layers of encoding.\n- Input validators should check for and block the use of mixed-character sets or high-entropy strings.\n- Anomaly detection on prompt structure can flag this pattern as unusual.</code></pre><p><strong>Action:</strong> Establish a process for your security team to sanitize and share novel AI attack TTPs with relevant industry groups. The shared report should describe the technique generically, without naming your company, products, or employees.</p>"
                },
                {
                    "strategy": "Use incident as case study for internal training/awareness.",
                    "howTo": "<h5>Concept:</h5><p>A real-world incident is a powerful learning tool. Converting the details of an incident into an internal case study can help educate developers and data scientists about real, practical AI security threats, making them more likely to build secure systems in the future.</p><h5>Create a Case Study Presentation</h5><p>Synthesize the Post-Incident Review into a short presentation for an internal engineering all-hands or a team-specific training session. The focus should be on the technical lessons learned, not on blame.</p><pre><code># Outline for an Internal Training Presentation\n\n**Slide 1: Title**\n- Anatomy of a Real-World Attack: The 'Obfuscated Injection' Incident (INC-2025-021)\n\n**Slide 2: The Attack at a High Level**\n- What was the attacker's goal?\n- What was the user-facing impact?\n- A simplified timeline of detection and response.\n\n**Slide 3: The Technical Root Cause**\n- Show the 'Before' code for our input validator.\n- Show the attacker's clever Base64 + Homoglyph payload.\n- Explain *why* our original defense failed.\n\n**Slide 4: The Fix**\n- Show the 'After' code for the new, multi-stage input validator.\n- Explain how the new defense-in-depth approach blocks this attack.\n\n**Slide 5: Key Takeaways for Developers**\n- 1. All user input is a potential attack vector.\n- 2. Attackers will use multiple layers of obfuscation.\n- 3. Security is a continuous process of responding to new TTPs.\n- 4. Link to the updated secure coding guidelines.</code></pre><p><strong>Action:</strong> Once a quarter, have the AI security team present a sanitized case study of a recent security incident to the broader engineering organization. Use real (but non-attributable) examples to demonstrate how attackers are targeting your systems and how the team's defensive work is mitigating those threats.</p>"
                }
            ]
        },
        {
            "id": "AID-R-005",
            "name": "Rapid Vector Index Rollback & Quarantine",
            "description": "Implement fast, reliable recovery procedures for a Retrieval-Augmented Generation (RAG) system's vector index after a poisoning attack has been detected. This technique relies on versioning the index to enable rapid rollback to the last known-good state. It also includes mechanisms to quarantine suspicious document chunks, removing them from the active index for forensic analysis while maintaining the availability of the rest of the system. The goal is to minimize service disruption and ensure the restored index is clean and trustworthy.",
            "phase": "improvement",
            "pillar": "data",
            "defendsAgainst": [
                { "framework": "MITRE ATLAS", "items": ["AML.T0070 RAG Poisoning", "AML.T0059 Erode Dataset Integrity"] },
                { "framework": "MAESTRO", "items": ["Compromised RAG Pipelines (L2)", "Data Poisoning (L2)"] },
                { "framework": "OWASP LLM Top 10 2025", "items": ["LLM08:2025 Vector and Embedding Weaknesses", "LLM04:2025 Data and Model Poisoning"] },
                { "framework": "OWASP ML Top 10 2023", "items": ["ML02:2023 Data Poisoning Attack"] }
            ],
            "subTechniques": [],
            "implementationStrategies": [
                {
                    "strategy": "Use index aliases/pointers for atomic cutover and rollback; preserve full provenance metadata when quarantining.",
                    "howTo": "<h5>Concept:</h5><p>Do not operate on a single, live index. Treat indices as immutable build artifacts. Each update should create a completely new, version-tagged index. An alias pointing to the 'production' version allows for instant switching and rollback between versions.</p><h5>Pattern:</h5><p>The workflow is: build a new index `rag_index_v2`, validate it, then atomically switch the `rag_prod` alias to point to it. If an incident occurs on v2, the rollback is a single command to switch the alias back to `rag_index_v1`. When quarantining, copy the suspect chunks with all their metadata to a separate forensic store (e.g., an S3 bucket) before deleting them from the production index.</p><p><strong>Action:</strong> Implement an index build process where each update creates a new collection/index with a unique version number. Use an alias (e.g., `production_alias`) to point to the currently active index. Your application should always query this alias. A rollback becomes an atomic operation of switching the alias back to the last known-good version.</p>"
                }
            ],
            "toolsOpenSource": ["Qdrant", "Elasticsearch", "Milvus"],
            "toolsCommercial": ["Pinecone", "Weaviate", "Amazon OpenSearch Service"]
        }
    ]
};