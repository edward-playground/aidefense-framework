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
                            "strategy": "Maintain immutable, versioned backups of all production model artifacts with recorded hashes and attestations.",
                            "howTo": "<h5>Concept:</h5><p>You cannot restore what you cannot trust. Every model promoted to production must be snapshotted into an append-only / versioned / access-restricted backup location (e.g. an S3 bucket with Object Versioning and Object Lock, writeable only by CI/CD). For each snapshot you must store: (1) the model artifact, (2) its cryptographic hash, (3) its build/signing attestation (supply-chain provenance), and (4) deployment metadata (who approved promotion).</p><h5>Configure a Versioned Backup Store</h5><p>Use Infrastructure as Code to provision a dedicated bucket with versioning enabled. Enable policies so runtime services cannot retroactively overwrite past versions.</p><pre><code># File: infrastructure/model_backups.tf (Terraform)\n\nresource \"aws_s3_bucket\" \"model_backups\" {\n  bucket = \"aidefend-prod-model-backups\"\n}\n\nresource \"aws_s3_bucket_versioning\" \"model_backups_versioning\" {\n  bucket = aws_s3_bucket.model_backups.id\n  versioning_configuration {\n    status = \"Enabled\"\n  }\n}\n\n# (Recommended) Also configure Object Lock / retention to prevent tampering.\n</code></pre><p><strong>Action:</strong> As the final step of each production promotion pipeline, push the model artifact into this versioned store, record its SHA-256 (and, if available, its cryptographic signature / attestation) in the model registry, and mark it as restore-capable.</p>"
                        },
                        {
                            "strategy": "Identify the last known-good model version that predates the incident window.",
                            "howTo": "<h5>Concept:</h5><p>During incident response, you must figure out which model version last ran correctly before compromise. This requires an auditable model registry with timestamps, promotion history, and security status flags (e.g. 'passed security validation', 'no anomaly reports').</p><h5>Query the Registry by Timestamp</h5><p>Use your model registry (MLflow, SageMaker Model Registry, etc.) to locate the most recent version <em>created and promoted before</em> the incident start timestamp, and which still has a valid attestation/hash recorded.</p><pre><code># File: restore/find_good_version.py\nfrom mlflow.tracking import MlflowClient\n\n# INCIDENT_START_TIMESTAMP = ... (epoch ms or similar)\n# client = MlflowClient()\n# versions = client.search_model_versions(\"name='My-Production-Model'\")\n# known_good_version = None\n# for v in sorted(versions, key=lambda x: x.creation_timestamp, reverse=True):\n#     if v.creation_timestamp < INCIDENT_START_TIMESTAMP and \\\n#        v.tags.get('security_status') == 'clean' and \\\n#        'sha256_hash' in v.tags:\n#         known_good_version = v\n#         break\n# if known_good_version:\n#     print(f\"Identified last known-good version: {known_good_version.version}\")\n# else:\n#     print(\"No trusted pre-incident version found!\")</code></pre><p><strong>Action:</strong> Your IR runbook must explicitly include 'Identify last known-good version' as a step. The definition of 'known-good' must include both timeline (<em>before</em> compromise) and trust evidence (hash/signature, no prior anomaly flags).</p>"
                        },
                        {
                            "strategy": "Verify the integrity and provenance of the backup artifact before redeployment.",
                            "howTo": "<h5>Concept:</h5><p>Never blindly restore. Before you redeploy a rollback model, you must cryptographically prove that the artifact you're about to deploy is byte-for-byte identical to the trusted snapshot you approved earlier. This usually means verifying both the stored hash and any build/signing attestation (e.g. GPG signature, cosign/SLSA provenance).</p><h5>Integrity Check in the Rollback Script</h5><pre><code># File: restore/verify_and_restore.py\n\n# Assume 'known_good_version' was identified in the previous step\n# Assume 'get_sha256_hash()' and 'verify_signature()' are trusted utilities\n\n# 1. Pull the trusted metadata from registry\n# authorized_hash = known_good_version.tags.get('sha256_hash')\n# authorized_sig  = known_good_version.tags.get('signature_ref')  # e.g. GPG key ID or cosign attestation\n\n# 2. Download the backup artifact from the immutable backup store\n# local_path = client.download_artifacts(\n#     f\"models:/{known_good_version.name}/{known_good_version.version}\",\n#     \".\"\n# )\n\n# 3. Recalculate hash\n# actual_hash = get_sha256_hash(local_path + \"/model.pkl\")\n# if actual_hash != authorized_hash:\n#     raise SecurityException(\"CRITICAL: Hash mismatch. Aborting restore.\")\n\n# 4. (If present) verify signature/attestation\n# if not verify_signature(local_path + \"/model.pkl\", authorized_sig):\n#     raise SecurityException(\"CRITICAL: Signature/attestation verification failed.\")\n\n# print(\"✅ Backup integrity and provenance verified. Safe to proceed.\")</code></pre><p><strong>Action:</strong> Treat signature/hash verification as a <em>blocking</em> gate in the rollback pipeline. If verification fails, you do <em>not</em> restore that artifact into production.</p>"
                        },
                        {
                            "strategy": "Use an audited, parameterized rollback pipeline to redeploy the known-good model and its serving environment.",
                            "howTo": "<h5>Concept:</h5><p>Restoring a clean model isn't enough if the runtime stack (container image, inference server, plugin/tool stack) is still compromised. The rollback deployment must (1) take the vetted model artifact, (2) pair it with a trusted serving image or container digest from before the incident, and (3) promote that pair through a controlled, auditable pipeline (GitOps/CI/CD) instead of manual copy.</p><h5>Trigger a Controlled Rollback Workflow</h5><pre><code># Conceptual GitHub Actions workflow (workflow_dispatch)\n# name: Rollback Production Model\n# on:\n#   workflow_dispatch:\n#     inputs:\n#       model_name:\n#         description: 'Model to roll back'\n#         required: true\n#       version_to_restore:\n#         description: 'Known-good model version'\n#         required: true\n#       serving_image_digest:\n#         description: 'Trusted serving container digest to deploy'\n#         required: true\n# jobs:\n#   rollback:\n#     runs-on: ubuntu-latest\n#     steps:\n#       - name: Verify Artifact Integrity\n#         run: python restore/verify_and_restore.py \\\n#              --model ${{ github.event.inputs.model_name }} \\\n#              --version ${{ github.event.inputs.version_to_restore }}\n#       - name: Deploy Known-Good Stack\n#         run: |\n#           ./deploy_inference_service.sh \\\n#             --model_version ${{ github.event.inputs.version_to_restore }} \\\n#             --image_digest  ${{ github.event.inputs.serving_image_digest }}\n</code></pre><p><strong>Action:</strong> Your rollback pipeline must also restore (or verify) the serving runtime/container image, not just the model weights. The entire inference stack should match a previously trusted state. The pipeline run itself is now an auditable artifact for incident closure.</p>"
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
                            "strategy": "Identify and evict malicious data points, poisoned graph nodes, or compromised federated clients before retraining.",
                            "howTo": "<h5>Concept:</h5><p>Before you retrain a \"clean\" model, you must build a sanitized dataset. That means removing the exact samples, graph nodes/edges, or client contributions that introduced the backdoor, skew, or bias. This step uses outputs from detection / eviction techniques (e.g. AID-D-012 for graph anomaly detection, AID-E-003.002 for poisoned data cleansing, or federated client trust scoring).</p><h5>Automated Cleansing Script</h5><pre><code># File: remediation/cleanse_data.py\n# full_dataset: pandas DataFrame or similar\n# malicious_indices: list of row indices flagged as poisoned or malicious\n\ndef create_clean_dataset(full_dataset, malicious_indices):\n    print(f\"Original dataset size: {len(full_dataset)}\")\n    clean_dataset = full_dataset.drop(index=malicious_indices)\n    print(f\"Removed {len(malicious_indices)} malicious data points.\")\n    print(f\"Cleansed dataset size: {len(clean_dataset)}\")\n    return clean_dataset\n\n# Graph case: remove malicious nodes/edges (see AID-E-003.004)\n# Federated case: exclude updates from all clients flagged as malicious.\n</code></pre><p><strong>Action:</strong> Build a repeatable cleansing step that (1) takes the list of malicious artifacts (indices, node IDs, client IDs), (2) produces a \"cleansed\" dataset or graph snapshot, and (3) logs exactly what was removed (who/what/when) into your incident record for audit and accountability.</p>"
                        },
                        {
                            "strategy": "Trigger a secure, isolated full retraining job using only the cleansed dataset.",
                            "howTo": "<h5>Concept:</h5><p>If the model itself is already compromised (e.g. embedded backdoor neurons, heavily poisoned fine-tune), fine-tuning is often not enough. The most reliable remediation is to train a fresh model from scratch using only the sanitized data. This must happen in a hardened, controlled environment so you don't reintroduce the same exploit via tampered training code or dependencies.</p><h5>Launch a Controlled Retraining Pipeline</h5><pre><code># 1. Version-control the cleansed dataset (e.g. with DVC or object storage + hash)\n# > dvc add data/cleansed_dataset_v2.csv\n# > git commit -m \"feat: sanitized dataset for post-incident retraining\"\n\n# 2. Kick off a secure training pipeline\n# > ./trigger_training_pipeline.sh \\\n#      --dataset_uri s3://secure-bucket/cleansed_dataset_v2.csv \\\n#      --model_name \"my-model-remediated-v1\" \\\n#      --training_image_digest sha256:trusted_image_digest_here\n\n# 3. Ensure the training code instantiates a NEW model object\n#    (do NOT continue fine-tuning the compromised weights)\n\ndef train_new_model(clean_data):\n    model = MyModelArchitecture(...)  # fresh weights every time\n    optimizer = Adam(model.parameters())\n    # ... standard training loop on clean_data ...\n    return model\n</code></pre><p><strong>Action:</strong> The remediation playbook must require: (a) training starts from fresh weights, (b) training runs in a hardened/attested container image that has already been patched per AID-E-004, and (c) all hyperparameters, code commits, container digests, and dataset hashes are logged for audit and reproducibility.</p>"
                        },
                        {
                            "strategy": "Apply approximate unlearning for Federated Learning or large-scale distributed models when full retraining is prohibitively expensive.",
                            "howTo": "<h5>Concept:</h5><p>In Federated Learning, fully retraining the global model from scratch after evicting malicious clients can be slow and expensive. An interim containment technique is approximate unlearning: mathematically estimate the malicious clients' contribution to the global weights, then apply an equal and opposite update to \"subtract out\" their influence.</p><h5>Negative-Gradient Style Unlearning</h5><pre><code># Pseudocode for approximate unlearning\n# global_model: compromised global model (PyTorch module)\n# malicious_updates: list of parameter update tensors from flagged clients\n\n# 1. Aggregate the malicious contribution\n# total_bad_update = aggregate(malicious_updates)\n\n# 2. Apply an opposite update to rollback their influence\n# with torch.no_grad():\n#     for param, bad_grad in zip(global_model.parameters(), total_bad_update):\n#         param.data -= LEARNING_RATE * bad_grad\n\n# print(\"Applied negative updates to approximately unlearn malicious client influence.\")\n\n# After this, continue fine-tuning ONLY on trusted client data or clean global data.\n</code></pre><p><strong>Action:</strong> Use approximate unlearning as a cost-control / speed measure in FL or distributed training. Always follow up with additional fine-tuning on cleansed data and then run the full security validation step below. Document that this was an approximate remediation, not a guaranteed full purge.</p>"
                        },
                        {
                            "strategy": "Run a post-remediation validation suite to prove the new model is both safe and still useful.",
                            "howTo": "<h5>Concept:</h5><p>The final gate before redeployment is validation. You must show (1) normal functionality didn't collapse, and (2) the exploit that triggered remediation is actually neutralized. This proof becomes part of the incident closure record and should be attached back to the model registry entry for the remediated version.</p><h5>Evaluate Clean Performance and Attack Resistance</h5><pre><code># File: remediation/validate_retraining.py\n# remediated_model: the newly trained or unlearned model\n# clean_test_data: standard evaluation dataset\n# attack_test_data: dataset (or prompts/triggers) representing the original exploit\n\n# 1. Check normal task performance\n# clean_accuracy = evaluate(remediated_model, clean_test_data)\n# if clean_accuracy < ACCEPTABLE_ACCURACY_THRESHOLD:\n#     print(\"WARNING: Functional regression after remediation.\")\n\n# 2. Check if the original attack still works\n# attack_success_rate = evaluate_attack_success(remediated_model, attack_test_data)\n# if attack_success_rate < 0.05:\n#     print(\"✅ REMEDIATION VERIFIED: Attack no longer effective.\")\n# else:\n#     print(\"❌ REMEDIATION FAILED: Model still vulnerable to the original vector.\")\n\n# 3. Record results to registry / IR ticket for audit\n</code></pre><p><strong>Action:</strong> Promotion of the remediated model to production must be blocked unless: (a) it meets acceptable quality on clean evaluation data, and (b) the attack success rate (e.g., backdoor trigger activation, poisoned behavior) is driven down to an agreed threshold. Store these validation metrics, dataset hashes, and model version IDs in the incident ticket and in the model registry as formal recovery evidence.</p>"
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
                    "strategy": "Identify all affected data stores, downstream assets, and derived artifacts.",
                    "howTo": "<h5>Concept:</h5><p>Before recovery, you must understand the full blast radius. Corrupted data almost never lives in isolation: it may have been copied into feature stores, embedded into vector DBs for RAG, cached in retrieval indexes, logged as 'trusted output', or even used to train/finetune downstream models. You need a complete dependency map so you know what must be restored, re-generated, or retrained.</p><h5>Use Lineage to Trace Propagation</h5><p>Starting from the first known compromised dataset (e.g. a poisoned upload batch), recursively enumerate all downstream assets that consumed it: feature tables, analytics tables, vector databases / embedding indexes, prompt memory stores, and any production models trained or fine-tuned on it.</p><pre><code># File: recovery/identify_blast_radius.py\n# Conceptually queries a lineage/catalog service (DataHub, OpenMetadata, Collibra, etc.)\n\ndef find_downstream_assets(asset_uri: str):\n    \"\"\"Recursively find all assets downstream of a compromised asset.\"\"\"\n    affected = {asset_uri}\n    queue = [asset_uri]\n    while queue:\n        current = queue.pop(0)\n        downstream = lineage_client.get_downstream_lineage(current)\n        for asset in downstream:\n            if asset.uri not in affected:\n                affected.add(asset.uri)\n                queue.append(asset.uri)\n    return list(affected)\n\n# During incident response:\n# compromised_root = \"s3://aidefend-datasets/raw/batch_123.csv\"\n# all_affected = find_downstream_assets(compromised_root)\n# print(\"POTENTIALLY COMPROMISED ASSETS:\")\n# for a in all_affected:\n#     print(\"-\", a)\n</code></pre><p><strong>Action:</strong> Generate and record (in the incident ticket) a complete list of affected assets, including: raw datasets, feature stores, RAG/vector DB namespaces, embedding stores, prompt/context memory logs, and any models trained on that data. This defines the official scope for restoration and retraining (and feeds directly into AID-R-001 if model rollback/retrain is required).</p>"
                },
                {
                    "strategy": "Restore each affected data store from the most recent trusted, pre-incident backup or snapshot.",
                    "howTo": "<h5>Concept:</h5><p>Primary recovery method: roll back to a known-good snapshot taken before the compromise window. This applies to S3 buckets, SQL/NoSQL databases, vector databases (FAISS/Milvus/Pinecone), and embedding indexes. You must pick a restore timestamp just before the first malicious write.</p><h5>Point-in-Time / Version Restoration</h5><p>Below is an example using S3 Object Versioning to restore a dataset to its last known-good version. The same principle applies to vector DB snapshots (restore prior index dump) and feature stores (restore from point-in-time backup).</p><pre><code># File: recovery/restore_s3_object.sh\nBUCKET_NAME=\"aidefend-prod-training-data\"\nOBJECT_KEY=\"critical_dataset.csv\"\n\n# 1. List historical versions and identify the versionId from before the incident start.\naws s3api list-object-versions --bucket ${BUCKET_NAME} --prefix ${OBJECT_KEY}\n\nGOOD_VERSION_ID=\"a1b2c3d4e5f6g7h8\"  # chosen based on timestamp < incident start\n\n# 2. Promote that known-good version back to 'current'.\necho \"Restoring ${OBJECT_KEY} to version ${GOOD_VERSION_ID}...\"\naws s3api copy-object \\\n    --bucket ${BUCKET_NAME} \\\n    --copy-source \"${BUCKET_NAME}/${OBJECT_KEY}?versionId=${GOOD_VERSION_ID}\" \\\n    --key ${OBJECT_KEY}\n\necho \"✅ Restore complete (object now rolled back).\"\n</code></pre><p><strong>Action:</strong> For every compromised asset (including vector DB namespaces used by RAG), perform a restoration <em>into an isolated staging environment first</em>, not straight into production. In that staging environment, you will run integrity and quality validation (see below). Only after validation passes do you promote the restored snapshot back into production.</p>"
                },
                {
                    "strategy": "If no clean backup exists, reconstruct or repair data in place using deterministic rules and validation logic.",
                    "howTo": "<h5>Concept:</h5><p>Worst case: backups are missing, also corrupted, or too out-of-date. Then you must salvage what you have. This means writing a repair script that removes identifiable bad rows/chunks/vectors based on rules derived from the incident investigation (invalid schema, impossible values, malicious prompts injected into RAG context, etc.). The result is a reduced but trustworthy dataset/index.</p><h5>Heuristic Data Repair Script</h5><p>The following example shows a CSV-style dataset repair. In practice you must apply the same idea to RAG/embedding stores (e.g. drop vectors that originated from untrusted domains or attacker-controlled sources).</p><pre><code># File: recovery/repair_data.py\nimport pandas as pd\nimport great_expectations as gx\n\n# Load the corrupted dataset\ndf = pd.read_csv(\"data/corrupted_dataset.csv\")\noriginal_rows = len(df)\n\n# Rule 1: Remove rows missing critical fields\ndf.dropna(subset=[\"user_id\", \"transaction_amount\"], inplace=True)\n\n# Rule 2: Enforce schema/range constraints (Great Expectations or similar)\nvalidator = gx.from_pandas(df)\nvalid_mask = validator.expect_column_values_to_be_between(\n    \"transaction_amount\", min_value=0, max_value=100000\n).success\n# Keep only rows that passed basic validation\ndf = df[valid_mask]\n\n# Rule 3: Remove malicious outliers / injected payloads\n# e.g. rows flagged by anomaly detection, or RAG chunks from unapproved domains\n# outlier_mask = find_outliers(df[\"feature_x\"])\n# df = df[~outlier_mask]\n\nprint(f\"Repair complete. Removed {original_rows - len(df)} corrupted rows.\")\n# df.to_csv(\"data/repaired_dataset.csv\", index=False)\n</code></pre><p><strong>Action:</strong> Document the exact filtering logic you apply (which columns were validated, which rows/vectors were dropped, which client or data source was deemed malicious). Save this as part of the incident record, so you can defend in audit why certain data was removed or altered. Treat repaired output as <em>provisionally trusted</em> until it passes the full validation step.</p>"
                },
                {
                    "strategy": "Re-validate integrity, schema, and statistical consistency of restored/repaired data before reuse.",
                    "howTo": "<h5>Concept:</h5><p>After restore or repair, you must prove the dataset (or vector index / feature store) is trustworthy again. That means: cryptographic integrity (matches known-good snapshot hash when available), schema & quality checks, and distribution sanity checks vs. your pre-incident baseline. For RAG/vector DBs, this also includes confirming that only approved sources / namespaces remain, and no attacker-planted prompts/snippets persist.</p><h5>Post-Restoration Validation Pipeline</h5><p>The validation step should run automatically in an isolated staging environment. Only if it passes, the dataset/index is allowed back into production or into retraining pipelines.</p><pre><code># File: recovery/validate_restored_data.py\n# Assumes helper funcs:\n# get_sha256_hash(), run_great_expectations_checkpoint(), generate_data_profile()\n\nKNOWN_GOOD_HASH = \"a1b2c3d4e5f6...\"   # from backup manifest or baseline catalog\nRESTORED_FILE = \"data/restored_dataset.csv\"\n\n# 1. Cryptographic integrity check (if we had a snapshot manifest)\nactual_hash = get_sha256_hash(RESTORED_FILE)\nif actual_hash != KNOWN_GOOD_HASH:\n    raise SecurityException(\"Hash mismatch on restored dataset!\")\n\n# 2. Schema / constraint / range validation\nvalidation_result = run_great_expectations_checkpoint(RESTORED_FILE, \"my_checkpoint\")\nif not validation_result[\"success\"]:\n    raise DataQualityException(\"Restored data failed validation checks!\")\n\n# 3. Distribution / profile comparison\n# profile = generate_data_profile(RESTORED_FILE)\n# Compare profile vs. pre-incident baseline (row counts, value ranges, class balance, etc.)\n# If deviation is extreme or suspicious, require human review.\n\nprint(\"✅ All validation checks passed: data is ready for reuse.\")\n</code></pre><p><strong>Action:</strong> Attach the validation report (hash check results, schema validation outcome, distribution comparison notes, RAG/vector index source whitelist report) to the incident ticket and update the data catalog/lineage system to mark this asset as recovered and trusted. No restored dataset or vector index should be reintroduced into production pipelines or model retraining (AID-R-001.002) until this step passes.</p>"
                },
                {
                    "strategy": "Harden ingestion and update pipelines to prevent recurrence of the same corruption pattern.",
                    "howTo": "<h5>Concept:</h5><p>Recovery is not done until you close the hole. The exact validation steps that would have caught this incident must now become permanent gates in your ingestion / ETL / vector-db-upsert pipelines. That includes schema validation, source allowlists, anomaly/outlier screens, and cryptographic provenance checks (did this chunk/vector actually come from an approved source?).</p><h5>Embed Permanent Validation into the Pipeline</h5><p>Below is an example for tabular ingestion, but you must apply the same idea to RAG index builders: reject any new document/chunk that isn't from an approved source or that fails content/format policy.</p><pre><code># BEFORE: vulnerable ingestion (no validation)\ndef vulnerable_ingestion(source_file):\n    df = pd.read_csv(source_file)\n    df.to_sql('my_table', con=db_engine, if_exists='append')\n\n# AFTER: hardened ingestion with enforcement\nimport pandas as pd\n\ndef hardened_ingestion(source_file):\n    df = pd.read_csv(source_file)\n\n    # Example rule derived from the incident's root cause:\n    # All user_id values must be positive integers\n    if not pd.to_numeric(df['user_id'], errors='coerce').notna().all() or not (df['user_id'] > 0).all():\n        raise ValueError(\"Ingestion blocked: invalid user_id values detected.\")\n\n    # (For RAG/vector DB pipelines)\n    # - Verify each document chunk's source domain is on an approved whitelist.\n    # - Reject chunks containing attacker-supplied prompt injections or malicious instructions.\n\n    df.to_sql('my_table', con=db_engine, if_exists='append')\n</code></pre><p><strong>Action:</strong> Do a root cause analysis for the data corruption event. Convert that root cause into one or more mandatory validation checks inside your production ingestion / RAG indexing / feature generation pipelines. Version and audit these new controls so you can prove to compliance and leadership that the specific failure mode that caused this incident is now permanently guarded against.</p>"
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
                    "strategy": "Ensure re-established sessions use strong authentication (MFA / step-up) and hardened transport (TLS/HSTS).",
                    "howTo": "<h5>Concept:</h5><p>After a global eviction (AID-E-005), you cannot let everyone just log back in with the same habits. All new sessions must go through stronger identity proof (e.g. MFA or step-up auth), and all network channels must be hardened to prevent attackers from hijacking re-onboarding traffic. You also temporarily run in a \"high scrutiny\" mode: shorter token lifetimes, forced refresh, no remembered-trust cookies.</p><h5>Step 1: Enforce Modern TLS Only and Enable HSTS</h5><pre><code># Example hardened Nginx/TLS config for post-incident window\nserver {\n    listen 443 ssl http2;\n    ssl_protocols TLSv1.2 TLSv1.3;           # Drop TLSv1.0/1.1\n    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';\n    ssl_prefer_server_ciphers on;\n    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;\n    # ... rest of config ...\n}\n</code></pre><h5>Step 2: Require Step-Up / MFA for All Re-Logins After Eviction</h5><pre><code># Conceptual IdP policy (Okta/Keycloak-like pseudo-logic)\nIF user.session.was_globally_revoked == true\nAND user.auth_method == 'password_only'\nTHEN REQUIRE additional_factor IN ['push_notification','totp_code']\nELSE ALLOW access\n</code></pre><h5>Step 3: Short-Lived Tokens During Observation Window</h5><p>For the first N hours after eviction, issue only short-lived access tokens and rotate refresh tokens on every successful re-auth. High-risk API calls (like ones that let an agent write to external systems, invoke tools with side effects, or access sensitive data) should require a \"fresh\" token (recent MFA).</p><p><strong>Action:</strong> Immediately after eviction, force all users/agents to sign in again over TLS 1.2+/HSTS, require MFA or step-up auth for that first login, and temporarily shorten session/token TTL. Treat this as a temporary \"post-incident hardened mode\" with elevated requirements until monitoring (see below) shows no signs of re-compromise.</p>"
                },
                {
                    "strategy": "Restore clean conversational / agent state cautiously and progressively re-enable capabilities.",
                    "howTo": "<h5>Concept:</h5><p>During eviction (AID-E-005), you purged suspicious session state, cached prompts, tool bindings, and conversational memory to kick out the attacker and erase poisoned context. Now you need to rebuild trust for legitimate users and agents. You do <em>not</em> just reload the exact same state from before; you restore only vetted, known-good baseline state and you reintroduce capability in controlled stages.</p><h5>Step 1: Rehydrate from Trusted Snapshots</h5><p>For each agent/user, load a minimal baseline context from an auditable, integrity-checked snapshot (e.g. a signed/hashed backup taken before the compromise window). Do not restore any state captured during the suspected compromise period.</p><h5>Step 2: Stage Capability Re-Enablement</h5><p>Start the agent in a reduced-permission mode: read-only tools first, no write/execution, no external system modification. Only after a short observation period (and no suspicious activity) do you re-enable higher-privilege tools.</p><p>Each privilege escalation step (e.g. re-allowing code execution, financial transactions, production config changes) should be logged and ideally require human approval or change-control style signoff.</p><p><strong>Action:</strong> Define, in your recovery runbook, exactly: (1) which snapshot is considered trustworthy for restoring memory/context and how its integrity is verified, and (2) the staged sequence for re-granting tool capabilities. Record each capability re-enable event (who approved, timestamp) for audit and for post-incident review.</p>"
                },
                {
                    "strategy": "Communicate the session reset and new login requirements clearly to legitimate users.",
                    "howTo": "<h5>Concept:</h5><p>Mass session invalidation is disruptive. If you don't explain it, users will think it's an outage or phishing. Clear, proactive communication turns users into an ally: they know to expect MFA, they understand why, and they will alert you if they see suspicious login prompts they didn't initiate.</p><h5>Automate Secure User Notification</h5><pre><code># File: incident_response/notify_users.py\nfrom sendgrid import SendGridAPIClient\nfrom sendgrid.helpers.mail import Mail\n\ndef send_session_reset_notification(user_list, template):\n    \"\"\"Send a pre-approved security incident notice to all affected users.\"\"\"\n    # Iterate users and send via provider API (SendGrid/Twilio/etc.)\n    # The template should:\n    # 1. Explain that sessions were reset for security reasons.\n    # 2. Tell users they will be prompted for MFA again.\n    # 3. Instruct: \"If you receive login/MFA prompts you did NOT initiate, contact us immediately.\" \n    pass\n</code></pre><p><strong>Action:</strong> Maintain pre-approved, legally reviewed communication templates (email/SMS/in-app banner) that you can broadcast immediately after eviction. The message must (a) explain the reset, (b) set expectation for MFA/step-up, and (c) ask users to report unexpected login prompts. Store evidence of this communication in the incident record to show that impacted users were notified and instructed.</p>"
                },
                {
                    "strategy": "Monitor newly established sessions at elevated sensitivity for signs of re-compromise.",
                    "howTo": "<h5>Concept:</h5><p>The hours right after restoration are the highest-risk period. The attacker may still have stolen credentials, old tokens, or knowledge of how your system behaves. You run in an \"observation window\" with <em>custom high-sensitivity detections</em> and you keep audit logs proving you were actively watching.</p><h5>Create High-Risk Correlation Rules in SIEM</h5><pre><code># Example Splunk SPL correlation rule:\n# 1. Find successful password reset events.\nindex=idp sourcetype=okta eventType=user.account.reset_password status=SUCCESS\n| fields user, source_ip AS reset_ip, source_country AS reset_country\n| join user [\n    # 2. Join with successful login events within 5 minutes after reset.\n    search index=idp sourcetype=okta eventType=user.session.start status=SUCCESS earliest=-5m latest=now\n    | fields user, source_ip AS login_ip, source_country AS login_country\n]\n# 3. Alert if geo/IP don't match -> possible credential handoff to attacker.\n| where reset_ip != login_ip OR reset_country != login_country\n| table user, reset_ip, reset_country, login_ip, login_country\n</code></pre><p><strong>Action:</strong> During the post-eviction observation window, enable heightened monitoring rules that specifically look for: (1) password reset → login from a different country/IP, (2) abnormal spikes in token issuance or tool authorization requests by a single identity, (3) agents immediately requesting high-privilege actions after capability re-enable. All alerts and analyst responses during this hardened monitoring window should be attached to the incident ticket. When the window closes and you return to normal auth/session policy, record that change as part of the incident's final closure.</p>"
                }
            ]
        },
        {
            "id": "AID-R-004",
            "name": "Post-Incident Hardening, Verification & Institutionalization",
            "pillar": "data, infra, model, app",
            "phase": "improvement",
            "description": "Following containment and recovery, convert the incident into durable security improvements. This includes: (1) producing a formal, version-controlled Post-Incident Review (PIR) that documents root cause and precise TTPs; (2) updating threat models and risk scores based on real evidence; (3) enforcing fixes through engineering tickets with measurable acceptance tests; (4) validating fixes via targeted security testing and storing proof; (5) updating policy-as-code, IaC modules, shared security libraries, and CI/CD lint rules so that the same class of failure cannot silently recur; and (6) generating auditable communication/notification artifacts for legal, compliance, and (if needed) customers without leaking exploit detail.",
            "toolsOpenSource": [
                "MITRE ATLAS Navigator (to map observed TTPs)",
                "AI red teaming / LLM security testing frameworks (garak, Counterfit, vigil-llm)",
                "Breach and Attack Simulation tooling / replay harnesses for AI systems",
                "Great Expectations / data quality validation suites for post-recovery data checks",
                "SIEM / log analytics platforms (ELK Stack, OpenSearch, Grafana Loki)",
                "MISP (Malware Information Sharing Platform) for sanitized TTP & IOC sharing",
                "Version control systems (Git, GitHub/GitLab) for PIR, threat model diffs, and evidence artifacts"
            ],
            "toolsCommercial": [
                "SOAR/SIEM platforms (Splunk, Microsoft Sentinel, Datadog) for correlation rules and automated paging",
                "BAS / adversarial simulation platforms for regression validation of fixes",
                "Enterprise MLOps / model registries (SageMaker, Vertex AI, Databricks) to tie incident timeline to model versions",
                "GRC / compliance platforms for audit tracking and regulatory notification evidence bundles",
                "Managed threat intelligence / ISAC-style sharing channels for sanitized TTP distribution"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "Reduces likelihood of repeat execution of previously successful techniques such as AML.T0020 Poison Training Data, AML.T0018 Manipulate AI Model, AML.T0031 Erode AI Model Integrity, by turning those observed TTPs into hardened controls, SIEM/SOAR detections, and regression tests.",
                        "Improves long-term resilience against Persistence (AML.T0017) and Valid Accounts abuse (AML.T0012) by forcing re-authentication policy updates and session hygiene to become standard practice after incidents."
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "L1 / L2 model manipulation and data poisoning attacks become part of automated regression tests and MLOps gating, reducing the chance of re-poisoning or model tampering on redeploy.",
                        "L6 Security & Compliance: creates auditable PIR artifacts, legal/regulatory notification bundles, and communication matrices so that future high-severity incidents can be handled consistently and provably."
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (lessons are codified into hardened input/output sanitizers and enforced via shared libraries and CI lint rules).",
                        "LLM02:2025 Sensitive Information Disclosure (post-incident rollout of mandatory PII redaction filters and corresponding SIEM alerts).",
                        "LLM04:2025 Data and Model Poisoning (threat model likelihood raised, regression tests added for data poisoning vectors).",
                        "LLM03:2025 Supply Chain (root-caused attacks on components/tooling are converted into policy-as-code hardening and artifact integrity verification steps)."
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack and ML10:2023 Model Poisoning: produces cleansed training pipelines, adds validation gates, and requires cryptographic integrity checks before redeployment.",
                        "ML06:2023 AI Supply Chain Attacks: forces codebase / IaC / dependency hardening and artifact signing to become default in future releases."
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Run a structured Post-Incident Review (PIR) / Root Cause Analysis (RCA) and store it as an auditable artifact in version control.",
                    "howTo": "<h5>Concept:</h5><p>The PIR is not just a meeting. It is a security artifact that documents the full exploit chain, exact TTPs, affected assets, detection gaps, and required remediation tasks. It must explicitly map which AIDEFEND techniques/subtechniques failed, were missing, or were insufficient.</p><h5>Create a Version-Controlled PIR Document</h5><pre><code># File: post_mortems/2025-06-08-Prompt-Injection.md\n\n## Post-Incident Review: Prompt Injection leading to PII Leakage\n- Incident ID: INC-2025-021\n- Date: 2025-06-08\n- Lead: @security_lead\n\n### 1. Timeline of Events\n10:00 UTC  Alert fired for anomalous output\n10:15 UTC  PII leakage confirmed; kill-switch (AID-I-005) activated\n10:30 UTC  Root cause linked to Base64+homoglyph prompt injection bypassing input validation\n11:00 UTC  Hardened input sanitizer (AID-H-002) deployed\n11:30 UTC  Service restored via controlled rollback (AID-R-001)\n\n### 2. Root Cause (5 Whys)\n1. Bot leaked PII due to malicious prompt injection.\n2. Injection bypassed naive keyword-based filter.\n3. Filter did not recursively decode Base64 or detect homoglyphs.\n4. No PII output scanning (AID-D-003) on this endpoint.\n5. Control was deprioritized.\n\n### 3. Control Mapping\n- Weak/missing controls:\n  - AID-H-002.001 (input sanitization)\n  - AID-D-003.002 (PII output redaction)\n  - AID-I-005 (automated kill-switch trigger not yet enforced)\n\n### 4. Required Follow-Ups (Engineering Tickets)\n- AISEC-123: Add recursive decode + homoglyph detection to sanitizer (Owner: @ml_infra, SLA: 7d)\n- AISEC-124: Enforce PII redaction in support bot responses (Owner: @ml_infra, SLA: 3d)\n- AISEC-125: Automate kill-switch trigger criteria in SOAR (Owner: @sec_eng, SLA: 14d)</code></pre><p><strong>Action:</strong> Every AI/ML security incident must produce a PIR file under version control. The PIR must: (1) capture the exploit chain and TTPs, (2) identify which AIDEFEND techniques/subtechniques need to be hardened or newly adopted, and (3) generate trackable remediation tasks with owners, SLAs, and acceptance tests.</p>"
                },
                {
                    "strategy": "Maintain a pre-approved, version-controlled incident communication and escalation matrix consumable by SOAR.",
                    "howTo": "<h5>Concept:</h5><p>Who gets notified, how fast, and with what structured data cannot be improvised. You maintain a machine-readable escalation/notification matrix that your SOAR or incident tooling can parse. It encodes severity levels, required stakeholders (CISO, ML Infra Lead, Legal, Privacy, Customer Trust), and whether regulatory/customer notice is required.</p><h5>Communication Matrix (YAML)</h5><pre><code># File: docs/incident_response/AI_COMMS_PLAN.yaml\nseverity_levels:\n  SEV-1:\n    notify:\n      - role: \"CISO\"\n      - role: \"AI Security Lead\"\n      - role: \"Legal Counsel\"\n      - role: \"Privacy Officer\"\n      - role: \"Public Status Page Owner\"\n    external_notice_required: true\n    regulatory_timer_start: true\n    customer_comm_channel: \"status_page,broadcast_email\"\n  SEV-2:\n    notify:\n      - role: \"CISO\"\n      - role: \"AI Security Lead\"\n      - role: \"Legal Counsel\"\n    external_notice_required: conditional\n    regulatory_timer_start: conditional\n  SEV-3:\n    notify:\n      - role: \"AI Security Lead\"\n    external_notice_required: false\n    regulatory_timer_start: false</code></pre><p><strong>Action:</strong> Store this matrix in version control. Your SOAR/IR runbooks should ingest it automatically to (a) page Legal/Privacy, (b) mark when regulatory clocks start, and (c) generate initial customer/regulator notification drafts. This makes escalation repeatable, auditable, and technically enforced instead of ad hoc email chains.</p>"
                },
                {
                    "strategy": "Produce two reports per incident: an internal forensic report (full TTP, hashes, affected assets) and an external/regulator-safe summary (impact + remediation, no exploit PoC).",
                    "howTo": "<h5>Concept:</h5><p>Internal teams need exact IOCs, exploited code paths, failed controls, and affected model/data artifacts. Regulators/customers need factual impact, mitigation status, and assurance — but not operational secrets or weaponizable exploit detail. Both are generated as structured artifacts tied to the incident ID.</p><h5>External / Regulator-Facing Summary Template</h5><pre><code>Title: Service Security Event on 2025-06-08\nImpact Window: 10:00–11:30 UTC\nSummary:\n  Our automated monitoring detected anomalous AI assistant responses.\n  We contained the issue and restored normal service.\nData Exposure:\n  We have no evidence of unauthorized account access.\nRemediation:\n  We deployed stricter input validation and additional output filtering.\n  We added continuous monitoring rules to detect similar attempts.\nNext Steps:\n  We are validating the fix in a controlled environment.\n</code></pre><p><strong>Action:</strong> Store (1) the internal forensic report in a restricted incident repo (including hashes of impacted model artifacts, dataset URIs, infra version IDs, SIEM gaps found); and (2) the sanitized summary as an immutable evidence item. This proves both due diligence and non-disclosure of exploit-enabling details.</p>"
                },
                {
                    "strategy": "Trigger regulatory / legal notification workflow when regulated data or protected jurisdictions are implicated, and generate an auditable evidence bundle.",
                    "howTo": "<h5>Concept:</h5><p>Certain incidents (PII leakage, PHI exposure, payment data misuse, biometric inference) start a legal reporting clock (e.g. 72 hours). You need a repeatable workflow. The workflow gathers data category, affected jurisdictions, timeline timestamps, and containment steps into a structured bundle for Legal/Privacy.</p><h5>Breach Triage Checklist</h5><pre><code># File: incident_response/breach_triage_checklist.md\n- [ ] Incident ID assigned, severity level set\n- [ ] Legal + Privacy paged via SOAR\n- [ ] Affected data classes enumerated (PII, PHI, payment, biometric)\n- [ ] User geography mapped (EU, CA, US-CA, etc.)\n- [ ] Regulatory notification matrix consulted\n- [ ] T0 timestamp (breach confirmed) recorded to start regulatory SLA clock\n- [ ] Evidence bundle started:\n      - forensic summary (timeline, root cause)\n      - impacted systems/datasets/model versions\n      - containment and hardening actions already executed</code></pre><p><strong>Action:</strong> Implement an automated step in the incident runbook that, upon classification as SEV-1 or any PII/PHI event, (1) pages Legal/Privacy, (2) records the clock start timestamp, and (3) assembles this evidence bundle. This turns regulatory response into an operational control instead of a last-minute scramble.</p>"
                },
                {
                    "strategy": "Update threat models, risk scoring, and AIDEFEND control prioritization based on real incident evidence, and commit those changes to version control.",
                    "howTo": "<h5>Concept:</h5><p>After an incident, theoretical threats become proven threats. You must raise their likelihood, update impact assessments, and link them to the incident's PIR. This also drives prioritization of which AIDEFEND techniques/subtechniques become mandatory (baseline vs advanced vs highly specialized) for specific services going forward.</p><h5>Threat Model Diff</h5><pre><code># File: docs/THREAT_MODEL.md (Git diff)\n### Component: User Prompt API Endpoint\n- Likelihood: Medium\n+ Likelihood: High  (Observed in INC-2025-021 via Base64+homoglyph prompt injection)\nImpact: High (PII disclosure vector identified)\nMitigations:\n  - AID-H-002.001 hardened to recursively decode and detect homoglyphs\n  - AID-D-003.002 PII redaction enforced pre-response\n  - SOAR kill-switch automation (AID-I-005) now mandatory for this service\nAudit:\n  - PIR: post_mortems/2025-06-08-Prompt-Injection.md\n  - Owner: @security_lead</code></pre><p><strong>Action:</strong> Every PIR must result in a Git commit to the threat model and risk metadata. The commit must reference the incident ID and explicitly adjust likelihood/impact. This creates an auditable chain from real-world exploit → updated risk model → mandated controls.</p>"
                },
                {
                    "strategy": "Translate PIR action items into enforceable engineering tickets with mapped AIDEFEND techniques, SLAs, owners, and machine-checkable acceptance tests.",
                    "howTo": "<h5>Concept:</h5><p>Root cause analysis only matters if it becomes enforced engineering work. Each PIR action item becomes an engineering ticket that (1) cites the AIDEFEND control it strengthens, (2) has an explicit SLA/owner, and (3) defines a measurable acceptance test (for example 'garak injection probes = 0', 'PII redaction must trigger on any phone number before response').</p><h5>Example Engineering Ticket</h5><pre><code># GitHub Issue\nTitle: Enforce PII Output Scanning on Support Bot (Ref: INC-2025-021)\nLabels: security, aidefend:AID-D-003.002, SLA:3d\nDescription:\n  Add PII detection/redaction to Support Bot response pipeline.\nAcceptance Criteria:\n  - Presidio-style PII scanner (AID-D-003.002) runs on all bot responses before sending output to user.\n  - Detected PII is replaced with placeholders (e.g. <PERSON>).\n  - SIEM alert rule created for 'PII detected pre-redaction'.\n  - garak-style prompt injection regression test shows 0 unredacted PII leaks in staging.\nOwner: @ml_infra\nDue: 2025-06-11</code></pre><p><strong>Action:</strong> No PIR is considered closed until each mandatory safeguard has a corresponding ticket with clear SLA, owner, mapped AIDEFEND technique/subtechnique, and objective acceptance tests. This makes remediation auditable and prevents silent deferral.</p>"
                },
                {
                    "strategy": "Perform targeted regression validation of fixes using AI-specific security testing and archive the results as evidence.",
                    "howTo": "<h5>Concept:</h5><p>After applying mitigations, you must prove they work. Replay attacker TTPs (prompt injection strings, model backdoor triggers, poisoned samples) against a staging copy. Record success/fail metrics and store them alongside the PIR.</p><h5>Targeted Regression Test Example</h5><pre><code># Run garak prompt-injection probes against the patched staging endpoint\npython -m garak --model_type test --model_name http://staging-ai-bot.local/v1/chat \\\n  --probes injection.all \\\n  --report output/INC-2025-021/garak_results.json\n\n# Expectation:\n#   - 0 successful prompt injection exploits\n#   - PII redaction triggered before response when sensitive entities are present\n\n# The resulting garak_results.json is stored under:\n# post_mortems/INC-2025-021/regression_tests/garak_results.json</code></pre><p><strong>Action:</strong> For each high-severity incident, run focused red-team style regression tests (prompt injection scanners, BAS scenarios, poisoning replay) in staging. Store the report (JSON, CSV, etc.) under the incident’s evidence directory. This becomes audit-grade proof that the fix is effective and continuously testable.</p>"
                },
                {
                    "strategy": "Institutionalize the lessons: update policy-as-code, shared security libraries, IaC modules, and CI/CD lint rules so that the fixed control becomes the new default.",
                    "howTo": "<h5>Concept:</h5><p>Instead of relying on 'tribal knowledge' or one-time slide decks, you permanently bake the defense into code. That means updating reusable Terraform modules, baseline Kubernetes policies, input sanitization libraries, output redaction middleware, and CI/CD lint rules so future services cannot ship without the new guardrail.</p><h5>Example: Hardened Shared Sanitizer Library</h5><pre><code># File: libs/security/input_sanitizer.py  (updated post-incident)\n\ndef sanitize_user_prompt(raw_input: str) -> str:\n    # 1. Recursively decode Base64 layers\n    # 2. Detect homoglyph / mixed-script anomalies\n    # 3. Block tool-escalation or data-exfil instructions\n    # Returns a cleaned/safe prompt required by all AI-facing services\n    pass\n\n# Enforced via CI:\n# - Lint rule fails build if a public AI endpoint does NOT call sanitize_user_prompt()\n# - Terraform/Kubernetes baseline modules require output PII redaction middleware for certain services</code></pre><p><strong>Action:</strong> After each major AI security incident, update shared libraries, IaC baselines, runtime policies, and CI/CD enforcement rules to require the new mitigation. This turns one incident’s lesson into an organization-wide default hardening control, preventing silent regression in future services.</p>"
                },
                {
                    "strategy": "Share sanitized TTPs and mitigations with trusted intelligence channels (e.g. ISAC, MISP) without exposing proprietary details.",
                    "howTo": "<h5>Concept:</h5><p>If the attacker used a novel AI/LLM-specific TTP (for example, multi-layer Base64 + homoglyph prompt injection to force data exfil), you should publish a sanitized version of that TTP to trusted sharing communities. This strengthens collective defense and accelerates ecosystem-level detection rules.</p><h5>Sanitized TTP Package</h5><pre><code># Title: Nested Base64 + Homoglyph Prompt Injection for Instruction Override\nObserved Behavior:\n  1. Attacker encodes malicious instructions using homoglyph substitutions.\n  2. Payload is Base64-encoded multiple times.\n  3. LLM is instructed to decode and execute that payload.\nMitigation Highlights:\n  - Recursive decode and homoglyph detection in input sanitizer (AID-H-002.001)\n  - Mandatory PII redaction of model output (AID-D-003.002)\n  - Automated kill-switch trigger (AID-I-005)\nShared Indicators (sanitized):\n  - Structural patterns (multi-layer Base64 + mixed-script charsets)\n  - Behavioral signature (LLM asked to self-decode and obey decoded payload)</code></pre><p><strong>Action:</strong> Produce a sanitized TTP/IOC summary that (1) does not mention internal system names, bucket names, model version strings, etc., but (2) clearly explains the attacker’s technique and the high-level mitigations. Share via MISP / ISAC / vetted industry channels. This helps defenders elsewhere add similar detections and guardrails, and it documents that your org contributed to collective defense.</p>"
                }
            ]
        },
        {
            "id": "AID-R-005",
            "name": "Rapid Vector Index Rollback & Quarantine",
            "pillar": "data",
            "phase": "improvement",
            "description": "Provide fast, controlled recovery for Retrieval-Augmented Generation (RAG) pipelines after index poisoning or malicious content injection is detected. The vector index is treated as an immutable, versioned artifact. Recovery happens in three stages: (1) atomically roll back to a last known-good snapshot, (2) quarantine and preserve suspicious chunks for forensics while removing them from production retrieval, and (3) rebuild and re-promote a clean index that enforces provenance, policy, and security approvals. Goal: restore trustworthy retrieval quality quickly while preventing re-serving tainted data.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0070 RAG Poisoning (malicious or manipulative content injected into the retrieval corpus)",
                        "AML.T0059 Erode Dataset Integrity (attacker alters knowledge base quality/accuracy to steer model behavior)",
                        "AML.T0025 Exfiltration via Cyber Means (attacker plants prompts/instructions that coerce the model to leak internal secrets)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Compromised RAG Pipelines (L2, untrusted or adversarial retrieval context fed to the model/agent)",
                        "Data Poisoning (L2, subversion of the retrieval knowledge source to mislead downstream reasoning)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM08:2025 Vector and Embedding Weaknesses (poisoned or weaponized embeddings/chunks inside the vector DB)",
                        "LLM04:2025 Data and Model Poisoning (index corruption that influences model behavior through retrieval context)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack (insertion of polluted or malicious data into training/evaluation/retrieval stores)"
                    ]
                }
            ],
            "implementationStrategies": [
                {
                    "strategy": "Use immutable versioned indices and an alias/pointer for atomic cutover and rollback.",
                    "ownerTeamHint": "AI platform / RAG infrastructure / search relevance",
                    "howTo": "<h5>Concept:</h5><p>Never serve traffic directly from a mutable 'live' index. Each ingest/build produces a new immutable index (e.g. <code>rag_index_v42</code>). Production queries always go through an alias (e.g. <code>rag_prod</code>). Promotion = repoint alias to the new version. Rollback = repoint alias back to the last known-good version. This makes rollback a single atomic operation and avoids serving poisoned content.</p><h5>Example (OpenSearch / Elasticsearch style):</h5><pre><code># Create new versioned index and bulk-ingest embeddings/chunks\nPUT rag_index_v42\n{ \"settings\": { ... }, \"mappings\": { ... } }\n\n# After validation succeeds, atomically repoint prod alias\nPOST _aliases\n{\n  \"actions\": [\n    { \"remove\": { \"alias\": \"rag_prod\", \"index\": \"rag_index_v41\" }},\n    { \"add\":    { \"alias\": \"rag_prod\", \"index\": \"rag_index_v42\" }}\n  ]\n}\n\n# Emergency rollback = same alias swap back to rag_index_v41.</code></pre><p><h5>Integrity manifest:</h5><p>For each index version, generate a signed manifest that records:</p><ul><li>index_version (e.g. <code>rag_index_v42</code>)</li><li>timestamp built</li><li>embedding_model_sha256</li><li>per-chunk SHA-256 and source_uri</li><li>approver / promotion request ID</li><li>cryptographic signature (Sigstore / cosign / GPG)</li></ul><p>This manifest proves which snapshot is trusted. Only versions with a valid manifest are allowed to become <code>rag_prod</code>.</p>"
                },
                {
                    "strategy": "Quarantine and preserve suspicious chunks before removal from production retrieval.",
                    "ownerTeamHint": "AI security / IR (incident response) with RAG platform support",
                    "howTo": "<h5>Concept:</h5><p>When detection rules flag malicious or policy-violating chunks (exfil instructions, jailbreak scaffolding, disinformation, self-modifying tool calls, etc.), you must immediately remove those chunks from the active index so they cannot be retrieved — but you cannot discard evidence. You export the chunk plus full provenance into an immutable forensic/quarantine store, then delete it from the production index.</p><h5>Example (Qdrant-style pseudo-code):</h5><pre><code># Step 1: enumerate suspect points from current prod index version\nsuspect_points = qdrant_client.scroll(\n    collection_name=\"rag_index_v42\",\n    scroll_filter={\"must\": [{\"key\": \"suspicious_flag\", \"match\": {\"value\": true}}]}\n)\n\n# Step 2: persist all flagged chunks + metadata into quarantine store\nfor p in suspect_points:\n    forensic_record = {\n        \"point_id\": p.id,\n        \"vector_sha256\": sha256(p.vector),\n        \"source_uri\": p.payload[\"source_uri\"],\n        \"ingested_at\": p.payload[\"ingested_at\"],\n        \"reason_flagged\": p.payload[\"reason_flagged\"],\n        \"submitter_user_id\": p.payload.get(\"submitter_user_id\"),\n        \"submitter_ip\": p.payload.get(\"submitter_ip\"),\n        \"extracted_text\": p.payload[\"text\"]\n    }\n    write_to_quarantine_store(forensic_record)  # e.g. S3 bucket with Object Lock/WORM\n\n# Step 3: delete from prod index so it cannot be retrieved again\nqdrant_client.delete(\n    collection_name=\"rag_index_v42\",\n    points_selector=[p.id]\n)</code></pre><p><h5>Enrichment / triage:</h5><p>Store enrichment fields with each quarantined chunk, such as:</p><ul><li><code>matched_rule</code> (which detector fired)</li><li><code>similarity_to_known_bad</code> (cosine sim to known malicious payloads)</li><li><code>policy_scan_pass</code> / <code>policy_scan_fail_reason</code></li><li>embedding model ID used</li></ul><p>That gives incident responders enough signal to do attribution, feed PIR / RCA (<code>AID-R-004</code>), and improve upstream ingestion policy.</p>"
                },
                {
                    "strategy": "Rebuild a clean candidate index from trusted sources with provenance, policy scanning, and approval gating before promotion.",
                    "ownerTeamHint": "RAG infrastructure / AI platform with AI security approval",
                    "howTo": "<h5>Concept:</h5><p>After rollback, you're running on an older snapshot. You still need a new 'good' index to go forward. That rebuild pipeline must enforce provenance and content policy before anything is eligible for production. Steps:</p><ol><li>Enumerate only allowlisted sources (approved repos, curated knowledge base, compliance-approved docs).</li><li>Verify each document's hash matches an expected value or signed attestation. Reject modified or unverified sources.</li><li>Run automated content/policy scans to block high-risk chunks (PII leakage, self-referential jailbreak instructions, 'ignore safety and do X', 'dump secrets', etc.).</li><li>Embed and index only the chunks that pass.</li><li>Generate a new manifest (index_version, per-chunk hash, scan results, embedding model hash, build timestamp).</li><li>Open a change request that requires explicit AI security / platform security approval before alias cutover.</li></ol><h5>Example (conceptual pipeline snippet):</h5><pre><code># Pseudocode for secure rebuild\nfor doc in approved_content_inventory:\n    if !verify_source_hash(doc):\n        continue  # reject untrusted/altered sources\n    if !passes_policy_scan(doc):\n        continue  # reject exfil/jailbreak/secret-leak patterns\n\n    embedding = embed(doc.text, model=\"text-embedding-3-large\")\n    record = {\n        \"vector\": embedding,\n        \"text\": doc.text,\n        \"source_uri\": doc.uri,\n        \"provenance_hash\": doc.sha256,\n        \"ingested_at\": now(),\n        \"policy_scan_pass\": true\n    }\n    add_to_index_build(\"rag_index_v43_candidate\", record)\n\n# produce signed manifest, then request security approval to promote\ncreate_change_request(\n    candidate_index=\"rag_index_v43_candidate\",\n    risk_summary=\"all quarantined content excluded; policy scans passed\",\n    approver_role=\"AI_Security_Oncall\"\n)</code></pre><p><h5>Promotion control / auditability:</h5><p>The alias (e.g. <code>rag_prod</code>) must <strong>not</strong> point to the new index until AI Security (or equivalent risk owner) signs off. That approval event, plus the manifest signature, becomes auditable evidence of due diligence. This mirrors model rollback / restore controls in <code>AID-R-001</code>.</p>"
                },
                {
                    "strategy": "Continuously monitor retrieval context for high-risk patterns and auto-trigger rollback/quarantine.",
                    "ownerTeamHint": "Detection & Response / SOC / AI Security",
                    "howTo": "<h5>Concept:</h5><p>Recovery only works if you know you’re poisoned. Add runtime detectors that watch the <em>retrieved context chunks</em> (not just final LLM answer) for indicators such as:</p><ul><li>Explicit instructions to bypass safety policies (\"ignore previous rules\", \"return secrets\").</li><li>Credential-like strings (API keys, tokens, secrets).</li><li>High similarity to previously quarantined malicious payloads.</li><li>Adversarial prompt scaffolding that forces tool invocation or data exfil.</li></ul><p>When a detector fires above threshold, trigger an automatic workflow:<br>1. mark the current index version as tainted in its manifest,<br>2. quarantine those chunks (see previous strategy),<br>3. cut the alias back to last known-good snapshot immediately.</p><p>These detectors can run in the retrieval layer or as middleware in the agent pipeline before the LLM sees the context. This reduces time-to-containment for RAG poisoning attacks from hours to seconds.</p>"
                }
            ],
            "toolsOpenSource": [
                "Qdrant (collections, scroll/delete)",
                "Milvus / FAISS (vector storage, offline rebuild and re-ingest)",
                "OpenSearch / Elasticsearch (index aliases for atomic cutover)",
                "Great Expectations or custom content/policy scanners for pre-ingest validation",
                "Sigstore / cosign / GPG for signed manifests and change approval evidence",
                "sha256sum for per-chunk integrity tracking"
            ],
            "toolsCommercial": [
                "Pinecone (namespaces / collection versions / delete-by-ID)",
                "Weaviate Enterprise (schema hooks, metadata policies, ACLs)",
                "Amazon OpenSearch Service (managed aliases, snapshots)",
                "Datadog / Splunk / Microsoft Sentinel for retrieval anomaly alerting and correlation",
                "Cloud object storage with Object Lock / WORM mode for forensic quarantine (e.g. S3 Object Lock)"
            ]
        }

    ]
};