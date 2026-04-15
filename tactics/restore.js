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
                        "AML.T0018 Manipulate AI Model",
                        "AML.T0019 Publish Poisoned Datasets",
                        "AML.T0020 Poison Training Data",
                        "AML.T0031 Erode AI Model Integrity",
                        "AML.T0058 Publish Poisoned Models",
                        "AML.T0076 Corrupt AI Model",
                        "AML.T0043.004 Craft Adversarial Data: Insert Backdoor Trigger (restoration removes backdoor triggers from training pipeline)",
                        "AML.T0010 AI Supply Chain Compromise (restoration recovers from supply chain compromise)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Backdoor Attacks (L1)",
                        "Data Poisoning (Training Phase) (L1)",
                        "Data Poisoning (L2)",
                        "Supply Chain Attacks (L3)",
                        "Compromised Container Images (L4) (restoration deploys from verified, pre-incident container images)",
                        "Supply Chain Attacks (Cross-Layer)"
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
                        "ML02:2023 Data Poisoning Attack",
                        "ML06:2023 AI Supply Chain Attacks (restoring from trusted backups undoes supply chain compromise)",
                        "ML07:2023 Transfer Learning Attack (restoring pre-compromise model reverses transfer learning attacks)",
                        "ML10:2023 Model Poisoning"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI04:2026 Agentic Supply Chain Vulnerabilities"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.011 Model Poisoning (Availability)",
                        "NISTAML.013 Data Poisoning",
                        "NISTAML.023 Backdoor Poisoning",
                        "NISTAML.024 Targeted Poisoning",
                        "NISTAML.026 Model Poisoning (Integrity)",
                        "NISTAML.051 Model Poisoning (Supply Chain)",
                        "NISTAML.012 Clean-label Poisoning (restoration removes clean-label poisoned data)",
                        "NISTAML.021 Clean-label Backdoor (restoration removes clean-label backdoors)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-6.1 Training Data Poisoning",
                        "AITech-7.1 Reasoning Corruption",
                        "AITech-7.2 Memory System Corruption",
                        "AITech-9.1 Model or Agentic System Manipulation",
                        "AITech-9.2 Detection Evasion (restoring known-good model removes evasion-enabling modifications)",
                        "AITech-9.3 Dependency / Plugin Compromise (verified rollback restores trusted dependency stack)",
                        "AISubtech-9.2.2 Backdoors and Trojans (restoration removes backdoors from compromised models)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "DP: Data Poisoning (restoration recovers from data poisoning effects on model behavior)",
                        "MST: Model Source Tampering (restoration reverts to pre-tampering model state)",
                        "MDT: Model Deployment Tampering (restoration redeploys verified pre-incident model and serving stack)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Datasets 3.1: Data poisoning (restoration recovers from data poisoning effects on model)",
                        "Model 7.1: Backdoor machine learning / Trojaned model (restoration reverts to pre-backdoor model)",
                        "Model 7.3: ML Supply chain vulnerabilities (restoration recovers from supply chain compromise)",
                        "Model 7.4: Source code control attack (restoration reverts to pre-tampering model code)"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-R-001.001",
                    "name": "Versioned Model Rollback & Restoration", "pillar": ["model"], "phase": ["improvement"],
                    "description": "Restores a compromised AI model to a known-good state by deploying a trusted, previously saved version from a secure artifact repository or model registry. This technique is the primary recovery method when a deployed model artifact has been tampered with post-deployment or when an incident requires reverting to the last known-secure version. It relies on maintaining immutable, versioned, and verifiable backups of all production models.",
                    "implementationGuidance": [
                        {
                            "implementation": "Maintain immutable, versioned backups of all production model artifacts with recorded hashes and attestations.",
                            "howTo": "<h5>Concept:</h5><p>You cannot restore what you cannot trust. Every model promoted to production must be snapshotted into an append-only / versioned / access-restricted backup location (e.g. an S3 bucket with Object Versioning and Object Lock, writeable only by CI/CD). For each snapshot you must store: (1) the model artifact, (2) its cryptographic hash, (3) its build/signing attestation (supply-chain provenance), and (4) deployment metadata (who approved promotion).</p><h5>Configure a Versioned Backup Store</h5><p>Use Infrastructure as Code to provision a dedicated bucket with versioning enabled. Enable policies so runtime services cannot retroactively overwrite past versions.</p><pre><code># File: infrastructure/model_backups.tf (Terraform)\n\nresource \"aws_s3_bucket\" \"model_backups\" {\n  bucket = \"aidefend-prod-model-backups\"\n}\n\nresource \"aws_s3_bucket_versioning\" \"model_backups_versioning\" {\n  bucket = aws_s3_bucket.model_backups.id\n  versioning_configuration {\n    status = \"Enabled\"\n  }\n}\n\n# (Recommended) Also configure Object Lock / retention to prevent tampering.\n</code></pre><p><strong>Action:</strong> As the final step of each production promotion pipeline, push the model artifact into this versioned store, record its SHA-256 (and, if available, its cryptographic signature / attestation) in the model registry, and mark it as restore-capable.</p>"
                        },
                        {
                            "implementation": "Run an audited rollback procedure to identify the last known-good model version, verify its integrity, and redeploy the trusted model and serving stack.",
                            "howTo": `<h5>Concept:</h5><p>Rollback is one operational runbook, not three independent controls. The recovery team must identify the last known-good model version, cryptographically verify the backup artifact, and redeploy the trusted model together with a verified serving image or runtime package through one audited workflow.</p><h5>Step 1: Identify the last known-good model version</h5><pre><code># File: restore/find_good_version.py
import sys
from mlflow.tracking import MlflowClient

MODEL_NAME = "My-Production-Model"
INCIDENT_START_TIMESTAMP = 1711900800000

client = MlflowClient()
versions = client.search_model_versions(f"name='{MODEL_NAME}'")

known_good_version = None
for version in sorted(versions, key=lambda item: item.creation_timestamp, reverse=True):
    if (
        version.creation_timestamp < INCIDENT_START_TIMESTAMP
        and version.tags.get("security_status") == "clean"
        and "sha256_hash" in version.tags
    ):
        known_good_version = version
        break

if not known_good_version:
    print("ERROR: No trusted pre-incident version found!")
    sys.exit(1)

print(f"Last known-good version: {known_good_version.version}")
print(f"Expected hash: {known_good_version.tags['sha256_hash']}")</code></pre><h5>Step 2: Verify the artifact before deployment</h5><pre><code># File: restore/verify_artifact.py
import hashlib
import sys
from mlflow.tracking import MlflowClient


def get_sha256_hash(filepath: str) -> str:
    digest = hashlib.sha256()
    with open(filepath, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()

client = MlflowClient()
version = client.get_model_version("My-Production-Model", "3")
authorized_hash = version.tags.get("sha256_hash")

if not authorized_hash:
    print("ERROR: trusted hash missing")
    sys.exit(1)

local_path = client.download_artifacts(version.run_id, "model")
artifact_file = local_path + "/model.pkl"
actual_hash = get_sha256_hash(artifact_file)

if actual_hash != authorized_hash:
    print("CRITICAL: Hash mismatch")
    sys.exit(1)

print("Backup integrity verified")</code></pre><h5>Step 3: Redeploy the trusted model and serving stack through a controlled workflow</h5><pre><code># File: .github/workflows/rollback_production_model.yml
name: Rollback Production Model

on:
  workflow_dispatch:
    inputs:
      model_name:
        required: true
      version_to_restore:
        required: true
      serving_image_digest:
        required: true

jobs:
  rollback:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify artifact integrity
        run: python restore/verify_artifact.py
      - name: Deploy known-good stack
        run: |
          ./deploy_inference_service.sh \
            --model_version \${{ github.event.inputs.version_to_restore }} \
            --image_digest \${{ github.event.inputs.serving_image_digest }}</code></pre><p><strong>Action:</strong> Treat the registry query, artifact-verification log, and rollback workflow run as one evidence bundle for this guidance. Rollback is complete only when the trusted model <em>and</em> its serving runtime are restored together through the audited runbook.</p>`
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
                                "AML.T0058 Publish Poisoned Models",
                                "AML.T0076 Corrupt AI Model",
                                "AML.T0031 Erode AI Model Integrity (rollback restores model integrity)",
                                "AML.T0020 Poison Training Data (rollback reverts to pre-poisoning model)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Backdoor Attacks (L1)",
                                "Supply Chain Attacks (L3)",
                                "Compromised Container Images (L4)",
                                "Supply Chain Attacks (Cross-Layer)",
                                "Data Poisoning (Training Phase) (L1) (rollback reverts to pre-poisoning checkpoint)"
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
                                "ML06:2023 AI Supply Chain Attacks (rollback to pre-compromise version removes supply chain artifacts)",
                                "ML07:2023 Transfer Learning Attack (rollback reverses effects of compromised transfer learning)",
                                "ML10:2023 Model Poisoning",
                                "ML02:2023 Data Poisoning Attack (rollback reverts to pre-poisoning model)"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.011 Model Poisoning (Availability)",
                                "NISTAML.023 Backdoor Poisoning",
                                "NISTAML.026 Model Poisoning (Integrity)",
                                "NISTAML.051 Model Poisoning (Supply Chain)",
                                "NISTAML.013 Data Poisoning (rollback restores model to pre-poisoning state)",
                                "NISTAML.024 Targeted Poisoning (rollback reverts targeted poisoning effects)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-9.1 Model or Agentic System Manipulation",
                                "AITech-9.2 Detection Evasion",
                                "AITech-9.3 Dependency / Plugin Compromise",
                                "AITech-6.1 Training Data Poisoning (rollback reverts poisoning effects)",
                                "AISubtech-9.2.2 Backdoors and Trojans (rollback restores to pre-backdoor checkpoint)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "DP: Data Poisoning (rollback reverts model to pre-poisoning state)",
                                "MST: Model Source Tampering (rollback restores pre-tampering model artifact with integrity verification)",
                                "MDT: Model Deployment Tampering (rollback redeploys trusted serving stack from verified backup)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Model 7.1: Backdoor machine learning / Trojaned model (rollback restores pre-backdoor model version)",
                                "Model 7.3: ML Supply chain vulnerabilities (rollback to pre-compromise version removes supply chain artifacts)",
                                "Datasets 3.1: Data poisoning (rollback reverts to model trained on clean data)"
                            ]
                        }
                    ]
                },
                {
                    "id": "AID-R-001.002",
                    "name": "Model Retraining for Remediation", "pillar": ["model"], "phase": ["improvement"],
                    "description": "This sub-technique covers restoration when the compromised model cannot simply be rolled back to a trusted prior version. It focuses on building sanitized recovery-training inputs, launching a fresh retraining or recovery-learning workflow, and proving the remediated model is safe enough to return to service.",
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
                                "AML.T0018 Manipulate AI Model",
                                "AML.T0019 Publish Poisoned Datasets",
                                "AML.T0020 Poison Training Data",
                                "AML.T0059 Erode Dataset Integrity",
                                "AML.T0031 Erode AI Model Integrity (retraining restores model integrity)",
                                "AML.T0043.004 Craft Adversarial Data: Insert Backdoor Trigger (retraining on clean data removes backdoor triggers)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Backdoor Attacks (L1)",
                                "Data Poisoning (Training Phase) (L1)",
                                "Data Poisoning (L2)",
                                "Compromised RAG Pipelines (L2) (retraining on clean data fixes models trained on poisoned RAG outputs)"
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
                                "ML10:2023 Model Poisoning",
                                "ML07:2023 Transfer Learning Attack (retraining on verified base removes transfer attack vectors)"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.012 Clean-label Poisoning",
                                "NISTAML.013 Data Poisoning",
                                "NISTAML.021 Clean-label Backdoor",
                                "NISTAML.023 Backdoor Poisoning",
                                "NISTAML.024 Targeted Poisoning",
                                "NISTAML.026 Model Poisoning (Integrity)",
                                "NISTAML.011 Model Poisoning (Availability) (retraining restores model availability)",
                                "NISTAML.051 Model Poisoning (Supply Chain) (retraining from verified sources remediates supply chain poisoning)",
                                "NISTAML.037 Training Data Attacks"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-6.1 Training Data Poisoning",
                                "AITech-7.1 Reasoning Corruption",
                                "AITech-9.1 Model or Agentic System Manipulation",
                                "AITech-9.2 Detection Evasion",
                                "AISubtech-9.2.2 Backdoors and Trojans (retraining on clean data removes backdoors)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "DP: Data Poisoning (retraining on sanitized data eliminates poisoning effects)",
                                "UTD: Unauthorized Training Data (retraining ensures only authorized data is used)",
                                "MST: Model Source Tampering (fresh retraining from verified code eliminates source tampering)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Datasets 3.1: Data poisoning (retraining on clean data eliminates poisoned samples)",
                                "Datasets 3.3: Label flipping (retraining removes label-flipped data from training process)",
                                "Model 7.1: Backdoor machine learning / Trojaned model (retraining from scratch removes embedded backdoors)",
                                "Raw Data 1.7: Lack of data trustworthiness (retraining on verified data restores trustworthiness)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Retrain from sanitized recovery inputs by first removing compromised training artifacts and then launching a fresh, isolated recovery-training job.",
                            "howTo": `<h5>Concept:</h5><p>For retraining-led recovery, dataset cleansing and fresh retraining form one operational unit. The recovery team first prepares a sanitized training input set that excludes the malicious influence, then launches a new training run from fresh weights in a hardened environment. Count this as one guidance because neither half has recovery value without the other.</p><h5>Step 1: Produce a sanitized recovery-training input set</h5><p>Select the cleansing variant that matches the affected training substrate, and preserve the exact removal manifest as incident evidence.</p><pre><code># File: remediation/prepare_retraining_inputs.py
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import networkx as nx
from networkx.readwrite import json_graph


def cleanse_tabular_dataset(dataset_path: str, removal_manifest_path: str, output_path: str) -> dict:
    df = pd.read_csv(dataset_path)
    manifest = json.loads(Path(removal_manifest_path).read_text(encoding="utf-8"))
    remove_rows = manifest["remove_row_ids"]
    cleansed = df[~df["row_id"].isin(remove_rows)].copy()
    cleansed.to_csv(output_path, index=False)
    return {"removed_rows": len(remove_rows), "output_path": output_path}


def cleanse_graph_dataset(graph_path: str, removal_manifest_path: str, output_path: str) -> dict:
    graph_payload = json.loads(Path(graph_path).read_text(encoding="utf-8"))
    graph = json_graph.node_link_graph(graph_payload)
    manifest = json.loads(Path(removal_manifest_path).read_text(encoding="utf-8"))
    graph.remove_nodes_from(manifest.get("remove_nodes", []))
    graph.remove_edges_from([tuple(edge) for edge in manifest.get("remove_edges", [])])
    Path(output_path).write_text(
        json.dumps(json_graph.node_link_data(graph), indent=2),
        encoding="utf-8",
    )
    return {
        "removed_nodes": len(manifest.get("remove_nodes", [])),
        "removed_edges": len(manifest.get("remove_edges", [])),
        "output_path": output_path,
    }


def filter_federated_clients(update_records: list[dict], blocked_client_ids: list[str]) -> list[dict]:
    blocked = set(blocked_client_ids)
    return [record for record in update_records if record["client_id"] not in blocked]</code></pre><p><strong>Variant notes:</strong> Use the row-level removal path when the incident output comes from <code>AID-E-003.002</code>, the graph-removal path when the incident produced a graph-manifest from <code>AID-E-003.004</code>, and the federated exclusion path when the malicious influence came from compromised client updates.</p><h5>Step 2: Launch a fresh recovery-training run</h5><pre><code># File: remediation/run_recovery_retraining.sh
#!/usr/bin/env bash
set -euo pipefail

SANITIZED_DATASET_URI="$1"
MODEL_NAME="$2"
TRAINING_IMAGE_DIGEST="$3"

./trigger_training_pipeline.sh \
  --dataset_uri "\${SANITIZED_DATASET_URI}" \
  --model_name "\${MODEL_NAME}" \
  --training_image_digest "\${TRAINING_IMAGE_DIGEST}" \
  --start_from_fresh_weights true \
  --incident_mode recovery</code></pre><p><strong>Action:</strong> Treat the sanitized input manifest, the hardened training-run record, and the resulting remediated model version as one evidence bundle. Recovery retraining is not complete until the malicious input has been excluded <em>and</em> a fresh model has been produced from that sanitized input set.</p>`
                        },
                        {
                            "implementation": "Apply approximate unlearning for Federated Learning or large-scale distributed models when full retraining is prohibitively expensive.",
                            "howTo": `<h5>Concept:</h5><p>Approximate unlearning is a speed-vs-assurance tradeoff for distributed or federated recovery. Instead of retraining the global model from scratch, you estimate the malicious clients' net contribution, apply an equal-and-opposite rollback update, and then fine-tune on trusted data. This should be treated as a controlled recovery step with explicit validation, not as a silent substitute for full retraining.</p><h5>Step 1: Aggregate the malicious client deltas into one rollback update</h5><pre><code># File: remediation/approximate_unlearning.py
from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

import torch


StateDelta = OrderedDict[str, torch.Tensor]


def average_state_deltas(deltas: Iterable[StateDelta]) -&gt; StateDelta:
    deltas = list(deltas)
    if not deltas:
        raise ValueError("at least one malicious delta is required")

    aggregate = OrderedDict(
        (name, torch.zeros_like(tensor))
        for name, tensor in deltas[0].items()
    )

    for delta in deltas:
        for name, tensor in delta.items():
            aggregate[name] += tensor

    for name in aggregate:
        aggregate[name] /= len(deltas)

    return aggregate
</code></pre><h5>Step 2: Apply the rollback update to the compromised global model</h5><p>Subtract the averaged malicious contribution from the model weights under a no-grad context. Keep the rollback scale explicit and record it in the recovery evidence so reviewers can see how much influence was removed.</p><pre><code># File: remediation/approximate_unlearning.py
def apply_rollback_update(
    model: torch.nn.Module,
    malicious_deltas: Iterable[StateDelta],
    rollback_scale: float = 1.0,
) -&gt; torch.nn.Module:
    rollback_delta = average_state_deltas(malicious_deltas)
    state_dict = model.state_dict()

    with torch.no_grad():
        for name, param in state_dict.items():
            state_dict[name].copy_(param - rollback_scale * rollback_delta[name].to(param.device))

    model.load_state_dict(state_dict)
    return model
</code></pre><h5>Step 3: Fine-tune immediately on trusted post-incident data</h5><p>The rollback step alone rarely restores clean utility. Continue with a short recovery fine-tune using only trusted client updates or a clean server-side recovery dataset so the model re-stabilizes after the subtraction.</p><pre><code># File: remediation/recovery_finetune.py
from __future__ import annotations

import torch


def run_recovery_finetune(model, train_loader, device="cuda", epochs=1, lr=1e-5):
    model.to(device)
    model.train()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr)
    loss_fn = torch.nn.CrossEntropyLoss()

    for _ in range(epochs):
        for batch in train_loader:
            inputs = batch["input_ids"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad(set_to_none=True)
            logits = model(inputs)
            loss = loss_fn(logits, labels)
            loss.backward()
            optimizer.step()

    return model
</code></pre><h5>Step 4: Verify that the approximate remediation actually reduced the attack</h5><p>Measure both clean-task performance and attack success after the rollback. If the malicious behavior remains above the accepted threshold, stop and escalate to a full retraining workflow.</p><pre><code># File: remediation/verify_approximate_unlearning.py
def verify_recovery(clean_accuracy: float, attack_success_rate: float) -&gt; None:
    if clean_accuracy &lt; 0.85:
        raise SystemExit("approximate unlearning failed: clean quality below release threshold")
    if attack_success_rate &gt; 0.05:
        raise SystemExit("approximate unlearning failed: residual malicious behavior too high")

    print("Approximate unlearning passed release thresholds")
</code></pre><p><strong>Action:</strong> Use approximate unlearning only when speed matters and full retraining is temporarily impractical. Record the blocked client IDs, rollback scale, clean recovery dataset hash, and post-remediation validation metrics as formal recovery evidence.</p>`
                        },
                        {
                            "implementation": "Run a post-remediation validation suite to prove the new model is both safe and still useful.",
                            "howTo": "<h5>Concept:</h5><p>The final gate before redeployment is validation. You must show (1) normal functionality did not collapse, and (2) the exploit that triggered remediation is actually neutralized. This proof becomes part of the incident closure record and should be attached back to the model registry entry for the remediated version.</p><h5>Evaluate clean performance and attack resistance in one runnable gate</h5><pre><code># File: remediation/validate_retraining.py\nfrom __future__ import annotations\n\nimport json\nfrom pathlib import Path\n\nimport pandas as pd\n\nCLEAN_MIN_ACCURACY = 0.94\nMAX_ATTACK_SUCCESS_RATE = 0.05\n\nCLEAN_EVAL_PATH = Path(\"artifacts/eval/clean_predictions.csv\")\nATTACK_EVAL_PATH = Path(\"artifacts/eval/attack_results.csv\")\nOUTPUT_PATH = Path(\"artifacts/eval/remediation_validation.json\")\n\n\ndef require_columns(df: pd.DataFrame, required: set[str], path: Path) -> None:\n    missing = sorted(required - set(df.columns))\n    if missing:\n        raise ValueError(f\"{path} missing columns: {missing}\")\n\n\nclean_df = pd.read_csv(CLEAN_EVAL_PATH)\nattack_df = pd.read_csv(ATTACK_EVAL_PATH)\n\nrequire_columns(clean_df, {\"sample_id\", \"label\", \"predicted_label\"}, CLEAN_EVAL_PATH)\nrequire_columns(attack_df, {\"attack_case_id\", \"attack_success\"}, ATTACK_EVAL_PATH)\n\nclean_accuracy = float((clean_df[\"label\"] == clean_df[\"predicted_label\"]).mean())\nattack_success_rate = float(attack_df[\"attack_success\"].astype(bool).mean())\n\nreport = {\n    \"clean_accuracy\": clean_accuracy,\n    \"clean_min_accuracy\": CLEAN_MIN_ACCURACY,\n    \"attack_success_rate\": attack_success_rate,\n    \"max_attack_success_rate\": MAX_ATTACK_SUCCESS_RATE,\n    \"validation_passed\": (\n        clean_accuracy &gt;= CLEAN_MIN_ACCURACY\n        and attack_success_rate &lt;= MAX_ATTACK_SUCCESS_RATE\n    ),\n    \"clean_rows_evaluated\": int(len(clean_df)),\n    \"attack_cases_evaluated\": int(len(attack_df)),\n}\n\nOUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)\nOUTPUT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True), encoding=\"utf-8\")\n\nif not report[\"validation_passed\"]:\n    raise SystemExit(\n        \"Remediated model failed release gate: \"\n        f\"clean_accuracy={clean_accuracy:.4f}, attack_success_rate={attack_success_rate:.4f}\"\n    )\n\nprint(\n    \"✅ remediation verified: \"\n    f\"clean_accuracy={clean_accuracy:.4f}, attack_success_rate={attack_success_rate:.4f}\"\n)</code></pre><p><strong>Action:</strong> Promotion of the remediated model to production must be blocked unless: (a) it meets acceptable quality on clean evaluation data, and (b) the attack success rate (e.g., backdoor trigger activation, poisoned behavior) is driven down to an agreed threshold. Store the generated validation report, dataset hashes, and model version IDs in the incident ticket and in the model registry as formal recovery evidence.</p>"
                        }
                    ]
                }

            ]
        },
        {
            "id": "AID-R-002",
            "name": "Data Integrity Recovery for AI Systems", "pillar": ["data"], "phase": ["improvement"],
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
                        "AML.T0019 Publish Poisoned Datasets",
                        "AML.T0020 Poison Training Data",
                        "AML.T0059 Erode Dataset Integrity",
                        "AML.T0070 RAG Poisoning",
                        "AML.T0071 False RAG Entry Injection",
                        "AML.T0080.000 AI Agent Context Poisoning: Memory (recovery restores poisoned agent memory-like stores)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Data Poisoning (Training Phase) (L1) (data recovery provides clean data for model retraining)",
                        "Data Poisoning (L2)",
                        "Data Tampering (L2)",
                        "Compromised RAG Pipelines (L2)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM04:2025 Data and Model Poisoning",
                        "LLM08:2025 Vector and Embedding Weaknesses"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI06:2026 Memory & Context Poisoning"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.012 Clean-label Poisoning",
                        "NISTAML.013 Data Poisoning",
                        "NISTAML.024 Targeted Poisoning",
                        "NISTAML.037 Training Data Attacks",
                        "NISTAML.023 Backdoor Poisoning (data recovery removes backdoor-poisoned samples)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-6.1 Training Data Poisoning",
                        "AITech-7.2 Memory System Corruption",
                        "AITech-7.3 Data Source Abuse and Manipulation",
                        "AISubtech-6.1.1 Knowledge Base Poisoning (data recovery restores poisoned knowledge bases)",
                        "AISubtech-7.3.1 Corrupted Third-Party Data (recovery removes corrupted third-party data from AI datasets)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "DP: Data Poisoning (data recovery restores poisoned datasets to known-good state)",
                        "UTD: Unauthorized Training Data (recovery removes unauthorized data introduced during compromise)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Datasets 3.1: Data poisoning (data recovery restores poisoned training datasets)",
                        "Raw Data 1.7: Lack of data trustworthiness (recovery restores data trustworthiness through validation)",
                        "Raw Data 1.11: Compromised 3rd-party datasets (recovery removes compromised third-party data)",
                        "Agents - Core 13.1: Memory Poisoning (recovery restores poisoned RAG/vector data)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Identify all affected data stores, downstream assets, and derived artifacts.",
                    "howTo": "<h5>Concept:</h5><p>Before recovery, you must understand the full blast radius. Corrupted data almost never lives in isolation: it may have been copied into feature stores, embedded into vector DBs for RAG, cached in retrieval indexes, logged as trusted output, or even used to train downstream models. This guidance is a <strong>reusable module</strong>: the traversal logic is stable, while the lineage client adapter depends on your catalog platform.</p><h5>Use lineage to trace propagation</h5><p>Starting from the first known compromised dataset, recursively enumerate all downstream assets that consumed it: feature tables, analytics tables, vector databases or embedding indexes, memory stores, and any production models trained or fine-tuned on it.</p><pre><code># File: recovery/identify_blast_radius.py\nfrom __future__ import annotations\n\nfrom collections import deque\nfrom dataclasses import asdict, dataclass\nfrom typing import Protocol\n\n\n@dataclass(frozen=True)\nclass DownstreamAsset:\n    uri: str\n    asset_type: str\n    owner: str | None = None\n\n\nclass LineageClient(Protocol):\n    def get_downstream_lineage(self, asset_uri: str) -&gt; list[DownstreamAsset]:\n        ...\n\n\n\ndef find_downstream_assets(lineage_client: LineageClient, asset_uri: str) -&gt; list[DownstreamAsset]:\n    seen = {asset_uri}\n    queue = deque([asset_uri])\n    affected: list[DownstreamAsset] = []\n\n    while queue:\n        current = queue.popleft()\n        for asset in lineage_client.get_downstream_lineage(current):\n            if asset.uri in seen:\n                continue\n            seen.add(asset.uri)\n            affected.append(asset)\n            queue.append(asset.uri)\n\n    return affected\n\n\n\ndef build_blast_radius_report(lineage_client: LineageClient, compromised_root: str) -&gt; dict:\n    affected_assets = find_downstream_assets(lineage_client, compromised_root)\n    return {\n        \"compromised_root\": compromised_root,\n        \"affected_assets\": [asdict(asset) for asset in affected_assets],\n        \"total_affected_assets\": len(affected_assets),\n    }</code></pre><p><strong>Action:</strong> Generate and record a complete list of affected assets in the incident ticket, including raw datasets, feature stores, RAG or vector namespaces, embedding stores, memory logs, and any models trained on that data. This becomes the authoritative restoration scope.</p>"
                },
                {
                    "implementation": "Restore each affected data store from the most recent trusted, pre-incident backup or snapshot.",
                    "howTo": "<h5>Concept:</h5><p>Primary recovery method: roll back to a known-good snapshot taken before the compromise window. This applies to S3 buckets, SQL/NoSQL databases, vector databases (FAISS/Milvus/Pinecone), and embedding indexes. You must pick a restore timestamp just before the first malicious write.</p><h5>Point-in-Time / Version Restoration</h5><p>Below is an example using S3 Object Versioning to restore a dataset to its last known-good version. The same principle applies to vector DB snapshots (restore prior index dump) and feature stores (restore from point-in-time backup).</p><pre><code># File: recovery/restore_s3_object.sh\nBUCKET_NAME=\"aidefend-prod-training-data\"\nOBJECT_KEY=\"critical_dataset.csv\"\n\n# 1. List historical versions and identify the versionId from before the incident start.\naws s3api list-object-versions --bucket ${BUCKET_NAME} --prefix ${OBJECT_KEY}\n\nGOOD_VERSION_ID=\"a1b2c3d4e5f6g7h8\"  # chosen based on timestamp < incident start\n\n# 2. Promote that known-good version back to 'current'.\necho \"Restoring ${OBJECT_KEY} to version ${GOOD_VERSION_ID}...\"\naws s3api copy-object \\\n    --bucket ${BUCKET_NAME} \\\n    --copy-source \"${BUCKET_NAME}/${OBJECT_KEY}?versionId=${GOOD_VERSION_ID}\" \\\n    --key ${OBJECT_KEY}\n\necho \"✅ Restore complete (object now rolled back).\"\n</code></pre><p><strong>Action:</strong> For every compromised asset (including vector DB namespaces used by RAG), perform a restoration <em>into an isolated staging environment first</em>, not straight into production. In that staging environment, you will run integrity and quality validation (see below). Only after validation passes do you promote the restored snapshot back into production.</p>"
                },
                {
                    "implementation": "If no clean backup exists, reconstruct or repair data in place using deterministic rules and validation logic.",
                    "howTo": "<h5>Concept:</h5><p>Worst case: backups are missing, also corrupted, or too out-of-date. Then you must salvage what you have. This means writing a repair script that removes identifiable bad rows/chunks/vectors based on rules derived from the incident investigation (invalid schema, impossible values, malicious prompts injected into RAG context, etc.). The result is a reduced but trustworthy dataset/index.</p><h5>Heuristic Data Repair Script</h5><p>The following example shows a CSV-style dataset repair. In practice you must apply the same idea to RAG/embedding stores (e.g. drop vectors that originated from untrusted domains or attacker-controlled sources).</p><pre><code># File: recovery/repair_data.py\nimport pandas as pd\n\n# Load the corrupted dataset\ndf = pd.read_csv(\"data/corrupted_dataset.csv\")\noriginal_rows = len(df)\n\n# Rule 1: Remove rows missing critical fields\ndf.dropna(subset=[\"user_id\", \"transaction_amount\"], inplace=True)\n\n# Rule 2: Enforce range constraints (per-row filtering)\ndf = df[(df[\"transaction_amount\"] &gt;= 0) &amp; (df[\"transaction_amount\"] &lt;= 100000)]\n\n# Rule 3: Remove malicious outliers / injected payloads\n# e.g. rows flagged by anomaly detection, or RAG chunks from unapproved domains\n# outlier_mask = find_outliers(df[\"feature_x\"])\n# df = df[~outlier_mask]\n\nprint(f\"Repair complete. Removed {original_rows - len(df)} corrupted rows.\")\ndf.to_csv(\"data/repaired_dataset.csv\", index=False)\n</code></pre><p><strong>Action:</strong> Document the exact filtering logic you apply (which columns were validated, which rows/vectors were dropped, which client or data source was deemed malicious). Save this as part of the incident record, so you can defend in audit why certain data was removed or altered. Treat repaired output as <em>provisionally trusted</em> until it passes the full validation step.</p>"
                },
                {
                    "implementation": "Re-validate integrity, schema, and statistical consistency of restored/repaired data before reuse.",
                    "howTo": "<h5>Concept:</h5><p>After restore or repair, you must prove the dataset (or vector index / feature store) is trustworthy again. That means: cryptographic integrity (matches a known-good snapshot hash when available), schema & quality checks, and distribution sanity checks vs. your pre-incident baseline. For RAG/vector DBs, this also includes confirming that only approved sources / namespaces remain, and no attacker-planted prompts/snippets persist.</p><h5>Post-restoration validation pipeline</h5><p>The validation step should run automatically in an isolated staging environment. Only if it passes is the dataset/index allowed back into production or into retraining pipelines.</p><pre><code># File: recovery/validate_restored_data.py\nfrom __future__ import annotations\n\nimport hashlib\nimport json\nfrom pathlib import Path\n\nimport pandas as pd\n\nRESTORED_FILE = Path(\"data/restored_dataset.csv\")\nKNOWN_GOOD_HASH = Path(\"recovery/baselines/restored_dataset.sha256\").read_text(encoding=\"utf-8\").strip()\nBASELINE_PROFILE_PATH = Path(\"recovery/baselines/restored_dataset.profile.json\")\nREPORT_PATH = Path(\"recovery/out/restored_dataset_validation.json\")\n\nREQUIRED_COLUMNS = {\"user_id\", \"transaction_amount\", \"label\"}\nNUMERIC_RANGE_RULES = {\n    \"transaction_amount\": (0, 100000),\n}\nMAX_ALLOWED_ROW_COUNT_DRIFT = 0.20\nMAX_ALLOWED_CLASS_BALANCE_DRIFT = 0.10\n\n\ndef sha256_file(path: Path) -&gt; str:\n    digest = hashlib.sha256()\n    with path.open(\"rb\") as handle:\n        for chunk in iter(lambda: handle.read(8192), b\"\"):\n            digest.update(chunk)\n    return digest.hexdigest()\n\n\n\ndef validate_schema(df: pd.DataFrame) -&gt; None:\n    missing = sorted(REQUIRED_COLUMNS - set(df.columns))\n    if missing:\n        raise ValueError(f\"restored dataset missing required columns: {missing}\")\n\n    for column, (min_value, max_value) in NUMERIC_RANGE_RULES.items():\n        if not df[column].between(min_value, max_value).all():\n            raise ValueError(f\"column {column} contains values outside [{min_value}, {max_value}]\")\n\n\n\ndef generate_data_profile(df: pd.DataFrame) -&gt; dict:\n    class_balance = df[\"label\"].value_counts(normalize=True).sort_index().to_dict()\n    return {\n        \"row_count\": int(len(df)),\n        \"class_balance\": {str(key): float(value) for key, value in class_balance.items()},\n        \"transaction_amount_min\": float(df[\"transaction_amount\"].min()),\n        \"transaction_amount_max\": float(df[\"transaction_amount\"].max()),\n        \"transaction_amount_mean\": float(df[\"transaction_amount\"].mean()),\n    }\n\n\n\ndef compare_profiles(current: dict, baseline: dict) -&gt; None:\n    baseline_rows = baseline[\"row_count\"]\n    row_count_drift = abs(current[\"row_count\"] - baseline_rows) / baseline_rows\n    if row_count_drift &gt; MAX_ALLOWED_ROW_COUNT_DRIFT:\n        raise ValueError(f\"row-count drift too large: {row_count_drift:.2%}\")\n\n    for label, baseline_ratio in baseline[\"class_balance\"].items():\n        current_ratio = current[\"class_balance\"].get(label, 0.0)\n        if abs(current_ratio - baseline_ratio) &gt; MAX_ALLOWED_CLASS_BALANCE_DRIFT:\n            raise ValueError(\n                f\"class-balance drift too large for label {label}: \"\n                f\"baseline={baseline_ratio:.4f}, current={current_ratio:.4f}\"\n            )\n\n\nactual_hash = sha256_file(RESTORED_FILE)\nif actual_hash != KNOWN_GOOD_HASH:\n    raise RuntimeError(\"CRITICAL: hash mismatch on restored dataset\")\n\nrestored_df = pd.read_csv(RESTORED_FILE)\nvalidate_schema(restored_df)\ncurrent_profile = generate_data_profile(restored_df)\nbaseline_profile = json.loads(BASELINE_PROFILE_PATH.read_text(encoding=\"utf-8\"))\ncompare_profiles(current_profile, baseline_profile)\n\nreport = {\n    \"restored_file\": str(RESTORED_FILE),\n    \"sha256\": actual_hash,\n    \"schema_validation\": \"passed\",\n    \"distribution_validation\": \"passed\",\n    \"profile\": current_profile,\n}\nREPORT_PATH.parent.mkdir(parents=True, exist_ok=True)\nREPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True), encoding=\"utf-8\")\n\nprint(\"✅ All validation checks passed: data is ready for reuse.\")\n</code></pre><p><strong>Action:</strong> Attach the validation report (hash check results, schema validation outcome, distribution comparison notes, and any RAG/vector index source whitelist report) to the incident ticket and update the data catalog/lineage system to mark this asset as recovered and trusted. No restored dataset or vector index should be reintroduced into production pipelines or model retraining (AID-R-001.002) until this step passes.</p>"
                },
                {
                    "implementation": "Harden ingestion and update pipelines to prevent recurrence of the same corruption pattern.",
                    "howTo": "<h5>Concept:</h5><p>Recovery is not done until you close the hole. The exact validation steps that would have caught this incident must now become permanent gates in your ingestion / ETL / vector-db-upsert pipelines. That includes schema validation, source allowlists, anomaly/outlier screens, and cryptographic provenance checks (did this chunk/vector actually come from an approved source?).</p><h5>Embed Permanent Validation into the Pipeline</h5><p>Below is an example for tabular ingestion, but you must apply the same idea to RAG index builders: reject any new document/chunk that isn't from an approved source or that fails content/format policy.</p><pre><code># BEFORE: vulnerable ingestion (no validation)\ndef vulnerable_ingestion(source_file):\n    df = pd.read_csv(source_file)\n    df.to_sql('my_table', con=db_engine, if_exists='append')\n\n# AFTER: hardened ingestion with enforcement\nimport pandas as pd\n\ndef hardened_ingestion(source_file):\n    df = pd.read_csv(source_file)\n\n    # Example rule derived from the incident's root cause:\n    # All user_id values must be positive integers\n    if not pd.to_numeric(df['user_id'], errors='coerce').notna().all() or not (df['user_id'] > 0).all():\n        raise ValueError(\"Ingestion blocked: invalid user_id values detected.\")\n\n    # (For RAG/vector DB pipelines)\n    # - Verify each document chunk's source domain is on an approved whitelist.\n    # - Reject chunks containing attacker-supplied prompt injections or malicious instructions.\n\n    df.to_sql('my_table', con=db_engine, if_exists='append')\n</code></pre><p><strong>Action:</strong> Do a root cause analysis for the data corruption event. Convert that root cause into one or more mandatory validation checks inside your production ingestion / RAG indexing / feature generation pipelines. Version and audit these new controls so you can prove to compliance and leadership that the specific failure mode that caused this incident is now permanently guarded against.</p>"
                }
            ]
        },
        {
            "id": "AID-R-003",
            "name": "Secure Session & Identity Re-establishment",
            "pillar": ["infra", "app"],
            "phase": ["improvement"],
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
                        "AML.T0012 Valid Accounts",
                        "AML.T0055 Unsecured Credentials (re-auth invalidates previously unsecured credentials)",
                        "AML.T0083 Credentials from AI Agent Configuration (re-auth invalidates extracted agent credentials)",
                        "AML.T0091 Use Alternate Authentication Material",
                        "AML.T0091.000 Use Alternate Authentication Material: Application Access Token",
                        "AML.T0092 Manipulate User LLM Chat History (clean re-establishment restores trusted conversational context)",
                        "AML.T0080.001 AI Agent Context Poisoning: Thread (clean re-establishment restores trusted thread context)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Identity Attack (L7)",
                        "Agent Impersonation (L7)",
                        "Compromised Agents (L7) (clean session re-establishment after rogue agent containment)",
                        "Lateral Movement (L4) (re-auth breaks lateral movement within AI infrastructure)",
                        "Privilege Escalation (Cross-Layer) (re-auth with proper scoping prevents privilege escalation recurrence)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "N/A"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "N/A"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI02:2026 Tool Misuse and Exploitation (re-establishing identity prevents tool misuse via stolen sessions)",
                        "ASI03:2026 Identity and Privilege Abuse",
                        "ASI07:2026 Insecure Inter-Agent Communication (re-auth with fresh tokens secures inter-agent channels)",
                        "ASI10:2026 Rogue Agents (clean re-establishment helps contain and recover from rogue agents)",
                        "ASI06:2026 Memory & Context Poisoning"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.039 Compromising connected resources (re-auth prevents compromised sessions from reaching connected systems)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-3.1 Masquerading / Obfuscation / Impersonation",
                        "AITech-14.1 Unauthorized Access (re-auth invalidates unauthorized access gained via stolen credentials)",
                        "AITech-14.2 Abuse of Delegated Authority (re-auth with proper scoping prevents delegated authority abuse)",
                        "AISubtech-14.1.1 Credential Theft (re-establishment invalidates stolen credentials)",
                        "AISubtech-3.1.2 Trusted Agent Spoofing (clean identity re-establishment prevents continued spoofing)",
                        "AITech-7.2 Memory System Corruption",
                        "AISubtech-4.2.2 Session Boundary Violation (session re-establishment restores clean session boundaries)",
                        "AITech-16.1 Eavesdropping (TLS/HSTS hardening during re-onboarding prevents eavesdropping on recovery)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "SDD: Sensitive Data Disclosure (re-established sessions with MFA prevent continued disclosure via stolen credentials)",
                        "RA: Rogue Actions (progressive capability re-enablement prevents rogue actions during recovery)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Platform 12.4: Unauthorized privileged access (re-auth with MFA prevents continued unauthorized access)",
                        "Agents - Core 13.9: Identity Spoofing & Impersonation (clean identity re-establishment prevents continued impersonation)",
                        "Agents - Core 13.3: Privilege Compromise (re-auth with proper scoping prevents privilege re-abuse)",
                        "Agents - Tools MCP Server 13.19: Credential and Token Exposure (re-establishment replaces exposed credentials with fresh tokens)",
                        "Agents - Core 13.1: Memory Poisoning",
                        "Agents - Tools MCP Client 13.34: Session and State Management Failures (clean re-establishment addresses session/state management failures)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Require MFA or step-up authentication for all restored sessions.",
                    "howTo": "<h5>Concept:</h5><p>After global session eviction, identity proof must get stronger before any user or agent regains access. This is an identity-layer control with its own owner, evidence, and rollout path. The restore workflow should force a fresh sign-in, require MFA for all restored sessions, and demand a recent step-up event before sensitive actions proceed.</p><h5>Enforce Fresh MFA at the Session Boundary</h5><pre><code># File: app/security/session_reauth.py\nfrom time import time\n\nMAX_FRESH_AUTH_AGE_SECONDS = 10 * 60\n\n\ndef require_recent_mfa(jwt_claims: dict, require_fresh_auth: bool = True) -> None:\n    auth_methods = set(jwt_claims.get(\"amr\", []))\n    auth_time = int(jwt_claims.get(\"auth_time\", 0))\n\n    if \"mfa\" not in auth_methods:\n        raise PermissionError(\"MFA is required during the post-incident recovery window.\")\n\n    if require_fresh_auth and (time() - auth_time) > MAX_FRESH_AUTH_AGE_SECONDS:\n        raise PermissionError(\"Fresh step-up authentication is required for this operation.\")\n\n# Call require_recent_mfa(claims) on session re-establishment and before high-risk actions.\n</code></pre><p><strong>Action:</strong> Pair the application-side enforcement above with an IdP policy that disables remembered-device trust, shortens token TTL, and forces step-up for high-risk routes until the observation window closes. Store evidence of the activated policy, the TTL change, and the approval that authorized returning to normal authentication posture.</p>"
                },
                {
                    "implementation": "Enforce hardened transport requirements for all restored sessions.",
                    "howTo": "<h5>Concept:</h5><p>Transport hardening is separate from MFA. Even if identity proof is strong, restored sessions can still be exposed if re-onboarding traffic falls back to weak TLS, missing HSTS, or insecure cookies. Treat the post-incident session path as an edge-security change owned by the platform or SRE team.</p><h5>Apply a Hardened TLS and Cookie Baseline at the Edge</h5><pre><code># Example Nginx config for restored session traffic\nserver {\n    listen 443 ssl http2;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256;\n    ssl_session_tickets off;\n    ssl_prefer_server_ciphers off;\n\n    add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;\n    add_header X-Content-Type-Options \"nosniff\" always;\n\n    proxy_cookie_path / \"/; Secure; HttpOnly; SameSite=Lax\";\n\n    location / {\n        proxy_pass http://session_backend;\n    }\n}\n</code></pre><p><strong>Action:</strong> Apply the hardened transport profile to every restored login, callback, and token-refresh endpoint before reopening access. Validate the deployment with your TLS scanner of record, archive the scan result with the incident evidence, and do not treat this transport proof as a substitute for MFA enforcement evidence.</p>"
                },
                {
                    "implementation": "Restore trusted conversational or agent state from verified pre-incident snapshots.",
                    "howTo": "<h5>Concept:</h5><p>State restoration is a data-trust problem. Only reload conversational memory, agent scratchpads, cached tool bindings, or other working state from snapshots that were captured before the compromise window and that still pass integrity verification. Do not combine this step with privilege restoration; first rehydrate trusted state, then evaluate whether higher-risk capabilities should come back later.</p><h5>Rehydrate Only Verified Pre-Incident State</h5><pre><code># File: remediation/restore_agent_state.py\nimport hashlib\nimport json\nfrom pathlib import Path\n\n\ndef sha256_text(path: Path) -> str:\n    return hashlib.sha256(path.read_bytes()).hexdigest()\n\n\ndef restore_verified_state(snapshot_path: str, manifest_path: str) -> dict:\n    snapshot = Path(snapshot_path)\n    manifest = json.loads(Path(manifest_path).read_text(encoding=\"utf-8\"))\n\n    if manifest[\"captured_at\"] >= manifest[\"compromise_window_start\"]:\n        raise RuntimeError(\"Snapshot was captured inside the compromise window.\")\n\n    observed_hash = sha256_text(snapshot)\n    if observed_hash != manifest[\"snapshot_sha256\"]:\n        raise RuntimeError(\"Snapshot integrity verification failed.\")\n\n    restored_state = json.loads(snapshot.read_text(encoding=\"utf-8\"))\n    return {\n        \"agent_id\": manifest[\"agent_id\"],\n        \"restored_state\": restored_state,\n        \"snapshot_sha256\": observed_hash,\n        \"snapshot_version\": manifest[\"snapshot_version\"],\n    }\n</code></pre><p><strong>Action:</strong> Keep a clear record of which snapshot version was restored, who approved it, and why it was considered trustworthy. If any user or agent lacks a verified pre-incident snapshot, restore only a minimal default baseline instead of copying forward untrusted state from the compromised period.</p>"
                },
                {
                    "implementation": "Re-enable tools and privileges progressively after post-restore verification.",
                    "howTo": "<h5>Concept:</h5><p>Privilege restoration is a separate recovery control. Once trusted state is back, the service should restart in a reduced-permission mode and regain higher-risk tools in stages. This lets you observe behavior at each stage and prevents one bad restore from instantly reopening write paths, external actions, or production-side effects.</p><h5>Stage Capability Re-Enablement with an Explicit Recovery Profile</h5><pre><code># File: config/recovery_profiles.yaml\nprofiles:\n  quarantine:\n    allowed_tools: [\"search_docs\", \"read_ticket\"]\n  limited:\n    allowed_tools: [\"search_docs\", \"read_ticket\", \"create_draft\"]\n  full:\n    allowed_tools: [\"search_docs\", \"read_ticket\", \"create_draft\", \"write_ticket\", \"run_approved_tool\"]\n</code></pre><pre><code># File: app/security/capability_gate.py\nimport yaml\n\nwith open(\"config/recovery_profiles.yaml\", \"r\", encoding=\"utf-8\") as handle:\n    RECOVERY_PROFILES = yaml.safe_load(handle)[\"profiles\"]\n\n\ndef tool_allowed(profile_name: str, tool_name: str) -> bool:\n    allowed_tools = set(RECOVERY_PROFILES[profile_name][\"allowed_tools\"])\n    return tool_name in allowed_tools\n</code></pre><p><strong>Action:</strong> Promote identities or agents from `quarantine` to `limited` to `full` only after the defined observation checks pass and the required approver signs off. Log every promotion event with the profile change, approver, and timestamp so post-incident review can prove exactly when sensitive capabilities were restored.</p>"
                },
                {
                    "implementation": "Communicate the session reset and new login requirements clearly to legitimate users.",
                    "howTo": "<h5>Concept:</h5><p>Mass session invalidation is disruptive. If you don't explain it, users will think it's an outage or phishing. Clear, proactive communication turns users into an ally: they know to expect MFA, they understand why, and they will alert you if they see suspicious login prompts they didn't initiate.</p><h5>Automate Secure User Notification</h5><pre><code># File: incident_response/notify_users.py\nfrom sendgrid import SendGridAPIClient\nfrom sendgrid.helpers.mail import Mail\n\ndef send_session_reset_notification(user_list, template):\n    \"\"\"Send a pre-approved security incident notice to all affected users.\"\"\"\n    # Iterate users and send via provider API (SendGrid/Twilio/etc.)\n    # The template should:\n    # 1. Explain that sessions were reset for security reasons.\n    # 2. Tell users they will be prompted for MFA again.\n    # 3. Instruct: \"If you receive login/MFA prompts you did NOT initiate, contact us immediately.\" \n    pass\n</code></pre><p><strong>Action:</strong> Maintain pre-approved, legally reviewed communication templates (email/SMS/in-app banner) that you can broadcast immediately after eviction. The message must (a) explain the reset, (b) set expectation for MFA/step-up, and (c) ask users to report unexpected login prompts. Store evidence of this communication in the incident record to show that impacted users were notified and instructed.</p>"
                },
                {
                    "implementation": "Monitor newly established sessions at elevated sensitivity for signs of re-compromise.",
                    "howTo": "<h5>Concept:</h5><p>The hours right after restoration are the highest-risk period. The attacker may still have stolen credentials, old tokens, or knowledge of how your system behaves. You run in an \"observation window\" with <em>custom high-sensitivity detections</em> and you keep audit logs proving you were actively watching.</p><h5>Create High-Risk Correlation Rules in SIEM</h5><pre><code># Example Splunk SPL correlation rule:\n# 1. Find successful password reset events.\nindex=idp sourcetype=okta eventType=user.account.reset_password status=SUCCESS\n| fields user, source_ip AS reset_ip, source_country AS reset_country\n| join user [\n    # 2. Join with successful login events within 5 minutes after reset.\n    search index=idp sourcetype=okta eventType=user.session.start status=SUCCESS earliest=-5m latest=now\n    | fields user, source_ip AS login_ip, source_country AS login_country\n]\n# 3. Alert if geo/IP don't match -> possible credential handoff to attacker.\n| where reset_ip != login_ip OR reset_country != login_country\n| table user, reset_ip, reset_country, login_ip, login_country\n</code></pre><p><strong>Action:</strong> During the post-eviction observation window, enable heightened monitoring rules that specifically look for: (1) password reset → login from a different country/IP, (2) abnormal spikes in token issuance or tool authorization requests by a single identity, (3) agents immediately requesting high-privilege actions after capability re-enable. All alerts and analyst responses during this hardened monitoring window should be attached to the incident ticket. When the window closes and you return to normal auth/session policy, record that change as part of the incident's final closure.</p>"
                }
            ]
        },
        {
            "id": "AID-R-004",
            "name": "Post-Incident Hardening, Verification & Institutionalization",
            "pillar": ["data", "infra", "model", "app"],
            "phase": ["improvement"],
            "description": "Following containment, recovery, and immediate tactical patching, convert the incident into durable security improvements over the following days to weeks.<br/><br/><strong>Post-Incident Steps</strong><ol><li>Produce a formal, version-controlled Post-Incident Review (PIR) that documents root cause and precise TTPs</li><li>Update threat models and risk scores based on real evidence</li><li>Enforce fixes through engineering tickets with measurable acceptance tests</li><li>Validate fixes via targeted security testing and store proof</li><li>Update policy-as-code, IaC modules, shared security libraries, and CI/CD lint rules so that the same class of failure cannot silently recur</li><li>Generate auditable communication/notification artifacts for legal, compliance, and (if needed) customers without leaking exploit detail</li></ol><br/><br/><strong>Scoring boundary:</strong> The implementations in this family are intentionally separate because each produces a different owner workflow, evidence artifact, placement target, and maturity signal even when the underlying engineering pattern overlaps with Harden, Detect, or GRC programs.",
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
                "Splunk Enterprise Security",
                "Microsoft Sentinel",
                "Datadog Cloud SIEM",
                "AttackIQ",
                "SafeBreach",
                "Amazon SageMaker Model Registry",
                "Google Vertex AI Model Registry",
                "Databricks Unity Catalog",
                "ServiceNow GRC",
                "Recorded Future",
                "Mandiant Threat Intelligence"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0010 AI Supply Chain Compromise (hardening updates supply chain provenance and signing requirements)",
                        "AML.T0018 Manipulate AI Model (PIR creates regression tests validating model integrity controls)",
                        "AML.T0020 Poison Training Data (hardening updates data ingestion validation policies)",
                        "AML.T0031 Erode AI Model Integrity (hardening creates monitoring baselines for integrity drift)",
                        "AML.T0051 LLM Prompt Injection (hardening updates sanitization rules and detection systems)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Backdoor Attacks (L1) (PIR creates backdoor detection regression tests)",
                        "Data Poisoning (L2) (hardening updates data ingestion and validation policies)",
                        "Compromised Framework Components (L3) (hardening updates framework dependency security controls)",
                        "Supply Chain Attacks (Cross-Layer) (hardening updates supply chain provenance and signing)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (hardening creates permanent input sanitization and detection rules)",
                        "LLM03:2025 Supply Chain (hardening updates supply chain validation and provenance checks)",
                        "LLM04:2025 Data and Model Poisoning (hardening creates data/model validation regression tests)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack (hardening creates permanent data validation gates)",
                        "ML06:2023 AI Supply Chain Attacks (hardening updates supply chain security policies)",
                        "ML10:2023 Model Poisoning (hardening creates model integrity verification tests)"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI01:2026 Agent Goal Hijack (hardening updates goal integrity monitoring thresholds)",
                        "ASI04:2026 Agentic Supply Chain Vulnerabilities (hardening updates agentic supply chain controls)",
                        "ASI05:2026 Unexpected Code Execution (RCE) (hardening updates sandboxing and execution policies)"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.013 Data Poisoning (hardening institutionalizes data sanitization policies)",
                        "NISTAML.018 Prompt Injection (hardening creates permanent prompt defense rules)",
                        "NISTAML.023 Backdoor Poisoning (PIR creates backdoor detection regression tests)",
                        "NISTAML.051 Model Poisoning (Supply Chain) (hardening updates supply chain provenance requirements)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-6.1 Training Data Poisoning (hardening updates data ingestion validation)",
                        "AITech-9.1 Model or Agentic System Manipulation (hardening creates model integrity verification)",
                        "AITech-9.3 Dependency / Plugin Compromise (hardening updates dependency security controls)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "DP: Data Poisoning (hardening institutionalizes data validation and sanitization policies)",
                        "PIJ: Prompt Injection (hardening creates permanent input sanitization and detection rules)",
                        "MST: Model Source Tampering (hardening updates supply chain provenance and signing requirements)",
                        "MDT: Model Deployment Tampering (hardening updates deployment integrity verification)",
                        "IIC: Insecure Integrated Component (hardening updates integrated component security controls)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Platform 12.3: Lack of incident response (PIR and hardening strengthen incident response capabilities)",
                        "Operations 11.1: Lack of MLOps - repeatable enforced standards (hardening codifies security into MLOps standards)",
                        "Governance 4.2: Lack of end-to-end ML lifecycle (hardening improves ML lifecycle security controls)",
                        "Model 7.3: ML Supply chain vulnerabilities (hardening updates supply chain security policies)",
                        "Platform 12.2: Lack of penetration testing, red teaming and bug bounty (BAS/TTP replay validates fixes through targeted security testing)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Run a structured Post-Incident Review (PIR) / Root Cause Analysis (RCA) and store it as an auditable artifact in version control.",
                    "howTo": "<h5>Concept:</h5><p>The PIR is not just a meeting. It is a security artifact that documents the full exploit chain, exact TTPs, affected assets, detection gaps, and required remediation tasks. It must explicitly map which AIDEFEND techniques/subtechniques failed, were missing, or were insufficient.</p><h5>Create a Version-Controlled PIR Document</h5><pre><code># File: post_mortems/2025-06-08-Prompt-Injection.md\n\n## Post-Incident Review: Prompt Injection leading to PII Leakage\n- Incident ID: INC-2025-021\n- Date: 2025-06-08\n- Lead: @security_lead\n\n### 1. Timeline of Events\n10:00 UTC  Alert fired for anomalous output\n10:15 UTC  PII leakage confirmed; kill-switch (AID-I-005) activated\n10:30 UTC  Root cause linked to Base64+homoglyph prompt injection bypassing input validation\n11:00 UTC  Hardened input sanitizer (AID-H-002) deployed\n11:30 UTC  Service restored via controlled rollback (AID-R-001)\n\n### 2. Root Cause (5 Whys)\n1. Bot leaked PII due to malicious prompt injection.\n2. Injection bypassed naive keyword-based filter.\n3. Filter did not recursively decode Base64 or detect homoglyphs.\n4. No PII output scanning (AID-D-003) on this endpoint.\n5. Control was deprioritized.\n\n### 3. Control Mapping\n- Weak/missing controls:\n  - AID-H-002.001 (input sanitization)\n  - AID-D-003.002 (PII output redaction)\n  - AID-I-005 (automated kill-switch trigger not yet enforced)\n\n### 4. Required Follow-Ups (Engineering Tickets)\n- AISEC-123: Add recursive decode + homoglyph detection to sanitizer (Owner: @ml_infra, SLA: 7d)\n- AISEC-124: Enforce PII redaction in support bot responses (Owner: @ml_infra, SLA: 3d)\n- AISEC-125: Automate kill-switch trigger criteria in SOAR (Owner: @sec_eng, SLA: 14d)</code></pre><p><strong>Action:</strong> Every AI/ML security incident must produce a PIR file under version control. The PIR must: (1) capture the exploit chain and TTPs, (2) identify which AIDEFEND techniques/subtechniques need to be hardened or newly adopted, and (3) generate trackable remediation tasks with owners, SLAs, and acceptance tests.</p>"
                },
                {
                    "implementation": "Maintain a pre-approved, version-controlled incident communication and escalation matrix consumable by SOAR.",
                    "howTo": "<h5>Concept:</h5><p>Who gets notified, how fast, and with what structured data cannot be improvised. You maintain a machine-readable escalation/notification matrix that your SOAR or incident tooling can parse. It encodes severity levels, required stakeholders (CISO, ML Infra Lead, Legal, Privacy, Customer Trust), and whether regulatory/customer notice is required.</p><h5>Communication Matrix (YAML)</h5><pre><code># File: docs/incident_response/AI_COMMS_PLAN.yaml\nseverity_levels:\n  SEV-1:\n    notify:\n      - role: \"CISO\"\n      - role: \"AI Security Lead\"\n      - role: \"Legal Counsel\"\n      - role: \"Privacy Officer\"\n      - role: \"Public Status Page Owner\"\n    external_notice_required: true\n    regulatory_timer_start: true\n    customer_comm_channel: \"status_page,broadcast_email\"\n  SEV-2:\n    notify:\n      - role: \"CISO\"\n      - role: \"AI Security Lead\"\n      - role: \"Legal Counsel\"\n    external_notice_required: conditional\n    regulatory_timer_start: conditional\n  SEV-3:\n    notify:\n      - role: \"AI Security Lead\"\n    external_notice_required: false\n    regulatory_timer_start: false</code></pre><p><strong>Action:</strong> Store this matrix in version control. Your SOAR/IR runbooks should ingest it automatically to (a) page Legal/Privacy, (b) mark when regulatory clocks start, and (c) generate initial customer/regulator notification drafts. This makes escalation repeatable, auditable, and technically enforced instead of ad hoc email chains.</p>"
                },
                {
                    "implementation": "Produce a restricted internal forensic incident report.",
                    "howTo": "<h5>Concept:</h5><p>The internal report is the full-fidelity engineering and forensic record for the incident. It should include exact TTPs, affected model or data artifact identifiers, compromised infrastructure versions, failed controls, and the evidence chain that supports root-cause analysis. This artifact belongs in a restricted repository or case-management system with explicit access control.</p><h5>Internal Forensic Report Template</h5><pre><code># File: post_mortems/INC-2026-041/internal_forensic_report.md\n# Incident: INC-2026-041\n\n## Executive Timeline\n- First confirmed malicious event:\n- Containment completed:\n- Recovery completed:\n\n## Technical Root Cause\n- Initial access vector:\n- Failed safeguard(s):\n- Affected service / model / dataset versions:\n\n## Evidence Inventory\n- Model artifact digests:\n- Dataset URIs and hashes:\n- Container image digests:\n- Relevant SIEM detection IDs:\n\n## Remediation Performed\n- Eviction actions:\n- Recovery actions:\n- Validation evidence:\n\n## Follow-up Engineering Work\n- Required tickets:\n- Owners and due dates:\n</code></pre><p><strong>Action:</strong> Store the internal report in the restricted incident repository, link every quoted digest or artifact ID back to its evidence source, and keep change history in version control. This report is the canonical engineering record used for post-incident validation, audit, and future threat-model updates.</p>"
                },
                {
                    "implementation": "Produce a sanitized external or regulator-safe incident summary.",
                    "howTo": "<h5>Concept:</h5><p>The external or regulator-safe summary has a different audience and evidence threshold. It must state what happened, what was impacted, what remediation was taken, and what obligations are still open, but it must not disclose exploit chains, live indicators, internal hostnames, or code-level details that would help an attacker reproduce the incident.</p><h5>External / Regulator-Safe Summary Template</h5><pre><code>Title: Security Event Affecting AI Service on 2026-04-08\nImpact Window: 10:00-11:30 UTC\nSummary:\n  We detected and contained a security event affecting an AI-enabled service.\nScope:\n  Impacted functionality:\n  Data categories involved:\n  Jurisdictions affected:\nRemediation:\n  Sessions were revoked, affected artifacts were restored, and additional safeguards were deployed.\nCustomer / Regulator Guidance:\n  Users should re-authenticate and follow any posted recovery instructions.\nNext Steps:\n  We are completing post-incident validation and any required notifications.\n</code></pre><p><strong>Action:</strong> Generate the sanitized summary from an approved template, require review by Legal or the incident communications owner before release, and store the signed-off version as immutable incident evidence. Treat this as a separate deliverable from the forensic report, not a redacted copy of the same document.</p>"
                },
                {
                    "implementation": "Trigger regulatory / legal notification workflow when regulated data or protected jurisdictions are implicated, and generate an auditable evidence bundle.",
                    "howTo": "<h5>Concept:</h5><p>Certain incidents (PII leakage, PHI exposure, payment data misuse, biometric inference) start a legal reporting clock (e.g. 72 hours). You need a repeatable workflow. The workflow gathers data category, affected jurisdictions, timeline timestamps, and containment steps into a structured bundle for Legal/Privacy.</p><h5>Breach Triage Checklist</h5><pre><code># File: incident_response/breach_triage_checklist.md\n- [ ] Incident ID assigned, severity level set\n- [ ] Legal + Privacy paged via SOAR\n- [ ] Affected data classes enumerated (PII, PHI, payment, biometric)\n- [ ] User geography mapped (EU, CA, US-CA, etc.)\n- [ ] Regulatory notification matrix consulted\n- [ ] T0 timestamp (breach confirmed) recorded to start regulatory SLA clock\n- [ ] Evidence bundle started:\n      - forensic summary (timeline, root cause)\n      - impacted systems/datasets/model versions\n      - containment and hardening actions already executed</code></pre><p><strong>Action:</strong> Implement an automated step in the incident runbook that, upon classification as SEV-1 or any PII/PHI event, (1) pages Legal/Privacy, (2) records the clock start timestamp, and (3) assembles this evidence bundle. This turns regulatory response into an operational control instead of a last-minute scramble.</p>"
                },
                {
                    "implementation": "Update threat models and risk scores based on real incident evidence, and commit those changes to version control.",
                    "howTo": `<h5>Concept:</h5><p>After an incident, theoretical threats become observed threats. This guidance is specifically about updating the threat-model artifact and the system's recorded likelihood or impact scores. Keep remediation-ticket creation and broader control rollout decisions in their sibling governance guidance so the evidence for this item stays a clean threat-model diff.</p><h5>Step 1: Record the incident-driven threat-model change in version control</h5><pre><code># File: docs/THREAT_MODEL.md (Git diff)
### Component: User Prompt API Endpoint
- Likelihood: Medium
+ Likelihood: High  (Observed in INC-2025-021 via Base64+homoglyph prompt injection)
Impact: High (PII disclosure vector identified)
Mitigations:
  - AID-H-002.001 hardened to recursively decode and detect homoglyphs
  - AID-D-003.002 PII redaction enforced pre-response
Audit:
  - PIR: post_mortems/2025-06-08-Prompt-Injection.md
  - Owner: @security_lead</code></pre><h5>Step 2: Update the machine-readable risk register</h5><pre><code># File: threat_model/risk_register.yaml
threats:
  - threat_id: THR-PI-001
    title: prompt injection with encoded override payloads
    likelihood: high
    impact: high
    incident_reference: INC-2025-021
    last_revalidated_at: "2026-04-09T18:42:00Z"</code></pre><p><strong>Action:</strong> Every PIR should produce a committed diff that references the incident ID and explicitly shows which likelihood or impact values changed. The evidence for this guidance is the merged threat-model change, not the downstream prioritization or ticketing workflow.</p>`
                },
                {
                    "implementation": "Translate PIR action items into enforceable engineering tickets with mapped AIDEFEND techniques, SLAs, owners, and machine-checkable acceptance tests.",
                    "howTo": "<h5>Concept:</h5><p>Root cause analysis only matters if it becomes enforced engineering work. Each PIR action item becomes an engineering ticket that (1) cites the AIDEFEND control it strengthens, (2) has an explicit SLA/owner, and (3) defines a measurable acceptance test (for example 'garak injection probes = 0', 'PII redaction must trigger on any phone number before response').</p><h5>Example Engineering Ticket</h5><pre><code># GitHub Issue\nTitle: Enforce PII Output Scanning on Support Bot (Ref: INC-2025-021)\nLabels: security, aidefend:AID-D-003.002, SLA:3d\nDescription:\n  Add PII detection/redaction to Support Bot response pipeline.\nAcceptance Criteria:\n  - Presidio-style PII scanner (AID-D-003.002) runs on all bot responses before sending output to user.\n  - Detected PII is replaced with placeholders (e.g. <PERSON>).\n  - SIEM alert rule created for 'PII detected pre-redaction'.\n  - garak-style prompt injection regression test shows 0 unredacted PII leaks in staging.\nOwner: @ml_infra\nDue: 2025-06-11</code></pre><p><strong>Action:</strong> No PIR is considered closed until each mandatory safeguard has a corresponding ticket with clear SLA, owner, mapped AIDEFEND technique/subtechnique, and objective acceptance tests. This makes remediation auditable and prevents silent deferral.</p>"
                },
                {
                    "implementation": "Perform targeted regression validation of fixes using AI-specific security testing and archive the results as evidence.",
                    "howTo": "<h5>Concept:</h5><p>Post-incident fixes are incomplete until the original exploit path is replayed and fails under staging conditions.</p><h5>Run targeted regression probe set</h5><pre><code>python -m garak --model_type rest --model_name staging-ai-bot \\\n  --probes promptinject \\\n  --report_prefix output/INC-2025-021/garak_regression</code></pre><h5>Gate on machine-checkable result</h5><pre><code>python - <<'PY'\nimport json,glob,sys\nfiles=glob.glob('output/INC-2025-021/garak_regression*.json')\nif not files:\n    raise SystemExit('missing garak report')\nreport=json.load(open(files[0],encoding='utf-8'))\nif report.get('hits',0) > 0:\n    raise SystemExit('regression failed: prompt-injection hit detected')\nprint('regression passed')\nPY</code></pre><p><strong>Action:</strong> Archive command output and report JSON under the incident evidence directory, and block closure if replayed exploit paths still succeed.</p>"
                },
                {
                    "implementation": "Institutionalize the mitigation in shared security libraries and reusable runtime policy baselines so future services inherit the fixed control by default.",
                    "howTo": `<h5>Concept:</h5><p>This guidance turns an incident-specific mitigation into a <strong>reusable runtime artifact</strong>. The artifact can be a shared middleware package, policy bundle, prompt-sanitization library, output-redaction component, or signed runtime-policy release that downstream services import directly. Keep this scope focused on reusable runtime dependencies and their release evidence; do not mix it with IaC rollout or CI gate enforcement.</p><h5>Step 1: Publish the fixed control as a versioned shared artifact</h5><pre><code># File: libs/security_guardrails/manifest.yaml
artifact_name: security-guardrails
artifact_version: 2.4.0
incident_reference: INC-2026-041
controls_included:
  - control_id: AID-H-002.001
    capability: recursive_prompt_decoding_and_homoglyph_detection
    minimum_runtime_config:
      decode_layers: 3
      block_mixed_script_override: true
  - control_id: AID-D-003.002
    capability: output_pii_redaction
    minimum_runtime_config:
      redact_before_delivery: true
release_owner: security-platform
approval:
  security_signoff: approved
  qa_regression_suite: passed</code></pre><h5>Step 2: Ship a regression-backed shared implementation</h5><pre><code># File: libs/security_guardrails/input_sanitizer.py
def sanitize_user_prompt(raw_input: str) -> str:
    decoded = recursively_decode_base64(raw_input, max_layers=3)
    decoded = normalize_homoglyphs(decoded)
    assert_no_tool_escalation_instruction(decoded)
    return decoded


# File: libs/security_guardrails/tests/test_inc_2026_041.py
def test_nested_base64_homoglyph_override_is_blocked():
    payload = 'SWdub3JlIGFsbCDinaEg4oCcZ3VhcmRyb2FpbHPigJ0='
    blocked = sanitize_user_prompt(payload)
    assert 'ignore all' not in blocked.lower()</code></pre><p><strong>Action:</strong> Release the fixed mitigation as a versioned shared artifact with an incident reference, explicit control IDs, and regression evidence. The evidence for this guidance should be the artifact manifest, release notes, versioned package or policy bundle, and regression-test results.</p>`
                },
                {
                    "implementation": "Enforce organization-wide adoption of the institutionalized mitigation through IaC baselines and CI/CD policy gates.",
                    "howTo": `<h5>Concept:</h5><p>This guidance is the <strong>delivery enforcement</strong> companion to the shared-library update. Its job is to make sure new or changed services cannot bypass the institutionalized safeguard. Evidence here is not the runtime library release itself; it is the baseline module update, CI policy, and build or deployment gate that proves adoption is mandatory.</p><h5>Step 1: Encode the control requirement in reusable deployment baselines</h5><pre><code># File: terraform/modules/ai_service/main.tf
variable "require_security_guardrails_version" {
  type    = string
  default = "2.4.0"
}

resource "kubernetes_config_map" "ai_security_defaults" {
  metadata {
    name      = "ai-security-defaults"
    namespace = var.namespace
  }

  data = {
    SECURITY_GUARDRAILS_VERSION = var.require_security_guardrails_version
    REQUIRE_PROMPT_SANITIZER    = "true"
    REQUIRE_OUTPUT_REDACTION    = "true"
  }
}</code></pre><h5>Step 2: Fail CI when a service does not adopt the required baseline</h5><pre><code># File: policy/check_ai_service_baseline.py
import pathlib
import sys
import yaml

service_config = yaml.safe_load(pathlib.Path('service.yaml').read_text())
required_version = '2.4.0'

errors = []
if service_config.get('security_guardrails_version') != required_version:
    errors.append(f'missing required security_guardrails_version={required_version}')
if service_config.get('prompt_sanitizer_enabled') is not True:
    errors.append('prompt sanitizer must be enabled')
if service_config.get('output_redaction_enabled') is not True:
    errors.append('output redaction must be enabled')

if errors:
    for error in errors:
        print(f'POLICY_ERROR: {error}')
    sys.exit(1)</code></pre><p><strong>Action:</strong> Update the reusable IaC baseline and CI policy so services cannot deploy without the required institutionalized control version. The evidence for this guidance should be the baseline-module PR, the policy-gate code, and successful CI or deployment records showing the mandate is enforced.</p>`
                },
                {
                    "implementation": "Share sanitized TTPs and mitigations with trusted intelligence channels (e.g. ISAC, MISP) without exposing proprietary details.",
                    "howTo": "<h5>Concept:</h5><p>If the attacker used a novel AI/LLM-specific TTP (for example, multi-layer Base64 + homoglyph prompt injection to force data exfil), you should publish a sanitized version of that TTP to trusted sharing communities. This strengthens collective defense and accelerates ecosystem-level detection rules.</p><h5>Sanitized TTP Package</h5><pre><code># Title: Nested Base64 + Homoglyph Prompt Injection for Instruction Override\nObserved Behavior:\n  1. Attacker encodes malicious instructions using homoglyph substitutions.\n  2. Payload is Base64-encoded multiple times.\n  3. LLM is instructed to decode and execute that payload.\nMitigation Highlights:\n  - Recursive decode and homoglyph detection in input sanitizer (AID-H-002.001)\n  - Mandatory PII redaction of model output (AID-D-003.002)\n  - Automated kill-switch trigger (AID-I-005)\nShared Indicators (sanitized):\n  - Structural patterns (multi-layer Base64 + mixed-script charsets)\n  - Behavioral signature (LLM asked to self-decode and obey decoded payload)</code></pre><p><strong>Action:</strong> Produce a sanitized TTP/IOC summary that (1) does not mention internal system names, bucket names, model version strings, etc., but (2) clearly explains the attacker’s technique and the high-level mitigations. Share via MISP / ISAC / vetted industry channels. This helps defenders elsewhere add similar detections and guardrails, and it documents that your org contributed to collective defense.</p>"
                }
            ]
        },
        {
            "id": "AID-R-005",
            "name": "Rapid Vector Index Rollback & Quarantine",
            "pillar": ["data"],
            "phase": ["response", "improvement"],
            "description": "Provide fast, controlled recovery for Retrieval-Augmented Generation (RAG) pipelines after index poisoning or malicious content injection is detected. The vector index is treated as an immutable, versioned artifact.<br/><br/><strong>Three-Stage Recovery</strong><ol><li><strong>Rollback</strong> — Atomically roll back to a last known-good snapshot</li><li><strong>Quarantine</strong> — Quarantine and preserve suspicious chunks for forensics while removing them from production retrieval</li><li><strong>Rebuild</strong> — Rebuild and re-promote a clean index that enforces provenance, policy, and security approvals</li></ol><strong>Goal:</strong> Restore trustworthy retrieval quality quickly while preventing re-serving tainted data.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0059 Erode Dataset Integrity",
                        "AML.T0070 RAG Poisoning",
                        "AML.T0071 False RAG Entry Injection",
                        "AML.T0051 LLM Prompt Injection (rollback removes injected content from vector index)",
                        "AML.T0080.000 AI Agent Context Poisoning: Memory (rollback restores poisoned retrieval memory context)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Data Poisoning (L2)",
                        "Data Tampering (L2)",
                        "Compromised RAG Pipelines (L2)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection (rollback removes indirect prompt injections embedded in RAG index)",
                        "LLM04:2025 Data and Model Poisoning",
                        "LLM08:2025 Vector and Embedding Weaknesses"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML02:2023 Data Poisoning Attack"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI01:2026 Agent Goal Hijack (rollback removes RAG content that could redirect agent goals)",
                        "ASI06:2026 Memory & Context Poisoning",
                        "ASI08:2026 Cascading Failures (rapid rollback prevents poisoned RAG from cascading across agents)"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.013 Data Poisoning",
                        "NISTAML.015 Indirect Prompt Injection",
                        "NISTAML.024 Targeted Poisoning",
                        "NISTAML.027 Misaligned Outputs (rollback removes RAG content causing misaligned LLM outputs)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-7.2 Memory System Corruption",
                        "AITech-7.3 Data Source Abuse and Manipulation",
                        "AISubtech-6.1.1 Knowledge Base Poisoning (rollback restores poisoned knowledge base indices)",
                        "AITech-1.2 Indirect Prompt Injection (rollback removes indirect injection content from vector stores)",
                        "AITech-4.2 Context Boundary Attacks",
                        "AISubtech-7.3.1 Corrupted Third-Party Data (rollback removes corrupted third-party content from vector index)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "DP: Data Poisoning (rollback removes poisoned data from vector index)",
                        "PIJ: Prompt Injection (rollback removes indirect prompt injections embedded in RAG index)",
                        "IMO: Insecure Model Output (rollback removes RAG content causing insecure model outputs)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Datasets 3.1: Data poisoning (rollback removes poisoned embeddings from vector index)",
                        "Raw Data 1.7: Lack of data trustworthiness (rollback restores trustworthy vector index state)",
                        "Raw Data 1.11: Compromised 3rd-party datasets (rollback removes compromised third-party RAG content)",
                        "Agents - Core 13.1: Memory Poisoning (rollback removes poisoned RAG content from agent retrieval)",
                        "Agents - Core 13.12: Agent Communication Poisoning (rollback removes poisoned content propagated through RAG)",
                        "Agents - Core 13.5: Cascading Hallucination Attacks",
                        "Agents - Tools MCP Server 13.24: Context Spoofing and Manipulation (rollback removes spoofed/manipulated context from retrieval index)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Use immutable versioned indices and an alias/pointer for atomic cutover and rollback.",
                    "howTo": "<h5>Concept:</h5><p>Never serve traffic directly from a mutable 'live' index. Each ingest/build produces a new immutable index (e.g. <code>rag_index_v42</code>). Production queries always go through an alias (e.g. <code>rag_prod</code>). Promotion = repoint alias to the new version. Rollback = repoint alias back to the last known-good version. This makes rollback a single atomic operation and avoids serving poisoned content.</p><h5>Example (OpenSearch / Elasticsearch style):</h5><pre><code># Create new versioned index and bulk-ingest embeddings/chunks\nPUT rag_index_v42\n{ \"settings\": { ... }, \"mappings\": { ... } }\n\n# After validation succeeds, atomically repoint prod alias\nPOST _aliases\n{\n  \"actions\": [\n    { \"remove\": { \"alias\": \"rag_prod\", \"index\": \"rag_index_v41\" }},\n    { \"add\":    { \"alias\": \"rag_prod\", \"index\": \"rag_index_v42\" }}\n  ]\n}\n\n# Emergency rollback = same alias swap back to rag_index_v41.</code></pre><p><h5>Integrity manifest:</h5><p>For each index version, generate a signed manifest that records:</p><ul><li>index_version (e.g. <code>rag_index_v42</code>)</li><li>timestamp built</li><li>embedding_model_sha256</li><li>per-chunk SHA-256 and source_uri</li><li>approver / promotion request ID</li><li>cryptographic signature (Sigstore / cosign / GPG)</li></ul><p>This manifest proves which snapshot is trusted. Only versions with a valid manifest are allowed to become <code>rag_prod</code>.</p>"
                },
                {
                    "implementation": "Quarantine and preserve suspicious chunks before removal from production retrieval.",
                    "howTo": `<h5>Concept:</h5><p>Chunk quarantine has two simultaneous goals: immediately stop poisoned content from being retrieved, and preserve enough forensic evidence to support incident response and later rebuild decisions. The workflow should therefore export the exact flagged records into an immutable quarantine store before deleting them from the active collection.</p><h5>Step 1: Enumerate flagged points from the active Qdrant collection</h5><pre><code># File: recovery/quarantine_chunks.py
from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timezone

import numpy as np
from qdrant_client import QdrantClient
from qdrant_client.models import FieldCondition, Filter, MatchValue


def sha256_vector(vector) -&gt; str:
    array = np.asarray(vector, dtype=np.float32)
    return hashlib.sha256(array.tobytes()).hexdigest()


client = QdrantClient(url="http://127.0.0.1:6333")
collection_name = "rag_index_v42"
quarantine_path = pathlib.Path("forensics/quarantine/rag_index_v42.jsonl")
quarantine_path.parent.mkdir(parents=True, exist_ok=True)

offset = None
flagged_ids = []

with quarantine_path.open("a", encoding="utf-8") as sink:
    while True:
        points, offset = client.scroll(
            collection_name=collection_name,
            scroll_filter=Filter(
                must=[FieldCondition(key="suspicious_flag", match=MatchValue(value=True))]
            ),
            limit=100,
            offset=offset,
            with_payload=True,
            with_vectors=True,
        )

        for point in points:
            record = {
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
                "collection_name": collection_name,
                "point_id": point.id,
                "vector_sha256": sha256_vector(point.vector),
                "payload": point.payload,
            }
            sink.write(json.dumps(record) + "\\n")
            flagged_ids.append(point.id)

        if offset is None:
            break
</code></pre><h5>Step 2: Delete the quarantined points from production retrieval only after evidence is written</h5><p>The same job that writes the quarantine evidence should remove the flagged point IDs from the active collection. Keep the delete idempotent so reruns do not create partial containment states.</p><pre><code># File: recovery/quarantine_chunks.py
if flagged_ids:
    client.delete(
        collection_name=collection_name,
        points_selector=flagged_ids,
        wait=True,
    )
    print(f"Quarantined and removed {len(flagged_ids)} points from {collection_name}")
else:
    print("No flagged points found")
</code></pre><h5>Step 3: Add triage enrichment that supports PIR and rebuild decisions</h5><p>Include enough metadata to answer who inserted the chunk, why it was flagged, and which build it came from. This is what lets recovery, PIR, and future blocklists improve instead of treating the event as a blind delete.</p><pre><code># Example JSONL record written to forensics/quarantine/rag_index_v42.jsonl
{
  "quarantined_at": "2026-04-12T14:25:03+00:00",
  "collection_name": "rag_index_v42",
  "point_id": 88421,
  "vector_sha256": "7f98ce7c5e9b2f8a7d5c2c27b5bdf1c8662d68d4c4b463f89f9f6cb4b17ef0e2",
  "payload": {
    "source_uri": "s3://corp-rag/legal/notice-88421.txt",
    "ingested_at": "2026-04-10T03:12:11Z",
    "reason_flagged": "matched_rule:rag_jailbreak_phrase",
    "submitter_user_id": "svc-rag-loader",
    "index_build_id": "rag-build-2026-04-10-02"
  }
}
</code></pre><h5>Step 4: Verify that the poisoned chunks no longer appear in retrieval</h5><p>Run a post-delete retrieval check or direct point lookup against the production alias. Recovery is incomplete if the same point IDs or their cloned duplicates still appear.</p><pre><code># Example verification
remaining_points, _ = client.scroll(
    collection_name=collection_name,
    scroll_filter=Filter(
        must=[FieldCondition(key="suspicious_flag", match=MatchValue(value=True))]
    ),
    limit=10,
    with_payload=False,
)

if remaining_points:
    raise SystemExit("quarantine failed: suspicious points still present in production collection")
</code></pre><p><strong>Action:</strong> Export first, delete second, verify third. Keep the quarantine JSONL or Object-Lock bucket immutable so investigators can prove exactly which poisoned chunks were removed and why.</p>`
                },
                {
                    "implementation": "Rebuild a clean candidate index from trusted sources with provenance, policy scanning, and approval gating before promotion.",
                    "howTo": `<h5>Concept:</h5><p>A clean candidate index should be rebuilt from trusted sources only, with provenance verification and content-policy scanning applied before any vector is promoted. The rebuild pipeline is a security boundary: if a document fails provenance or policy checks, it must never enter the candidate collection.</p><h5>Step 1: Verify trusted source inventory before embedding</h5><pre><code># File: recovery/rebuild_candidate_index.py
from __future__ import annotations

import hashlib
import json
import pathlib
import re
from datetime import datetime, timezone

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams
from sentence_transformers import SentenceTransformer


JAILBREAK_PATTERNS = [
    re.compile(r"ignore (all|previous) instructions", re.IGNORECASE),
    re.compile(r"(api[_-]?key|secret|token)", re.IGNORECASE),
    re.compile(r"send .* to https?://", re.IGNORECASE),
]


def sha256_text(text: str) -&gt; str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def passes_policy_scan(text: str) -&gt; bool:
    return not any(pattern.search(text) for pattern in JAILBREAK_PATTERNS)


approved_inventory = [
    {
        "doc_id": "doc-001",
        "source_uri": "s3://trusted-kb/hr/leave-policy.txt",
        "expected_sha256": "2c63f0c4b0f67f9fcf80d8b6ef291d1d9a7ecdef6779d9b6426168f33fe8a1be",
        "text_path": "recovery/input/doc-001.txt",
    }
]

client = QdrantClient(url="http://127.0.0.1:6333")
encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
candidate_collection = "rag_index_v43_candidate"

if not client.collection_exists(candidate_collection):
    client.create_collection(
        collection_name=candidate_collection,
        vectors_config=VectorParams(size=384, distance=Distance.COSINE),
    )
</code></pre><h5>Step 2: Embed only the documents that pass provenance and policy gates</h5><p>Read each approved source, verify its hash, run the policy scan, and only then upsert the record into the candidate collection with build metadata attached.</p><pre><code># File: recovery/rebuild_candidate_index.py
points = []
manifest_rows = []

for index, doc in enumerate(approved_inventory, start=1):
    text = pathlib.Path(doc["text_path"]).read_text(encoding="utf-8")
    actual_sha256 = sha256_text(text)

    if actual_sha256 != doc["expected_sha256"]:
        continue
    if not passes_policy_scan(text):
        continue

    vector = encoder.encode(text, normalize_embeddings=True).tolist()
    points.append(
        PointStruct(
            id=index,
            vector=vector,
            payload={
                "doc_id": doc["doc_id"],
                "source_uri": doc["source_uri"],
                "provenance_hash": actual_sha256,
                "policy_scan_pass": True,
                "candidate_index": candidate_collection,
            },
        )
    )
    manifest_rows.append(
        {
            "doc_id": doc["doc_id"],
            "source_uri": doc["source_uri"],
            "provenance_hash": actual_sha256,
        }
    )

if points:
    client.upsert(collection_name=candidate_collection, points=points, wait=True)
</code></pre><h5>Step 3: Produce a signed rebuild manifest and hold promotion behind approval</h5><p>The candidate index should not be promoted based on trust in the job runner alone. Write a manifest that records the candidate collection, embedding model, approved documents, and build time, then sign it so the later cutover decision is auditable.</p><pre><code># File: recovery/write_candidate_manifest.py
import json
import pathlib
import subprocess

manifest = {
    "candidate_index": "rag_index_v43_candidate",
    "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
    "built_at": datetime.now(timezone.utc).isoformat(),
    "documents": manifest_rows,
}

manifest_path = pathlib.Path("recovery/manifests/rag_index_v43_candidate.json")
manifest_path.parent.mkdir(parents=True, exist_ok=True)
manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

subprocess.run(
    [
        "cosign",
        "sign-blob",
        "--yes",
        "--key",
        "keys/rag-build.key",
        "--output-signature",
        "recovery/manifests/rag_index_v43_candidate.sig",
        str(manifest_path),
    ],
    check=True,
)
</code></pre><h5>Step 4: Verify candidate readiness before alias cutover</h5><p>Promotion should require both a successful manifest verification and an explicit security approval record. Keep the cutover blocked if any candidate record lacks provenance, policy metadata, or approval evidence.</p><pre><code>cosign verify-blob --key keys/rag-build.pub --signature recovery/manifests/rag_index_v43_candidate.sig recovery/manifests/rag_index_v43_candidate.json
</code></pre><p><strong>Action:</strong> Rebuild the candidate collection only from allowlisted sources, attach provenance and policy metadata to every record, sign the manifest, and require explicit approval before any alias points production traffic at the rebuilt index.</p>`
                },
                {
                    "implementation": "Continuously monitor retrieved context for high-risk injection or poisoning patterns.",
                    "howTo": "<h5>Concept:</h5><p>Detection must happen on the retrieved chunks themselves, not only on the final model response. This control should inspect retrieved context for jailbreak instructions, secrets, policy-bypass phrases, or similarity to previously quarantined malicious content, then emit a structured risk finding. Do not bundle rollback logic into the detector; the detector's job is to score and report.</p><h5>Score Retrieved Chunks Before They Reach the Model</h5><pre><code># File: rag/retrieval_risk_detector.py\nimport re\nfrom dataclasses import dataclass\n\nHIGH_RISK_PATTERNS = [\n    re.compile(r\"ignore (all|previous) instructions\", re.IGNORECASE),\n    re.compile(r\"(api[_-]?key|access[_-]?token|secret)\", re.IGNORECASE),\n    re.compile(r\"exfiltrat(e|ion)|send .* to http\", re.IGNORECASE),\n]\n\n\n@dataclass\nclass RetrievalFinding:\n    chunk_id: str\n    risk_score: int\n    reason: str\n\n\ndef score_chunk(chunk_id: str, text: str) -> RetrievalFinding | None:\n    for pattern in HIGH_RISK_PATTERNS:\n        if pattern.search(text):\n            return RetrievalFinding(chunk_id=chunk_id, risk_score=90, reason=pattern.pattern)\n    return None\n</code></pre><p><strong>Action:</strong> Run this detector in the retrieval service or pre-generation middleware, send every finding to your SIEM or incident event stream, and attach the detector version, index version, and chunk IDs to the event. This evidence belongs to the monitoring side of recovery and should stay independent from the response automation that may follow.</p>"
                },
                {
                    "implementation": "Trigger automated rollback or quarantine workflows when retrieval-risk thresholds are crossed.",
                    "howTo": "<h5>Concept:</h5><p>Response automation belongs after detection. Once retrieval-risk findings cross a defined threshold, the platform should mark the active index as tainted, quarantine the implicated chunks, and cut traffic back to a trusted alias or snapshot. This workflow may run fully automatically or behind an approval gate, but it should consume structured detector output rather than re-scanning content itself.</p><h5>Consume Detector Findings and Execute the Recovery Workflow</h5><pre><code># File: rag/retrieval_response.py\n\ndef handle_retrieval_risk_event(event: dict, index_registry, alias_manager, quarantine_store) -> str:\n    if event[\"risk_score\"] &lt; 80:\n        return \"monitor_only\"\n\n    index_registry.mark_tainted(\n        index_name=event[\"active_index\"],\n        reason=\"retrieval-risk-threshold-crossed\",\n        incident_id=event[\"incident_id\"],\n    )\n\n    quarantine_store.quarantine_chunks(\n        chunk_ids=event[\"chunk_ids\"],\n        incident_id=event[\"incident_id\"],\n        source_index=event[\"active_index\"],\n    )\n\n    alias_manager.point_alias(\n        alias_name=event[\"serving_alias\"],\n        target_index=event[\"last_known_good_index\"],\n    )\n    return \"rollback_executed\"\n</code></pre><p><strong>Action:</strong> Define the exact risk threshold, approval mode, and fallback index selection in the recovery runbook. Archive the triggering detector event, the alias change, and the quarantine manifest together so the rollback can be justified and replayed during post-incident review.</p>"
                }
            ],
            "toolsOpenSource": [
                "Qdrant (collections, scroll/delete)",
                "Milvus / FAISS (vector storage, offline rebuild and re-ingest)",
                "OpenSearch / Elasticsearch (index aliases for atomic cutover)",
                "Great Expectations (pre-ingest dataset and schema validation)",
                "Open Policy Agent (pre-ingest policy checks for restored content)",
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
