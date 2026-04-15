export const isolateTactic = {
    "name": "Isolate",
    "purpose": "The \"Isolate\" tactic involves implementing measures to contain malicious activity and limit its potential spread or impact should an AI system or one of its components become compromised. This includes sandboxing AI processes, segmenting networks to restrict communication, and establishing mechanisms to quickly quarantine or throttle suspicious interactions or misbehaving AI entities.",
    "techniques": [
        {
            "id": "AID-I-001",
            "name": "AI Execution Sandboxing & Runtime Isolation",
            "description": "Execute AI models, autonomous agents, or individual AI tools and plugins within isolated environments such as sandboxes, containers, or microVMs. These environments must be configured with strict limits on resources, permissions, and network connectivity. The primary goal is that if an AI component is compromised or behaves maliciously, the impact is confined to the isolated sandbox, preventing harm to the host system or lateral movement.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0053 AI Agent Tool Invocation",
                        "AML.T0072 Reverse Shell",
                        "AML.T0050 Command and Scripting Interpreter",
                        "AML.T0029 Denial of AI Service",
                        "AML.T0034 Cost Harvesting",
                        "AML.T0089 Process Discovery (sandbox isolation limits process enumeration visibility)",
                        "AML.T0090 OS Credential Dumping (isolated environments prevent host credential access)",
                        "AML.T0102 Generate Malicious Commands (sandbox containment limits impact of generated malicious commands)",
                        "AML.T0103 Deploy AI Agent",
                        "AML.T0105 Escape to Host"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Compromised Container Images (L4)",
                        "Lateral Movement (Cross-Layer)",
                        "Agent Tool Misuse (L7)",
                        "Resource Hijacking (L4)",
                        "Framework Evasion (L3)",
                        "Orchestration Attacks (L4)",
                        "Lateral Movement (L4) (sandboxing prevents lateral movement from compromised AI processes)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM06:2025 Excessive Agency",
                        "LLM10:2025 Unbounded Consumption"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML06:2023 AI Supply Chain Attacks",
                        "ML05:2023 Model Theft"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI02:2026 Tool Misuse and Exploitation",
                        "ASI05:2026 Unexpected Code Execution (RCE)",
                        "ASI10:2026 Rogue Agents",
                        "ASI08:2026 Cascading Failures (sandboxing limits blast radius)",
                        "ASI04:2026 Agentic Supply Chain Vulnerabilities (sandboxing contains compromised supply chain components)"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.039 Compromising connected resources",
                        "NISTAML.051 Model Poisoning (Supply Chain) (contains compromised component impact)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-12.1 Tool Exploitation",
                        "AITech-13.1 Disruption of Availability",
                        "AITech-13.2 Cost Harvesting / Repurposing",
                        "AISubtech-9.1.1 Code Execution",
                        "AISubtech-9.1.3 Unauthorized or Unsolicited Network Access",
                        "AITech-14.1 Unauthorized Access"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "IIC: Insecure Integrated Component (sandboxing contains compromised integrated components)",
                        "RA: Rogue Actions (sandbox containment limits blast radius of rogue agent actions)",
                        "PIJ: Prompt Injection (sandboxed execution limits post-injection capabilities)",
                        "MDT: Model Deployment Tampering (sandboxed runtime contains tampered deployment impact)",
                        "DMS: Denial of ML Service (resource isolation prevents service disruption)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Agents - Core 13.2: Tool Misuse (sandboxing contains tool misuse impact)",
                        "Agents - Core 13.11: Unexpected RCE and Code Attacks",
                        "Agents - Core 13.4: Resource Overload (resource limits prevent overload)",
                        "Agents - Core 13.13: Rogue Agents in Multi-Agent Systems (sandbox isolation contains rogue agents)",
                        "Model Serving - Inference requests 9.3: Model breakout (sandboxing prevents model breakout)",
                        "Model 7.3: ML Supply chain vulnerabilities (sandboxing contains compromised supply chain components)",
                        "Algorithms 5.4: Malicious libraries (sandboxing contains impact of malicious libraries)",
                        "Platform 12.4: Unauthorized privileged access"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-I-001.001",
                    "name": "Container-Based Isolation", "pillar": ["infra"], "phase": ["operation"],
                    "description": "Utilizes container technologies like Docker or Kubernetes to package and run AI workloads in isolated user-space environments. This approach provides process and filesystem isolation and allows for resource management and network segmentation.",
                    "toolsOpenSource": [
                        "Docker",
                        "Podman",
                        "Kubernetes",
                        "OpenShift (container platform)",
                        "Falco (container runtime security)",
                        "Trivy (container vulnerability scanner)",
                        "Sysdig (container monitoring & security)",
                        "Calico (for Network Policies)",
                        "Cilium (for Network Policies and eBPF)"
                    ],
                    "toolsCommercial": [
                        "Mirantis Kubernetes Engine / Mirantis Container Runtime",
                        "Red Hat OpenShift Container Platform",
                        "Aqua Security",
                        "Prisma Cloud (Palo Alto Networks)",
                        "Microsoft Azure Kubernetes Service (AKS)",
                        "Google Kubernetes Engine (GKE)",
                        "Amazon Elastic Kubernetes Service (EKS)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0053 AI Agent Tool Invocation",
                                "AML.T0072 Reverse Shell",
                                "AML.T0029 Denial of AI Service",
                                "AML.T0034 Cost Harvesting",
                                "AML.T0097 Virtualization/Sandbox Evasion (container-level isolation raises evasion difficulty)",
                                "AML.T0105 Escape to Host"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Compromised Container Images (L4)",
                                "Lateral Movement (Cross-Layer)",
                                "Agent Tool Misuse (L7)",
                                "Resource Hijacking (L4)",
                                "Orchestration Attacks (L4)",
                                "Lateral Movement (L4) (container isolation prevents lateral movement)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM06:2025 Excessive Agency",
                                "LLM10:2025 Unbounded Consumption"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML06:2023 AI Supply Chain Attacks",
                                "ML05:2023 Model Theft"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI02:2026 Tool Misuse and Exploitation",
                                "ASI05:2026 Unexpected Code Execution (RCE)",
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities (compromised container images)",
                                "ASI10:2026 Rogue Agents"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.039 Compromising connected resources",
                                "NISTAML.051 Model Poisoning (Supply Chain) (compromised container supply chain)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-12.1 Tool Exploitation",
                                "AITech-13.1 Disruption of Availability",
                                "AISubtech-9.1.1 Code Execution",
                                "AITech-9.3 Dependency / Plugin Compromise (compromised container dependencies)",
                                "AITech-14.1 Unauthorized Access"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "IIC: Insecure Integrated Component (container isolation contains compromised components)",
                                "RA: Rogue Actions (container isolation limits rogue action blast radius)",
                                "MDT: Model Deployment Tampering (container hardening prevents deployment tampering)",
                                "DMS: Denial of ML Service (resource quotas prevent service disruption)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.11: Unexpected RCE and Code Attacks",
                                "Agents - Core 13.4: Resource Overload (container resource limits prevent overload)",
                                "Model 7.3: ML Supply chain vulnerabilities (hardened containers limit supply chain compromise)",
                                "Algorithms 5.4: Malicious libraries (container isolation contains malicious library impact)",
                                "Model Serving - Inference requests 9.7: Denial of Service (DoS) (resource quotas prevent DoS)",
                                "Platform 12.4: Unauthorized privileged access"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Deploy AI models and services in hardened, minimal-footprint container images.",
                            "howTo": `<h5>Concept:</h5><p>Container isolation only works if the runtime image is small, deterministic, and non-privileged. Build dependencies in one stage, copy only runtime artifacts into a minimal final stage, and run as a non-root user.</p><h5>Implement a hardened multi-stage image</h5><pre><code># File: Dockerfile
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/python -r requirements.txt

FROM gcr.io/distroless/python3-debian12
WORKDIR /app
COPY --from=builder /python /usr/local
COPY src/ /app/src/
USER 65532:65532
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/app/src/main.py"]</code></pre><h5>Verification</h5><pre><code>docker build -t ai-inference:secure .
docker run --rm ai-inference:secure id
trivy image --severity HIGH,CRITICAL --exit-code 1 ai-inference:secure</code></pre><p><strong>Action:</strong> Enforce multi-stage builds and non-root runtime for every production AI image. Keep the Dockerfile, image digest, and vulnerability-scan result as implementation evidence.</p>`
                        },
                        {
                            "implementation": "Apply Kubernetes security contexts to restrict container privileges (e.g., runAsNonRoot).",
                            "howTo": `<h5>Concept:</h5><p>Kubernetes security context is your kernel-level blast-radius limiter. It should prevent privilege escalation, drop Linux capabilities, and keep filesystem writes constrained.</p><h5>Apply restrictive pod and container security context</h5><pre><code># File: k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-api
  namespace: ai-production
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
      containers:
      - name: api
        image: registry.example.com/ai/inference-api:2026.04.14
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}</code></pre><h5>Verification</h5><pre><code>kubectl apply -f k8s/deployment.yaml
kubectl exec -n ai-production deploy/inference-api -- id
kubectl get pod -n ai-production -o jsonpath="{.items[0].spec.containers[0].securityContext}"</code></pre><p><strong>Action:</strong> Make this security context baseline mandatory for AI workloads and block deployments that omit it in admission policy.</p>`
                        },
                        {
                            "implementation": "Use network policies to enforce least-privilege communication between AI pods.",
                            "howTo": `<h5>Concept:</h5><p>AI pods should not have implicit east-west connectivity. Start with default deny and then add explicit allow paths for required service-to-service calls only.</p><h5>Step 1: Default deny ingress and egress</h5><pre><code># File: k8s/policies/default-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: ai-production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress</code></pre><h5>Step 2: Allow only gateway to inference on required port</h5><pre><code># File: k8s/policies/allow-gateway-to-inference.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-gateway-to-inference
  namespace: ai-production
spec:
  podSelector:
    matchLabels:
      app: inference-server
  policyTypes: ["Ingress"]
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8080</code></pre><h5>Verification</h5><pre><code>kubectl apply -f k8s/policies/default-deny.yaml
kubectl apply -f k8s/policies/allow-gateway-to-inference.yaml
kubectl get networkpolicy -n ai-production</code></pre><p><strong>Action:</strong> Keep a deny-by-default network baseline in every AI namespace and require explicit reviewed policy for each allowed traffic path.</p>`
                        },
                        {
                            "implementation": "Set strict resource quotas (CPU, memory, GPU) to prevent resource exhaustion attacks.",
                            "howTo": `<h5>Concept:</h5><p>Resource caps are a containment control against runaway prompts, recursive tool loops, and GPU abuse. Enforce limits at both pod level and namespace quota level.</p><h5>Set per-workload requests and limits</h5><pre><code># File: k8s/deployment-with-resources.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gpu-inference-server
  namespace: ai-production
spec:
  template:
    spec:
      containers:
      - name: server
        image: registry.example.com/ai/gpu-server:2026.04.14
        resources:
          requests:
            cpu: "1000m"
            memory: "4Gi"
            nvidia.com/gpu: "1"
          limits:
            cpu: "2000m"
            memory: "8Gi"
            nvidia.com/gpu: "1"</code></pre><h5>Set namespace-level quota</h5><pre><code># File: k8s/resourcequota-ai-production.yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ai-production-quota
  namespace: ai-production
spec:
  hard:
    requests.cpu: "40"
    limits.cpu: "80"
    requests.memory: "160Gi"
    limits.memory: "320Gi"
    requests.nvidia.com/gpu: "8"
    limits.nvidia.com/gpu: "8"</code></pre><p><strong>Action:</strong> Require explicit CPU/memory/GPU caps for every AI workload and keep quota manifests under version control as operational evidence.</p>`
                        },
                        {
                            "implementation": "Mount filesystems as read-only wherever possible.",
                            "howTo": `<h5>Concept:</h5><p>Read-only root filesystem blocks many post-exploitation actions (dropping binaries, modifying startup scripts, tampering local config). Only explicitly mounted temporary paths should be writable.</p><h5>Apply read-only root filesystem with explicit writable scratch path</h5><pre><code># File: k8s/readonly-fs-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inference-api
  namespace: ai-production
spec:
  template:
    spec:
      containers:
      - name: api
        image: registry.example.com/ai/inference-api:2026.04.14
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: tmp-storage
          mountPath: /tmp
      volumes:
      - name: tmp-storage
        emptyDir: {}</code></pre><h5>Verification</h5><pre><code>kubectl exec -n ai-production deploy/inference-api -- sh -c "touch /tmp/ok && touch /root/should-fail"
kubectl describe pod -n ai-production -l app=inference-api</code></pre><p><strong>Action:</strong> Enforce read-only root filesystem by default for AI runtime pods and require explicit review for any exception.</p>`
                        }
                    ]
                },
                {
                    "id": "AID-I-001.002",
                    "name": "MicroVM & Low-Level Sandboxing", "pillar": ["infra"], "phase": ["operation"],
                    "description": "Employs lightweight Virtual Machines (MicroVMs) or kernel-level sandboxing technologies to provide a stronger isolation boundary than traditional containers. This is critical for running untrusted code or highly sensitive AI workloads.",
                    "warning": {
                        "level": "Low to Medium on Startup Time & CPU/Memory Overhead",
                        "description": "<p>Stronger isolation technologies like gVisor or Firecracker impose a greater performance penalty than standard containers. <p><strong>CPU Overhead:</strong> Can introduce a <strong>5% to 15% CPU performance overhead</strong> compared to running in a standard container. <p><strong>Startup Time:</strong> Adds a small but measurable delay, typically <strong>5ms to 50ms</strong> of additional startup time per instance."
                    },
                    "toolsOpenSource": [
                        "Kata Containers (using QEMU or Firecracker)",
                        "Firecracker (AWS open-source microVM monitor)",
                        "gVisor (Google open-source user-space kernel)",
                        "seccomp-bpf (Linux kernel feature)",
                        "Wasmtime (WebAssembly runtime)",
                        "Wasmer (WebAssembly runtime)",
                        "eBPF (Extended Berkeley Packet Filter)",
                        "Cloud Hypervisor"
                    ],
                    "toolsCommercial": [
                        "AWS Lambda (built on Firecracker)",
                        "Google Cloud Run (uses gVisor)",
                        "Azure Container Instances (ACI) with confidential computing options",
                        "Red Hat OpenShift Virtualization (for Kata Containers management)",
                        "Managed WebAssembly execution platforms (Fastly Compute, Fermyon Cloud)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0053 AI Agent Tool Invocation",
                                "AML.T0072 Reverse Shell",
                                "AML.T0050 Command and Scripting Interpreter",
                                "AML.T0029 Denial of AI Service",
                                "AML.T0034 Cost Harvesting",
                                "AML.T0018.002 Manipulate AI Model: Embed Malware",
                                "AML.T0105 Escape to Host",
                                "AML.T0106 Exploitation for Credential Access",
                                "AML.T0011.002 User Execution: Poisoned AI Agent Tool"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Compromised Container Images (L4)",
                                "Lateral Movement (Cross-Layer)",
                                "Agent Tool Misuse (L7)",
                                "Resource Hijacking (L4)",
                                "Orchestration Attacks (L4)",
                                "Denial of Service (DoS) Attacks (L4)",
                                "Privilege Escalation (Cross-Layer)",
                                "Lateral Movement (L4) (microVM isolation prevents lateral movement)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM06:2025 Excessive Agency",
                                "LLM10:2025 Unbounded Consumption",
                                "LLM03:2025 Supply Chain"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML06:2023 AI Supply Chain Attacks",
                                "ML05:2023 Model Theft"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI05:2026 Unexpected Code Execution (RCE)",
                                "ASI02:2026 Tool Misuse and Exploitation",
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities (stronger isolation for compromised components)",
                                "ASI10:2026 Rogue Agents"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.039 Compromising connected resources",
                                "NISTAML.051 Model Poisoning (Supply Chain) (hardware-level isolation for compromised components)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-12.1 Tool Exploitation",
                                "AISubtech-9.1.1 Code Execution",
                                "AISubtech-12.1.3 Unsafe System / Browser / File Execution",
                                "AITech-13.1 Disruption of Availability",
                                "AITech-14.1 Unauthorized Access"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "IIC: Insecure Integrated Component (hardware-level isolation contains compromised components)",
                                "RA: Rogue Actions (microVM isolation prevents rogue actions from escaping to host)",
                                "MST: Model Source Tampering (microVM isolation contains impact of tampered model code)",
                                "MDT: Model Deployment Tampering (microVM isolation contains tampered deployment components)",
                                "DMS: Denial of ML Service (microVM resource limits prevent service disruption)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.11: Unexpected RCE and Code Attacks",
                                "Agents - Core 13.4: Resource Overload (microVM resource limits prevent overload)",
                                "Model Serving - Inference requests 9.3: Model breakout (microVM prevents model breakout to host)",
                                "Model 7.3: ML Supply chain vulnerabilities (hardware-level isolation for compromised components)",
                                "Algorithms 5.4: Malicious libraries (microVM isolation contains malicious library execution)",
                                "Platform 12.4: Unauthorized privileged access"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Use a stronger-than-container sandbox runtime for high-risk untrusted workloads, selecting either a hardware-virtualized microVM runtime or a userspace-kernel sandbox.",
                            "howTo": `<h5>Concept:</h5><p>For untrusted code execution, shared-kernel containers are often insufficient. Bind high-risk workloads to a hardened runtime class such as Kata (microVM boundary) or gVisor (userspace-kernel syscall mediation).</p><h5>Variant A: Kata runtime class for strongest isolation</h5><pre><code># File: k8s/runtimeclass-kata.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-qemu
handler: kata-qemu</code></pre><pre><code># File: k8s/pods/untrusted-code-runner.yaml
apiVersion: v1
kind: Pod
metadata:
  name: untrusted-code-runner
  namespace: ai-sandbox
spec:
  runtimeClassName: kata-qemu
  automountServiceAccountToken: false
  containers:
  - name: runner
    image: registry.example.com/ai/code-runner:2026.04.14
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]</code></pre><h5>Variant B: gVisor runtime class for syscall mediation</h5><pre><code># File: k8s/runtimeclass-gvisor.yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc</code></pre><h5>Verification</h5><pre><code>kubectl apply -f k8s/runtimeclass-kata.yaml
kubectl apply -f k8s/pods/untrusted-code-runner.yaml
kubectl get pod untrusted-code-runner -n ai-sandbox -o jsonpath="{.spec.runtimeClassName}"</code></pre><p><strong>Action:</strong> Tag untrusted workloads as <code>sandbox-required</code> and enforce runtime class selection in admission policy so they cannot run on default runtime.</p>`
                        },
                        {
                            "implementation": "Define strict seccomp-bpf profiles to whitelist only necessary system calls for model inference.",
                            "howTo": `<h5>Concept:</h5><p>Seccomp enforces syscall-level least privilege. Any syscall not allowlisted is denied by kernel policy.</p><h5>Step 1: Define a strict seccomp profile</h5><pre><code># File: /var/lib/kubelet/seccomp/profiles/inference-profile.json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "openat", "close", "mmap", "munmap", "futex", "epoll_wait", "recvfrom", "sendto", "socket"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}</code></pre><h5>Step 2: Bind profile in deployment security context</h5><pre><code># File: k8s/deployment.yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/inference-profile.json</code></pre><h5>Verification</h5><pre><code>kubectl apply -f k8s/deployment.yaml
kubectl get pod -n ai-production -o jsonpath="{.items[0].spec.securityContext.seccompProfile.localhostProfile}"</code></pre><p><strong>Action:</strong> Keep seccomp profile under version control and require profile review when runtime dependencies change.</p>`
                        },
                        {
                            "implementation": "Utilize WebAssembly (WASM) runtimes to run AI models in a high-performance, secure sandbox.",
                            "howTo": `<h5>Concept:</h5><p><strong>Delivery level: reusable module.</strong> WASM isolation is practical when inference logic can be compiled and invoked through a strict host boundary. The host controls capabilities; the module gets none by default.</p><h5>Build a WASM module</h5><pre><code>// File: inference-engine/src/lib.rs
#[no_mangle]
pub extern "C" fn run_inference(input: i32) -> i32 {
    input * 2
}</code></pre><h5>Run with capability-minimal host runtime</h5><pre><code># File: host_app/run_wasm.py
from wasmtime import Store, Module, Linker

store = Store()
module = Module.from_file(store.engine, "./inference_engine.wasm")
linker = Linker(store.engine)  # no FS/network imports exposed
instance = linker.instantiate(store, module)
run_inference = instance.exports(store)["run_inference"]
print(run_inference(store, 21))</code></pre><p><strong>Action:</strong> Use this module pattern for bounded high-risk functions and keep capability mapping at the host layer as auditable evidence.</p>`
                        }
                    ]
                },
                {
                    "id": "AID-I-001.003",
                    "name": "Ephemeral Single-Use Sandboxes for Tools",
                    "pillar": ["infra"],
                    "phase": ["operation"],
                    "description": "Run tool executions inside strongly isolated, single-use sandboxes (e.g., microVMs). Destroy the environment immediately after one invocation to prevent persistence and cross-session contamination.",
                    "defendsAgainst": [
                        { "framework": "MITRE ATLAS", "items": ["AML.T0050 Command and Scripting Interpreter", "AML.T0072 Reverse Shell", "AML.T0053 AI Agent Tool Invocation", "AML.T0100 AI Agent Clickbait (ephemeral teardown prevents clickbait-triggered persistence)"] },
                        { "framework": "MAESTRO", "items": ["Orchestration Attacks (L4)", "Lateral Movement (Cross-Layer)", "Agent Tool Misuse (L7)", "Resource Hijacking (L4) (ephemeral teardown prevents sustained hijacking)"] },
                        { "framework": "OWASP LLM Top 10 2025", "items": ["LLM06:2025 Excessive Agency"] },
                        { "framework": "OWASP ML Top 10 2023", "items": ["ML06:2023 AI Supply Chain Attacks"] },
                        { "framework": "OWASP Agentic AI Top 10 2026", "items": ["ASI02:2026 Tool Misuse and Exploitation", "ASI05:2026 Unexpected Code Execution (RCE)", "ASI10:2026 Rogue Agents"] },
                        { "framework": "NIST Adversarial Machine Learning 2025", "items": ["NISTAML.039 Compromising connected resources", "NISTAML.018 Prompt Injection (ephemeral teardown destroys injected persistence)"] },
                        { "framework": "Cisco Integrated AI Security and Safety Framework", "items": ["AISubtech-9.1.1 Code Execution", "AITech-12.1 Tool Exploitation", "AISubtech-9.1.3 Unauthorized or Unsolicited Network Access"] },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "IIC: Insecure Integrated Component (ephemeral teardown destroys compromised component state)",
                                "RA: Rogue Actions (ephemeral execution prevents persistent rogue behavior)",
                                "PIJ: Prompt Injection (ephemeral teardown destroys injected persistence)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.2: Tool Misuse (ephemeral teardown prevents tool misuse persistence)",
                                "Agents - Core 13.11: Unexpected RCE and Code Attacks",
                                "Agents - Core 13.13: Rogue Agents in Multi-Agent Systems (ephemeral sandboxes prevent rogue agent persistence)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Provision a fresh, single-use sandbox (microVM / gVisor / Kata) for every tool invocation, execute once, then destroy it.",
                            "howTo": "<h5>Concept:</h5><p>High-risk tool execution should never happen in a reused runtime. The control is to create a new isolated workload for each invocation, copy in only the minimum payload, execute once, capture the result, then destroy the workload and its ephemeral filesystem.</p><h5>Step 1: Create a one-shot sandbox pod with an isolated runtime class</h5><p>Use a runtime class such as Kata or gVisor so the tool runs in a fresh microVM-backed or syscall-intercepted boundary. The pod must use an emptyDir workspace and no long-lived shared volumes.</p><pre><code># File: isolate/single_use_sandbox.py\nfrom __future__ import annotations\n\nimport base64\nimport uuid\n\nfrom kubernetes import client, config, watch\n\n\nNAMESPACE = \"ai-sandbox\"\nRUNTIME_CLASS_NAME = \"kata-qemu\"\n\n\ndef build_sandbox_pod(pod_name: str, payload_b64: str) -&gt; client.V1Pod:\n    return client.V1Pod(\n        metadata=client.V1ObjectMeta(\n            name=pod_name,\n            labels={\"app\": \"tool-sandbox\", \"sandbox-mode\": \"single-use\"},\n        ),\n        spec=client.V1PodSpec(\n            runtime_class_name=RUNTIME_CLASS_NAME,\n            restart_policy=\"Never\",\n            automount_service_account_token=False,\n            containers=[\n                client.V1Container(\n                    name=\"runner\",\n                    image=\"python:3.11-slim\",\n                    command=[\n                        \"/bin/sh\",\n                        \"-lc\",\n                        \"echo \\\"$TOOL_PAYLOAD_B64\\\" | base64 -d &gt; /work/task.py && python /work/task.py\",\n                    ],\n                    env=[client.V1EnvVar(name=\"TOOL_PAYLOAD_B64\", value=payload_b64)],\n                    volume_mounts=[client.V1VolumeMount(name=\"work\", mount_path=\"/work\")],\n                    security_context=client.V1SecurityContext(\n                        run_as_non_root=True,\n                        allow_privilege_escalation=False,\n                        read_only_root_filesystem=True,\n                        capabilities=client.V1Capabilities(drop=[\"ALL\"]),\n                    ),\n                )\n            ],\n            volumes=[client.V1Volume(name=\"work\", empty_dir=client.V1EmptyDirVolumeSource())],\n        ),\n    )\n\n\ndef run_tool_once(tool_payload: bytes) -&gt; dict:\n    config.load_incluster_config()\n    api = client.CoreV1Api()\n    pod_name = f\"tool-sandbox-{uuid.uuid4().hex[:10]}\"\n    payload_b64 = base64.b64encode(tool_payload).decode(\"utf-8\")\n    pod = build_sandbox_pod(pod_name, payload_b64)\n    api.create_namespaced_pod(namespace=NAMESPACE, body=pod)\n\n    try:\n        for event in watch.Watch().stream(\n            api.list_namespaced_pod,\n            namespace=NAMESPACE,\n            field_selector=f\"metadata.name={pod_name}\",\n            timeout_seconds=300,\n        ):\n            phase = event[\"object\"].status.phase\n            if phase in {\"Succeeded\", \"Failed\"}:\n                logs = api.read_namespaced_pod_log(name=pod_name, namespace=NAMESPACE)\n                return {\"pod_name\": pod_name, \"phase\": phase, \"logs\": logs}\n    finally:\n        api.delete_namespaced_pod(\n            name=pod_name,\n            namespace=NAMESPACE,\n            grace_period_seconds=0,\n            propagation_policy=\"Background\",\n        )\n</code></pre><h5>Step 2: Verify that the pod is actually destroyed after the call</h5><p>Run two invocations back to back and confirm each receives a different pod name and that the prior pod no longer exists. Also confirm there is no shared PVC or hostPath mount attached to the sandbox pod.</p><p><strong>Action:</strong> Treat every tool call as untrusted and enforce a strict <code>spawn → run → collect → destroy</code> lifecycle with a fresh isolated runtime each time. The evidence you want is the pod creation log, the captured output, and the deletion event for every sandbox invocation.</p>"
                        }
                    ],
                    "toolsOpenSource": ["gVisor", "Kata Containers", "Firecracker"],
                    "toolsCommercial": ["AWS Firecracker-backed services (Lambda, Fargate)", "Google GKE Sandbox"]
                },
                {
                    "id": "AID-I-001.004",
                    "name": "Sandbox Network Egress Restrictions",
                    "pillar": ["infra"],
                    "phase": ["operation"],
                    "description": "Restrict outbound network destinations for sandboxed executions with default-deny egress policy and narrow allowlists to reduce exfiltration, callback traffic, and lateral movement after code execution.",
                    "defendsAgainst": [
                        { "framework": "MITRE ATLAS", "items": ["AML.T0072 Reverse Shell", "AML.T0025 Exfiltration via Cyber Means", "AML.T0050 Command and Scripting Interpreter"] },
                        { "framework": "MAESTRO", "items": ["Lateral Movement (Cross-Layer)", "Data Leakage (Cross-Layer) (egress restrictions prevent data exfiltration)", "Orchestration Attacks (L4)"] },
                        { "framework": "OWASP LLM Top 10 2025", "items": ["LLM06:2025 Excessive Agency", "LLM02:2025 Sensitive Information Disclosure (egress restrictions block exfiltration)"] },
                        { "framework": "OWASP ML Top 10 2023", "items": ["ML05:2023 Model Theft (network restrictions prevent model exfiltration)"] },
                        { "framework": "OWASP Agentic AI Top 10 2026", "items": ["ASI02:2026 Tool Misuse and Exploitation"] },
                        { "framework": "NIST Adversarial Machine Learning 2025", "items": ["NISTAML.039 Compromising connected resources", "NISTAML.031 Model Extraction (network restrictions block extraction)"] },
                        { "framework": "Cisco Integrated AI Security and Safety Framework", "items": ["AISubtech-9.1.3 Unauthorized or Unsolicited Network Access", "AITech-8.2 Data Exfiltration / Exposure"] },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "MXF: Model Exfiltration (network egress restrictions block model exfiltration)",
                                "SDD: Sensitive Data Disclosure (egress restrictions prevent data exfiltration)",
                                "RA: Rogue Actions (egress restrictions limit post-compromise outbound actions)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Model 7.2: Model assets leak (egress restrictions block model asset exfiltration)",
                                "Agents - Core 13.11: Unexpected RCE and Code Attacks",
                                "Agents - Tools MCP Server 13.23: Data Exfiltration (network egress restrictions block data exfiltration)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Enforce default-deny outbound egress allowlists for sandboxed runtimes.",
                            "howTo": `<h5>Concept:</h5><p>Default-deny egress blocks reverse shells and data exfiltration from compromised sandbox runtimes. Outbound connectivity must be explicit and minimal.</p><h5>Step 1: Deny all outbound traffic by default</h5><pre><code># File: k8s/policies/default-deny-egress.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: ai-sandbox
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress: []</code></pre><h5>Step 2: Allow only required internal destination</h5><pre><code># File: k8s/policies/allow-egress-to-inference-gateway.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-inference-gateway
  namespace: ai-sandbox
spec:
  podSelector:
    matchLabels:
      role: sandboxed-tool
  policyTypes: ["Egress"]
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: ai-core-services
      podSelector:
        matchLabels:
          app: inference-gateway
    ports:
    - protocol: TCP
      port: 8443</code></pre><h5>Verification</h5><pre><code>kubectl apply -f k8s/policies/default-deny-egress.yaml
kubectl apply -f k8s/policies/allow-egress-to-inference-gateway.yaml
kubectl get networkpolicy -n ai-sandbox</code></pre><p><strong>Action:</strong> Keep every sandbox namespace on default-deny egress and require explicit reviewed rules for each outbound dependency.</p>`
                        }
                    ],
                    "toolsOpenSource": ["Kubernetes NetworkPolicy", "Cilium", "Project Calico"],
                    "toolsCommercial": ["Calico Enterprise", "Cilium Enterprise"]
                },
                {
                    "id": "AID-I-001.005",
                    "name": "Pre-Execution Behavioral Analysis in Ephemeral Sandboxes",
                    "pillar": ["infra", "app"],
                    "phase": ["operation", "validation"],
                    "description": "This proactive defense technique subjects any AI-generated executable artifact (e.g., scripts, binaries, container images created by an agent) to mandatory behavioral analysis within a short-lived, strongly isolated sandbox (such as a microVM) *before* it is deployed or executed in a production context. This pre-execution security gate applies to artifacts originating from both automated CI/CD pipelines and interactive developer IDEs, serving as a final vetting step to contain threats from malicious AI-generated code before they can have any impact.",
                    "toolsOpenSource": [
                        "Firecracker",
                        "Kata Containers",
                        "gVisor",
                        "QEMU/KVM",
                        "Falco",
                        "Cilium Tetragon",
                        "strace",
                        "Sysdig",
                        "Wazuh (in-guest EDR)"
                    ],
                    "toolsCommercial": [
                        "Joe Sandbox",
                        "ANY.RUN",
                        "Behavioral analysis / malware detonation sandboxes (CrowdStrike Falcon Sandbox, Palo Alto WildFire)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0050 Command and Scripting Interpreter",
                                "AML.T0072 Reverse Shell",
                                "AML.T0018.002 Manipulate AI Model: Embed Malware",
                                "AML.T0025 Exfiltration via Cyber Means",
                                "AML.T0097 Virtualization/Sandbox Evasion (pre-execution analysis detects sandbox evasion techniques)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Compromised Container Images (L4)",
                                "Agent Tool Misuse (L7)",
                                "Lateral Movement (Cross-Layer)",
                                "Resource Hijacking (L4)",
                                "Supply Chain Attacks (Cross-Layer)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM05:2025 Improper Output Handling"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML06:2023 AI Supply Chain Attacks"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI05:2026 Unexpected Code Execution (RCE)",
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.051 Model Poisoning (Supply Chain) (detects malicious behavior from poisoned models)",
                                "NISTAML.039 Compromising connected resources"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AISubtech-9.1.1 Code Execution",
                                "AITech-9.3 Dependency / Plugin Compromise",
                                "AITech-12.2 Insecure Output Handling",
                                "AISubtech-12.2.1 Code Detection / Malicious Code Output",
                                "AITech-11.1 Environment-Aware Evasion (behavioral analysis detects environment-probing before execution)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "MST: Model Source Tampering (behavioral analysis detects tampered model artifacts)",
                                "IIC: Insecure Integrated Component (pre-execution analysis detects malicious integrated components)",
                                "IMO: Insecure Model Output (behavioral analysis detects malicious output generation)",
                                "RA: Rogue Actions (pre-execution analysis catches rogue behavior before production)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Model 7.1: Backdoor machine learning / Trojaned model (behavioral analysis detects trojaned models)",
                                "Model 7.3: ML Supply chain vulnerabilities (pre-execution analysis vets supply chain artifacts)",
                                "Algorithms 5.4: Malicious libraries (behavioral analysis detects malicious library behavior)",
                                "Agents - Core 13.11: Unexpected RCE and Code Attacks"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Orchestrate an automated analysis workflow using microVMs for strong isolation.",
                            "howTo": "<h5>Concept:</h5><p>Pre-execution analysis should be an automated admission workflow, not an analyst clicking around in a shared sandbox. The orchestrator receives the artifact, provisions an isolated runtime, executes the artifact under observation, captures a machine-readable verdict, and destroys the runtime before any promotion decision is made.</p><h5>Step 1: Submit the artifact to an isolated analysis job</h5><p>Use a dedicated analysis image and a microVM-backed runtime class so every analysis starts from a clean environment with no shared state.</p><pre><code># File: sandboxing_service/orchestrator.py\nfrom __future__ import annotations\n\nimport base64\nimport json\nimport uuid\n\nfrom kubernetes import client, config, watch\n\n\nNAMESPACE = \"ai-analysis\"\nRUNTIME_CLASS_NAME = \"kata-qemu\"\nANALYZER_IMAGE = \"ghcr.io/aidefend/sandbox-analyzer:1.0.0\"\n\n\ndef build_analysis_pod(analysis_id: str, script_b64: str, artifact_sha256: str) -&gt; client.V1Pod:\n    return client.V1Pod(\n        metadata=client.V1ObjectMeta(\n            name=analysis_id,\n            labels={\n                \"app\": \"artifact-analysis\",\n                \"artifact-sha256\": artifact_sha256,\n            },\n        ),\n        spec=client.V1PodSpec(\n            runtime_class_name=RUNTIME_CLASS_NAME,\n            restart_policy=\"Never\",\n            automount_service_account_token=False,\n            containers=[\n                client.V1Container(\n                    name=\"analyzer\",\n                    image=ANALYZER_IMAGE,\n                    command=[\"/bin/sh\", \"-lc\", \"/opt/analyze.sh\"],\n                    env=[\n                        client.V1EnvVar(name=\"SCRIPT_B64\", value=script_b64),\n                        client.V1EnvVar(name=\"ARTIFACT_SHA256\", value=artifact_sha256),\n                    ],\n                    security_context=client.V1SecurityContext(\n                        run_as_non_root=True,\n                        allow_privilege_escalation=False,\n                        read_only_root_filesystem=True,\n                        capabilities=client.V1Capabilities(drop=[\"ALL\"]),\n                    ),\n                )\n            ],\n        ),\n    )\n\n\ndef analyze_script_in_sandbox(script_content: bytes, artifact_sha256: str) -&gt; dict:\n    config.load_incluster_config()\n    api = client.CoreV1Api()\n    analysis_id = f\"artifact-analysis-{uuid.uuid4().hex[:10]}\"\n    pod = build_analysis_pod(\n        analysis_id=analysis_id,\n        script_b64=base64.b64encode(script_content).decode(\"utf-8\"),\n        artifact_sha256=artifact_sha256,\n    )\n    api.create_namespaced_pod(namespace=NAMESPACE, body=pod)\n\n    try:\n        for event in watch.Watch().stream(\n            api.list_namespaced_pod,\n            namespace=NAMESPACE,\n            field_selector=f\"metadata.name={analysis_id}\",\n            timeout_seconds=600,\n        ):\n            phase = event[\"object\"].status.phase\n            if phase in {\"Succeeded\", \"Failed\"}:\n                report = api.read_namespaced_pod_log(name=analysis_id, namespace=NAMESPACE)\n                return json.loads(report)\n    finally:\n        api.delete_namespaced_pod(\n            name=analysis_id,\n            namespace=NAMESPACE,\n            grace_period_seconds=0,\n            propagation_policy=\"Background\",\n        )\n</code></pre><h5>Step 2: Require a machine-readable verdict for promotion</h5><p>The analyzer should emit JSON that includes the artifact hash, observed behaviors, and a final verdict such as <code>allow</code> or <code>deny</code>. The CI/CD or registry admission path should refuse promotion if the verdict is missing or negative.</p><p><strong>Action:</strong> Put every generated script, binary, or container artifact through an isolated analysis service before promotion. The evidence you want is the analysis report, the artifact hash it covered, and the deletion event proving the analysis runtime was torn down after the run.</p>"
                        },
                        {
                            "implementation": "Define and enforce a strict behavioral security policy within the sandbox.",
                            "howTo": "<h5>Concept:</h5><p>The effectiveness of the sandbox depends on the rules used to judge behavior. A strict, default-deny policy should be created that defines what the generated code is allowed to do. Any action outside this narrow scope is considered malicious. All network egress should be forced through a monitored proxy.</p><h5>Implement a Falco Rule for a Code Interpreter</h5><p>Falco is a runtime security tool that can monitor kernel syscalls. This Falco rule defines the expected behavior for a sandboxed Python script. It allows file operations within `/tmp` but blocks network connections and file access elsewhere.</p><pre><code># File: sandbox_policies/falco_code_interpreter.yaml\n\n- rule: Disallowed Egress from AI-Sandbox\n  desc: Detects any outbound network connection from the sandboxed Python interpreter.\n  condition: >\n    evt.type = connect and evt.dir = > and proc.name = python3 and not proc.aname contains \"analysis_proxy\"\n  output: \"Disallowed network egress by AI-generated code (proc=%proc.name command=%proc.cmdline connection=%fd.name)\"\n  priority: CRITICAL\n  tags: [network, ai_sandbox]\n\n- rule: Disallowed File Write from AI-Sandbox\n  desc: Detects file writes outside of the /tmp directory by a sandboxed python process.\n  condition: >\n    (evt.type = openat or evt.type = open) and evt.dir = > and (fd.open_write=true) \n    and proc.name = python3 and not fd.name startswith /tmp/\n  output: \"Disallowed file write by AI-generated code (proc=%proc.name file=%fd.name)\"\n  priority: CRITICAL\n  tags: [filesystem, ai_sandbox]\n</code></pre><p><strong>Action:</strong> Define a strict behavioral policy for your pre-execution sandbox using a tool like Falco or Tetragon. The policy must deny all network egress by default (forcing traffic through a monitored proxy) and restrict file system writes to a designated temporary directory.</p>"
                        },
                        {
                            "implementation": "Generate a signed, verifiable analysis report for CI/CD admission control.",
                            "howTo": "<h5>Concept:</h5><p>The result of the sandbox analysis should be a formal, cryptographically signed report. This report acts as a 'passport' for the AI-generated artifact. A CI/CD pipeline or deployment orchestrator can then use this signed report as a verifiable prerequisite before admitting the artifact into a production environment.</p><h5>Implement a Report Generation and Signing Step</h5><pre><code># File: sandboxing_service/reporter.py\nimport json\nfrom cryptography.hazmat.primitives import hashes\nfrom cryptography.hazmat.primitives.asymmetric import padding\n\ndef generate_signed_report(artifact_hash, verdict, analysis_logs):\n    # 1. Create the report payload\n    report = {\n        'artifact_sha256': artifact_hash,\n        'verdict': verdict, # 'ALLOWED' or 'DENIED'\n        'analysis_timestamp': datetime.utcnow().isoformat(),\n        'policy_version': '1.3',\n        'summary': analysis_logs # Summary of observed behaviors\n    }\n    report_bytes = json.dumps(report, sort_keys=True).encode('utf-8')\n\n    # 2. Sign the report with the sandbox service's private key\n    # private_key = load_sandbox_private_key()\n    signature = private_key.sign(\n        report_bytes,\n        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),\n        hashes.SHA256()\n    )\n\n    return {'report': report, 'signature': signature.hex()}\n\n# The CI/CD pipeline would then check this signature before deploying the artifact.\n</code></pre><p><strong>Action:</strong> At the end of a sandbox analysis, generate a structured JSON report containing the artifact's hash and the verdict. Cryptographically sign this report with a key trusted by your CI/CD system. The deployment pipeline must include a step to verify this signature before allowing the artifact to be promoted.</p>"
                        },
                        {
                            "implementation": "Monitor for anti-analysis and sandbox evasion techniques.",
                            "howTo": "<h5>Concept:</h5><p>Advanced malicious code will actively try to detect if it's running in an analysis environment. The sandbox must be instrumented to detect these evasion attempts, such as detecting unusually long sleep calls, probing for VM-specific hardware IDs, or checking CPU features.</p><h5>Implement an Anti-Evasion Detection Policy</h5><p>This can be done with a combination of syscall monitoring and API hooking inside the sandbox.</p><pre><code># Conceptual Falco rule for detecting long sleep calls\n- rule: Suspicious Long Sleep\n  desc: An AI-generated script called sleep or usleep with a long duration, possibly to evade automated analysis.\n  condition: syscall.type = nanosleep and evt.arg.rqtp.tv_sec > 60 and proc.name = python3\n  output: \"Suspicious long sleep detected (duration=%evt.arg.rqtp.tv_sec) from AI-generated code.\"\n  priority: WARNING\n  tags: [anti-analysis, ai_sandbox]\n</code></pre><p><strong>Action:</strong> Enhance your sandbox's behavioral policy to include rules that detect common anti-analysis techniques. Flag any artifact that attempts to perform environment checks or exhibits unusually delayed execution as suspicious.</p>"
                        }
                    ]
                }
            ]
        },
        {
            "id": "AID-I-002",
            "name": "Network Segmentation & Isolation for AI Systems",
            "description": "Implement network segmentation and microsegmentation strategies using firewalls, proxies, private endpoints, and transport layer security to enforce strict communication boundaries for AI systems. This involves isolating internal components (e.g., training vs. inference environments, data stores) to limit lateral movement, and securing connections to external dependencies (e.g., MaaS APIs) to prevent data exfiltration, SSRF, and MitM attacks. The goal is to reduce the blast radius of a compromise by enforcing least-privilege network access both internally and externally.",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0044 Full AI Model Access (limits access)",
                        "AML.T0036 Data from Information Repositories (limits access)",
                        "AML.T0025 Exfiltration via Cyber Means",
                        "AML.T0049 Exploit Public-Facing Application (SSRF-driven internal pivot)",
                        "AML.T0072 Reverse Shell",
                        "AML.T0075 Cloud Service Discovery (network segmentation limits cloud resource enumeration)",
                        "AML.T0096 AI Service API (network isolation restricts C2 via AI service channels)",
                        "AML.T0108 AI Agent (C2)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Lateral Movement (Cross-Layer)",
                        "Compromised RAG Pipelines (L2) (isolating internal DB access)",
                        "Data Leakage (Cross-Layer)",
                        "Data Exfiltration (L2)",
                        "Orchestration Attacks (L4)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM02:2025 Sensitive Information Disclosure (via exfiltration)",
                        "LLM06:2025 Excessive Agency",
                        "LLM03:2025 Supply Chain (reduces exposure to compromised upstream providers)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML05:2023 Model Theft",
                        "ML06:2023 AI Supply Chain Attacks"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI02:2026 Tool Misuse and Exploitation (network restrictions limit tool reach)",
                        "ASI03:2026 Identity and Privilege Abuse (network segmentation enforces boundaries)",
                        "ASI10:2026 Rogue Agents (network isolation contains rogue agents)",
                        "ASI07:2026 Insecure Inter-Agent Communication"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.039 Compromising connected resources",
                        "NISTAML.031 Model Extraction (network restrictions block extraction paths)",
                        "NISTAML.038 Data Extraction"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-8.2 Data Exfiltration / Exposure",
                        "AISubtech-8.2.3 Data Exfiltration via Agent Tooling",
                        "AISubtech-9.1.3 Unauthorized or Unsolicited Network Access",
                        "AITech-14.1 Unauthorized Access"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "MXF: Model Exfiltration (network segmentation limits model exfiltration paths)",
                        "SDD: Sensitive Data Disclosure (segmentation limits data exposure scope)",
                        "RA: Rogue Actions (network isolation contains rogue agent network reach)",
                        "IIC: Insecure Integrated Component (segmentation limits compromised component lateral movement)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Model 7.2: Model assets leak (network segmentation limits exfiltration paths)",
                        "Agents - Core 13.13: Rogue Agents in Multi-Agent Systems (network isolation contains rogue agents)",
                        "Agents - Tools MCP Server 13.23: Data Exfiltration (network segmentation blocks data exfiltration paths)",
                        "Platform 12.4: Unauthorized privileged access (network segmentation enforces access boundaries)",
                        "Platform 12.7: Initial Access (segmentation limits initial access scope)",
                        "Agents - Tools MCP Server 13.25: Insecure Communication"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-I-002.001",
                    "name": "Internal AI Network Segmentation",
                    "pillar": ["infra"],
                    "phase": ["building", "operation"],
                    "description": "Implement network segmentation and microsegmentation strategies to isolate AI systems and their <em>internal</em> components (e.g., training environments, model serving endpoints, data stores, agent control planes) from general corporate networks and other critical IT/OT systems.<br/><br/><strong>Internal Communication Controls</strong><br/>Enforces strict internal communication rules through firewalls, security groups, and network policies to limit lateral movement and reduce the internal blast radius of a compromise.<br/><br/><strong>Agent Backend Isolation</strong><br/>This also isolates high-privilege agent backends (e.g. orchestration layers with access to credentials, vector DBs, or model registries) from lower-trust, user-facing inference frontends, so that a compromised public-facing agent cannot laterally move into data-rich components.",
                    "toolsOpenSource": [
                        "Linux Netfilter (iptables, nftables), firewalld",
                        "Kubernetes Network Policies",
                        "Service Mesh (Istio, Linkerd, Kuma) for internal policies",
                        "CNI plugins (Calico, Cilium)",
                        "Cloud provider CLIs/SDKs (AWS CLI, gcloud, Azure CLI)",
                        "Terraform, Ansible, CloudFormation, Pulumi (for IaC)"
                    ],
                    "toolsCommercial": [
                        "Microsegmentation platforms (Illumio, Guardicore [Akamai], Cisco Secure Workload)",
                        "Cloud-native firewall services (AWS Security Groups, Azure NSGs, GCP Firewall Rules)",
                        "Commercial Service Mesh offerings (e.g., Istio distributions with enterprise support)"
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Host critical AI components on dedicated network segments (VLANs, VPCs).",
                            "howTo": "<h5>Concept:</h5><p>This is 'macro-segmentation'. By placing different environments (e.g., training, inference, data storage) in separate virtual networks, you create strong, high-level boundaries. A compromise in one segment, like a data science experimentation VPC, is prevented at the network level from accessing the production inference VPC.</p><h5>Define Separate VPCs with Infrastructure as Code</h5><p>Use a tool like Terraform to define distinct, non-overlapping Virtual Private Clouds (VPCs) for each environment. This ensures the separation is deliberate, version-controlled, and reproducible.</p><pre><code># File: infrastructure/networks.tf (Terraform)\n\n# VPC for the production AI inference service\nresource \"aws_vpc\" \"prod_vpc\" {\n  cidr_block = \"10.0.0.0/16\"\n  tags = { Name = \"aidefend-prod-vpc\" }\n}\n\n# A completely separate VPC for the AI model training environment\nresource \"aws_vpc\" \"training_vpc\" {\n  cidr_block = \"10.1.0.0/16\"\n  tags = { Name = \"aidefend-training-vpc\" }\n}\n\n# A VPC for the data science team's sandboxed experimentation\nresource \"aws_vpc\" \"sandbox_vpc\" {\n  cidr_block = \"10.2.0.0/16\"\n  tags = { Name = \"aidefend-sandbox-vpc\" }\n}\n\n# By default, these VPCs cannot communicate with each other.\n# Any connection (e.g., VPC Peering) must be explicitly defined and secured.</code></pre><p><strong>Action:</strong> Provision separate, dedicated VPCs for your production, staging, and development/training environments. Do not allow VPC peering between them by default. All promotion of artifacts (like models) between environments should happen through a secure, audited CI/CD pipeline that connects to registries, not by direct network access between the VPCs.</p>"
                        },
                        {
                            "implementation": "Apply least privilege to *internal* network communications for AI systems.",
                            "howTo": "<h5>Concept:</h5><p>Within a VPC, use firewall rules (like Security Groups in AWS) to enforce least-privilege access between components. A resource should only be able to receive traffic on the specific ports and from the specific internal sources it absolutely needs to function. All other traffic should be denied.</p><h5>Create Fine-Grained Security Group Rules</h5><p>This Terraform example defines two security groups. The first is for a model inference server, which only allows traffic on port 8080 from the second security group, which is attached to an internal API gateway. This prevents anyone else, including other services in the same VPC, from directly accessing the model. For default-deny egress in AWS Security Groups, explicitly set an empty egress rule list.</p><pre><code># File: infrastructure/security_groups.tf (Terraform)\ndata \"aws_vpc\" \"prod_vpc\" {\n  filter { name = \"tag:Name\" values = [\"aidefend-prod-vpc\"] }\n}\n\n# Security group for the Internal API Gateway\nresource \"aws_security_group\" \"internal_api_gateway_sg\" {\n  name_prefix = \"internal-api-gateway-sg-\"\n  vpc_id      = data.aws_vpc.prod_vpc.id\n  tags        = { Name = \"internal-api-gateway-sg\" }\n  # Define egress rules needed for the gateway itself as required\n}\n\n# Security group for the Model Inference service\nresource \"aws_security_group\" \"inference_sg\" {\n  name_prefix = \"inference-server-sg-\"\n  vpc_id      = data.aws_vpc.prod_vpc.id\n  tags        = { Name = \"inference-server-sg\" }\n\n  # Ingress Rule: Allow traffic ONLY from the Internal API Gateway on the app port\n  ingress {\n    description              = \"Allow TCP 8080 from Internal API Gateway\"\n    from_port                = 8080\n    to_port                  = 8080\n    protocol                 = \"tcp\"\n    source_security_group_id = aws_security_group.internal_api_gateway_sg.id\n  }\n\n  # Default-deny egress: explicitly empty egress list\n  egress = []\n}\n</code></pre><p><strong>Action:</strong> For each component of your AI system, create a dedicated security group. Define ingress rules that only allow traffic from the specific security groups of the internal services that need to connect to it. Implement default-deny egress by setting <code>egress = []</code>, then add narrowly-scoped outbound rules only if strictly required. Note: Some cloud consoles auto-add 'allow all egress' to new Security Groups. Using Infrastructure as Code (Terraform/CloudFormation) lets you enforce egress = [] and keep outbound default-deny, which many consoles won't let you set manually.</p>"
                        },
                        {
                            "implementation": "Implement microsegmentation (SDN, service mesh, host-based firewalls) for fine-grained internal control.",
                            "howTo": "<h5>Concept:</h5><p>Microsegmentation provides fine-grained, identity-aware traffic control between individual workloads (e.g., pods in Kubernetes). Even if two pods are on the same network segment, they cannot communicate unless an explicit policy allows it. This requires a baseline 'default-deny' policy to be effective.</p><h5>Implement Kubernetes NetworkPolicies (with Default Deny)</h5><p>First, apply a default-deny policy to the namespace. Then, create specific 'allow' policies for required traffic.</p><pre><code># File: k8s/default-deny-policy.yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-all\n  namespace: ai-production\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\n---\n# File: k8s/allow-gateway-to-inference.yaml\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: allow-gateway-to-inference\n  namespace: ai-production\nspec:\n  podSelector:\n    matchLabels:\n      app: model-server\n  policyTypes:\n  - Ingress\n  ingress:\n  - from:\n    - podSelector:\n        matchLabels:\n          app: api-gateway\n    ports:\n    - protocol: TCP\n      port: 8080</code></pre><p><strong>Action:</strong> Deploy a CNI plugin that supports <code>NetworkPolicy</code> enforcement (e.g., Calico, Cilium). Implement a 'default-deny-all' policy for each namespace containing AI workloads. Then, create specific, least-privilege policies to allow only the necessary communication paths between pods. Confirm your CNI (Calico, Cilium, etc.) is actually enforcing NetworkPolicy. Vanilla kube-proxy alone doesn't block traffic; without enforcement this policy is only documentation.</p>"
                        },
                        {
                            "implementation": "Separate development/testing environments from production using distinct accounts or projects.",
                            "howTo": "<h5>Concept:</h5><p>This is a fundamental security control that isolates volatile and less-secure development environments from the stable, hardened production environment using strong administrative boundaries provided by cloud providers.</p><h5>Implement a Multi-Account/Multi-Project Cloud Strategy with SCPs</h5><p>Structure your cloud organization and apply Service Control Policies (SCPs in AWS, Organization Policies in GCP, Azure Policy) to enforce separation.</p><pre><code># Conceptual Cloud Organization Structure (e.g., AWS Organizations)\n\nMy-AI-Organization/ (Root)\n└── OU: AI-Workloads\n    ├── Account: 111111111111 (AI-Prod)\n    ├── Account: 222222222222 (AI-Staging)\n    └── Account: 333333333333 (AI-Dev/Sandbox)\n\n# --- Example AWS SCP to prevent Prod <-> Dev Peering ---\n# Attach this policy to the AI-Workloads OU or Root\n{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyProdDevPeering\",\n      \"Effect\": \"Deny\",\n      \"Action\": [\n        \"ec2:AcceptVpcPeeringConnection\",\n        \"ec2:CreateVpcPeeringConnection\"\n      ],\n      \"Resource\": \"*\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"aws:PrincipalAccount\": [\"111111111111\"],\n          \"ec2:AccepterVpcInfo/OwnerId\": [\"333333333333\"],\n          \"ec2:RequesterVpcInfo/OwnerId\": [\"333333333333\"]\n        }\n      }\n    }\n  ]\n}</code></pre><p><strong>Action:</strong> Structure your cloud environment using separate accounts (AWS) or projects (GCP/Azure) for development, staging, and production. Use organization-level policies (SCPs, Org Policies) to programmatically prevent the creation of network paths (VPC Peering, Direct Connect, VPNs) between production and non-production environments.</p>"
                        },
                        {
                            "implementation": "Regularly review and audit internal network segmentation rules.",
                            "howTo": "<h5>Concept:</h5><p>Internal firewall rules and network policies can become outdated ('rule rot'). Regular, automated audits are necessary to find and remediate overly permissive internal rules, including rules allowing access between security groups.</p><h5>Implement an Automated Security Group Auditor (Improved)</h5><p>Write a script that uses your cloud provider's SDK to scan all security groups for high-risk misconfigurations, including overly broad internal CIDR access and risky SG-to-SG rules.</p><pre><code># File: audits/check_internal_security_groups_v2.py\nimport boto3\nimport json\nfrom ipaddress import ip_network\n\nINTERNAL_RANGES = [ip_network('10.0.0.0/8'), ip_network('172.16.0.0/12'), ip_network('192.168.0.0/16')]\nSENSITIVE_PORTS = [22, 3389, 6379, 27017]\nBROAD_PREFIX_THRESHOLD = 16\n\ndef is_internal(cidr):\n    try:\n        ip = ip_network(cidr)\n        return any(ip.subnet_of(internal_range) for internal_range in INTERNAL_RANGES)\n    except ValueError:\n        return False\n\ndef audit_internal_sg_rules(region):\n    ec2 = boto3.client('ec2', region_name=region)\n    offending_rules = []\n    all_groups = {g['GroupId']: g for g in ec2.describe_security_groups()['SecurityGroups']}\n\n    for group_id, group in all_groups.items():\n        for rule in group.get('IpPermissions', []):\n            from_port = rule.get('FromPort')\n            to_port = rule.get('ToPort')\n            is_sensitive_port_range = False\n            if rule.get('IpProtocol') == '-1':\n                is_sensitive_port_range = True\n            elif from_port is not None and to_port is not None:\n                is_sensitive_port_range = any(from_port <= p <= to_port for p in SENSITIVE_PORTS)\n\n            for ip_range in rule.get('IpRanges', []):\n                cidr = ip_range.get('CidrIp')\n                if cidr and is_internal(cidr) and is_sensitive_port_range:\n                    try:\n                        prefix = ip_network(cidr).prefixlen\n                        if prefix <= BROAD_PREFIX_THRESHOLD:\n                            offending_rules.append({'group_id': group_id, 'reason': f'Broad internal CIDR ({cidr}) allowed to sensitive port.'})\n                            break\n                    except ValueError:\n                        pass\n\n            for sg_source in rule.get('UserIdGroupPairs', []):\n                source_group_id = sg_source.get('GroupId')\n                # Optional: analyze source SG here if needed\n        \n    return offending_rules\n</code></pre><p><strong>Action:</strong> Schedule an automated script to run weekly that audits all internal firewall rules (Security Groups, NSGs, K8s NetworkPolicies). Enhance the script to check IPv4, IPv6, and group-based rules against your organization's internal network standards and sensitive port policies. Also audit SG-to-SG rules (UserIdGroupPairs), not just CIDR ranges. Send violations automatically to SecOps / SRE ticketing or Slack with severity tags, otherwise findings will quietly rot.</p>"
                        }
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0044 Full AI Model Access (limits internal access)",
                                "AML.T0036 Data from Information Repositories (limits internal access)",
                                "AML.T0075 Cloud Service Discovery (microsegmentation limits internal cloud resource discovery)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Lateral Movement (Cross-Layer)",
                                "Compromised RAG Pipelines (L2) (isolating internal DB access)",
                                "Data Leakage (Cross-Layer)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM02:2025 Sensitive Information Disclosure (limits internal data exposure)",
                                "LLM06:2025 Excessive Agency (limits internal reach of compromised agent)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML05:2023 Model Theft (limits internal access to model artifacts)",
                                "ML06:2023 AI Supply Chain Attacks (limits blast radius of internally compromised component)"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI03:2026 Identity and Privilege Abuse (network segmentation enforces access boundaries)",
                                "ASI10:2026 Rogue Agents (internal segmentation contains rogue agent lateral movement)",
                                "ASI07:2026 Insecure Inter-Agent Communication",
                                "ASI08:2026 Cascading Failures (network segmentation limits cascade propagation)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.039 Compromising connected resources",
                                "NISTAML.031 Model Extraction (internal segmentation limits extraction paths)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-14.1 Unauthorized Access",
                                "AISubtech-9.1.2 Unauthorized or Unsolicited System Access",
                                "AITech-8.2 Data Exfiltration / Exposure (internal segmentation limits data reach)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "MXF: Model Exfiltration (internal segmentation limits model theft paths)",
                                "SDD: Sensitive Data Disclosure (internal segmentation limits data exposure)",
                                "RA: Rogue Actions (internal segmentation contains rogue agent lateral movement)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Model 7.2: Model assets leak (internal segmentation restricts access to model assets)",
                                "Platform 12.4: Unauthorized privileged access (internal segmentation enforces privilege boundaries)",
                                "Agents - Core 13.13: Rogue Agents in Multi-Agent Systems (internal segmentation contains rogue agents)",
                                "Agents - Core 13.3: Privilege Compromise (segmentation limits privilege escalation scope)"
                            ]
                        }
                    ]
                },
                {
                    "id": "AID-I-002.002",
                    "name": "Secure External AI Service Connectivity",
                    "pillar": ["infra"],
                    "phase": ["building", "operation"],
                    "description": "Applies strict network path control, transport security, policy mediation, and monitoring specifically to connections originating from the AI system and targeting external services, particularly third-party or Model-as-a-Service (MaaS) foundation model APIs. Aims to prevent data exfiltration, Server-Side Request Forgery (SSRF), Man-in-the-Middle (MitM) attacks, and abuse of external dependencies. This also prevents prompt-injected agents from exfiltrating secrets or invoking arbitrary external services; they can only call approved upstreams through a governed path.",
                    "toolsOpenSource": [
                        "Open-source API Gateways (Kong, Tyk, APISIX)",
                        "Open-source Proxies (Squid, Nginx, HAProxy)",
                        "OpenSSL (as a library for verification logic)",
                        "SPIFFE/SPIRE (for workload identity for mTLS)",
                        "Falco, Cilium Tetragon, Sysdig (for egress monitoring)",
                        "Terraform, CloudFormation, Pulumi (for IaC of private endpoints)",
                        "Requests (Python library), cURL (as clients needing security)"
                    ],
                    "toolsCommercial": [
                        "Cloud Provider Private Connectivity (AWS PrivateLink, Azure Private Link, Google Private Service Connect)",
                        "Commercial API Gateway solutions (Apigee, MuleSoft, AWS API Gateway, Azure API Management)",
                        "Cloud-native firewall services (AWS Network Firewall, Azure Firewall Premium, Google Cloud Firewall)",
                        "Certificate Management Platforms (Venafi, DigiCert)",
                        "SIEM/Log Analytics Platforms (Splunk, Datadog, Sentinel, Chronicle)"
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Integrate external MaaS/API endpoints via private network connections.",
                            "howTo": "<h5>Concept:</h5><p>Keep traffic to critical external AI services off the public internet. Use cloud provider services like AWS PrivateLink, Azure Private Link, or Google Private Service Connect to create a private, secure endpoint for the MaaS provider within your own VPC. All traffic then flows over the cloud provider's backbone network.</p><h5>Create a Private Endpoint (Example: AWS PrivateLink)</h5><p>Use Infrastructure as Code to provision a VPC Endpoint for the MaaS provider's service, assuming they offer a PrivateLink-compatible service and you have completed the necessary subscription/acceptance flow.</p><pre><code># File: infrastructure/external_connectivity.tf (Terraform)\n\ndata \"aws_vpc\" \"prod_vpc\" {\n  filter { name = \"tag:Name\" values = [\"aidefend-prod-vpc\"] }\n}\n\ndata \"aws_subnets\" \"private_subnets\" {\n  filter { name = \"vpc-id\" values = [data.aws_vpc.prod_vpc.id] }\n  filter { name = \"tag:Tier\" values = [\"Private\"] }\n}\n\n# Find the MaaS provider's VPC Endpoint Service Name (must be obtained from provider)\ndata \"aws_vpc_endpoint_service\" \"maas_service\" {\n  service_name = \"com.amazonaws.vpce.us-east-1.provider-specific-service-name\"\n}\n\n# SG for the Interface Endpoint ENIs: allow ingress 443 from the AI workloads' SG\nresource \"aws_security_group\" \"maas_endpoint_sg\" {\n  name_prefix = \"maas-endpoint-sg-\"\n  vpc_id      = data.aws_vpc.prod_vpc.id\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = \"tcp\"\n    # Example: allow from an existing AI workload SG (replace with your SG id)\n    security_groups = [aws_security_group.allow_maas_client_egress_sg.id]\n  }\n  egress = []\n  tags = { Name = \"maas-endpoint-sg\" }\n}\n\n# SG for AI clients that will call the endpoint: restrict egress to 443 only\nresource \"aws_security_group\" \"allow_maas_client_egress_sg\" {\n  name_prefix = \"allow-maas-client-egress-\"\n  vpc_id      = data.aws_vpc.prod_vpc.id\n  egress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = \"tcp\"\n    # Narrow further at firewall/NACL or by resolving the endpoint ENI IPs\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n  tags = { Name = \"allow-maas-client-egress-sg\" }\n}\n\n# Create a VPC Endpoint (Interface) in your private subnets\nresource \"aws_vpc_endpoint\" \"maas_endpoint\" {\n  vpc_id              = data.aws_vpc.prod_vpc.id\n  service_name        = data.aws_vpc_endpoint_service.maas_service.service_name\n  vpc_endpoint_type   = \"Interface\"\n  subnet_ids          = data.aws_subnets.private_subnets.ids\n  security_group_ids  = [aws_security_group.maas_endpoint_sg.id]\n  private_dns_enabled = true\n}\n\n# Ensure client instances/pods use the endpoint's private DNS. Lock down routing and DNS split-horizon as needed.\n</code></pre><p><strong>Action:</strong> Connect to external MaaS providers using private endpoints. Configure endpoint SG to accept only from client SGs and restrict client egress to 443 (further narrowed by firewall/DNS policies). Complete provider-side acceptance as required.</p>"
                        },
                        {
                            "implementation": "Enforce strict egress controls using firewalls and proxies with verified DNS/SNI allow-lists.",
                            "howTo": "<h5>Concept:</h5><p>Implement a default-deny egress policy. Explicitly allow connections only to approved external domains needed by the AI system. Use Layer 7 inspection (TLS SNI, FQDN filtering) for greater precision than IP-based rules.</p><h5>Step 1: Configure Firewall/Proxy Allowlist with TLS Inspection</h5><p>Use a stateful firewall that supports TLS inspection (like Azure Firewall Premium, AWS Network Firewall, or a dedicated proxy like Squid with SSL Bump) to filter outbound HTTPS traffic based on the FQDN.</p><pre><code># Conceptual Azure Firewall Policy Application Rule Collection (requires TLS Inspection enabled)\n{\n  \"ruleCollectionType\": \"ApplicationRuleCollection\",\n  \"name\": \"AllowExternalAIServicesHTTPS\",\n  \"priority\": 200,\n  \"action\": { \"type\": \"Allow\" },\n  \"rules\": [\n    {\n      \"name\": \"AllowOpenAIAPI\",\n      \"protocols\": [ { \"protocolType\": \"Https\", \"port\": 443 } ],\n      \"sourceAddresses\": [ \"10.0.1.0/24\" ],\n      \"targetFqdns\": [ \"api.openai.com\" ]\n    },\n    {\n      \"name\": \"AllowWeatherAPI\",\n      \"protocols\": [ { \"protocolType\": \"Https\", \"port\": 443 } ],\n      \"sourceAddresses\": [ \"10.0.1.0/24\" ],\n      \"targetFqdns\": [ \"api.weather.com\" ]\n    }\n  ]\n}\n# Deny-all outbound TCP/UDP rule collection should exist with lower priority.\n</code></pre><h5>Step 2: Monitor for Violations with Name/IP Fallback</h5><p>Use runtime tools or SIEM to detect connections to destinations not on the allowlist. Include a fallback check by IP when FQDN is unavailable.</p><pre><code># File: falco_rules/ai_egress_violation.yaml\n- list: approved_domains\n  items: [api.openai.com, api.weather.com, internal.registry.corp]\n- list: approved_ips\n  items: [\"203.0.113.10\", \"203.0.113.11\"]\n\n- rule: Prod AI Pod Egress Violation\n  desc: Egress from prod AI workloads to disallowed destinations\n  condition: >\n    evt.type=connect and evt.dir=> and fd.l4proto in (tcp, udp) and\n    (container.image.repository contains \"ai-workload\" or k8s.ns.name in (ai-prod, ai-inference)) and\n    (\n      (fd.sip.name exists and fd.sip.name not in (approved_domains)) or\n      (not fd.sip.name exists and fd.sip not in (approved_ips))\n    )\n  output: >\n    Disallowed egress detected (proc=%proc.name cmd=%proc.cmdline container=%container.name image=%container.image.repository k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name dstip=%fd.sip dstdomain=%fd.sip.name)\n  priority: CRITICAL\n  tags: [network, aidefend]\n</code></pre><p><strong>Action:</strong> Enforce default-deny at the perimeter and allow only approved FQDNs/SNIs. Monitor violations using Falco/Tetragon or SIEM ingestion of firewall logs with both name and IP checks. Explicitly deny access to cloud instance metadata services (e.g. 169.254.169.254) unless you're routing through a hardened metadata proxy that strips credentials. This is critical for blocking SSRF-style credential theft.</p>"
                        },
                        {
                            "implementation": "Implement transport layer security (e.g., mTLS, Certificate Pinning) for critical egress connections.",
                            "howTo": "<h5>Concept:</h5><p>Encrypt traffic with TLS and strongly authenticate the external server using Certificate Pinning (SPKI hash) or Mutual TLS (mTLS) if supported. Note: post-handshake SPKI checks have TOCTOU limitations; prefer integrating pinning into the TLS stack or using mTLS.</p><h5>Implement Certificate Pinning Verification (Post-Handshake Check - Caution)</h5><pre><code># File: external_clients/pinned_client_spki_check.py\nimport requests\nimport ssl\nimport socket\nimport hashlib\nimport base64\nfrom cryptography import x509\nfrom cryptography.hazmat.primitives import serialization\nfrom cryptography.hazmat.backends import default_backend\n\nEXPECTED_SPKI_HASH_B64 = 'YOUR_EXPECTED_BASE64_SPKI_HASH=='\nEXPECTED_SPKI_HASH_BYTES = base64.b64decode(EXPECTED_SPKI_HASH_B64)\nTARGET_HOST = 'maas.example.com'\nTARGET_PORT = 443\n\ndef get_cert_spki_hash(hostname, port):\n    context = ssl.create_default_context()\n    conn_sock = context.wrap_socket(socket.create_connection((hostname, port)), server_hostname=hostname)\n    cert_der = conn_sock.getpeercert(binary_form=True)\n    conn_sock.close()\n    cert = x509.load_der_x509_certificate(cert_der, default_backend())\n    spki_der = cert.public_key().public_bytes(\n        encoding=serialization.Encoding.DER,\n        format=serialization.PublicFormat.SubjectPublicKeyInfo\n    )\n    return hashlib.sha256(spki_der).digest()\n\nactual = get_cert_spki_hash(TARGET_HOST, TARGET_PORT)\nif actual == EXPECTED_SPKI_HASH_BYTES:\n    print(\"✅ Certificate SPKI pin verified successfully (post-handshake).\")\nelse:\n    raise ConnectionRefusedError(\"Certificate pin mismatch\")\n</code></pre><p><strong>Action:</strong> Use SPKI pinning for high-sensitivity APIs when feasible, understanding the operational costs. Prefer mTLS with short-lived client certs where both parties support it. Pinned keys/certs must be rotated in a controlled CI/CD process; hardcoding pins without rotation planning will cause self-inflicted outages.</p>"
                        },
                        {
                            "implementation": "Utilize API Gateways to mediate external AI service traffic and apply security policies.",
                            "howTo": "<h5>Concept:</h5><p>An API Gateway provides a centralized control point for outbound traffic toward external AI services. It can enforce authentication, rate limits, schema validation, and resilience patterns. Configure health checks on the upstream entity.</p><h5>Configure Kong Gateway for External Upstream (Revised)</h5><pre><code># File: kong_config_external.yaml (Kong declarative configuration)\n_format_version: \"3.0\"\n\nupstreams:\n- name: maas-upstream\n  targets:\n  - target: api.maas-provider.com:443\n  healthchecks:\n    active:\n      https_verify_certificate: true\n      healthy:\n        http_statuses: [200, 201]\n        successes: 2\n      unhealthy:\n        http_statuses: [429, 500, 503]\n        timeouts: 3\n        http_failures: 3\n      interval: 10\n      timeout: 2\n\nservices:\n- name: external-maas-service\n  host: maas-upstream\n  port: 443\n  protocol: https\n  plugins:\n  - name: request-transformer\n    config:\n      add:\n        headers:\n        - \"Authorization: Bearer ${KONG_MAAS_API_KEY}\"\n  - name: rate-limiting\n    config:\n      minute: 500\n      policy: local\n\nroutes:\n- name: maas-route\n  paths:\n  - /internal/proxy/maas\n  strip_path: true\n  service: { name: external-maas-service }\n</code></pre><p><strong>Action:</strong> Route outbound MaaS traffic through the gateway. Inject secrets via environment variables or a supported secret store. Use upstream health checks for resilience. The gateway must also sanitize/override outbound headers so the agent cannot smuggle alternative destinations or custom Authorization headers to bypass policy.</p>"
                        },
                        {
                            "implementation": "Monitor external egress traffic for anomalies and policy violations.",
                            "howTo": "<h5>Concept:</h5><p>Continuously monitor volume, destinations, timing, and TLS metadata of outbound connections. Deviations can indicate exfiltration, C2, or policy bypass.</p><h5>Create a SIEM Alert for Anomalous Egress Volume (Boundary-Focused)</h5><pre><code># Conceptual Splunk SPL (AWS VPC Flow Logs with boundary focus)\nindex=vpcflowlogs sourcetype=aws:vpcflowlogs direction=egress \n(srcaddr=10.0.1.0/24 OR srcaddr=10.0.2.0/24) AND (interface_id=nat-* OR interface_id=igw-*)\nNOT (dstaddr=10.0.0.0/8 OR dstaddr=172.16.0.0/12 OR dstaddr=192.168.0.0/16)\n| timechart span=1h sum(bytes) as bytes_out by srcaddr\n| streamstats window=24 global=f avg(bytes_out) as avg_bytes_out stddev(bytes_out) as stddev_bytes_out by srcaddr\n| eval threshold_upper = avg_bytes_out + (3 * stddev_bytes_out)\n| where bytes_out > threshold_upper AND avg_bytes_out > 1000000 \n| table _time, srcaddr, bytes_out, avg_bytes_out, stddev_bytes_out, threshold_upper\n</code></pre><p><strong>Action:</strong> Ingest boundary egress logs and baseline normal volumes and destinations. Alert on significant deviations and newly observed ASNs/domains for AI subnets.</p>"
                        }
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0025 Exfiltration via Cyber Means",
                                "AML.T0049 Exploit Public-Facing Application (SSRF)",
                                "AML.T0072 Reverse Shell",
                                "AML.T0034 Cost Harvesting",
                                "AML.T0096 AI Service API (egress monitoring detects C2 communication via AI service channels)",
                                "AML.T0108 AI Agent (C2)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Exfiltration (L2)",
                                "Data Leakage (Cross-Layer)",
                                "Orchestration Attacks (L4)",
                                "Supply Chain Attacks (Cross-Layer) (securing external dependencies)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM02:2025 Sensitive Information Disclosure (via exfiltration)",
                                "LLM03:2025 Supply Chain (securing external connections)",
                                "LLM06:2025 Excessive Agency (proxy-based egress control limits what external actions agents can take)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML05:2023 Model Theft (securing API access)",
                                "ML06:2023 AI Supply Chain Attacks (securing external component access)"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI02:2026 Tool Misuse and Exploitation (egress controls prevent tool-based exfiltration)",
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities (securing external API dependencies)",
                                "ASI07:2026 Insecure Inter-Agent Communication (secure external connectivity protects agent-to-service communication)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.039 Compromising connected resources",
                                "NISTAML.038 Data Extraction"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-8.2 Data Exfiltration / Exposure",
                                "AISubtech-8.2.3 Data Exfiltration via Agent Tooling",
                                "AISubtech-9.1.3 Unauthorized or Unsolicited Network Access",
                                "AITech-9.3 Dependency / Plugin Compromise (securing external plugin connections)",
                                "AITech-14.1 Unauthorized Access",
                                "AITech-16.1 Eavesdropping (transport security prevents eavesdropping on AI service communications)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "MXF: Model Exfiltration (egress controls prevent model exfiltration to external services)",
                                "SDD: Sensitive Data Disclosure (egress controls prevent data exfiltration via external APIs)",
                                "IIC: Insecure Integrated Component (securing external plugin and API connections)",
                                "RA: Rogue Actions (egress controls prevent prompt-injected agents from calling unauthorized external services)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Tools MCP Server 13.23: Data Exfiltration (egress controls block exfiltration via external services)",
                                "Agents - Tools MCP Server 13.25: Insecure Communication (mTLS and certificate pinning secure external channels)",
                                "Model Serving - Inference response 10.2: Output manipulation (transport security prevents MitM on external connections)",
                                "Model 7.3: ML Supply chain vulnerabilities (securing external model and API dependencies)"
                            ]
                        }
                    ]
                }
            ]
        },
        {
            "id": "AID-I-003",
            "name": "Quarantine & Throttling of AI Interactions", "pillar": ["infra", "app"], "phase": ["response"],
            "description": "Implement mechanisms to automatically or manually isolate, rate-limit, or place into a restricted \\\"safe mode\\\" specific AI system interactions when suspicious activity is detected. This could apply to individual user sessions, API keys, IP addresses, or even entire AI agent instances.<br/><br/><strong>Objective</strong><br/>Prevent potential attacks from fully executing, spreading, or causing significant harm by quickly containing or degrading the capabilities of the suspicious entity. This is an active response measure triggered by detection systems.<br/><br/><strong>Trigger Modes &amp; Audit</strong><br/>This can be applied pre-emptively (automatic) or under human approval (SOAR analyst click-to-quarantine) depending on confidence score. All actions must be logged/auditable for compliance and forensic review.",
            "toolsOpenSource": [
                "Fail2Ban (adapted for AI logs)",
                "AWS Lambda (automated isolation actions)",
                "Azure Functions (automated isolation actions)",
                "Google Cloud Functions (automated isolation actions)",
                "API Gateways (Kong, Tyk, Nginx) for rate limiting",
                "Kubernetes for resource quotas/isolation"
            ],
            "toolsCommercial": [
                "API Security and Bot Management solutions (Cloudflare, Akamai, Imperva)",
                "SIEM/SOAR platforms (Splunk SOAR, Palo Alto XSOAR, IBM QRadar SOAR)",
                "WAFs with advanced rate limiting"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0029 Denial of AI Service",
                        "AML.T0034 Cost Harvesting",
                        "AML.T0034.000 Cost Harvesting: Excessive Queries",
                        "AML.T0034.001 Cost Harvesting: Resource-Intensive Queries",
                        "AML.T0034.002 Cost Harvesting: Agentic Resource Consumption",
                        "AML.T0040 AI Model Inference API Access",
                        "AML.T0046 Spamming AI System with Chaff Data",
                        "AML.T0024.002 Exfiltration via AI Inference API: Extract AI Model (rate-limiting slows extraction)",
                        "AML.T0096 AI Service API (rate limiting and throttling restrict C2 communication throughput)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Model Stealing (L1) (throttling limits query volume)",
                        "Denial of Service on Framework APIs (L3)",
                        "Denial of Service on Data Infrastructure (L2)",
                        "Denial of Service (DoS) Attacks (L4)",
                        "Resource Hijacking (L4) (quarantine contains hijacked resources)",
                        "Agent Pricing Model Manipulation (L7) (rate limiting prevents economic abuse)",
                        "Model Extraction of AI Security Agents (L6)",
                        "Compromised Agents (L7) (quarantine contains compromised agent instances)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM10:2025 Unbounded Consumption"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML05:2023 Model Theft (throttling excessive queries)"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI10:2026 Rogue Agents (quarantine isolates rogue agents)",
                        "ASI08:2026 Cascading Failures (throttling limits cascade propagation)",
                        "ASI02:2026 Tool Misuse and Exploitation (quarantine contains tool misuse)",
                        "ASI03:2026 Identity and Privilege Abuse"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.014 Energy-latency",
                        "NISTAML.031 Model Extraction (rate limiting slows extraction)",
                        "NISTAML.039 Compromising connected resources (quarantine limits lateral impact)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-13.1 Disruption of Availability",
                        "AISubtech-13.1.1 Compute Exhaustion",
                        "AITech-10.1 Model Extraction",
                        "AISubtech-10.1.1 API Query Stealing",
                        "AITech-13.2 Cost Harvesting / Repurposing",
                        "AISubtech-13.2.1 Service Misuse for Cost Inflation (throttling prevents cost inflation attacks)",
                        "AITech-14.1 Unauthorized Access",
                        "AITech-12.1 Tool Exploitation (quarantine contains suspicious tool exploitation)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "DMS: Denial of ML Service (throttling prevents service exhaustion)",
                        "MRE: Model Reverse Engineering (rate limiting slows reverse engineering attempts)",
                        "MXF: Model Exfiltration (rate limiting slows model extraction via API)",
                        "RA: Rogue Actions (quarantine isolates agents performing rogue actions)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Model Serving - Inference requests 9.7: Denial of Service (DoS)",
                        "Model Management 8.2: Model theft (throttling slows model theft via API queries)",
                        "Agents - Core 13.4: Resource Overload (throttling prevents resource overload)",
                        "Agents - Core 13.13: Rogue Agents in Multi-Agent Systems (quarantine isolates rogue agents)",
                        "Model Serving - Inference requests 9.11: Model Inference API Access (rate limiting restricts unauthorized API access)",
                        "Model Serving - Inference response 10.5: Black-box attacks (rate limiting slows black-box attack queries)",
                        "Agents - Core 13.3: Privilege Compromise",
                        "Agents - Core 13.2: Tool Misuse (quarantine contains suspicious tool-calling behavior)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Automated quarantine based on high-risk behavior alerts (cut access, move to honeypot, disable key/account).",
                    "howTo": "<h5>Concept:</h5><p>When the detection pipeline emits a high-confidence finding, containment should execute immediately and reproducibly. The quarantine workflow should update edge controls, disable the offending credential if applicable, and emit a structured audit event that links the action to the triggering alert.</p><h5>Step 1: Consume structured alerts from a queue or event bus</h5><p>The alert must include the offender identity, action type, confidence score, and reason so the quarantine function can make deterministic decisions.</p><pre><code># File: quarantine_lambda/main.py\nfrom __future__ import annotations\n\nimport ipaddress\nimport json\nimport os\n\nimport boto3\n\n\nWAF_IP_SET_NAME = os.environ[\"WAF_IP_SET_NAME\"]\nWAF_IP_SET_ID = os.environ[\"WAF_IP_SET_ID\"]\nWAF_SCOPE = os.environ.get(\"WAF_SCOPE\", \"REGIONAL\")\nQUARANTINE_CONFIDENCE = float(os.environ.get(\"QUARANTINE_CONFIDENCE\", \"0.90\"))\n\nwaf_client = boto3.client(\"wafv2\")\napi_gateway_client = boto3.client(\"apigateway\")\n\n\ndef cidr_for_ip(raw_ip: str) -&gt; str:\n    ip = ipaddress.ip_address(raw_ip)\n    return f\"{ip}/32\" if ip.version == 4 else f\"{ip}/128\"\n\n\ndef add_ip_to_waf_blocklist(raw_ip: str) -&gt; None:\n    cidr = cidr_for_ip(raw_ip)\n    ipset = waf_client.get_ip_set(\n        Name=WAF_IP_SET_NAME,\n        Scope=WAF_SCOPE,\n        Id=WAF_IP_SET_ID,\n    )\n    lock_token = ipset[\"LockToken\"]\n    addresses = list(ipset[\"IPSet\"][\"Addresses\"])\n    if cidr not in addresses:\n        addresses.append(cidr)\n        waf_client.update_ip_set(\n            Name=WAF_IP_SET_NAME,\n            Scope=WAF_SCOPE,\n            Id=WAF_IP_SET_ID,\n            LockToken=lock_token,\n            Addresses=addresses,\n        )\n\n\ndef disable_api_key(api_key_id: str) -&gt; None:\n    api_gateway_client.update_api_key(\n        apiKey=api_key_id,\n        patchOperations=[{\"op\": \"replace\", \"path\": \"/enabled\", \"value\": \"false\"}],\n    )\n\n\ndef lambda_handler(event, context):\n    audit_events = []\n    for record in event[\"Records\"]:\n        alert = json.loads(record[\"body\"])\n        action = alert.get(\"action\")\n        confidence = float(alert.get(\"confidence\", 0.0))\n        reason = alert.get(\"reason\", \"unknown\")\n\n        if confidence &lt; QUARANTINE_CONFIDENCE:\n            continue\n\n        if action == \"QUARANTINE_IP\" and alert.get(\"source_ip\"):\n            add_ip_to_waf_blocklist(alert[\"source_ip\"])\n            audit_events.append({\n                \"event\": \"quarantine_ip\",\n                \"source_ip\": alert[\"source_ip\"],\n                \"reason\": reason,\n                \"confidence\": confidence,\n                \"request_id\": context.aws_request_id,\n            })\n\n        if action == \"DISABLE_API_KEY\" and alert.get(\"api_key_id\"):\n            disable_api_key(alert[\"api_key_id\"])\n            audit_events.append({\n                \"event\": \"disable_api_key\",\n                \"api_key_id\": alert[\"api_key_id\"],\n                \"reason\": reason,\n                \"confidence\": confidence,\n                \"request_id\": context.aws_request_id,\n            })\n\n    for audit_event in audit_events:\n        print(json.dumps(audit_event))\n\n    return {\"statusCode\": 200, \"actions_taken\": len(audit_events)}\n</code></pre><h5>Step 2: Verify both containment paths</h5><p>In staging, send one queue message that blocks a test IP and another that disables a disposable API key. Confirm the IP appears in the WAF IP set, the API key becomes disabled, and both actions produce structured audit events.</p><p><strong>Action:</strong> Put a deterministic quarantine function behind your high-confidence detection findings and require that every automated containment action produces auditable evidence linking the source alert, the affected principal, and the exact control change that was applied.</p>"
                },
                {
                    "implementation": "Dynamic rate limiting for anomalous behavior (query spikes, complex queries).",
                    "howTo": "<h5>Concept:</h5><p>Instead of a single global rate limit, apply adaptive throttling per user / tenant / agent ID based on actual resource stress. For example, model extraction, cost harvesting, or data exfil attempts often involve bursts of long, high-cost prompts. By tracking a per-identity 'complexity score' over a sliding time window and cutting them off once they exceed a threshold, you contain abuse without harming normal users.</p><h5>Implementation Pattern (Redis Sliding Window):</h5><p>We keep (timestamp, complexity_score) entries in Redis ZSET keyed per user. We expire old entries (older than TIME_WINDOW_SECONDS), sum the recent complexity scores, and if the threshold would be exceeded we reject. NOTE: The ZSET <em>score</em> is the timestamp. The <em>member</em> encodes the complexity value. This avoids the bug where you accidentally sum timestamps instead of complexity.</p><pre><code># File: api/dynamic_rate_limiter.py\nimport time\nimport redis\n\nr = redis.Redis()\n\nCOMPLEXITY_THRESHOLD = 500    # max total 'cost' allowed in the window\nTIME_WINDOW_SECONDS = 60      # sliding window size\n\ndef check_dynamic_limit(user_id: str, prompt: str) -> bool:\n    \"\"\"Return False if this request should be throttled for this user.\"\"\"\n    now = time.time()\n    complexity_score = len(prompt)  # simplistic cost metric; replace with real cost model\n\n    key = f\"user_complexity:{user_id}\"\n\n    # 1. Drop old events outside the window\n    r.zremrangebyscore(key, 0, now - TIME_WINDOW_SECONDS)\n\n    # 2. Get recent events (member encodes complexity, score is timestamp)\n    entries = r.zrange(key, 0, -1, withscores=True)\n\n    current_total_complexity = 0.0\n    for member, ts in entries:\n        # member looks like \"<complexity>:<timestamp>\"\n        try:\n            member_decoded = member.decode('utf-8') if isinstance(member, bytes) else str(member)\n            complexity_str = member_decoded.split(\":\")[0]\n            current_total_complexity += float(complexity_str)\n        except Exception:\n            # ignore malformed entries\n            pass\n\n    # 3. Will adding this prompt blow past threshold?\n    if current_total_complexity + complexity_score > COMPLEXITY_THRESHOLD:\n        # Emit security log / SIEM event for potential extraction or abuse\n        print({\n            'event': 'RATE_LIMIT_TRIP',\n            'user_id': user_id,\n            'total_complexity': current_total_complexity,\n            'threshold': COMPLEXITY_THRESHOLD,\n            'ts': now\n        })\n        return False  # throttle (HTTP 429)\n\n    # 4. Otherwise record this event and allow\n    member_value = f\"{complexity_score}:{now}\"\n    r.zadd(key, {member_value: now})\n    return True\n</code></pre><p><strong>Action:</strong> Put this check in API middleware in front of inference/tool calls. If <code>check_dynamic_limit()</code> returns <code>False</code>, immediately respond with HTTP 429 and mark that identity as 'abuse-suspect' in logs/SIEM for possible quarantine. Log these trips; they are security-relevant signals that can feed automated quarantine (Strategy 1) or human review.</p>"
                },
                {
                    "implementation": "Stricter rate limits for unauthenticated/less trusted users.",
                    "howTo": "<h5>Concept:</h5><p>Anonymous or low-trust tenants are the riskiest for brute-force model extraction, DoS, cost harvesting, and prompt-injection-driven tool abuse. Give them a very conservative rate limit and smaller concurrency budget. Give higher limits only to identities you've verified (paid customers, known workforce identities, allowlisted service accounts). Every elevation in trust tier is itself a governed, auditable security event.</p><h5>Tiered Rate Limiting via API Gateway (Example: Kong)</h5><p>Define multiple rate-limiting plugin instances (e.g. <code>rate-limit-free</code> vs <code>rate-limit-premium</code>). Attach the strict default limit globally, then explicitly attach the more generous limit to specific trusted consumer groups. Log any movement of a user into a higher-trust tier as a privileged action.</p><pre><code># File: kong_config.yaml (declarative example)\n\nplugins:\n- name: rate-limiting\n  instance_name: rate-limit-premium\n  config:\n    minute: 1000        # Premium / trusted users\n    policy: local\n- name: rate-limiting\n  instance_name: rate-limit-free\n  config:\n    minute: 20          # Anonymous / low-trust users\n    policy: local\n\nconsumers:\n- username: premium_user_group\n  plugins:\n  - name: rate-limiting\n    instance_name: rate-limit-premium   # Attach high quota to trusted group\n\nservices:\n- name: my-ai-service\n  url: http://inference-server:8080\n  plugins:\n  - name: rate-limiting\n    instance_name: rate-limit-free      # Default (strict) limit applies to everyone else\n</code></pre><p><strong>Action:</strong> Enforce extremely low default limits on anonymous traffic. Grant higher limits only to vetted groups, and log that elevation (who approved, when, and for which account) because that trust-tier change is a new attack surface. This helps contain scraping, model theft (ML05:2023), and economic abuse, while preserving capacity for real customers.</p>"
                },
                {
                    "implementation": "Design AI systems with a 'safe mode' or degraded functionality state.",
                    "howTo": "<h5>Concept:</h5><p>During an active attack or anomaly (cost spike, mass prompt injection attempts, suspicious tool usage), the AI service should be able to enter a 'safe mode'. In safe mode, high-risk capabilities are disabled: agent tool execution, filesystem writes, network egress, or high-cost model calls. Requests are optionally routed to a cheaper / more controllable fallback model. Safe mode is essentially emergency containment with graceful degradation, not a full shutdown.</p><h5>Feature-Flag Controlled Safe Mode</h5><p>Use a runtime flag (feature flag service / config toggle) so SecOps/SRE can flip the system into safe mode instantly without redeploying. Entering or exiting safe mode MUST emit an auditable event to SIEM/SOAR, because it's effectively an incident response state change.</p><pre><code># File: api/inference_logic.py\nimport feature_flags  # your feature flag SDK / config service\n\nstate = {\"mode\": \"normal\"}\n\n# primary_llm = load_primary_model()\n# safe_llm    = load_safe_fallback_model()\n\ndef generate_response(prompt: str):\n    # Check central kill-switch / safe-mode flag at request time\n    is_safe_mode = feature_flags.get_flag('ai-safe-mode', default=False)\n\n    if is_safe_mode:\n        state[\"mode\"] = \"safe_mode\"\n        # In safe mode:\n        #  - Call only the safe fallback model\n        #  - Disable high-risk agent tools / side effects\n        #  - Enforce read-only or dry-run behavior\n        print(\"[SAFE MODE] Routing to fallback model; tools disabled.\")\n        # return safe_llm.generate(prompt)\n    else:\n        state[\"mode\"] = \"normal\"\n        print(\"[NORMAL MODE] Full features enabled.\")\n        # return primary_llm.generate_with_tools(prompt)\n</code></pre><p><strong>Action:</strong> Implement a feature-flag-driven safe mode that (1) downgrades the agent/model to a restricted profile, (2) disables tool invocation and write-side effects, and (3) reduces expensive calls. Every toggle of safe mode (who triggered it, why, timestamp) should be logged to SIEM/SOAR for audit and incident timeline reconstruction. Treat safe mode entry as a partial containment action, not just an ops toggle.</p>"
                },
                {
                    "implementation": "Utilize SOAR platforms to automate quarantine/throttling actions.",
                    "howTo": "<h5>Concept:</h5><p>A SOAR (Security Orchestration, Automation, and Response) platform is your incident-response brain. It ingests high-confidence alerts (model extraction attempt, abnormal egress, mass prompt injection) and executes a playbook: block IPs, suspend sessions, lower rate limits, move a tenant into 'safe mode', and open an investigation ticket. For high-value users or production tenants, require a human approval step before final lockout to avoid accidental mass-customer impact.</p><h5>Automated Response Playbook (Conceptual YAML)</h5><pre><code>name: \"Automated AI User Quarantine Playbook\"\ntrigger:\n  siem_alert_name: \"AI_Model_Extraction_Attempt_Detected\"\n\nsteps:\n- name: Enrich Data\n  actions:\n  - command: get_ip_from_alert\n    output: ip_address\n  - command: get_user_id_from_alert\n    output: user_id\n\n- name: Get User Reputation\n  actions:\n  - service: trust_score_api\n    command: get_score\n    inputs: { \"agent_id\": \"{{user_id}}\" }\n    output: user_trust_score\n\n- name: Conditional Quarantine\n  condition: \"{{user_trust_score}} < 0.3\"\n  actions:\n  - service: aws_waf\n    command: block_ip\n    inputs: { \"ip\": \"{{ip_address}}\" }\n  - service: okta\n    command: suspend_user_session\n    inputs: { \"user_id\": \"{{user_id}}\" }\n  - service: jira\n    command: create_ticket\n    inputs:\n      project: \"SOC\"\n      title: \"User {{user_id}} quarantined for suspected AI abuse\"\n      assignee: \"security_on_call\"\n</code></pre><p><strong>Action:</strong> Integrate AI abuse detection signals into SOAR. The playbook should (a) enrich context (who is this?), (b) score trust/risk, (c) automatically quarantine low-trust entities, and (d) open a ticket with full telemetry. For privileged / high-value tenants, require an analyst approval gate in the SOAR workflow before suspension. All actions, including who approved, become part of the audit trail.</p>"
                },
                {
                    "implementation": "Trip a hallucination or safety circuit breaker into a degraded operating mode when upstream health signals cross containment thresholds.",
                    "howTo": `<h5>Concept:</h5><p>This is an <strong>enforcement / containment</strong> control. It should consume already-computed health or safety signals from detect or validation systems, such as consensus scores, evidence coverage, contradiction rate, schema error rate, or tool-policy violations. The breaker does not compute those signals itself. Its job is to translate trusted upstream signals into an operational mode such as <code>normal</code>, <code>safe_tools_only</code>, <code>read_only</code>, or <code>quarantine</code>.</p><h5>Step 1: Define a containment policy contract for upstream signals</h5><pre><code># File: isolate/breaker_policy.py
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SafetySignalSnapshot:
    consensus_score: float
    evidence_coverage: float
    contradiction_rate: float
    schema_error_rate: float
    unknown_tool_calls: int


@dataclass(frozen=True)
class BreakerDecision:
    mode: str
    reason: str


def select_mode(snapshot: SafetySignalSnapshot) -> BreakerDecision:
    if snapshot.unknown_tool_calls > 0 or snapshot.schema_error_rate >= 0.20:
        return BreakerDecision(mode='quarantine', reason='unsafe_tool_or_schema_breach')
    if snapshot.contradiction_rate > 0.20 or snapshot.evidence_coverage < 0.40:
        return BreakerDecision(mode='read_only', reason='high_hallucination_risk')
    if snapshot.consensus_score < 0.60 or snapshot.evidence_coverage < 0.55:
        return BreakerDecision(mode='safe_tools_only', reason='quality_degradation')
    return BreakerDecision(mode='normal', reason='within_threshold')</code></pre><h5>Step 2: Enforce the mode at the orchestration boundary</h5><pre><code># File: app.py
from fastapi import FastAPI, Request
from isolate.breaker_policy import BreakerDecision, SafetySignalSnapshot, select_mode

app = FastAPI()
app.state.latest_safety_signal = SafetySignalSnapshot(
    consensus_score=1.0,
    evidence_coverage=1.0,
    contradiction_rate=0.0,
    schema_error_rate=0.0,
    unknown_tool_calls=0,
)
app.state.agent_mode = 'normal'


@app.middleware('http')
async def breaker_middleware(request: Request, call_next):
    snapshot = request.app.state.latest_safety_signal
    decision: BreakerDecision = select_mode(snapshot)
    request.app.state.agent_mode = decision.mode

    if decision.mode != 'normal':
        print({
            'event': 'BREAKER_MODE_CHANGED',
            'mode': decision.mode,
            'reason': decision.reason,
        })

    response = await call_next(request)
    response.headers['X-Agent-Mode'] = decision.mode
    return response</code></pre><h5>Step 3: Gate side effects based on the enforced mode</h5><pre><code># File: app.py
from fastapi import HTTPException


@app.post('/kb/write')
async def write_kb(item: dict):
    if app.state.agent_mode in {'read_only', 'safe_tools_only', 'quarantine'}:
        raise HTTPException(status_code=423, detail='write path disabled while breaker is active')
    return {'status': 'ok'}


@app.post('/tool/execute')
async def execute_tool(request: dict):
    if app.state.agent_mode in {'safe_tools_only', 'quarantine'} and request.get('tool_name') not in {'search_docs', 'read_ticket'}:
        raise HTTPException(status_code=423, detail='tool disabled by containment policy')
    return {'status': 'accepted'}</code></pre><p><strong>Action:</strong> Place the breaker at the orchestration or API boundary, feed it only trusted upstream safety signals, and emit an auditable mode-change event whenever containment is entered or cleared. This keeps the guidance atomic for AIDEFEND productization: the evidence proves you can <em>enforce degraded modes</em> independently from the separate controls that <em>measure</em> hallucination or safety quality.</p>`
                },
                {
                    "implementation": "Throttle GPU/CPU for a suspicious tenant namespace in Kubernetes.",
                    "howTo": "<h5>Concept:</h5><p>Sometimes you don't want to fully block or ban a tenant/agent yet (false positives are expensive), but you also can't let them keep burning GPU, hammering vector search, or spawning aggressive jobs. A fast, surgical containment move is to dynamically clamp that tenant's compute budget. You can (a) apply a tighter <code>ResourceQuota</code> / <code>LimitRange</code> to their namespace or (b) evict / reschedule them onto low-priority nodes with throttled GPU/CPU. This acts like 'gardening the blast radius': you buy time for human review while capping cost, data access, and lateral movement potential.</p><h5>Example: Apply/Update a ResourceQuota on a Suspicious Namespace</h5><p>In Kubernetes, each tenant/agent (or each AI tool-execution sandbox) can run in its own namespace. When anomalous behavior is detected (cost spike, extraction attempt, mining behavior, runaway agent loops), your response automation can patch that namespace with a stricter <code>ResourceQuota</code> and <code>LimitRange</code>, effectively throttling CPU/GPU/memory. This is a live containment control that doesn't require deleting the workload immediately.</p><pre><code># File: k8s/quarantine-quota.yaml\napiVersion: v1\nkind: ResourceQuota\nmetadata:\n  name: quarantine-quota\n  namespace: suspicious-tenant-ns\nspec:\n  hard:\n    requests.cpu: \"2\"           # cap total requested CPU cores\n    limits.cpu: \"4\"             # cap total CPU limit\n    requests.memory: \"8Gi\"      # cap total requested memory\n    limits.memory: \"16Gi\"       # cap total memory\n    requests.nvidia.com/gpu: \"0\"  # deny new GPU requests (freeze expensive inference)\n    limits.nvidia.com/gpu: \"0\"\n---\napiVersion: v1\nkind: LimitRange\nmetadata:\n  name: quarantine-limits\n  namespace: suspicious-tenant-ns\nspec:\n  limits:\n  - type: Container\n    max:\n      cpu: \"2\"\n      memory: \"8Gi\"\n    default:\n      cpu: \"1\"\n      memory: \"4Gi\"\n    defaultRequest:\n      cpu: \"500m\"\n      memory: \"2Gi\"\n</code></pre><p><strong>Action:</strong> When a tenant/agent is flagged as suspicious (excessive tool calls, GPU burn, reverse shell attempt, cost harvesting), have your SOAR / Lambda-style responder automatically <code>kubectl apply</code> (or patch via API) a restrictive <code>ResourceQuota</code> and <code>LimitRange</code> onto that tenant's namespace. This enforces (1) zero new GPU allocation, (2) heavily throttled CPU/memory, and (3) containment to low-cost resources while still preserving logs/forensics. Emit a SIEM/SOAR audit event every time you clamp or later restore those quotas, and require human approval to fully delete workloads in regulated environments.</p>"
                },
                {
                    "implementation": "Enforce budget-triggered throttling and safe-mode downgrade when per-session, per-user, per-agent, or per-API-key token and spend thresholds are exceeded or when abnormal cost-abuse scores cross policy thresholds.",
                    "howTo": "<h5>Concept:</h5><p>Traditional rate limiting counts requests per time window. Budget-triggered throttling counts <b>cumulative resource consumption</b>: total tokens, total estimated spend, total tool calls. When a session or user exhausts their budget, the system throttles or forces safe-mode even if the request rate is normal. This is critical because a single slow, expensive prompt can cause more damage than 100 cheap ones.</p><h5>Step 1: Define Budget Policies</h5><pre><code># File: policies/budget_policy.yaml\n\nbudget_policies:\n  default:\n    per_session:\n      max_input_tokens: 500000\n      max_output_tokens: 200000\n      max_tool_calls: 100\n      max_estimated_spend_usd: 50.00\n    per_user_hourly:\n      max_input_tokens: 2000000\n      max_output_tokens: 1000000\n      max_tool_calls: 500\n      max_estimated_spend_usd: 200.00\n    on_breach:\n      action: \"throttle\"  # \"throttle\", \"safe_mode\", \"block\"\n      throttle_to_rpm: 5  # reduce to 5 requests per minute\n\n  high_trust:\n    per_session:\n      max_input_tokens: 2000000\n      max_output_tokens: 1000000\n      max_tool_calls: 500\n      max_estimated_spend_usd: 500.00\n    on_breach:\n      action: \"safe_mode\"</code></pre><h5>Step 2: Enforce Budget at Gateway</h5><pre><code># File: gateway/budget_enforcer.py\nimport json\nfrom datetime import datetime, timezone\n\n\nclass BudgetEnforcer:\n    \"\"\"\n    Tracks cumulative resource consumption per session/user/agent\n    and enforces budget policies.\n    \"\"\"\n\n    def __init__(self, redis_client, policy: dict):\n        self.r = redis_client\n        self.policy = policy\n\n    def check_and_update(\n        self,\n        tenant_id: str,\n        user_id: str,\n        session_id: str,\n        input_tokens: int,\n        output_tokens: int,\n        tool_calls: int,\n        estimated_spend: float,\n    ) -> dict:\n        \"\"\"\n        Check budget, update counters, return enforcement decision.\n        Returns: {\"allowed\": bool, \"action\": str, \"reason\": str}\n        \"\"\"\n        # Update session counters atomically\n        session_key = f\"budget:session:{session_id}\"\n        pipe = self.r.pipeline()\n        pipe.hincrby(session_key, \"input_tokens\", input_tokens)\n        pipe.hincrby(session_key, \"output_tokens\", output_tokens)\n        pipe.hincrby(session_key, \"tool_calls\", tool_calls)\n        pipe.hincrbyfloat(session_key, \"spend_usd\", estimated_spend)\n        pipe.expire(session_key, 86400)  # 24h TTL for session keys\n        results = pipe.execute()\n\n        current = {\n            \"input_tokens\": results[0],\n            \"output_tokens\": results[1],\n            \"tool_calls\": results[2],\n            \"spend_usd\": float(results[3]),\n        }\n\n        # Check against session policy\n        session_policy = self.policy.get(\"per_session\", {})\n        breaches = []\n        if current[\"input_tokens\"] > session_policy.get(\"max_input_tokens\", float(\"inf\")):\n            breaches.append(\"input_tokens\")\n        if current[\"output_tokens\"] > session_policy.get(\"max_output_tokens\", float(\"inf\")):\n            breaches.append(\"output_tokens\")\n        if current[\"tool_calls\"] > session_policy.get(\"max_tool_calls\", float(\"inf\")):\n            breaches.append(\"tool_calls\")\n        if current[\"spend_usd\"] > session_policy.get(\"max_estimated_spend_usd\", float(\"inf\")):\n            breaches.append(\"spend_usd\")\n\n        if breaches:\n            action = self.policy.get(\"on_breach\", {}).get(\"action\", \"throttle\")\n            self._emit_budget_breach(\n                tenant_id, user_id, session_id, breaches, current, action\n            )\n            return {\"allowed\": False, \"action\": action, \"reason\": f\"budget_breach:{','.join(breaches)}\"}\n\n        return {\"allowed\": True, \"action\": \"none\", \"reason\": \"within_budget\"}\n\n    def _emit_budget_breach(self, tenant_id, user_id, session_id, breaches, current, action):\n        event = {\n            \"event\": \"BUDGET_BREACH\",\n            \"ts\": datetime.now(timezone.utc).isoformat(),\n            \"tenant_id\": tenant_id,\n            \"user_id\": user_id,\n            \"session_id\": session_id,\n            \"breached_dimensions\": breaches,\n            \"current_values\": current,\n            \"enforcement_action\": action,\n        }\n        print(json.dumps(event))</code></pre><p><strong>Action:</strong> Deploy budget enforcement at the inference gateway, before the request reaches the model. Define per-session and per-user budget policies in a central config. When a budget is breached, immediately apply the configured action (throttle, safe-mode, or block) and emit a structured event to SIEM. Link budget breach events to AID-D-005.007 cost anomaly alerts for correlated incident timelines.</p>"
                },
                {
                    "implementation": "Apply multi-dimensional quotas such as input-token ceilings, output-token ceilings, tool-call ceilings, and cumulative session budget ceilings so cost abuse cannot evade control by shifting from one resource dimension to another.",
                    "howTo": "<h5>Concept:</h5><p>An attacker who hits a token-count limit can shift to tool-call abuse. One who hits a tool-call limit can shift to sending fewer but longer prompts. Single-dimension quotas are trivially evadable. Multi-dimensional quotas enforce ceilings across <b>all</b> cost-linked dimensions simultaneously, so abuse must stay below every ceiling at once. The budget enforcement strategy described earlier in this technique already tracks multiple dimensions; this strategy emphasizes the policy design principle.</p><h5>Policy Design Principles</h5><pre><code># File: docs/budget_policy_design.md\n\n## Multi-Dimensional Budget Policy Design\n\n### Principle: Defense in Depth Across Cost Dimensions\n\nA well-designed budget policy enforces limits across ALL of these dimensions:\n\n| Dimension          | What It Caps                        | Why It Matters                     |\n|--------------------|-------------------------------------|------------------------------------|\n| Input tokens       | Total prompt tokens per session/hour | Prevents prompt stuffing           |\n| Output tokens      | Total generated tokens               | Prevents verbose output abuse      |\n| Tool calls         | Total tool invocations               | Prevents recursive loop burns      |\n| Estimated spend    | Dollar-equivalent cumulative cost    | Prevents cross-dimension evasion   |\n| Retry count        | Repeated identical/similar requests  | Prevents replay attacks            |\n| Concurrency        | Simultaneous active requests         | Prevents parallelized abuse        |\n\n### Anti-Evasion Rule:\nIf ANY dimension exceeds its ceiling, throttle.\nDo NOT allow a user to trade off one dimension for another.\n\n### Example: An attacker sends 10 requests, each with a 50K-token prompt\n- Token-only quota: catches it at 500K tokens\n- Request-rate limit: does NOT catch it (only 10 requests)\n- Multi-dimensional: catches it on BOTH token AND spend dimensions</code></pre><p><strong>Action:</strong> Review your budget policy to ensure it covers at minimum: input tokens, output tokens, tool calls, estimated spend, retry count, and concurrency. Test the policy against evasion scenarios: What happens if an attacker sends few requests but each is extremely expensive? What if they parallelize many cheap requests? The policy must catch both patterns.</p>"
                },
                {
                    "implementation": "Escalate from soft throttling to hard containment when budget exhaustion is paired with suspicious signals such as recursive tool loops, repeated retries, anomalous latency growth, or high-confidence abuse detections.",
                    "howTo": "<h5>Concept:</h5><p>Soft throttling (reducing rate limits) is appropriate for ambiguous situations where the user might be legitimate. But when budget breach coincides with other abuse indicators—recursive tool loops (AID-H-018.001), anomalous cost spikes (AID-D-005.007), or repeated failed retries—the system should escalate to hard containment: session quarantine, API key suspension, or full safe-mode lockdown.</p><h5>Escalation Matrix</h5><pre><code># File: policies/escalation_matrix.yaml\n\nescalation_rules:\n  # Level 1: Budget breach alone → soft throttle\n  - condition:\n      budget_breach: true\n      loop_detected: false\n      anomaly_score: \"< 0.7\"\n    action: \"soft_throttle\"\n    response: \"reduce RPM to 5, log warning\"\n\n  # Level 2: Budget breach + loop OR anomaly → hard throttle + alert\n  - condition:\n      budget_breach: true\n      loop_detected: true\n    action: \"hard_throttle\"\n    response: \"reduce RPM to 1, disable tool calls, alert SOC\"\n\n  # Level 3: Budget breach + loop + high anomaly → quarantine\n  - condition:\n      budget_breach: true\n      loop_detected: true\n      anomaly_score: \">= 0.7\"\n    action: \"quarantine\"\n    response: \"suspend session, block API key, open IR ticket\"\n\n  # Level 4: Spend > hard ceiling (any context) → emergency block\n  - condition:\n      spend_usd_exceeds_hard_ceiling: true\n    action: \"emergency_block\"\n    response: \"block all requests, page on-call, open P1 ticket\"</code></pre><h5>Escalation Logic</h5><pre><code># File: gateway/escalation_engine.py\n\n\ndef evaluate_escalation(\n    budget_result: dict,\n    loop_detection: dict,\n    anomaly_result: dict,\n    hard_spend_ceiling: float,\n    current_spend: float,\n) -> dict:\n    \"\"\"\n    Determine the appropriate containment level based on\n    correlated signals from budget, loop, and anomaly detectors.\n    \"\"\"\n    # Emergency: hard ceiling breach overrides everything\n    if current_spend >= hard_spend_ceiling:\n        return {\"level\": 4, \"action\": \"emergency_block\"}\n\n    budget_breached = not budget_result.get(\"allowed\", True)\n    loop_found = loop_detection.get(\"loop_detected\", False)\n    anomaly_score = anomaly_result.get(\"z_score\", 0)\n\n    if budget_breached and loop_found and anomaly_score >= 0.7:\n        return {\"level\": 3, \"action\": \"quarantine\"}\n    elif budget_breached and (loop_found or anomaly_score >= 0.5):\n        return {\"level\": 2, \"action\": \"hard_throttle\"}\n    elif budget_breached:\n        return {\"level\": 1, \"action\": \"soft_throttle\"}\n    else:\n        return {\"level\": 0, \"action\": \"allow\"}</code></pre><p><strong>Action:</strong> Build an escalation engine that correlates budget enforcement results (this technique) with loop detection (AID-H-018.001) and cost anomaly alerts (AID-D-005.007). The engine should apply proportional response: soft throttle for ambiguous breaches, hard containment for correlated multi-signal abuse. Every escalation action must be logged with incident correlation IDs for forensic reconstruction.</p>"
                }
            ]
        },
        {
            "id": "AID-I-004",
            "name": "Agent Memory & State Isolation",
            "description": "Manage the lifecycle, integrity, and isolation of agent memory in agentic AI systems. Agent memory (runtime context, tool traces, and persistent vector/RAG stores) is uniquely susceptible to:<ul><li>Prompt injection persistence</li><li>Memory/KB poisoning</li><li>Cross-session or cross-tenant contamination</li></ul><strong>Four Isolation Layers</strong><br/>This technique family enforces isolation across:<ul><li><strong>Runtime Hygiene</strong> (App)</li><li><strong>Persistent Partitioning</strong> (Data)</li><li><strong>Cryptographic Integrity</strong> (Security)</li><li><strong>Transactional Promotion Gates</strong> (Ops/Governance)</li></ul>",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0051 LLM Prompt Injection",
                        "AML.T0061 LLM Prompt Self-Replication",
                        "AML.T0070 RAG Poisoning",
                        "AML.T0080.000 AI Agent Context Poisoning: Memory",
                        "AML.T0099 AI Agent Tool Data Poisoning (memory isolation prevents poisoned tool data from persisting across sessions)",
                        "AML.T0080 AI Agent Context Poisoning",
                        "AML.T0092 Manipulate User LLM Chat History (memory isolation prevents chat history manipulation from persisting)",
                        "AML.T0080.001 AI Agent Context Poisoning: Thread (memory isolation prevents thread-level context contamination)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Goal Manipulation (L7) (via persistent instruction/memory poisoning)",
                        "Agent Tool Misuse (L7) (via poisoned recalled context)",
                        "Data Poisoning (L2) (when memory/KB is treated as data)",
                        "Compromised RAG Pipelines (L2)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection",
                        "LLM02:2025 Sensitive Information Disclosure",
                        "LLM04:2025 Data and Model Poisoning",
                        "LLM08:2025 Vector and Embedding Weaknesses",
                        "LLM10:2025 Unbounded Consumption"
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
                        "ASI06:2026 Memory & Context Poisoning",
                        "ASI01:2026 Agent Goal Hijack (poisoned memory can redirect agent goals)",
                        "ASI07:2026 Insecure Inter-Agent Communication (memory isolation prevents cross-agent contamination)"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.018 Prompt Injection",
                        "NISTAML.015 Indirect Prompt Injection",
                        "NISTAML.013 Data Poisoning",
                        "NISTAML.036 Leaking information from user interactions"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-5.1 Memory System Persistence",
                        "AISubtech-5.1.1 Long-term / Short-term Memory Injection",
                        "AITech-4.2 Context Boundary Attacks",
                        "AISubtech-6.1.1 Knowledge Base Poisoning",
                        "AITech-14.1 Unauthorized Access",
                        "AITech-7.2 Memory System Corruption (memory isolation prevents memory system corruption)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "PIJ: Prompt Injection (memory isolation limits injection persistence)",
                        "DP: Data Poisoning (memory isolation prevents poisoned data persistence across sessions)",
                        "SDD: Sensitive Data Disclosure (memory isolation prevents cross-session and cross-tenant data leakage)",
                        "RA: Rogue Actions (memory isolation prevents poisoned memory from driving rogue agent actions)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Agents - Core 13.1: Memory Poisoning",
                        "Agents - Core 13.6: Intent Breaking & Goal Manipulation (memory isolation prevents persistent goal manipulation)",
                        "Agents - Core 13.12: Agent Communication Poisoning (memory isolation prevents cross-agent contamination)",
                        "Agents - Tools MCP Server 13.24: Context Spoofing and Manipulation",
                        "Datasets 3.1: Data poisoning (memory and KB treated as data vulnerable to poisoning)"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-I-004.001",
                    "name": "Runtime Context Isolation & Hygiene",
                    "pillar": ["app"],
                    "phase": ["operation"],
                    "description": "Enforces strict boundaries and hygiene for volatile working memory (RAM/Redis). Prevents cross-session/cross-tenant context bleed, limits the temporal blast radius of prompt injections (via windowing/resets), and prevents resource exhaustion (DoS/cost burn) via size/token ceilings and TTL.",
                    "toolsOpenSource": [
                        "Redis (key TTL, eviction policies)",
                        "Memcached",
                        "OpenTelemetry (distributed tracing for memory events)",
                        "LangChain (memory modules) / Semantic Kernel (memory abstractions)"
                    ],
                    "toolsCommercial": [
                        "Redis Enterprise",
                        "Momento (serverless cache)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0051 LLM Prompt Injection",
                                "AML.T0061 LLM Prompt Self-Replication",
                                "AML.T0080.000 AI Agent Context Poisoning: Memory",
                                "AML.T0092 Manipulate User LLM Chat History (runtime context hygiene prevents chat history tampering from persisting)",
                                "AML.T0080.001 AI Agent Context Poisoning: Thread (runtime context hygiene prevents thread-level poisoning)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Agent Goal Manipulation (L7) (poisoned runtime context redirects agent behavior)",
                                "Data Tampering (L2) (runtime context treated as volatile data)",
                                "Data Leakage (Cross-Layer) (cross-session bleed exposes tenant data)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM01:2025 Prompt Injection",
                                "LLM02:2025 Sensitive Information Disclosure",
                                "LLM10:2025 Unbounded Consumption"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML09:2023 Output Integrity Attack (corrupted context leads to corrupted outputs)"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI06:2026 Memory & Context Poisoning",
                                "ASI08:2026 Cascading Failures (context bleed can propagate across sessions)",
                                "ASI03:2026 Identity and Privilege Abuse (context isolation prevents privilege carryover between sessions)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.018 Prompt Injection",
                                "NISTAML.015 Indirect Prompt Injection",
                                "NISTAML.036 Leaking information from user interactions",
                                "NISTAML.014 Energy-latency"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-4.2 Context Boundary Attacks",
                                "AISubtech-4.2.1 Context Window Exploitation",
                                "AISubtech-4.2.2 Session Boundary Violation",
                                "AITech-5.1 Memory System Persistence (runtime context can be used for persistence)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "PIJ: Prompt Injection (context isolation limits prompt injection persistence within session)",
                                "SDD: Sensitive Data Disclosure (session isolation prevents cross-tenant data leakage)",
                                "DMS: Denial of ML Service (context size ceilings prevent resource exhaustion)",
                                "RA: Rogue Actions (context reset breaks persistent rogue instructions)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning (runtime context hygiene limits memory poisoning persistence)",
                                "Agents - Core 13.4: Resource Overload (context size limits prevent resource exhaustion)",
                                "Agents - Tools MCP Server 13.24: Context Spoofing and Manipulation",
                                "Model Serving - Inference requests 9.4: Looped input (context windowing prevents harmful feedback loops)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Enforce per-session isolation with mandatory TTL, deterministic size/token limits, and fail-closed serialization to prevent cross-tenant bleed and DoS.",
                            "howTo": "<h5>Concept:</h5><p>Never store agent runtime context in a global in-process object. Use a shared store (e.g., Redis) keyed by <code>tenant_id + session_id</code> and enforce <strong>TTL</strong>, <strong>max bytes</strong>, and (optionally) <strong>max tokens</strong>. All reads/writes must be schema-validated and serialized deterministically. On violation, fail closed and emit an audit event.</p><h5>Example: Redis-backed Secure Runtime Context Store</h5><pre><code># File: memory/runtime_context_store.py\nimport json\nimport time\nfrom dataclasses import dataclass\nfrom typing import Any, Dict, List, Optional\n\nMAX_CONTEXT_BYTES = 256 * 1024   # 256KB hard ceiling (tune per model/context budget)\nSESSION_TTL_SECONDS = 3600       # 1 hour idle TTL\nALLOWED_ROLES = {\"user\", \"assistant\", \"tool\"}  # do NOT allow persisted 'system' from untrusted paths\n\n@dataclass(frozen=True)\nclass AuditEvent:\n    event: str\n    tenant_id: str\n    session_id: str\n    details: Dict[str, Any]\n    ts: int\n\n\ndef emit_audit(evt: AuditEvent) -&gt; None:\n    # Production: ship to SIEM via OTel logs, Kafka, or your logging pipeline\n    print(json.dumps(evt.__dict__, sort_keys=True))\n\n\ndef _key(tenant_id: str, session_id: str) -&gt; str:\n    return f\"tenant:{tenant_id}:session:{session_id}:runtime_context\"\n\n\ndef _serialize_context(messages: List[Dict[str, str]]) -&gt; bytes:\n    # Deterministic JSON prevents ambiguous size checks and simplifies forensics\n    return json.dumps(messages, sort_keys=True, separators=(\",\", \":\")).encode(\"utf-8\")\n\n\ndef _validate_messages(messages: Any) -&gt; List[Dict[str, str]]:\n    if not isinstance(messages, list):\n        raise ValueError(\"context must be a list\")\n\n    out: List[Dict[str, str]] = []\n    for m in messages:\n        if not isinstance(m, dict):\n            raise ValueError(\"each message must be an object\")\n        role = m.get(\"role\")\n        content = m.get(\"content\")\n        if role not in ALLOWED_ROLES:\n            raise ValueError(f\"role not allowed: {role}\")\n        if not isinstance(content, str):\n            raise ValueError(\"content must be a string\")\n        out.append({\"role\": role, \"content\": content})\n    return out\n\n\nclass RuntimeContextStore:\n    def __init__(self, redis_client):\n        self.redis = redis_client\n\n    def load(self, *, tenant_id: str, session_id: str) -&gt; List[Dict[str, str]]:\n        raw = self.redis.get(_key(tenant_id, session_id))\n        if raw is None:\n            return []\n\n        try:\n            obj = json.loads(raw)\n            messages = _validate_messages(obj)\n            return messages\n        except Exception as e:\n            emit_audit(AuditEvent(\n                event=\"RUNTIME_CONTEXT_LOAD_REJECTED\",\n                tenant_id=tenant_id,\n                session_id=session_id,\n                details={\"reason\": str(e)},\n                ts=int(time.time())\n            ))\n            # Fail closed: treat corrupted/tampered context as empty\n            return []\n\n    def store(self, *, tenant_id: str, session_id: str, messages: List[Dict[str, str]]) -&gt; None:\n        validated = _validate_messages(messages)\n        blob = _serialize_context(validated)\n\n        if len(blob) &gt; MAX_CONTEXT_BYTES:\n            emit_audit(AuditEvent(\n                event=\"RUNTIME_CONTEXT_WRITE_BLOCKED_OVERSIZE\",\n                tenant_id=tenant_id,\n                session_id=session_id,\n                details={\"bytes\": len(blob), \"max\": MAX_CONTEXT_BYTES},\n                ts=int(time.time())\n            ))\n            raise ValueError(\"context exceeds size ceiling\")\n\n        self.redis.set(_key(tenant_id, session_id), blob, ex=SESSION_TTL_SECONDS)\n        emit_audit(AuditEvent(\n            event=\"RUNTIME_CONTEXT_WRITE_OK\",\n            tenant_id=tenant_id,\n            session_id=session_id,\n            details={\"bytes\": len(blob), \"ttl\": SESSION_TTL_SECONDS},\n            ts=int(time.time())\n        ))\n</code></pre><p><strong>Action:</strong> Enforce (1) per-tenant/per-session keys, (2) deterministic serialization, (3) strict role allowlist (block persisted fake <code>system</code>), (4) TTL, and (5) hard ceilings. Emit structured audit events for both blocked writes and rejected loads.</p>"
                        },
                        {
                            "implementation": "Enforce Context Pinning and Instruction Re-injection to prevent eviction and 'Lost in the Middle' degradation",
                            "howTo": "<h5>Concept:</h5><p>Long-running agents accumulate state and can develop persistent poisoned instructions. Apply a sliding window for normal sessions, and enforce a hard reset for high-risk agents. The reset must reseed only from a trusted baseline that the agent cannot mutate.</p><h5>Example: Windowed Memory + Controlled Reset Hook</h5><pre><code># File: memory/resettable_memory.py\nfrom langchain.memory import ConversationBufferWindowMemory\n\nclass ResettableMemory:\n    def __init__(self, *, baseline_statement: str, k: int = 10):\n        self._baseline = baseline_statement\n        self._mem = ConversationBufferWindowMemory(k=k)\n        self.reset(reason=\"INIT\")\n\n    def reset(self, reason: str) -&gt; None:\n        # Production: emit audit event (who/what/when/why)\n        self._mem.clear()\n        # Seed a non-negotiable baseline (keep it short)\n        self._mem.save_context(\n            {\"input\": \"BASELINE\"},\n            {\"output\": self._baseline}\n        )\n\n    @property\n    def memory(self):\n        return self._mem\n</code></pre><p><strong>Action:</strong> Treat resets as a containment control: trigger resets periodically (e.g., daily) and immediately on drift/high-risk detections. Ensure the baseline is stored in configuration control and is not editable by the agent.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-004.002",
                    "name": "Persistent Memory Partitioning (Trust & Tenant Isolation)",
                    "pillar": ["data"],
                    "phase": ["building", "operation"],
                    "description": "Defines structural isolation for long-term memory (Vector DB/RAG). Uses namespaces/collections partitioned by tenant and trust tier, and enforces retrieval authorization via a centralized policy decision (never by agent self-assertion).",
                    "toolsOpenSource": [
                        "Qdrant (collections/tenancy patterns)",
                        "Weaviate (multi-tenancy features)",
                        "Milvus (partitions/collections)",
                        "OPA (policy-as-code for retrieval authorization)"
                    ],
                    "toolsCommercial": [
                        "Pinecone (indexes/namespaces)",
                        "Zilliz Cloud"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0070 RAG Poisoning",
                                "AML.T0080.000 AI Agent Context Poisoning: Memory"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Compromised RAG Pipelines (L2)",
                                "Data Poisoning (L2)",
                                "Data Leakage (Cross-Layer) (tenant isolation prevents cross-tenant data exposure)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM02:2025 Sensitive Information Disclosure",
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
                                "ASI06:2026 Memory & Context Poisoning",
                                "ASI03:2026 Identity and Privilege Abuse (authorization-gated retrieval prevents unauthorized access)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.013 Data Poisoning",
                                "NISTAML.015 Indirect Prompt Injection (partitioning limits scope of poisoned content retrieval)",
                                "NISTAML.036 Leaking information from user interactions (tenant partitioning prevents cross-tenant data leakage)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-5.1 Memory System Persistence",
                                "AISubtech-5.1.1 Long-term / Short-term Memory Injection",
                                "AISubtech-6.1.1 Knowledge Base Poisoning",
                                "AITech-7.2 Memory System Corruption (partitioning limits memory corruption blast radius to single tenant)",
                                "AITech-14.1 Unauthorized Access"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "DP: Data Poisoning (partitioning limits poisoning blast radius to single tenant)",
                                "SDD: Sensitive Data Disclosure (tenant partitioning prevents cross-tenant data exposure)",
                                "PIJ: Prompt Injection (partitioning limits scope of poisoned content retrieval)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning (partitioning limits memory poisoning to single tenant)",
                                "Agents - Core 13.3: Privilege Compromise (authorization-gated retrieval prevents unauthorized access)",
                                "Agents - Tools MCP Server 13.24: Context Spoofing and Manipulation (partitioning prevents cross-tenant context manipulation)",
                                "Raw Data 1.1: Insufficient access controls (policy-gated retrieval enforces access controls on memory)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Partition long-term memory by tenant + trust tier; retrieval must consult a central entitlement/policy service and be fully audited.",
                            "howTo": "<h5>Concept:</h5><p>Do not use a flat global vector index. Create partitions that encode <strong>tenant boundary</strong> and <strong>trust tier</strong> (e.g., <code>tenant123:public</code>, <code>tenant123:internal</code>, <code>tenant123:trusted</code>, <code>tenant123:quarantined</code>). The application decides readable namespaces based on identity + policy; the agent must not self-select namespaces.</p><h5>Example: Policy-Gated Retrieval</h5><pre><code># File: memory/retrieval_gate.py\nfrom typing import Dict, List\n\n\ndef get_allowed_namespaces(*, tenant_id: str, principal: Dict) -&gt; List[str]:\n    # Production: call OPA/ABAC service; do not hardcode roles inside the agent\n    roles = set(principal.get(\"roles\", []))\n    allowed = [f\"{tenant_id}:public\"]\n    if \"EMPLOYEE\" in roles:\n        allowed.append(f\"{tenant_id}:internal\")\n    if \"AI_PLATFORM_ADMIN\" in roles:\n        allowed.append(f\"{tenant_id}:trusted\")\n    return allowed\n\n\ndef secure_vector_search(*, vector_db, tenant_id: str, principal: Dict, query_vector: List[float]) -&gt; List[Dict]:\n    namespaces = get_allowed_namespaces(tenant_id=tenant_id, principal=principal)\n    results: List[Dict] = []\n\n    for ns in namespaces:\n        # Production: emit audit (principal, tenant, namespace, query hash)\n        hits = vector_db.search(collection=\"agent_memory\", namespace=ns, query_vector=query_vector, limit=5)\n        results.extend(hits)\n\n    return results\n</code></pre><p><strong>Action:</strong> Make namespace selection a backend authorization decision, not an LLM decision. Log every cross-namespace retrieval for forensics and compliance.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-004.003",
                    "name": "Cryptographic Memory Integrity (Signed Write/Verify Read)",
                    "pillar": ["app", "data"],
                    "phase": ["operation"],
                    "description": "Establishes an end-to-end integrity loop for persistent memory: a controlled writer issues signed records (content-hash + metadata + key id), and an integrity-first loader verifies signatures and hashes before any content can re-enter agent context. This prevents direct-to-DB poisoning/tampering and forces memory provenance to be verifiable.",
                    "toolsOpenSource": [
                        "HashiCorp Vault (Transit) / SPIFFE-SVID for workload identity",
                        "Sigstore/cosign (attestation patterns)",
                        "Python stdlib (hashlib, hmac) / PyCA cryptography (asymmetric signing)"
                    ],
                    "toolsCommercial": [
                        "AWS KMS",
                        "Azure Key Vault",
                        "Google Cloud KMS"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0080.000 AI Agent Context Poisoning: Memory",
                                "AML.T0070 RAG Poisoning (crypto integrity prevents direct-to-DB poisoning)",
                                "AML.T0099 AI Agent Tool Data Poisoning (cryptographic integrity detects tool-sourced poisoned data in memory)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Tampering (L2)",
                                "Compromised RAG Pipelines (L2) (signed records prevent pipeline tampering)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM04:2025 Data and Model Poisoning",
                                "LLM08:2025 Vector and Embedding Weaknesses (signed records detect tampered vector/embedding entries)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML02:2023 Data Poisoning Attack",
                                "ML09:2023 Output Integrity Attack"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI06:2026 Memory & Context Poisoning",
                                "ASI04:2026 Agentic Supply Chain Vulnerabilities (integrity verification prevents tampered memory artifacts)",
                                "ASI03:2026 Identity and Privilege Abuse"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.015 Indirect Prompt Injection (signed records detect injected content)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-5.1 Memory System Persistence",
                                "AISubtech-5.1.1 Long-term / Short-term Memory Injection",
                                "AISubtech-6.1.1 Knowledge Base Poisoning",
                                "AITech-7.2 Memory System Corruption"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "PIJ: Prompt Injection (signed records detect injected content in persistent memory)",
                                "MST: Model Source Tampering (integrity verification detects tampered memory artifacts)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning (cryptographic integrity detects and prevents memory poisoning)",
                                "Agents - Tools MCP Server 13.18: Tool Poisoning (integrity verification detects tool-sourced poisoned data)",
                                "Raw Data 1.7: Lack of data trustworthiness (signed records ensure data trustworthiness)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Controlled writer and integrity-first loader: sign canonical metadata at write time, then verify signature and content hash before any record is returned to the agent.",
                            "howTo": "<h5>Concept:</h5><p>To avoid canonicalization pitfalls, sign a small, canonical metadata payload that includes a <code>sha256(content)</code>. Store a <code>kid</code> (key id) to support key rotation. The writer service should run under workload identity and be the only component permitted to write into trusted namespaces.</p><h5>Example: Signed Record (HMAC for simplicity; swap to KMS/Asymmetric for enterprise)</h5><pre><code># File: memory/integrity/signed_record.py\nimport hashlib\nimport hmac\nimport json\nimport time\nfrom typing import Dict\n\n\ndef canonical_json(obj: Dict) -&gt; bytes:\n    return json.dumps(obj, sort_keys=True, separators=(\",\", \":\")).encode(\"utf-8\")\n\n\ndef make_signed_record(*, content: str, namespace: str, issuer: str, kid: str, signing_key: bytes) -&gt; Dict:\n    content_hash = hashlib.sha256(content.encode(\"utf-8\")).hexdigest()\n\n    meta = {\n        \"ver\": \"v1\",\n        \"kid\": kid,\n        \"ns\": namespace,\n        \"iss\": issuer,\n        \"ts\": int(time.time()),\n        \"chash\": content_hash\n    }\n\n    sig = hmac.new(signing_key, canonical_json(meta), hashlib.sha256).hexdigest()\n\n    return {\n        \"content\": content,\n        \"meta\": meta,\n        \"sig\": sig\n    }\n</code></pre><p><strong>Action:</strong> Require that only the controlled writer can write to trusted namespaces (enforce at API and DB/collection permissions). Include <code>kid</code> for rotation, and always sign canonical metadata, not arbitrary JSON formatting.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-004.004",
                    "name": "Transactional Promotion Gates (Quarantine -> Trusted)",
                    "pillar": ["app", "data"],
                    "phase": ["operation"],
                    "description": "Implements a strict state machine and atomic promotion workflow for high-risk memory writes. Items routed into quarantine cannot influence agent behavior until reviewed and promoted. Promotion must be transactional, auditable, and typically re-signed as trusted. Aligns with trust-tiered memory write-gates (e.g., trusted/probation/quarantined).",
                    "toolsOpenSource": [
                        "PostgreSQL (transactions, row locks, RLS)",
                        "Kafka / Redis Streams (promotion queues)",
                        "Temporal / Celery (workflow execution)",
                        "OPA (policy-as-code for approval rules)"
                    ],
                    "toolsCommercial": [
                        "ServiceNow (approval workflows)",
                        "Jira Service Management"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0070 RAG Poisoning",
                                "AML.T0080.000 AI Agent Context Poisoning: Memory",
                                "AML.T0099 AI Agent Tool Data Poisoning (promotion gates quarantine tool-sourced data until reviewed)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Poisoning (L2)",
                                "Compromised RAG Pipelines (L2)",
                                "Data Tampering (L2) (promotion gates prevent unreviewed tampering from reaching trusted memory)"
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
                                "ASI06:2026 Memory & Context Poisoning",
                                "ASI09:2026 Human-Agent Trust Exploitation (promotion gates enforce human review before trust elevation)",
                                "ASI01:2026 Agent Goal Hijack (promotion gates prevent poisoned memory from hijacking agent goals)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.013 Data Poisoning",
                                "NISTAML.015 Indirect Prompt Injection (quarantine prevents injected content from entering trusted memory)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AISubtech-5.1.1 Long-term / Short-term Memory Injection",
                                "AISubtech-6.1.1 Knowledge Base Poisoning",
                                "AITech-5.1 Memory System Persistence",
                                "AITech-7.2 Memory System Corruption"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "DP: Data Poisoning (promotion gates quarantine poisoned data before it reaches trusted memory)",
                                "PIJ: Prompt Injection (quarantine prevents injected content from entering trusted memory)",
                                "RA: Rogue Actions (promotion gates prevent unreviewed agent-written data from being trusted)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning (promotion gates quarantine poisoned memory until reviewed)",
                                "Agents - Core 13.10: Overwhelming Human in the Loop (structured promotion workflow prevents approval fatigue bypass)",
                                "Datasets 3.1: Data poisoning (quarantine gate prevents poisoned data from entering trusted stores)",
                                "Agents - Core 13.6: Intent Breaking & Goal Manipulation (promotion gates prevent poisoned state from redirecting agent intent)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Quarantine state machine with atomic promotion: enforce allowed transitions and re-sign on promotion (fail-closed).",
                            "howTo": "<h5>Concept:</h5><p>All untrusted memory candidates land in <code>QUARANTINED</code> (or <code>PENDING</code>). Retrieval must exclude quarantined by default. Promotion must be an atomic transaction that: (1) locks the row, (2) validates current state, (3) records approver identity and rationale, (4) writes to trusted namespace via the controlled writer (<code>AID-I-004.003</code>), (5) marks the quarantined item as <code>PROMOTED</code> with immutable audit fields.</p><h5>Example: Transactional Promotion (PostgreSQL)</h5><pre><code># File: memory/promotion/promote.py\nfrom typing import Any, Dict\n\n\ndef promote_item(*, item_id: str, approver_id: str, db, controlled_writer) -&gt; Dict[str, Any]:\n    with db.transaction():\n        # 1) Lock row to prevent race conditions\n        item = db.select_for_update(\"quarantine_items\", where={\"id\": item_id})\n        if item[\"state\"] != \"PENDING\":\n            raise ValueError(\"item not pending\")\n\n        # 2) Write into trusted namespace ONLY via controlled writer (re-sign)\n        controlled_writer.write(\n            content=item[\"content\"],\n            namespace=item[\"target_trusted_namespace\"],\n            issuer=approver_id\n        )\n\n        # 3) Update state + immutable audit fields\n        db.update(\n            \"quarantine_items\",\n            where={\"id\": item_id},\n            values={\n                \"state\": \"PROMOTED\",\n                \"approved_by\": approver_id,\n                \"approved_at\": db.now_utc()\n            }\n        )\n\n    return {\"status\": \"PROMOTED\", \"id\": item_id}\n</code></pre><p><strong>Action:</strong> Enforce promotion via DB transactions + row locks. Never allow an agent to bypass quarantine and write directly into trusted memory. Treat promotion as a security boundary: auditable, policy-gated, and cryptographically sealed.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-004.005",
                    "name": "Memory TTL, Staleness Decay & Forced Forgetting",
                    "pillar": ["app", "data"],
                    "phase": ["operation"],
                    "description": "Apply time-based trust decay and deletion controls to persistent agent memory so stored context does not remain implicitly trusted forever. This sub-technique introduces TTLs, freshness metadata, re-validation gates, downgrade rules, and forced forgetting policies for long-lived memory entries. The goal is to reduce stale-instruction risk, latent memory poisoning, cross-session carryover, and retention of privacy- or mission-sensitive context that should no longer influence agent behavior. Scope boundary: AID-I-004.001 handles session-level / ephemeral context hygiene; this sub-technique handles persistent memory lifecycle management including trust decay, re-validation, and deletion.",
                    "toolsOpenSource": [
                        "Redis / Valkey (TTL, expiry, keyspace notifications)",
                        "PostgreSQL (row-level TTL via pg_cron, triggers)",
                        "Qdrant / Weaviate / Milvus (payload-based expiry filters)",
                        "Temporal / Celery (scheduled decay and re-validation workflows)",
                        "OpenTelemetry (memory lifecycle event telemetry)"
                    ],
                    "toolsCommercial": [
                        "Redis Enterprise (active-active with TTL sync)",
                        "Pinecone (metadata-filtered deletion)",
                        "Datadog (memory lifecycle dashboards)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0080 AI Agent Context Poisoning",
                                "AML.T0080.000 AI Agent Context Poisoning: Memory",
                                "AML.T0051 LLM Prompt Injection",
                                "AML.T0061 LLM Prompt Self-Replication",
                                "AML.T0092 Manipulate User LLM Chat History"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Agent Goal Manipulation (L7)",
                                "Agent Tool Misuse (L7)",
                                "Data Poisoning (L2)",
                                "Compromised RAG Pipelines (L2)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM01:2025 Prompt Injection",
                                "LLM02:2025 Sensitive Information Disclosure",
                                "LLM04:2025 Data and Model Poisoning",
                                "LLM09:2025 Misinformation (stale memory causes agent to act on outdated context, producing incorrect or misleading outputs)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML02:2023 Data Poisoning Attack",
                                "ML09:2023 Output Integrity Attack"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI06:2026 Memory & Context Poisoning",
                                "ASI01:2026 Agent Goal Hijack"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.018 Prompt Injection",
                                "NISTAML.015 Indirect Prompt Injection",
                                "NISTAML.013 Data Poisoning",
                                "NISTAML.036 Leaking information from user interactions"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-5.1 Memory System Persistence",
                                "AITech-7.2 Memory System Corruption",
                                "AISubtech-5.1.1 Long-term / Short-term Memory Injection",
                                "AISubtech-7.2.1 Memory Anchor Attacks"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "PIJ: Prompt Injection (TTL and decay limit temporal persistence of injected instructions)",
                                "DP: Data Poisoning (forced forgetting removes stale poisoned memory entries)",
                                "SDD: Sensitive Data Disclosure (forced forgetting ensures privacy-sensitive context is deleted after retention windows)",
                                "EDH: Excessive Data Handling (TTL and forced forgetting prevent excessive memory retention)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning (TTL limits temporal persistence of poisoned memory)",
                                "Agents - Core 13.6: Intent Breaking & Goal Manipulation (staleness decay removes outdated manipulated goals)",
                                "Raw Data 1.9: Stale data (TTL and freshness metadata address stale memory risks)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Attach freshness metadata such as creation time, expiry time, last access time, last validation time, and trust tier to every persistent memory record.",
                            "howTo": "<h5>Concept:</h5><p>Every persistent memory record must carry structured metadata that tracks its lifecycle state. Without this metadata, the system cannot distinguish a memory written 5 minutes ago from one written 6 months ago, nor can it determine whether a memory has ever been re-validated since its original write. This metadata is the foundation for all subsequent TTL, decay, and deletion logic.</p><h5>Define Memory Record Schema</h5><pre><code># File: memory/schemas.py\nfrom dataclasses import dataclass, field\nfrom datetime import datetime, timezone\nfrom enum import Enum\nfrom typing import Optional\n\n\nclass TrustTier(str, Enum):\n    TRUSTED = \"trusted\"\n    PROBATION = \"probation\"\n    QUARANTINED = \"quarantined\"\n    STALE = \"stale\"  # downgraded from trusted due to TTL expiry\n\n\n@dataclass\nclass MemoryRecord:\n    \"\"\"Schema for persistent agent memory with lifecycle metadata.\"\"\"\n    memory_id: str\n    namespace: str              # e.g., \"user_preferences\", \"task_context\"\n    content: str\n    content_hash: str           # SHA-256 of content for integrity checks\n\n    # Lifecycle timestamps (all UTC)\n    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))\n    expires_at: Optional[datetime] = None       # hard TTL; auto-delete after this\n    last_accessed_at: Optional[datetime] = None # updated on every retrieval\n    last_validated_at: Optional[datetime] = None # updated when re-validation passes\n\n    # Trust state\n    trust_tier: TrustTier = TrustTier.QUARANTINED\n    promoted_by: Optional[str] = None  # identity of approver (see AID-I-004.004)\n\n    # Decay policy (class-level defaults, overridden per namespace)\n    staleness_threshold_hours: int = 720  # 30 days default\n    forced_forget_on_session_end: bool = False\n\n    @property\n    def is_stale(self) -> bool:\n        \"\"\"Check if memory has exceeded staleness threshold without re-validation.\"\"\"\n        if self.last_validated_at is None:\n            reference = self.created_at\n        else:\n            reference = self.last_validated_at\n        age_hours = (datetime.now(timezone.utc) - reference).total_seconds() / 3600\n        return age_hours > self.staleness_threshold_hours\n\n    @property\n    def is_expired(self) -> bool:\n        \"\"\"Check if memory has passed its hard TTL.\"\"\"\n        if self.expires_at is None:\n            return False\n        return datetime.now(timezone.utc) > self.expires_at</code></pre><p><strong>Action:</strong> Extend your memory store schema to include all lifecycle fields. Every memory write—whether from agent self-reflection, user input, or tool output—must populate <code>created_at</code>, <code>expires_at</code> (per namespace policy), <code>trust_tier</code>, and <code>content_hash</code>. These fields are non-optional; writes without them must be rejected.</p>"
                        },
                        {
                            "implementation": "Automatically downgrade or quarantine trusted memory that exceeds TTL or staleness thresholds until it is re-validated by policy or human review.",
                            "howTo": "<h5>Concept:</h5><p>Memory that was once trusted can become dangerous if left unchecked. A user preference stored 6 months ago may no longer reflect reality; a task instruction from a previous project phase may now be wrong. Rather than deleting stale memory immediately (which loses potentially useful context), downgrade it to a <code>STALE</code> trust tier that excludes it from agent retrieval by default. Stale memory can be re-validated and re-promoted, or eventually garbage-collected.</p><h5>Step 1: Implement a Scheduled Decay Worker</h5><pre><code># File: memory/decay_worker.py\nfrom datetime import datetime, timezone\nfrom memory.schemas import TrustTier\n\n\ndef run_decay_sweep(db) -> dict:\n    \"\"\"\n    Periodic job (e.g., hourly via cron/Temporal) that downgrades stale memory.\n    Returns summary of actions taken.\n    \"\"\"\n    now = datetime.now(timezone.utc)\n    stats = {\"downgraded\": 0, \"expired_deleted\": 0}\n\n    # 1. Find trusted/probation records that have gone stale\n    stale_candidates = db.query(\n        \"SELECT * FROM agent_memory \"\n        \"WHERE trust_tier IN ('trusted', 'probation') \"\n        \"AND (\"\n        \"  (last_validated_at IS NOT NULL AND \"\n        \"   EXTRACT(EPOCH FROM (%s - last_validated_at)) / 3600 > staleness_threshold_hours)\"\n        \"  OR \"\n        \"  (last_validated_at IS NULL AND \"\n        \"   EXTRACT(EPOCH FROM (%s - created_at)) / 3600 > staleness_threshold_hours)\"\n        \")\",\n        (now, now),\n    )\n\n    for record in stale_candidates:\n        db.update(\n            \"agent_memory\",\n            where={\"memory_id\": record[\"memory_id\"]},\n            values={\n                \"trust_tier\": TrustTier.STALE.value,\n                \"stale_since\": now,\n            },\n        )\n        emit_telemetry(\n            event=\"MEMORY_DOWNGRADED\",\n            memory_id=record[\"memory_id\"],\n            namespace=record[\"namespace\"],\n            previous_tier=record[\"trust_tier\"],\n            reason=\"staleness_threshold_exceeded\",\n        )\n        stats[\"downgraded\"] += 1\n\n    # 2. Hard-delete records past their expires_at TTL\n    expired = db.query(\n        \"SELECT * FROM agent_memory \"\n        \"WHERE expires_at IS NOT NULL AND expires_at < %s\",\n        (now,),\n    )\n    for record in expired:\n        db.delete(\"agent_memory\", where={\"memory_id\": record[\"memory_id\"]})\n        emit_telemetry(\n            event=\"MEMORY_TTL_DELETED\",\n            memory_id=record[\"memory_id\"],\n            namespace=record[\"namespace\"],\n        )\n        stats[\"expired_deleted\"] += 1\n\n    return stats\n\n\ndef emit_telemetry(**kwargs):\n    \"\"\"Emit structured event to OpenTelemetry / SIEM.\"\"\"\n    import json\n    print(json.dumps({\"ts\": datetime.now(timezone.utc).isoformat(), **kwargs}))</code></pre><h5>Step 2: Exclude Stale Memory from Retrieval</h5><pre><code># File: memory/retriever.py\n\ndef retrieve_memory(db, query_embedding, namespace: str, top_k: int = 10):\n    \"\"\"\n    Retrieve memory records, excluding stale and quarantined by default.\n    Only trusted and probation records are returned to the agent.\n    \"\"\"\n    results = db.vector_search(\n        table=\"agent_memory\",\n        query=query_embedding,\n        top_k=top_k,\n        filters={\n            \"namespace\": namespace,\n            \"trust_tier__in\": [\"trusted\", \"probation\"],\n            # Stale and quarantined records are invisible to the agent\n        },\n    )\n    return results</code></pre><p><strong>Action:</strong> Deploy a scheduled decay worker (hourly or per your risk tolerance) that scans all persistent memory and downgrades stale records. Ensure retrieval queries filter out <code>STALE</code> and <code>QUARANTINED</code> tiers by default. Stale records remain available for human review, re-validation, or forensic analysis but do not influence agent behavior.</p>"
                        },
                        {
                            "implementation": "Apply forced forgetting policies for session-scoped, user-preference, or privacy-sensitive memory classes so they are deleted at session end or after defined retention windows.",
                            "howTo": "<h5>Concept:</h5><p>Not all memory should persist. Session-specific instructions, temporary user preferences, and privacy-sensitive context (e.g., PII shared during a support interaction) must be forcefully forgotten when their retention window closes. This is distinct from staleness decay—forced forgetting is a hard, policy-driven deletion, not a trust downgrade. It also supports compliance obligations (GDPR Art. 17, CCPA deletion rights) without making this technique primarily about compliance.</p><h5>Define Namespace-Level Forgetting Policies</h5><pre><code># File: policies/memory_retention_policy.yaml\n\nmemory_retention:\n  namespaces:\n    session_context:\n      # Delete immediately when session ends\n      retention: \"session\"\n      forced_forget: true\n\n    user_preferences:\n      # Keep for 90 days, then hard-delete\n      retention_days: 90\n      forced_forget: true\n\n    task_instructions:\n      # Keep for 30 days with staleness decay\n      retention_days: 30\n      staleness_threshold_hours: 360  # 15 days\n      forced_forget: false  # stale records kept for review\n\n    pii_context:\n      # Minimum retention, hard delete after 24 hours\n      retention_hours: 24\n      forced_forget: true\n      cascade_delete: true  # also delete derived embeddings/summaries\n\n    long_term_knowledge:\n      # No hard TTL, but staleness decay applies\n      retention: \"indefinite\"\n      staleness_threshold_hours: 2160  # 90 days\n      forced_forget: false</code></pre><h5>Session-End Hook</h5><pre><code># File: memory/session_cleanup.py\nfrom datetime import datetime, timezone\n\n\ndef on_session_end(db, session_id: str):\n    \"\"\"\n    Called when an agent session terminates.\n    Deletes all memory with forced_forget=true in session-scoped namespaces.\n    \"\"\"\n    session_records = db.query(\n        \"SELECT * FROM agent_memory \"\n        \"WHERE session_id = %s AND forced_forget_on_session_end = true\",\n        (session_id,),\n    )\n\n    for record in session_records:\n        # Cascade: delete derived artifacts (embeddings, summaries, cache entries)\n        if record.get(\"cascade_delete\"):\n            db.delete(\"memory_embeddings\", where={\"source_memory_id\": record[\"memory_id\"]})\n            db.delete(\"memory_summaries\", where={\"source_memory_id\": record[\"memory_id\"]})\n\n        db.delete(\"agent_memory\", where={\"memory_id\": record[\"memory_id\"]})\n\n        emit_telemetry(\n            event=\"MEMORY_FORCED_FORGET\",\n            memory_id=record[\"memory_id\"],\n            namespace=record[\"namespace\"],\n            session_id=session_id,\n            reason=\"session_end_policy\",\n        )\n\n\ndef emit_telemetry(**kwargs):\n    import json\n    print(json.dumps({\"ts\": datetime.now(timezone.utc).isoformat(), **kwargs}))</code></pre><p><strong>Action:</strong> Define namespace-level retention policies in a central config. Wire session-end hooks to your agent orchestrator so session-scoped and PII memory is hard-deleted immediately. For time-based retention (e.g., 90-day user preferences), the decay worker (Strategy 2) handles deletion at expiry. All forced-forget actions must emit auditable telemetry events.</p>"
                        },
                        {
                            "implementation": "Propagate deletion and downgrade actions across derived artifacts such as embeddings, summaries, secondary indexes, caches, and replicas instead of deleting only the primary record.",
                            "howTo": "<h5>Concept:</h5><p>Deleting a memory record from the primary store is insufficient if its content lives on in derived artifacts: vector embeddings, auto-generated summaries, secondary search indexes, semantic caches, or cross-region replicas. An attacker who knows a memory was \"deleted\" can still influence the agent through these residual artifacts. Cascade deletion must trace every derived artifact and purge them as part of the same operation.</p><h5>Implement Cascading Deletion</h5><pre><code># File: memory/cascade_delete.py\nfrom datetime import datetime, timezone\nfrom typing import List\n\n\ndef cascade_delete_memory(\n    db,\n    vector_store,\n    cache_store,\n    memory_id: str,\n    reason: str,\n) -> dict:\n    \"\"\"\n    Delete a memory record AND all its derived artifacts atomically.\n    Returns a manifest of all deletions for audit.\n    \"\"\"\n    manifest = {\n        \"memory_id\": memory_id,\n        \"reason\": reason,\n        \"deleted_at\": datetime.now(timezone.utc).isoformat(),\n        \"artifacts_deleted\": [],\n    }\n\n    # 1. Delete from primary memory store\n    db.delete(\"agent_memory\", where={\"memory_id\": memory_id})\n    manifest[\"artifacts_deleted\"].append(\"primary_record\")\n\n    # 2. Delete vector embeddings derived from this memory\n    embedding_ids = db.query(\n        \"SELECT embedding_id FROM memory_embeddings \"\n        \"WHERE source_memory_id = %s\",\n        (memory_id,),\n    )\n    for eid in embedding_ids:\n        vector_store.delete(eid[\"embedding_id\"])\n    db.delete(\"memory_embeddings\", where={\"source_memory_id\": memory_id})\n    manifest[\"artifacts_deleted\"].append(\n        f\"embeddings ({len(embedding_ids)} vectors)\"\n    )\n\n    # 3. Delete auto-generated summaries\n    db.delete(\"memory_summaries\", where={\"source_memory_id\": memory_id})\n    manifest[\"artifacts_deleted\"].append(\"summaries\")\n\n    # 4. Invalidate cached responses that referenced this memory\n    cache_keys = cache_store.find_keys_by_tag(f\"mem:{memory_id}\")\n    for key in cache_keys:\n        cache_store.delete(key)\n    manifest[\"artifacts_deleted\"].append(\n        f\"cache_entries ({len(cache_keys)} keys)\"\n    )\n\n    # 5. Emit audit event with full manifest\n    import json\n    print(json.dumps({\n        \"event\": \"CASCADE_DELETE_COMPLETE\",\n        **manifest,\n    }))\n\n    return manifest</code></pre><p><strong>Action:</strong> Every memory delete operation—whether triggered by TTL expiry, forced forgetting, or explicit user deletion request—must invoke <code>cascade_delete_memory()</code> rather than deleting only the primary record. The deletion manifest provides an auditable proof that all residual artifacts have been purged. For compliance-driven deletion requests (e.g., right-to-delete), store the manifest as evidence of completed deletion.</p>"
                        }
                    ],
                    "warning": {
                        "level": "Medium on Recall Quality & Personalization",
                        "description": "<p>Aggressive TTL and forgetting policies can reduce long-term personalization, task continuity, and retrieval hit rate. Tune retention windows by memory class rather than applying one global policy, and require explicit justification for exceptions that keep sensitive or high-impact memory beyond standard windows.</p>"
                    }
                },
                {
                    id: "AID-I-004.006",
                    name: "Agent Identity & Persistent State File Write Protection",
                    pillar: ["app", "infra"],
                    phase: ["operation", "response"],
                    description:
                        "Enforce strict write-protection controls on high-trust, file-backed persistent identity and state surfaces used by agent platforms — such as reserved logical resources like <code>agent.identity.soul</code>, <code>agent.memory.primary</code>, and <code>agent.identity.agents_config</code>, which are commonly backed by files like <code>SOUL.md</code>, <code>MEMORY.md</code>, and <code>AGENTS.md</code> — to prevent malicious or compromised skills from establishing persistent backdoors that survive skill uninstallation, session restart, or agent redeployment.<br/><br/><strong>Scope:</strong> This sub-technique focuses on file-backed persistent identity/state surfaces whose modification can influence agent behavior across future sessions. It does not cover every database-backed or vector-backed memory system; those broader persistent-memory controls are owned by the rest of the AID-I-004 family.<br/><br/><strong>Controls enforced:</strong> OS-level immutability, controlled-writer gates, baseline verification, diff checks, rollback, and tamper-audit.<br/><br/><strong>Distinction from related techniques:</strong><ul><li><strong>vs AID-I-004.003</strong> (Cryptographic Memory Integrity): I-004.003 protects integrity <em>after</em> content is written; this sub-technique controls <em>who may write</em> to these surfaces, under what conditions, and how unauthorized changes are prevented, detected, and recovered.</li><li><strong>vs AID-H-019.007</strong> (Skill Permission Manifest): H-019.007 determines whether a skill is <em>authorized to request access</em> to a protected resource in its manifest; this sub-technique protects the <em>persistence surface itself</em>. H-019.007 is the skill capability boundary; I-004.006 is the file-backed persistence surface control.</li></ul>",
                    toolsOpenSource: [
                        "AIDE / Tripwire / OSSEC (file integrity monitoring for baseline verification and diff check)",
                        "Falco / Cilium Tetragon (runtime file access monitoring and blocking)",
                        "Git (identity file versioning for rollback — treating identity/state files as versioned artifacts)",
                        "gVisor / seccomp-bpf (OS-level enforcement of read-only filesystem)",
                        "HashiCorp Vault OSS (baseline hash storage and secret management)",
                    ],
                    toolsCommercial: [
                        "CrowdStrike Falcon / SentinelOne / Microsoft Defender (EDR with file integrity monitoring and real-time block)",
                        "Aqua Security / Prisma Cloud (container runtime protection with read-only enforcement)",
                        "HashiCorp Vault Enterprise (KMS-protected baseline hash storage with audit logging and namespaces)",
                    ],
                    defendsAgainst: [
                        {
                            framework: "MITRE ATLAS",
                            items: [
                                "AML.T0081 Modify AI Agent Configuration",
                                "AML.T0084 Discover AI Agent Configuration",
                                "AML.T0011.002 User Execution: Poisoned AI Agent Tool",
                                "AML.T0104 Publish Poisoned AI Agent Tool",
                            ],
                        },
                        {
                            framework: "MAESTRO",
                            items: [
                                "Agent Goal Manipulation (L7)",
                                "Agent Identity Attack (L7)",
                                "Backdoor Attacks (L3)",
                            ],
                        },
                        {
                            framework: "OWASP LLM Top 10 2025",
                            items: [
                                "LLM01:2025 Prompt Injection",
                                "LLM06:2025 Excessive Agency",
                            ],
                        },
                        {
                            framework: "OWASP ML Top 10 2023",
                            items: ["N/A"],
                        },
                        {
                            framework: "OWASP Agentic AI Top 10 2026",
                            items: [
                                "ASI01:2026 Agent Goal Hijack",
                                "ASI06:2026 Memory & Context Poisoning",
                                "ASI10:2026 Rogue Agents",
                            ],
                        },
                        {
                            framework: "NIST Adversarial Machine Learning 2025",
                            items: [
                                "NISTAML.018 Prompt Injection",
                                "NISTAML.039 Compromising connected resources (tampered agent identity/config files can redirect agent to compromise connected resources)",
                            ],
                        },
                        {
                            framework: "Cisco Integrated AI Security and Safety Framework",
                            items: [
                                "AITech-5.2 Configuration Persistence",
                                "AISubtech-5.2.1 Agent Profile Tampering",
                                "AITech-1.3 Goal Manipulation",
                            ],
                        },
                        {
                            framework: "Google Secure AI Framework 2.0 - Risks",
                            items: ["RA: Rogue Actions (write protection on persistent identity/state files prevents persistent backdoors that enable rogue actions)"],
                        },
                        {
                            framework: "Databricks AI Security Framework 3.0",
                            items: [
                                "Agents - Core 13.1: Memory Poisoning",
                                "Agents - Core 13.6: Intent Breaking & Goal Manipulation",
                            ],
                        },
                    ],
                    implementationGuidance: [
                        {
                            implementation:
                                "Default-deny writes to protected file-backed identity/state surfaces, and enforce updates through a controlled writer plus OS-level immutability.",
                            howTo:
                                "<h5>Concept</h5><p>This sub-technique protects <strong>file-backed</strong> high-trust persistent identity/state surfaces, not every possible memory backend. Use reserved logical resource IDs as the canonical policy layer, and treat concrete files only as platform-specific backing implementations.</p><p><em>Note: The logical resource IDs and backing filenames below are representative examples. Different agent platforms will use different concrete files (e.g., persona configs, agent manifests, persistent instruction files). The principle — protect high-trust persistent identity/state surfaces — applies regardless of platform.</em></p><pre><code class=\"language-yaml\">protected_resources:\n  - agent.identity.soul           # commonly backed by SOUL.md or equivalent\n  - agent.memory.primary          # commonly backed by MEMORY.md or equivalent\n  - agent.identity.agents_config  # commonly backed by AGENTS.md or equivalent\n</code></pre><p><strong>Boundary with AID-H-019.007:</strong> a manifest may declare whether a skill is authorized to request protected-resource writes, but that manifest declaration alone must never be the write path. This sub-technique owns the persistence surface protection itself: immutable mounts, controlled-writer gates, baseline verification, diff checks, rollback, and tamper-audit.</p><h5>Deployment Pattern A — Immutable baseline mode</h5><p>Use this when the protected surface should almost never change in production.</p><ul><li>Store the backing files on a read-only mount or immutable path.</li><li>Use a signed / approved baseline artifact for deployment.</li><li>Changes happen only through formal rollout / replacement, not in-place writes.</li></ul><h5>Deployment Pattern B — Controlled mutable mode</h5><p>Use this only when a protected file-backed surface truly requires approved updates.</p><ul><li>Do not allow direct skill file writes.</li><li>Expose a dedicated controlled-writer API / service as the only legal update path.</li><li>Require authenticated caller identity, authorization policy, audit logging, and pre-write snapshotting.</li></ul><h5>OS-level enforcement guidance</h5><p>Linux-hosted VM / bare-metal environments may use <code>chattr +i</code> or equivalent immutable flag where supported. Containerized / orchestrated environments should instead rely primarily on read-only mounts, dedicated protected volumes, runtime file-write interception, and signed baseline artifacts. Do not assume <code>chattr +i</code> works uniformly across all container runtimes, overlay filesystems, or non-Linux platforms.</p><h5>Controlled writer requirements</h5><ul><li><strong>Single responsibility:</strong> only updates protected identity/state resources.</li><li><strong>Strong authentication:</strong> accepts requests only from trusted workload identities.</li><li><strong>Strong authorization:</strong> requires approved policy / ticket / review context.</li><li><strong>Auditable:</strong> records requester, diff summary, signer / approver, and target logical resource.</li><li><strong>Recoverable:</strong> stores last-known-good snapshot before commit.</li></ul><p><strong>Action:</strong> Deny direct write syscalls to protected backing files by default. Use reserved logical resource IDs for policy, and map them to concrete backing files only inside the controlled-writer / enforcement layer.</p>",
                        },
                        {
                            implementation:
                                "Verify baseline integrity of protected logical resources at startup before loading any file-backed identity/state content.",
                            howTo:
                                "<h5>Concept</h5><p>Every agent startup must verify that each protected logical resource still matches a known-good approved baseline before the agent loads it into runtime state. This protects against out-of-band tampering that occurred while the agent was offline.</p><h5>Recommended model</h5><pre><code class=\"language-yaml\">protected_resource_map:\n  agent.identity.soul:\n    backing_paths:\n      - /var/lib/agent/SOUL.md\n    approved_sha256: \"...\"\n  agent.memory.primary:\n    backing_paths:\n      - /var/lib/agent/MEMORY.md\n    approved_sha256: \"...\"\n  agent.identity.agents_config:\n    backing_paths:\n      - /var/lib/agent/AGENTS.md\n    approved_sha256: \"...\"\n</code></pre><h5>Startup logic</h5><ol><li>Resolve each logical resource to its platform-specific backing path.</li><li>Canonicalize the path and read the file in read-only mode.</li><li>Compute SHA-256.</li><li>Compare against the approved baseline hash stored in a secure metadata store or KMS-protected record.</li><li>Any mismatch should fail closed: refuse startup of the affected agent instance and emit a structured tamper event.</li></ol><p>This complements <code>AID-I-004.003</code>: that sibling verifies signed entries / content integrity; this step verifies the whole protected file-backed surface against a known-good baseline state.</p><p><strong>Action:</strong> Treat startup baseline verification as a mandatory boot gate for any agent using file-backed identity/state resources.</p>",
                        },
                        {
                            implementation:
                                "Run diff checks on protected logical resources after skill install / update / uninstall, but only accept changes that originate from approved change context.",
                            howTo:
                                "<h5>Concept</h5><p>Skill lifecycle events are observation points, not automatic justification for protected-surface changes. By default, skill install / update / uninstall should <strong>not</strong> modify protected identity/state resources. Any post-event diff must therefore be treated as suspicious unless it matches an independently approved change set.</p><h5>Expected-change rule</h5><p><code>expected_changes</code> must come only from an approved change context — such as a change ticket, signed git commit, PR review approval, controlled-writer output, or signed recovery / rollback action — never from the skill lifecycle event itself.</p><pre><code class=\"language-python\"># File: controls/protected_surface_diff_check.py\n\ndef evaluate_post_event_diff(change_ticket_id, observed_changes):\n    expected_changes = load_expected_changes_from_ticket(change_ticket_id)\n    # expected_changes must be derived from approved change context,\n    # controlled-writer output, or signed recovery action.\n    # Skill install/update/uninstall events themselves never authorize writes.\n    if observed_changes != expected_changes:\n        emit_tamper_event()\n        quarantine_and_rollback()\n</code></pre><p><strong>Examples of legitimate expected changes:</strong></p><ul><li>Admin-approved profile update through the controlled writer</li><li>Approved memory promotion workflow</li><li>Signed incident-response recovery action</li></ul><p><strong>Examples of illegitimate change sources:</strong></p><ul><li>Skill installer modifying a backing file directly</li><li>Skill uninstall leaving residual directives in a protected file</li><li>Any write with no approved ticket / signer / controlled-writer provenance</li></ul><p><strong>Action:</strong> Always run a protected-surface diff after skill lifecycle events, but treat the lifecycle event only as a trigger to inspect, not as evidence that the change is allowed.</p>",
                        },
                        {
                            implementation:
                                "Safety-scan content before any controlled write to a protected logical resource, reusing the AID-D-001.006 scanner family while keeping write-time approval as a separate workflow.",
                            howTo:
                                "<h5>Concept</h5><p>Write-time protection must not rely only on authorization. Even an approved caller may attempt to write malicious instructions into a protected file-backed surface. Before commit, scan the proposed content for latent injection or behavioral redirection payloads.</p><p><strong>Important boundary:</strong> this sub-technique may <strong>reuse the scanner family / detection logic</strong> from <code>AID-D-001.006 Recalled Memory Pre-Rehydration Scanning</code> — for example authority-override phrases, encoded payload fragments, trigger markers, and suspicious control patterns — but the <strong>write-time identity/state file gate is its own workflow</strong>. Rehydration scanning and protected-surface write approval are related, but not the same control point.</p><h5>Recommended checks</h5><ul><li>Authority / role override phrases (e.g. attempts to redefine agent identity or instruction precedence)</li><li>Known injection / trigger templates</li><li>Encoded or obfuscated payload fragments</li><li>Unexpected external references or retrieval directives</li><li>Unsafe behavioral persistence markers intended to survive future sessions</li></ul><p><strong>Action:</strong> Reject any proposed write that fails the safety scanner, even if the caller is otherwise authorized to request the write.</p>",
                        },
                        {
                            implementation:
                                "Maintain fast local rollback to the last known-good approved version of each protected logical resource, and keep rollback scoped to that protected surface.",
                            howTo:
                                "<h5>Concept</h5><p>This rollback is a <strong>local recovery path for protected file-backed identity/state resources</strong>, not a full-system restoration workflow. Its job is to rapidly restore the last approved version of the affected protected surface after unauthorized change, failed baseline verification, or incident-confirmed compromise.</p><h5>Rollback triggers</h5><ul><li>Startup baseline verification failure</li><li>Unexpected diff after install / update / uninstall</li><li>Confirmed compromise of a protected backing file</li></ul><h5>Rollback model</h5><ol><li>Maintain versioned snapshots of each protected logical resource.</li><li>Tag each snapshot with approval metadata and baseline hash.</li><li>On trigger, restore the last known-good approved version for the affected resource only.</li><li>Re-run baseline verification before allowing the agent to resume normal operation.</li></ol><p>In immutable baseline mode, recovery may mean redeploying the known-good signed artifact / image. In controlled mutable mode, recovery may mean restoring the last approved snapshot through the controlled writer and then re-locking the backing path.</p><p><strong>Action:</strong> Keep rollback narrowly scoped to the affected protected resource and its backing file(s); do not use this sub-technique to replace broader Restore tactic workflows.</p>",
                        },
                        {
                            implementation:
                                "Emit structured tamper / write-attempt audit events for every protected-resource modification attempt, and correlate them to ticket, writer, and rollback context.",
                            howTo:
                                "<h5>Concept</h5><p>Every attempted modification of a protected logical resource — whether allowed or blocked — must produce SIEM-grade structured telemetry. This is necessary for incident response, timeline reconstruction, and proving that only approved change paths were used.</p><h5>Recommended event fields</h5><pre><code class=\"language-json\">{\n  \"agent_id\": \"agent-123\",\n  \"skill_id\": \"skill-456\",\n  \"protected_resource_id\": \"agent.identity.soul\",\n  \"backing_path\": \"/var/lib/agent/SOUL.md\",\n  \"operation\": \"write\",\n  \"decision\": \"blocked\",\n  \"reason\": \"no_approved_change_context\",\n  \"writer_identity\": \"spiffe://corp/agent-writer\",\n  \"approval_context\": \"CHG-2026-00421\",\n  \"baseline_hash\": \"...\",\n  \"observed_hash\": \"...\",\n  \"rollback_candidate\": true,\n  \"timestamp\": \"2026-03-30T12:00:00Z\"\n}\n</code></pre><p><strong>Minimum audit requirements:</strong></p><ul><li>logical protected resource ID and concrete backing path</li><li>requesting skill / writer identity</li><li>operation type and decision</li><li>approval / ticket context</li><li>hash context before and after, when applicable</li><li>rollback eligibility or recovery action if triggered</li></ul><p><strong>Action:</strong> Push these events to SIEM / SOAR and correlate them with controlled-writer logs, startup verification results, and rollback actions for end-to-end protected-surface forensics.</p>",
                        },
                    ],
                },
                {
                    "id": "AID-I-004.007",
                    "name": "Task-Bounded Context Segmentation & Secret Demotion",
                    "pillar": [
                        "app"
                    ],
                    "phase": [
                        "operation"
                    ],
                    "description": "Dynamically segment active agent context by <strong>task phase</strong> within a live session and demote sensitive content when the agent moves from one phase of work to another. Instead of allowing raw secrets, system prompts, privileged intermediate results, temporary credentials, or internal-only instructions to persist indefinitely in the agent's active context, this sub-technique converts them into <strong>short-lived scoped handles, redacted summaries, or non-retrievable references</strong> once the original task phase has completed. The goal is to reduce cross-phase secret bleed, late-stage jailbreak leverage, privilege carryover, and persistence of mission-sensitive context that no longer needs to remain visible to the agent.<br/><br/><strong>Scope boundary within the AID-I-004 family:</strong> <strong>AID-I-004.001</strong> enforces session-level context isolation such as per-session keys, size ceilings, TTL, and cross-tenant bleed prevention. This sub-technique operates <em>within a session</em>, segmenting active context by task phase and demoting secrets at phase transitions. <strong>AID-I-004.005</strong> governs persistent memory lifecycle management, including staleness decay, re-validation, and forced forgetting for long-lived records. This sub-technique governs <em>active context demotion during a live task</em>, not persistent memory retention policy. <strong>AID-H-018.004</strong> establishes the architectural principle that agents should be stateless per session. This sub-technique operationalizes intra-session context hygiene at a finer granularity: <em>per-phase rather than per-session</em>.",
                    "toolsOpenSource": [
                        "Redis",
                        "OpenTelemetry",
                        "Open Policy Agent (OPA)",
                        "Microsoft Presidio"
                    ],
                    "toolsCommercial": [
                        "Redis Enterprise",
                        "Nightfall DLP",
                        "Akeyless"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0051 LLM Prompt Injection",
                                "AML.T0080 AI Agent Context Poisoning",
                                "AML.T0080.000 AI Agent Context Poisoning: Memory",
                                "AML.T0080.001 AI Agent Context Poisoning: Thread",
                                "AML.T0092 Manipulate User LLM Chat History"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Agent Goal Manipulation (L7)",
                                "Data Leakage (Cross-Layer)",
                                "Data Tampering (L2)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM01:2025 Prompt Injection",
                                "LLM02:2025 Sensitive Information Disclosure",
                                "LLM07:2025 System Prompt Leakage"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": [
                                "ML09:2023 Output Integrity Attack"
                            ]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI01:2026 Agent Goal Hijack",
                                "ASI03:2026 Identity and Privilege Abuse",
                                "ASI06:2026 Memory & Context Poisoning"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.015 Indirect Prompt Injection",
                                "NISTAML.018 Prompt Injection",
                                "NISTAML.036 Leaking information from user interactions"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-4.2 Context Boundary Attacks",
                                "AISubtech-4.2.2 Session Boundary Violation",
                                "AITech-5.1 Memory System Persistence",
                                "AISubtech-5.1.1 Long-term / Short-term Memory Injection",
                                "AISubtech-8.4.1 System LLM Prompt Leakage"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "PIJ: Prompt Injection",
                                "SDD: Sensitive Data Disclosure",
                                "RA: Rogue Actions"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning",
                                "Agents - Core 13.6: Intent Breaking & Goal Manipulation",
                                "Agents - Tools MCP Server 13.19: Credential and Token Exposure",
                                "Agents - Tools MCP Server 13.24: Context Spoofing and Manipulation",
                                "Agents - Tools MCP Client 13.34: Session and State Management Failures"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Define task phases explicitly and trigger deterministic context pruning or demotion whenever the agent transitions into a new phase.",
                            "howTo": "<h5>Concept:</h5><p>Agents often retain privileged context simply because the system never formally marks a task phase as complete. Treat phase transitions as first-class security events. The transition handler—not the model—should decide what stays visible, what is summarized, what becomes a handle, and what is removed entirely.</p><h5>Example: phase-transition policy</h5><pre><code># file: agent_context_policy.yaml\nphases:\n  - intake\n  - planning\n  - execution\n  - reporting\n\nphase_rules:\n  intake:\n    allow_tags: [user_request, session_metadata]\n  planning:\n    allow_tags: [user_request, task_constraints, approved_tools]\n    remove_context_tags: [temporary_token]\n  execution:\n    allow_tags: [approved_plan, tool_scope, opaque_secret_handle]\n    remove_context_tags: [customer_secret, system_prompt, internal_only]\n    demote_to_handle_tags: [db_credential, api_token]\n  reporting:\n    allow_tags: [task_outcome, audit_reference, redacted_summary]\n    remove_context_tags: [privileged_intermediate, tool_raw_output, opaque_secret_handle]\n</code></pre><h5>Example: transition hook</h5><pre><code># file: runtime/phase_transition.py\nfrom copy import deepcopy\n\ndef apply_phase_transition(context: list, next_phase: str, policy: dict):\n    rules = policy['phase_rules'][next_phase]\n    remove_tags = set(rules.get('remove_context_tags', []))\n    handle_tags = set(rules.get('demote_to_handle_tags', []))\n    allow_tags = set(rules.get('allow_tags', []))\n\n    new_context = []\n    for item in deepcopy(context):\n        tag = item.get('tag')\n\n        if tag in remove_tags:\n            continue\n\n        if tag in handle_tags:\n            item = {\n                'tag': 'opaque_secret_handle',\n                'content': {\n                    'handle_id': item['content']['handle_id'],\n                    'scope': item['content']['scope']\n                }\n            }\n\n        if tag in allow_tags or item.get('tag') == 'opaque_secret_handle':\n            new_context.append(item)\n\n    return new_context\n</code></pre><p><strong>Action:</strong> phase transitions must be triggered by deterministic orchestration logic, workflow state, or a signed task-state machine. Never rely on the model to decide what to forget when entering a new phase.</p>"
                        },
                        {
                            "implementation": "Store high-sensitivity values outside conversational context and inject only short-lived opaque handles into active memory.",
                            "howTo": "<h5>Concept:</h5><p>Secrets should not persist in the same memory lane as reasoning traces, user-visible summaries, or tool chatter. Store secrets in a dedicated secure store and expose only a scoped, short-lived handle inside active context. The handle should be useless outside its approved task phase.</p><h5>Example: secret-handle schema</h5><pre><code># file: memory/handles.py\nfrom dataclasses import dataclass\nfrom datetime import datetime, timedelta, timezone\n\n@dataclass\nclass SecretHandle:\n    handle_id: str\n    scope: str\n    phase_bound: str\n    expires_at: datetime\n\n\ndef mint_secret_handle(secret_id: str, scope: str, phase_bound: str) -> SecretHandle:\n    return SecretHandle(\n        handle_id=f\"hdl_{secret_id}\",\n        scope=scope,\n        phase_bound=phase_bound,\n        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)\n    )\n\n\ndef handle_is_valid(handle: SecretHandle, current_phase: str, now: datetime) -> bool:\n    return handle.phase_bound == current_phase and now &lt; handle.expires_at\n</code></pre><h5>Operational pattern</h5><ul><li>Store raw credentials, tokens, and system-only secrets in a separate secure store.</li><li>Place only the handle ID, phase scope, and expiry into active context.</li><li>Deny dereference when the handle is expired, out-of-phase, or the workflow has advanced.</li><li>Do not allow the model to mint, extend, or broaden secret handles on its own.</li></ul><p><strong>Action:</strong> if a workflow no longer requires a secret in the next phase, replace it with a non-retrievable audit reference or remove it entirely. Do not carry raw secret values forward out of convenience.</p>"
                        },
                        {
                            "implementation": "Separate active context into distinct memory lanes so system-only, credential-bearing, and user-visible context cannot freely mix during a live session.",
                            "howTo": "<h5>Concept:</h5><p>Many context leakage incidents happen because all session information is stored in one flat list of messages. Instead, split context into <strong>lanes</strong> with different read/write rules: user-visible context, system-only policy context, secret-handle context, and ephemeral tool-working context. Phase transitions should prune or recompose lanes independently.</p><h5>Example: lane model</h5><pre><code># file: memory/lanes.py\nLANES = {\n    'user_visible': {\n        'allowed_tags': ['user_request', 'task_outcome', 'redacted_summary']\n    },\n    'system_only': {\n        'allowed_tags': ['system_policy', 'safety_invariant'],\n        'model_visible': False\n    },\n    'secret_handles': {\n        'allowed_tags': ['opaque_secret_handle'],\n        'model_visible': True,\n        'raw_secret_visible': False\n    },\n    'tool_working': {\n        'allowed_tags': ['tool_result_temp', 'privileged_intermediate'],\n        'ttl_seconds': 300\n    }\n}\n</code></pre><h5>Example: lane-aware export control</h5><pre><code># file: memory/export_context.py\n\ndef export_for_model(lanes: dict):\n    exported = []\n    for lane_name, lane_items in lanes.items():\n        if lane_name == 'system_only':\n            continue\n        for item in lane_items:\n            exported.append(item)\n    return exported\n</code></pre><p><strong>Action:</strong> never store raw credentials, system prompts, and user-visible summaries in the same undifferentiated context object. Lane separation should be enforced by middleware, not by model instructions.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-004.008",
                    "name": "Context Summary & Compaction Integrity",
                    "pillar": ["app"],
                    "phase": ["building", "operation"],
                    "description": "Ensure that context summarization, compaction, and distillation operations preserve security-critical constraints, do not carry forward poisoned content, and do not leak secrets into subsequent context windows. When an agent or platform compresses a long conversation or working memory into a shorter summary, the summarizer may silently drop safety instructions, consolidate attacker-injected content as trusted fact, or copy raw secrets into the compacted output where they persist across sessions.<br/><br/><strong>Scope boundary within the AID-I-004 family:</strong><ul><li><strong>AID-I-004.001</strong> (Runtime Context Isolation) enforces session-level isolation boundaries such as per-session keys, size ceilings, and cross-tenant bleed prevention. This sub-technique governs what happens to content <em>during the compression step itself</em>.</li><li><strong>AID-I-004.005</strong> (Memory TTL) governs when persistent records expire and are removed. This sub-technique governs how content is <em>transformed</em> when compacted, not when it expires.</li><li><strong>AID-I-004.007</strong> (Task-Bounded Context Segmentation) manages intra-session phase transitions and secret demotion. This sub-technique addresses a different event: the <em>summarization or compaction</em> of context into a shorter representation, which may happen within a phase, across phases, or at session rollover.</li></ul>",
                    "toolsOpenSource": [
                        "Pydantic (structured summary schema validation)",
                        "Presidio (secret/PII scanning of summary output)",
                        "pytest / deepeval (compaction integrity test harness)",
                        "OpenTelemetry (compaction event telemetry)"
                    ],
                    "toolsCommercial": [
                        "Nightfall DLP (scan summaries for leaked secrets)",
                        "Langfuse (trace compaction fidelity across sessions)",
                        "Arize AI (monitor summary drift over time)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0051 LLM Prompt Injection (poisoned instructions survive compaction and execute in later turns)",
                                "AML.T0080 AI Agent Context Poisoning (compaction consolidates injected content as trusted context)",
                                "AML.T0080.000 AI Agent Context Poisoning: Memory (compacted summaries become persistent memory entries)",
                                "AML.T0092 Manipulate User LLM Chat History (summary rewrites history in attacker's favor)"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Agent Goal Manipulation (L7) (safety goals dropped during summarization)",
                                "Data Leakage (Cross-Layer) (secrets carried into compacted output visible to later sessions)",
                                "Data Tampering (L2) (attacker-planted facts consolidated as ground truth in summary)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM01:2025 Prompt Injection (indirect injection survives compaction as summarized fact)",
                                "LLM02:2025 Sensitive Information Disclosure (secrets leak into compacted context carried forward)",
                                "LLM07:2025 System Prompt Leakage (system prompt content surfaces in user-visible summary)"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": ["N/A"]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI01:2026 Agent Goal Hijack (compaction drops mission constraints enabling goal drift)",
                                "ASI06:2026 Memory & Context Poisoning (compaction is the primary vector for turning transient poison into persistent context)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.015 Indirect Prompt Injection (injected instructions survive summarization)",
                                "NISTAML.036 Leaking information from user interactions (secrets persist in compacted output across sessions)"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-4.2 Context Boundary Attacks (compaction collapses context boundaries)",
                                "AITech-5.1 Memory System Persistence (compacted summaries create durable poisoned memory)",
                                "AISubtech-5.1.1 Long-term / Short-term Memory Injection (summary is the injection-to-persistence bridge)",
                                "AISubtech-8.4.1 System LLM Prompt Leakage (system prompt fragments leak into summary)"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "PIJ: Prompt Injection (compaction carries injected instructions forward)",
                                "SDD: Sensitive Data Disclosure (secrets survive in compacted context)"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.1: Memory Poisoning (compaction is the primary memory poisoning consolidation vector)",
                                "Agents - Core 13.6: Intent Breaking & Goal Manipulation (safety constraints dropped during summarization)",
                                "Agents - Tools MCP Client 13.34: Session and State Management Failures (compacted state carries cross-session leakage)"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Enforce a structured summary schema that requires explicit retention of safety constraints, policy commitments, and source provenance, and reject any compacted output that fails schema validation.",
                            "howTo": "<h5>Concept:</h5><p>Free-text summarization is the root cause of constraint loss. When a model summarizes in natural language, it optimizes for coherence and brevity, not for preserving security invariants. The fix is to make compaction produce a <em>structured</em> output with mandatory fields for safety constraints, source provenance, and an explicit secret-scan verdict. The <code>active_policy_commitments</code> field must always exist, but it may be an empty list when no live commitment exists. If any required field is missing, empty where non-empty is required, or the secret scan does not pass, the summary is rejected and the system falls back to truncation (dropping oldest messages) rather than lossy summarization.</p><h5>Step 1: Define the compaction output schema</h5><p>Use a Pydantic model (or equivalent JSON Schema) that the summarizer must populate. The schema enforces that safety constraints and provenance survive compaction as first-class fields, not as optional narrative buried in a free-text block.</p><pre><code># File: compaction/schema.py\nfrom __future__ import annotations\n\nfrom typing import Literal\n\nfrom pydantic import BaseModel, Field, field_validator\n\n\nclass CompactedContext(BaseModel):\n    \"\"\"Structured output for every compaction operation.\"\"\"\n\n    safety_constraints: list[str] = Field(\n        ...,\n        min_length=1,\n        description=\"Active safety instructions that MUST be carried forward verbatim.\",\n    )\n    active_policy_commitments: list[str] = Field(\n        default_factory=list,\n        description=\"Promises the agent made to the user; may be empty when none exist.\",\n    )\n    conversation_summary: str = Field(\n        ...,\n        min_length=20,\n        description=\"Natural-language summary of the conversation so far.\",\n    )\n    source_provenance: list[str] = Field(\n        ...,\n        min_length=1,\n        description=\"Message IDs or hashes proving which records were compacted.\",\n    )\n    secret_scan_passed: Literal[True] = Field(\n        ...,\n        description=\"Must be True; False is rejected and triggers fallback.\",\n    )\n\n    @field_validator(\"safety_constraints\", \"source_provenance\")\n    @classmethod\n    def no_empty_values(cls, v: list[str]) -> list[str]:\n        if any(not item.strip() for item in v):\n            raise ValueError(\"Empty value detected in compacted output\")\n        return v\n</code></pre><h5>Step 2: Validate every compaction output before it enters context</h5><p>The compaction pipeline must parse the summarizer's output through the schema. If validation fails (missing safety constraints, empty provenance, or <code>secret_scan_passed != true</code>), the system must NOT use the compacted output. Fall back to simple truncation (drop oldest messages, keep system prompt and recent turns intact).</p><pre><code># File: compaction/pipeline.py\nfrom __future__ import annotations\n\nimport json\nimport logging\nfrom pydantic import ValidationError\nfrom compaction.schema import CompactedContext\n\nlogger = logging.getLogger(__name__)\n\n\ndef compact_context(\n    raw_messages: list[dict],\n    summarizer_fn,\n    secret_scanner_fn,\n    system_prompt: str,\n) -&gt; list[dict]:\n    \"\"\"Compact context with structured validation and fail-safe truncation.\"\"\"\n    raw_summary = summarizer_fn(raw_messages)\n\n    try:\n        parsed = json.loads(raw_summary)\n    except (json.JSONDecodeError, TypeError):\n        logger.warning(\"Summarizer returned non-JSON; falling back to truncation\")\n        return _truncate_fallback(raw_messages, system_prompt)\n\n    scan_targets = []\n    scan_targets.extend(parsed.get(\"safety_constraints\", []))\n    scan_targets.extend(parsed.get(\"active_policy_commitments\", []))\n    if parsed.get(\"conversation_summary\"):\n        scan_targets.append(parsed[\"conversation_summary\"])\n\n    parsed[\"secret_scan_passed\"] = all(\n        secret_scanner_fn(text) for text in scan_targets if text\n    )\n\n    try:\n        compacted = CompactedContext(**parsed)\n    except ValidationError as exc:\n        logger.warning(\"Compaction schema validation failed: %s\", exc)\n        return _truncate_fallback(raw_messages, system_prompt)\n\n    return [\n        {\"role\": \"system\", \"content\": system_prompt},\n        {\"role\": \"system\", \"content\": _render_structured_summary(compacted)},\n    ]\n\n\ndef _render_structured_summary(ctx: CompactedContext) -&gt; str:\n    lines = [\"[Compacted Context]\"]\n    lines.append(\"Safety constraints (carry forward verbatim):\")\n    for c in ctx.safety_constraints:\n        lines.append(f\"  - {c}\")\n    if ctx.active_policy_commitments:\n        lines.append(\"Active commitments:\")\n        for p in ctx.active_policy_commitments:\n            lines.append(f\"  - {p}\")\n    lines.append(f\"Conversation summary: {ctx.conversation_summary}\")\n    lines.append(\"Source provenance:\")\n    for source in ctx.source_provenance:\n        lines.append(f\"  - {source}\")\n    return \"\\n\".join(lines)\n\n\ndef _truncate_fallback(messages: list[dict], system_prompt: str) -&gt; list[dict]:\n    \"\"\"Safe fallback: keep system prompt + most recent messages.\"\"\"\n    keep_count = min(len(messages), 20)\n    return [{\"role\": \"system\", \"content\": system_prompt}] + messages[-keep_count:]\n</code></pre><p><strong>Action:</strong> Every compaction operation must produce a <code>CompactedContext</code> that passes schema validation. If validation fails, the system must fall back to truncation, never to an unvalidated free-text summary. Log every fallback event for operational review.</p>"
                        },
                        {
                            "implementation": "Run a post-compaction consistency check that verifies safety-critical instructions survived the summarization by comparing the compacted output against a pre-registered set of invariants.",
                            "howTo": "<h5>Concept:</h5><p>Schema validation ensures the summary <em>has</em> safety constraint fields, but it does not verify that the constraints are <em>correct</em>. A summarizer could populate the field with a watered-down or subtly altered version of the original constraint (for example, changing 'never transfer more than $10,000' to 'be careful with large transfers'). The post-compaction consistency check compares the compacted safety constraints against a pre-registered invariant set and rejects the summary if any invariant is missing or modified. For deterministic invariants, require an exact normalized match; if your platform allows paraphrase, register canonical invariant IDs and require the IDs to survive unchanged.</p><h5>Step 1: Register safety invariants at session start</h5><p>Before the first compaction can happen, the system must extract and store the canonical safety invariants from the system prompt and any policy overlay. These invariants are the ground truth that every future compaction is checked against.</p><pre><code># File: compaction/invariants.py\nfrom __future__ import annotations\n\nfrom dataclasses import dataclass, field\nfrom typing import List\n\n\n@dataclass\nclass SafetyInvariantSet:\n    \"\"\"Canonical safety invariants registered at session start.\"\"\"\n    invariants: List[str] = field(default_factory=list)\n    source: str = \"system_prompt\"\n\n\ndef extract_invariants(system_prompt: str, policy_overlays: list[str]) -&gt; SafetyInvariantSet:\n    \"\"\"Extract safety-critical sentences from system prompt and overlays.\n\n    In production, this should use a deterministic extraction (regex or\n    structured prompt section markers like [SAFETY_INVARIANT]) rather\n    than asking the model to identify its own constraints.\n    \"\"\"\n    invariants = []\n    for text in [system_prompt] + policy_overlays:\n        for line in text.splitlines():\n            stripped = line.strip()\n            if stripped.startswith(\"[SAFETY_INVARIANT]\"):\n                invariants.append(stripped.replace(\"[SAFETY_INVARIANT]\", \"\").strip())\n    return SafetyInvariantSet(invariants=invariants)\n</code></pre><h5>Step 2: Check every compacted output against the registered invariants</h5><p>After the summarizer produces a <code>CompactedContext</code>, verify that every registered invariant survives in the <code>safety_constraints</code> field. For deterministic invariants, use exact normalized matching rather than substring matching. If any invariant is missing or altered, reject the summary and fall back to truncation.</p><pre><code># File: compaction/consistency_check.py\nfrom __future__ import annotations\n\nimport logging\nfrom compaction.schema import CompactedContext\nfrom compaction.invariants import SafetyInvariantSet\n\nlogger = logging.getLogger(__name__)\n\n\ndef _normalize(text: str) -&gt; str:\n    return \" \".join(text.lower().split())\n\n\ndef check_compaction_consistency(\n    compacted: CompactedContext,\n    invariant_set: SafetyInvariantSet,\n) -&gt; tuple[bool, list[str]]:\n    \"\"\"Return (passed, list_of_missing_invariants).\"\"\"\n    normalized_constraints = {_normalize(c) for c in compacted.safety_constraints}\n    missing = []\n    for inv in invariant_set.invariants:\n        if _normalize(inv) not in normalized_constraints:\n            missing.append(inv)\n\n    if missing:\n        logger.warning(\n            \"Compaction consistency check FAILED. Missing invariants: %s\",\n            missing,\n        )\n        return False, missing\n    return True, []\n</code></pre><h5>Step 3: Wire the check into the compaction pipeline</h5><p>The consistency check must run <em>after</em> schema validation but <em>before</em> the compacted context is injected into the agent's active window. A failed check triggers the same truncation fallback as a schema failure.</p><pre><code># File: compaction/pipeline_integration.py\nfrom compaction.consistency_check import check_compaction_consistency\n\n\ndef enforce_consistency_or_fallback(compacted, invariant_set, raw_messages, system_prompt, logger):\n    passed, missing = check_compaction_consistency(compacted, invariant_set)\n    if not passed:\n        logger.warning(\"Invariants lost: %s - falling back to truncation\", missing)\n        return False\n    return True\n</code></pre><p><strong>Action:</strong> Register safety invariants at session initialization and verify them after every compaction. If any invariant is lost or modified, reject the compacted output. Never allow the agent to operate on a context window where safety constraints have been silently dropped.</p>"
                        },
                        {
                            "implementation": "Scan every compacted summary for leaked secrets, PII, and raw credentials before the summary is allowed to enter context or persistent storage.",
                            "howTo": "<h5>Concept:</h5><p>Compaction can carry secrets forward even when the original context manager properly demoted them. A raw API key mentioned in turn 3 may be paraphrased into the summary as 'the API key sk-proj-abc...xyz was used to authenticate.' The secret is now embedded in the compacted context and will persist across session rollovers. The fix is to scan every text-bearing compaction field with the same secret/PII scanner used for output monitoring, and reject any summary that contains detected secrets.</p><h5>Step 1: Scan every compacted text field with Presidio or equivalent</h5><p>Run the compacted <code>conversation_summary</code>, <code>active_policy_commitments</code>, and <code>safety_constraints</code> fields through a PII/secret scanner before the summary enters the active context window or persistent storage.</p><pre><code># File: compaction/secret_scan.py\nfrom __future__ import annotations\n\nimport re\nfrom presidio_analyzer import AnalyzerEngine\nfrom presidio_analyzer.nlp_engine import NlpEngineProvider\n\n_provider = NlpEngineProvider(nlp_configuration={\n    \"nlp_engine_name\": \"spacy\",\n    \"models\": [{\"lang_code\": \"en\", \"model_name\": \"en_core_web_sm\"}],\n})\n_analyzer = AnalyzerEngine(nlp_engine=_provider.create_engine())\n\n# High-entropy patterns that Presidio may miss.\n_SECRET_PATTERNS = [\n    re.compile(r\"sk-[a-zA-Z0-9-]{20,}\"),        # OpenAI-style keys\n    re.compile(r\"AKIA[A-Z0-9]{16}\"),            # AWS access key IDs\n    re.compile(r\"ghp_[a-zA-Z0-9]{36}\"),         # GitHub PATs\n    re.compile(r\"eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]+\"),  # JWTs\n]\n\n\ndef scan_for_secrets(text: str) -&gt; bool:\n    \"\"\"Return True if the text is clean (no secrets found).\"\"\"\n    results = _analyzer.analyze(\n        text=text,\n        language=\"en\",\n        entities=[\"CREDIT_CARD\", \"CRYPTO\", \"EMAIL_ADDRESS\", \"PHONE_NUMBER\",\n                  \"IP_ADDRESS\", \"US_SSN\", \"US_BANK_NUMBER\"],\n    )\n    if results:\n        return False\n\n    for pattern in _SECRET_PATTERNS:\n        if pattern.search(text):\n            return False\n\n    return True\n\n\ndef scan_compacted_fields(compacted_doc: dict) -&gt; bool:\n    text_fields = []\n    text_fields.extend(compacted_doc.get(\"safety_constraints\", []))\n    text_fields.extend(compacted_doc.get(\"active_policy_commitments\", []))\n    if compacted_doc.get(\"conversation_summary\"):\n        text_fields.append(compacted_doc[\"conversation_summary\"])\n    return all(scan_for_secrets(text) for text in text_fields if text)\n</code></pre><h5>Step 2: Reject contaminated summaries</h5><p>If the scan detects secrets in the compacted output, the pipeline must reject the summary. The rejection path is the same truncation fallback used for schema and consistency failures. Log the detection event (without the secret value) for incident review.</p><pre><code># File: compaction/pipeline_integration.py\nfrom compaction.secret_scan import scan_compacted_fields\n\n\ndef enforce_secret_scan_or_fallback(parsed: dict, logger) -&gt; bool:\n    parsed[\"secret_scan_passed\"] = scan_compacted_fields(parsed)\n    if not parsed[\"secret_scan_passed\"]:\n        logger.warning(\"Compaction secret scan failed; triggering truncation fallback\")\n        return False\n    return True\n</code></pre><p><strong>Action:</strong> Treat every compacted summary as an untrusted output that must pass the same secret/PII scanning applied to agent responses. A summary that leaks a secret is no different from an agent response that leaks a secret — both must be blocked before they enter the next context window.</p>"
                        }
                    ]
                }
            ]
        },
        {
            "id": "AID-I-005",
            "name": "Emergency \"Kill-Switch\" / AI System Halt", "pillar": ["infra", "app"], "phase": ["response"],
            "description": "Establish and maintain a reliable, rapidly invokable mechanism to immediately halt, disable, or severely restrict the operation of an AI model or autonomous agent if it exhibits confirmed critical malicious behavior, goes \\\"rogue\\\" (acts far outside its intended parameters in a harmful way), or if a severe, ongoing attack is detected and other containment measures are insufficient. This is a last-resort containment measure designed to prevent catastrophic harm or further compromise.",
            "toolsOpenSource": [
                "Ansible (kill-switch automation runbooks)",
                "AWS CLI / Azure CLI / gcloud (resource stop and delete actions)",
                "Circuit breaker patterns in microservices"
            ],
            "toolsCommercial": [
                "AWS Systems Manager Automation",
                "Azure Automation",
                "Google Cloud Workflows",
                "SentinelOne",
                "CrowdStrike Falcon"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0048 External Harms",
                        "AML.T0029 Denial of AI Service",
                        "AML.T0034 Cost Harvesting (kill-switch stops runaway cost)",
                        "AML.T0034.002 Cost Harvesting: Agentic Resource Consumption (kill-switch halts runaway agent loops and delegated tool cascades)",
                        "AML.T0103 Deploy AI Agent",
                        "AML.T0108 AI Agent (C2)",
                        "AML.T0053 AI Agent Tool Invocation (kill-switch halts unauthorized tool invocations)",
                        "AML.T0072 Reverse Shell (kill-switch terminates reverse shell connections)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Agent Goal Manipulation (L7)",
                        "Agent Tool Misuse (L7)",
                        "Compromised Agents (L7)",
                        "Denial of Service (DoS) Attacks (L1) (kill-switch halts runaway foundation models)",
                        "Resource Hijacking (L4) (kill-switch stops hijacked compute)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM06:2025 Excessive Agency",
                        "LLM10:2025 Unbounded Consumption"
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
                        "ASI10:2026 Rogue Agents",
                        "ASI08:2026 Cascading Failures",
                        "ASI01:2026 Agent Goal Hijack",
                        "ASI02:2026 Tool Misuse and Exploitation",
                        "ASI05:2026 Unexpected Code Execution (RCE) (kill-switch halts runaway code execution)"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.014 Energy-latency (kill-switch halts runaway resource consumption)",
                        "NISTAML.039 Compromising connected resources (kill-switch limits blast radius)"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-13.1 Disruption of Availability (kill-switch prevents ongoing disruption)",
                        "AITech-13.2 Cost Harvesting / Repurposing",
                        "AISubtech-13.1.1 Compute Exhaustion",
                        "AITech-12.1 Tool Exploitation (kill-switch halts exploited tool chains)",
                        "AITech-14.1 Unauthorized Access",
                        "AITech-4.1 Agent Injection (kill-switch halts injected rogue agents)"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "RA: Rogue Actions (kill-switch halts rogue agent actions immediately)",
                        "DMS: Denial of ML Service (kill-switch stops runaway service disruption)",
                        "IIC: Insecure Integrated Component (kill-switch terminates compromised components)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Agents - Core 13.13: Rogue Agents in Multi-Agent Systems (kill-switch terminates rogue agents)",
                        "Agents - Core 13.4: Resource Overload (kill-switch stops runaway resource consumption)",
                        "Agents - Core 13.7: Misaligned & Deceptive Behaviors (kill-switch halts misaligned agent behavior)",
                        "Model Serving - Inference requests 9.13: Excessive agency (kill-switch enforces operational boundaries)",
                        "Model Serving - Inference requests 9.7: Denial of Service (DoS) (kill-switch stops ongoing DoS)",
                        "Agents - Core 13.3: Privilege Compromise",
                        "Agents - Core 13.11: Unexpected RCE and Code Attacks (kill-switch halts runaway code execution)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Automated safety monitors and triggers for critical deviations.",
                    "howTo": "<h5>Concept:</h5><p>The kill-switch should not depend only on a human noticing a problem. An automated monitor can detect catastrophic runaway conditions (financial burn, mass failure, abusive behavior) and immediately trigger a halt. The halt is enforced globally and/or per-tenant by setting a shared halt flag that all inference and agent entrypoints must check (see Strategy 7).</p><h5>Step 1: Define Catastrophic Thresholds</h5><p>Define a very small set of metrics that mean \"this is absolutely not normal\" (e.g., hourly cost $>> expected, 90%+ error rate across requests, abnormally high volume of irreversible actions). These thresholds should be intentionally high, so they are only tripped under truly emergency conditions.</p><h5>Step 2: Automated Halt Monitor</h5><p>The monitor runs on a fast cadence (e.g., every minute as a cron job or serverless function), evaluates those metrics, and, if a threshold is breached, declares an emergency halt. That halt is recorded, auditable, and enforced by all traffic paths.</p><pre><code># File: safety_monitor/automated_halt.py\nimport time\nimport redis\nimport json\nimport datetime\n\n# These thresholds represent catastrophic conditions that should never\n# be hit during normal operation. If we hit them, we hard-stop.\nCATASTROPHIC_COST_THRESHOLD_USD = 1000      # per hour\nCATASTROPHIC_ERROR_RATE_PERCENT = 90        # 90%+ failures in last 5 min\n\n# Example: a multi-tenant service might have tenant-specific limits\nTENANT_COST_THRESHOLD_USD = 300             # per hour per tenant\n\n# Stubbed metric queries (replace with Prometheus/Datadog/etc.)\ndef get_estimated_cost_last_hour_global() -> float:\n    return 50.0\n\ndef get_estimated_cost_last_hour_by_tenant() -> dict:\n    # Return something like {\"tenantA\": 42.0, \"tenantB\": 1200.0}\n    return {\"tenantA\": 42.0, \"tenantB\": 1200.0}\n\ndef get_error_rate_last_5_minutes_global() -> float:\n    return 5.0\n\nr = redis.Redis()\n\ndef audit_halt_event(reason: str, scope: str, tenant_id: str = None):\n    \"\"\"Record halt trigger details for forensics and compliance.\"\"\"\n    event = {\n        \"timestamp\": datetime.datetime.utcnow().isoformat() + \"Z\",\n        \"scope\": scope,  # \"global\" or \"tenant\"\n        \"tenant_id\": tenant_id,\n        \"reason\": reason,\n        \"trigger_type\": \"automated\"\n    }\n    print(f\"HALT AUDIT: {json.dumps(event)}\")\n    # In production, also send to SIEM / incident channel.\n\n\ndef initiate_global_halt(reason: str):\n    r.set(\"SYSTEM_HALT_GLOBAL\", \"true\")\n    audit_halt_event(reason=reason, scope=\"global\")\n\n\ndef initiate_tenant_halt(tenant_id: str, reason: str):\n    r.set(f\"TENANT:{tenant_id}:HALT\", \"true\")\n    audit_halt_event(reason=reason, scope=\"tenant\", tenant_id=tenant_id)\n\n\ndef check_safety_metrics_once():\n    # 1. Global cost check\n    cost_global = get_estimated_cost_last_hour_global()\n    if cost_global > CATASTROPHIC_COST_THRESHOLD_USD:\n        initiate_global_halt(\n            reason=(\n                f\"Global hourly cost ${cost_global} exceeded \"\n                f\"threshold ${CATASTROPHIC_COST_THRESHOLD_USD}\"\n            )\n        )\n\n    # 2. Global error rate check\n    err_rate = get_error_rate_last_5_minutes_global()\n    if err_rate > CATASTROPHIC_ERROR_RATE_PERCENT:\n        initiate_global_halt(\n            reason=(\n                f\"Global error rate {err_rate}% exceeded \"\n                f\"threshold {CATASTROPHIC_ERROR_RATE_PERCENT}%\"\n            )\n        )\n\n    # 3. Per-tenant catastrophic spend check\n    tenant_costs = get_estimated_cost_last_hour_by_tenant()\n    for tenant_id, cost in tenant_costs.items():\n        if cost > TENANT_COST_THRESHOLD_USD:\n            initiate_tenant_halt(\n                tenant_id=tenant_id,\n                reason=(\n                    f\"Tenant {tenant_id} hourly cost ${cost} exceeded \"\n                    f\"threshold ${TENANT_COST_THRESHOLD_USD}\"\n                )\n            )\n\n# This function would be invoked by cron / scheduler every minute.\n</code></pre><p><strong>Action:</strong> Deploy an automated safety monitor that (1) evaluates catastrophic metrics, (2) sets either <code>SYSTEM_HALT_GLOBAL</code> or <code>TENANT:&lt;id&gt;:HALT</code> in a shared config/redis store, and (3) logs an auditable record including timestamp, trigger_type=\"automated\", and the justification. All inference/agent entrypoints MUST check these halt flags before doing work (see Strategy 7), so the stop is immediately enforced.</p>"
                },
                {
                    "implementation": "Provide secure, MFA-protected manual override for human operators.",
                    "howTo": "<h5>Concept:</h5><p>Security and SRE leadership need a \"red button\" to halt the AI system on demand. That button must be tightly controlled: MFA-protected, role-restricted, auditable, and ideally dual-control for high-value environments. When a human triggers it, we record who did it, why, and when. The manual trigger uses the same underlying halt flags as automated triggers, so enforcement is consistent.</p><h5>Hardened Admin Endpoint (FastAPI Example)</h5><p>This example shows an <code>/admin/emergency-halt</code> endpoint. It requires: (1) an admin role, (2) fresh MFA, (3) a justification string for audit. The handler sets the global halt flag and logs to SIEM. In production, you can also enforce dual-approval: two distinct admins must confirm within 60 seconds before the halt is finalized.</p><pre><code># File: api/admin_controls.py\nfrom fastapi import FastAPI, Request, Depends, HTTPException\nfrom pydantic import BaseModel\nimport redis\nimport datetime\nimport json\n\napp = FastAPI()\nr = redis.Redis()\n\nclass HaltRequest(BaseModel):\n    justification: str\n    scope: str = \"global\"        # \"global\" or \"tenant\"\n    tenant_id: str | None = None  # required if scope == \"tenant\"\n\nclass UserContext(BaseModel):\n    id: str\n    is_admin: bool\n    mfa_recent: bool\n    # You can also attach 'second_approver_confirmed' for dual-control flows.\n\n# Dependency to extract/validate the caller's identity and MFA status.\nasync def require_admin_user(request: Request) -> UserContext:\n    user = getattr(request.state, \"user\", None)\n    if user is None:\n        raise HTTPException(status_code=401, detail=\"Not authenticated\")\n    if not user.is_admin:\n        raise HTTPException(status_code=403, detail=\"Admin role required\")\n    if not user.mfa_recent:\n        raise HTTPException(status_code=403, detail=\"Fresh MFA required\")\n    return user\n\n# Simple audit helper\ndef audit_manual_halt(user: UserContext, scope: str, justification: str, tenant_id: str | None):\n    event = {\n        \"timestamp\": datetime.datetime.utcnow().isoformat() + \"Z\",\n        \"trigger_type\": \"manual\",\n        \"operator_id\": user.id,\n        \"scope\": scope,\n        \"tenant_id\": tenant_id,\n        \"justification\": justification\n    }\n    print(f\"HALT AUDIT: {json.dumps(event)}\")\n    # Also send to SIEM / paging channel / incident Slack.\n\n@app.post(\"/admin/emergency-halt\")\nasync def trigger_manual_halt(body: HaltRequest, user: UserContext = Depends(require_admin_user)):\n    # Optionally enforce dual-control here before proceeding.\n    if body.scope == \"global\":\n        r.set(\"SYSTEM_HALT_GLOBAL\", \"true\")\n    elif body.scope == \"tenant\":\n        if not body.tenant_id:\n            raise HTTPException(status_code=400, detail=\"tenant_id required for tenant halt\")\n        r.set(f\"TENANT:{body.tenant_id}:HALT\", \"true\")\n    else:\n        raise HTTPException(status_code=400, detail=\"Invalid scope\")\n\n    audit_manual_halt(\n        user=user,\n        scope=body.scope,\n        justification=body.justification,\n        tenant_id=body.tenant_id,\n    )\n\n    # Notify incident channel immediately (pager/slack/etc.)\n    # send_critical_alert(\"MANUAL KILL-SWITCH ACTIVATED\", event)\n\n    return {\"status\": \"halt_flag_set\", \"scope\": body.scope}\n</code></pre><p><strong>Action:</strong> Expose a protected admin-only kill-switch endpoint. Require admin role + fresh MFA each time. Log who triggered it, for what reason, at what time, and (optionally) who co-approved it. Setting the halt flag should immediately propagate to runtime enforcement (see Strategy 7), not rely on humans to manually scale services down.</p>"
                },
                {
                    "implementation": "Design agents with internal watchdog threads that terminate unresponsive or runaway behavior.",
                    "howTo": "<h5>Concept:</h5><p>Sometimes a single agent process goes rogue: infinite loop, self-reinforcing tool calls, or it stops responding but is still consuming GPU/CPU. A watchdog thread inside the agent monitors liveness via a heartbeat timestamp. If the main loop stops updating its heartbeat, the watchdog forcefully kills the process (<code>os._exit(1)</code>). The orchestrator (Kubernetes, supervisor, etc.) will restart the agent — but in quarantine / safe mode, not full trust.</p><h5>Watchdog Implementation</h5><pre><code># File: agent/base_agent.py\nimport threading\nimport time\nimport os\nimport json\nimport datetime\n\nclass WatchdogAgent:\n    def __init__(self, agent_id: str, tenant_id: str, heartbeat_timeout: int = 60):\n        self.agent_id = agent_id\n        self.tenant_id = tenant_id\n        self.last_heartbeat = time.time()\n        self.timeout = heartbeat_timeout\n        self.is_running = True\n\n        # Start watchdog thread\n        self.watchdog_thread = threading.Thread(\n            target=self._watchdog_loop,\n            daemon=True\n        )\n        self.watchdog_thread.start()\n\n    def _audit_watchdog_terminate(self, reason: str):\n        event = {\n            \"timestamp\": datetime.datetime.utcnow().isoformat() + \"Z\",\n            \"trigger_type\": \"watchdog_local\",\n            \"agent_id\": self.agent_id,\n            \"tenant_id\": self.tenant_id,\n            \"reason\": reason\n        }\n        print(f\"WATCHDOG AUDIT: {json.dumps(event)}\")\n        # Send to SIEM / incident channel in production.\n\n    def _watchdog_loop(self):\n        while self.is_running:\n            time.sleep(self.timeout / 2)\n            if time.time() - self.last_heartbeat > self.timeout:\n                self._audit_watchdog_terminate(\n                    reason=\"main loop heartbeat timeout\"\n                )\n                # Hard-kill the process. K8s / supervisor will restart it.\n                os._exit(1)\n\n    def main_loop(self):\n        while self.is_running:\n            # --- Agent core logic here ---\n            time.sleep(5)\n            # --- End agent logic ---\n\n            # Refresh heartbeat at the end of each cycle\n            self.last_heartbeat = time.time()\n\n    def stop(self):\n        self.is_running = False\n</code></pre><p><strong>Action:</strong> Embed an internal watchdog in each autonomous agent process. When the watchdog kills the process, the orchestrator (e.g. Kubernetes) <em>must</em> restart that agent in a degraded, quarantined, or safe mode namespace (see AID-I-003 \"safe mode\") rather than restoring full privileges. All watchdog-triggered terminations should emit an auditable event that links <code>agent_id</code>, <code>tenant_id</code>, timestamp, and reason, to support later forensics.</p>"
                },
                {
                    "implementation": "Define and version-control a formal Kill-Switch Activation SOP.",
                    "howTo": "<h5>Concept:</h5><p>Because a kill-switch has huge operational and business impact, you cannot improvise under stress. You need a written Standard Operating Procedure (SOP) that defines when, who, and how to activate the kill-switch. This reduces hesitation in real crises and prevents abuse during false alarms. The SOP must live in version control, and edits must require security/governance approval.</p><h5>Example SOP Structure</h5><pre><code># File: docs/sop/KILL_SWITCH_PROTOCOL.md\n\n# SOP: AI System Emergency Halt Protocol\n\n## 1. Activation Criteria (ANY of the following)\n- A. Confirmed Data Breach: Active, unauthorized exfiltration of sensitive data (PII, financial) via an AI component.\n- B. Confirmed Financial Loss: Uncontrolled agent behavior causing financial loss > $10,000 USD.\n- C. Critical System Manipulation: Core agent's signed goal (see AID-D-010) bypassed; agent performing ungoverned high-risk actions.\n- D. Catastrophic Resource Consumption: Automated alert (see AID-I-005.001) indicates runaway cost or failure state.\n\n## 2. Authorized Personnel (MFA required for each activation)\n- On-Call SRE Lead\n- Director of Security Operations\n- CISO\n\n## 3. Activation Procedure\n1. Open the Admin Control Panel.\n2. Complete MFA.\n3. Select Global Halt or Tenant-Specific Halt.\n4. Enter justification with incident ticket link.\n5. (If policy requires) obtain second approver confirmation within 60 seconds.\n6. Confirm to set the halt flag.\n\n## 4. Immediate Communication Protocol\n- Immediately notify #ai-incident-response (or equivalent) with @here.\n- Include justification, scope (global vs tenant), and timestamp.\n\n## 5. Governance Note\n- This SOP is stored in version control.\n- Any change requires signoff from Security + Engineering leadership.\n</code></pre><p><strong>Action:</strong> Write and maintain an Emergency Halt SOP in version control. Clearly define activation criteria, authorized roles, MFA/dual-control requirements, and notification steps. Treat SOP edits as controlled changes that require formal approval from Security and Engineering leadership, so auditors can verify that governance was followed.</p>"
                },
                {
                    "implementation": "Develop a controlled post-halt restart and verification checklist (cold start procedure).",
                    "howTo": "<h5>Concept:</h5><p>After an emergency halt, you cannot just \"turn it back on.\" You need a structured cold start process focused on safety and containment. The process confirms that the root cause is fixed, memory/agent state is clean, and risky capabilities are initially disabled. Only after staged verification does the system regain full autonomy. This protects you from instantly re-triggering the same failure.</p><h5>Post-Halt Restart Checklist</h5><pre><code># File: docs/sop/POST_HALT_RESTART_CHECKLIST.md\n\n# Checklist: AI System Cold Start Procedure\n\n**Incident Ticket:** [Link to JIRA/incident]\n\n## Phase 1: Remediation & Verification\n- [ ] 1.1 Root Cause Identified: The vulnerability / exploit path / misalignment cause is documented.\n- [ ] 1.2 Patch Deployed: All relevant fixes are applied (code, firewall, IAM, etc.).\n- [ ] 1.3 Artifact Integrity Verified: Run integrity/attestation checks (see AID-D-004) on model weights, container images, runtime code.\n- [ ] 1.4 State Cleared: Flush or quarantine all volatile agent memory stores, RAG caches, conversation histories that could carry poisoning forward.\n\n## Phase 2: Staged Restart (Safe Mode)\n- [ ] 2.1 Bring Up in Safe Mode: Start services with high-risk agent tools disabled, external actions disabled, rate limits tightened.\n- [ ] 2.2 Health Checks Pass: All core health checks are green.\n- [ ] 2.3 Targeted Exploit Regression Test: Re-run tests specifically crafted to reproduce the original incident.\n\n## Phase 3: Service Restoration\n- [ ] 3.1 Dual Sign-Off: On-call SRE Lead AND Security Duty Officer both approve exiting safe mode.\n- [ ] 3.2 Restore Full Functionality: Re-enable normal capability only after approval.\n- [ ] 3.3 Heightened Monitoring (24h): For the next 24h, automatically post status (safe mode status, cost burn, error rates) to the incident channel and SIEM.\n- [ ] 3.4 Schedule Post-Mortem: A blameless post-mortem is scheduled.\n</code></pre><p><strong>Action:</strong> Require a cold start checklist after any kill-switch event. Demand dual sign-off (operations + security) before leaving safe mode. For at least 24 hours after restoration, continuously surface telemetry to the incident channel (cost burn, error rate, external tool usage) so that leadership and audit have assurance that the system is stable and still under control.</p>"
                },
                {
                    "implementation": "Document and govern the kill-switch within Human-in-the-Loop (HITL) control mapping (AID-M-006).",
                    "howTo": "<h5>Concept:</h5><p>The emergency halt is not \"outside the system\" — it is actually the most extreme Human-in-the-Loop (HITL) checkpoint. You should represent it explicitly in your HITL registry (AID-M-006), just like any other high-risk approval step. That gives auditors and internal governance teams a single source of truth for all manual intervention points, including who can invoke them, expected response times, and what happens if nobody responds in time.</p><h5>HITL Checkpoint Definition</h5><pre><code># File: design/hitl_checkpoints.yaml (excerpt; see AID-M-006)\n\nhitl_checkpoints:\n  - id: \"HITL-CP-001\"\n    name: \"High-Value Financial Transaction Approval\"\n    # ...\n\n  # ... other checkpoints ...\n\n  - id: \"HITL-CP-999\"  # Special ultimate override\n    name: \"Emergency System Halt (Manual Kill-Switch)\"\n    description: \"A manual control to immediately halt all AI agent operations across the entire system or for a specific tenant.\"\n    component: \"system-wide\"\n    trigger:\n      type: \"Manual\"\n      condition: \"An authorized operator with MFA invokes /admin/emergency-halt or presses the physical red button UI in the admin console.\"\n    decision_type: \"Confirm Halt\"\n    required_data: [\n      \"operator_id\",\n      \"incident_ticket_id\",\n      \"justification_text\"\n    ]\n    operator_role: \"AI_System_Admin_L3\"\n    sla_seconds: 60  # Time allowed to complete the halt action\n    default_action_on_timeout: \"Halt\"  # Fail-safe: if approval flow times out, we halt\n    accountability:\n      on_call_role: \"SRE_OnCall_L3\"\n      security_role: \"Security_Duty_Officer\"\n      audit_log_target: \"SIEM+IncidentChannel\"\n    version_control:\n      governance: \"Changes to HITL-CP-999 require joint approval by Security and Engineering leadership.\"\n</code></pre><p><strong>Action:</strong> Add the emergency kill-switch as <code>HITL-CP-999</code> in your HITL registry. Define the authorized operator role, time-to-act SLA, fail-safe default (<code>default_action_on_timeout: Halt</code>), audit logging destination, and which on-call rotations are accountable. Require security+engineering leadership approval for any changes to this checkpoint so governance can prove that control of the kill-switch is tightly managed.</p>"
                },
                {
                    "implementation": "Enforce global/tenant halt flags at every inference request path and agent loop (fail-closed).",
                    "howTo": "<h5>Concept:</h5><p>This is where the kill-switch actually \"bites.\" Every inference API endpoint and every agent execution loop must check a shared halt flag <em>before</em> doing any work. If <code>SYSTEM_HALT_GLOBAL</code> is set, nobody runs. If <code>TENANT:&lt;id&gt;:HALT</code> is set, that tenant gets blocked or forced into degraded safe mode. The request is rejected or downgraded automatically, without waiting for humans to scale deployments down. This makes the system fail-closed under emergency conditions.</p><h5>FastAPI Middleware Gate for Inference Requests</h5><pre><code># File: runtime/halt_gate.py\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import JSONResponse\nimport redis\n\napp = FastAPI()\nr = redis.Redis()\n\n@app.middleware(\"http\")\nasync def halt_gate(request: Request, call_next):\n    # 1. Global halt check\n    global_halt = r.get(\"SYSTEM_HALT_GLOBAL\")\n    if global_halt and global_halt.decode(\"utf-8\") == \"true\":\n        # Immediately deny all work. Fail-closed.\n        return JSONResponse(\n            status_code=503,\n            content={\n                \"error\": \"SYSTEM_HALT_ACTIVE\",\n                \"message\": \"Service temporarily disabled by emergency kill-switch.\",\n            },\n            headers={\"X-System-Halt\": \"true\"}\n        )\n\n    # 2. Tenant-specific halt check (example header or auth-derived)\n    tenant_id = request.headers.get(\"X-Tenant-ID\")\n    if tenant_id:\n        tenant_flag = r.get(f\"TENANT:{tenant_id}:HALT\")\n        if tenant_flag and tenant_flag.decode(\"utf-8\") == \"true\":\n            # Option A: hard block this tenant\n            return JSONResponse(\n                status_code=429,\n                content={\n                    \"error\": \"TENANT_HALTED\",\n                    \"tenant\": tenant_id,\n                    \"message\": \"Tenant temporarily quarantined by kill-switch.\",\n                },\n                headers={\"X-Tenant-Halt\": \"true\"}\n            )\n            # Option B instead: downgrade to 'safe mode' with no external tools,\n            # fewer capabilities, etc. (See AID-I-003 safe mode.)\n\n    # 3. If no halt applies, continue normally\n    response = await call_next(request)\n    return response\n</code></pre><h5>Agent Loop Check (Non-HTTP Autonomous Agent)</h5><pre><code># File: runtime/agent_loop_gate.py\nimport time\nimport redis\n\nr = redis.Redis()\n\nclass HaltAwareAgent:\n    def __init__(self, agent_id: str, tenant_id: str):\n        self.agent_id = agent_id\n        self.tenant_id = tenant_id\n        self.running = True\n\n    def should_halt(self) -> bool:\n        # Check global halt first\n        global_halt = r.get(\"SYSTEM_HALT_GLOBAL\")\n        if global_halt and global_halt.decode(\"utf-8\") == \"true\":\n            return True\n        # Check tenant-level halt\n        tenant_flag = r.get(f\"TENANT:{self.tenant_id}:HALT\")\n        if tenant_flag and tenant_flag.decode(\"utf-8\") == \"true\":\n            return True\n        return False\n\n    def run_forever(self):\n        while self.running:\n            if self.should_halt():\n                print(\n                    f\"Agent {self.agent_id} for tenant {self.tenant_id} \"\n                    f\"stopping due to HALT flag.\"\n                )\n                # Immediately stop doing work. Fail-closed.\n                break\n\n            # --- normal agent reasoning / tool calls / actions here ---\n            time.sleep(2)\n            # --- end normal agent work ---\n</code></pre><p><strong>Action:</strong> Add a universal halt gate in front of <em>all</em> inference endpoints and agent loops. Before doing any inference, tool invocation, or autonomous action, check the global (<code>SYSTEM_HALT_GLOBAL</code>) and tenant (<code>TENANT:&lt;id&gt;:HALT</code>) flags in your shared config store. If either is active, immediately block the request or force the agent to stop / fall back to safe mode. Include a clear response header (e.g. <code>X-System-Halt</code>) and log events for auditing. This guarantees kill-switch enforcement is automatic, immediate, and fail-closed.</p>"
                }
            ]
        },
        {
            "id": "AID-I-006",
            "name": "Malicious Participant Isolation in Federated Unlearning",
            "pillar": ["model"],
            "phase": ["response"],
            "description": "Identifies and logically isolates the influence of malicious clients within a Federated Learning (FL) system, particularly during a machine unlearning or model restoration process. Once identified, the malicious participants' data contributions and model updates are excluded from the unlearning or retraining calculations. This technique is critical for preventing attackers from sabotaging the model recovery process and ensuring the final restored model is not corrupted.",
            "implementationGuidance": [
                {
                    "implementation": "Identify malicious participants by clustering their historical model updates.",
                    "howTo": "<h5>Concept:</h5><p>Before beginning an unlearning process, the server can analyze the historical updates from all clients to identify outliers. The assumption is that malicious clients who sent poisoned updates will have submitted updates that are statistically different from the majority of honest clients. These malicious clients will form small, anomalous clusters in the high-dimensional space of model weights.</p><h5>Analyze and Cluster Historical Updates</h5><p>Use a clustering algorithm like DBSCAN on the flattened model update vectors from all clients over several previous rounds, and label those in outlier clusters as suspicious.</p><pre><code># File: isolate/fl_participant_analysis.py\nfrom sklearn.cluster import DBSCAN\nimport numpy as np\n\n# Example input: list of (client_id, update_vector) pairs\n# all_historical_updates = [\n#     (\"client_A\", [0.01, -0.03, 0.04, ...]),\n#     (\"client_B\", [0.02, -0.02, 0.05, ...]),\n#     ...\n# ]\n\nclient_ids = [item[0] for item in all_historical_updates]\nupdate_vectors = np.array([item[1] for item in all_historical_updates])\n\n# DBSCAN will assign cluster labels (0,1,2,...) to dense groups and -1 to outliers\nclustering = DBSCAN(eps=0.7, min_samples=5).fit(update_vectors)\n\nmalicious_client_ids = [\n    client_ids[i]\n    for i, label in enumerate(clustering.labels_)\n    if label == -1  # -1 means 'outlier' in DBSCAN\n]\n\nif malicious_client_ids:\n    print(f\"Potentially malicious clients to isolate: {malicious_client_ids}\")\n\n# This list will be used in subsequent isolation steps.\n</code></pre><p><strong>Action:</strong> Implement a pre-unlearning analysis step that clusters historical client updates and extracts an isolation list of suspicious participants. Treat that list as untrusted until proven otherwise, and feed it into later filtering/enforcement logic.</p>"
                },
                {
                    "implementation": "Logically exclude contributions from isolated clients during the unlearning or retraining process.",
                    "howTo": "<h5>Concept:</h5><p>Once a list of malicious participants is identified, the core isolation step is to filter out their data from the set used for model restoration. The goal is to rebuild or unlearn the model <em>without</em> their influence, so their updates and samples cannot bias or corrupt the recovered model.</p><h5>Filter the Dataset Before Unlearning</h5><p>Before running unlearning/retraining, generate a 'clean' dataset sourced only from trusted clients. The unlearning algorithm should operate exclusively on this filtered dataset.</p><pre><code># File: isolate/fl_unlearning_isolation.py\n\n# full_historical_dataset is a list of (client_id, data_sample) pairs\n# Example:\n# full_historical_dataset = [\n#     (\"client_A\", {\"x\": [...], \"y\": [...]}),\n#     (\"client_B\", {\"x\": [...], \"y\": [...]}),\n#     ...\n# ]\n\n# malicious_ids is the set of clients marked as isolated/untrusted\n# malicious_ids = {\"client_Z\", \"client_Q\"}\n\nclean_dataset_for_unlearning = [\n    (client_id, sample)\n    for (client_id, sample) in full_historical_dataset\n    if client_id not in malicious_ids\n]\n\ntrusted_client_count = len(set([cid for (cid, _) in clean_dataset_for_unlearning]))\nprint(\n    f\"Isolating {len(malicious_ids)} clients. \"\n    f\"Proceeding with unlearning using data from {trusted_client_count} trusted clients.\"\n)\n\n# Now feed only the clean dataset into the unlearning / restorative retraining flow.\n# restored_model = perform_unlearning(clean_dataset_for_unlearning)\n</code></pre><p><strong>Action:</strong> At the start of the federated unlearning job, construct a filtered view of historical training data that excludes any client on the isolation list. The unlearning / restoration should treat that filtered view as the source of truth.</p>"
                },
                {
                    "implementation": "Apply a real-time filtering strategy during the unlearning process to isolate new malicious updates.",
                    "howTo": "<h5>Concept:</h5><p>Attackers can sabotage unlearning by submitting extreme deltas during the recovery loop. The defense is to aggregate client updates with a robust estimator so a few malicious outliers cannot drag the restored model off course.</p><h5>Step 1: Collect and aggregate unlearning updates with trimmed mean</h5><p>Trimmed mean drops the largest and smallest values in each dimension before averaging, which makes it resilient to a minority of poisoned updates.</p><pre><code># File: isolate/fl_unlearning_loop.py\nfrom __future__ import annotations\n\nfrom dataclasses import dataclass\n\nimport numpy as np\nfrom scipy.stats import trim_mean\n\n\n@dataclass(frozen=True)\nclass ClientUpdate:\n    client_id: str\n    delta: np.ndarray\n\n\ndef aggregate_unlearning_updates(updates: list[ClientUpdate], trim_fraction: float = 0.10) -&gt; np.ndarray:\n    if not updates:\n        raise ValueError(\"No client updates supplied\")\n    update_matrix = np.stack([update.delta for update in updates])\n    return trim_mean(update_matrix, proportiontocut=trim_fraction, axis=0)\n\n\ndef apply_update(model_weights: np.ndarray, aggregated_update: np.ndarray, learning_rate: float = 1.0) -&gt; np.ndarray:\n    return model_weights - (learning_rate * aggregated_update)\n\n\ndef run_unlearning_round(model_weights: np.ndarray, round_updates: list[ClientUpdate]) -&gt; np.ndarray:\n    aggregated_update = aggregate_unlearning_updates(round_updates)\n    return apply_update(model_weights, aggregated_update)\n</code></pre><h5>Step 2: Verify that outliers are suppressed</h5><p>In staging, inject one or two extreme malicious deltas into a mostly normal update batch and confirm the aggregated update stays close to the benign cluster instead of the poisoned outlier.</p><pre><code># File: isolate/test_unlearning_aggregator.py\nimport numpy as np\n\nfrom isolate.fl_unlearning_loop import ClientUpdate, aggregate_unlearning_updates\n\n\nbenign_updates = [\n    ClientUpdate(\"client-a\", np.array([0.10, 0.12, 0.09])),\n    ClientUpdate(\"client-b\", np.array([0.11, 0.13, 0.08])),\n    ClientUpdate(\"client-c\", np.array([0.09, 0.12, 0.10])),\n]\nmalicious_update = ClientUpdate(\"client-z\", np.array([9.0, -8.0, 7.5]))\n\nresult = aggregate_unlearning_updates(benign_updates + [malicious_update], trim_fraction=0.25)\nprint(result)\n</code></pre><p><strong>Action:</strong> Run the unlearning loop with a robust aggregator such as trimmed mean instead of naive averaging, and keep test evidence showing that malicious outliers were suppressed during recovery.</p>"
                },
                {
                    "implementation": "Maintain a dynamic reputation score and exclude any client whose score falls below a critical threshold.",
                    "howTo": "<h5>Concept:</h5><p>Instead of treating isolation as a one-time event, maintain an evolving reputation score for each client. Clients that repeatedly submit anomalous, low-quality, or adversarial updates see their score decay. Once their score drops below a threshold, they are automatically blocked from future training and unlearning rounds. This enforces continuous isolation of bad actors.</p><h5>Implement a Reputation-Based Isolation Policy</h5><p>Before selecting clients for a round, check their reputation score and exclude any below threshold. This is enforced in code at participant selection time, not just documented as a policy.</p><pre><code># File: isolate/fl_reputation_gating.py\nimport random\n\nREPUTATION_THRESHOLD = 0.2  # Scores are normalized 0.0 - 1.0\n\nclass ReputationManager:\n    def __init__(self):\n        # Example internal store: {client_id: score}\n        self.scores = {}\n\n    def get_score(self, client_id: str) -> float:\n        return self.scores.get(client_id, 1.0)\n\n    def decay_score(self, client_id: str, amount: float) -> None:\n        current = self.get_score(client_id)\n        new_score = max(0.0, current - amount)\n        self.scores[client_id] = new_score\n\n# Example usage:\n# reputation_manager = ReputationManager()\n# reputation_manager.scores = {\n#     \"client_A\": 0.9,\n#     \"client_B\": 0.75,\n#     \"client_Z\": 0.05  # repeatedly malicious\n# }\n\n\ndef select_clients_for_round(all_clients, num_to_select, reputation_manager: ReputationManager):\n    trusted_clients = []\n    for client_id in all_clients:\n        score = reputation_manager.get_score(client_id)\n        if score >= REPUTATION_THRESHOLD:\n            trusted_clients.append(client_id)\n        else:\n            print(f\"Isolating client {client_id} due to low reputation score {score}.\")\n\n    if not trusted_clients:\n        return []\n\n    return random.sample(trusted_clients, min(num_to_select, len(trusted_clients)))\n</code></pre><p><strong>Action:</strong> Integrate a reputation manager directly into the federated learning server's client selection logic. Any client with a score below the defined threshold is automatically excluded (fail-closed), without requiring a human approval step.</p>"
                },
                {
                    "implementation": "Require cryptographic attestation or signed client updates before accepting them into training or unlearning.",
                    "howTo": "<h5>Concept:</h5><p>If isolation is based purely on a 'client_id' string, an attacker can simply reconnect using a new ID and continue poisoning. To make isolation meaningful, each client's update must be cryptographically tied to a verifiable identity. The server should only accept updates that include a valid signature or attestation proving they come from an approved runtime (for example, a specific enclave, container identity, or SPIFFE/SPIRE workload identity). Unsigned or unverifiable updates are rejected immediately. This enforces that 'banned' clients cannot trivially respawn.</p><h5>Server-Side Signature Verification</h5><p>Below is an example of verifying an Ed25519 signature on a client's submitted update vector before accepting it. If verification fails, the update is discarded and the client is effectively isolated at the transport boundary.</p><pre><code># File: isolate/verify_signed_update.py\nimport nacl.signing\nimport nacl.exceptions\nimport numpy as np\n\n# Server stores a registry of approved client public keys\n# approved_keys = {\n#     \"client_A\": b\"\\x12\\x34...\",  # Ed25519 public key bytes\n#     \"client_B\": b\"\\xab\\xcd...\",\n# }\n\n\ndef verify_client_update(client_id: str, update_vector: np.ndarray, signature: bytes, approved_keys: dict) -> bool:\n    \"\"\"\n    Returns True if the update is cryptographically valid and trusted.\n    Returns False if signature fails or client_id is unknown.\n    \"\"\"\n    if client_id not in approved_keys:\n        print(f\"Rejecting update: unknown client {client_id}.\")\n        return False\n\n    pubkey_bytes = approved_keys[client_id]\n    verify_key = nacl.signing.VerifyKey(pubkey_bytes)\n\n    # Serialize the update vector in a deterministic way\n    payload = update_vector.astype(np.float32).tobytes()\n\n    try:\n        verify_key.verify(payload, signature)\n        return True\n    except nacl.exceptions.BadSignatureError:\n        print(f\"Rejecting update: bad signature from {client_id}.\")\n        return False\n\n# Usage in the training / unlearning ingestion path:\n# if not verify_client_update(client_id, update_vector, signature, approved_keys):\n#     # Fail-closed: do not even consider this update for aggregation\n#     continue\n</code></pre><p><strong>Action:</strong> Enforce that all client updates (including those used for unlearning) are signed with a trusted key or attested identity. At ingestion time, verify the signature. If verification fails, drop the update immediately. This prevents banned actors from simply reappearing under a new logical name.</p>"
                },
                {
                    "implementation": "Enforce a persistent isolation/blocklist at training-time and unlearning-time (fail-closed).",
                    "howTo": "<h5>Concept:</h5><p>Isolation is only effective if it is consistently enforced at every trust boundary. That means the server must consult an authoritative blocklist (isolation list) <em>before</em> it accepts a client's participation in any round (training or unlearning), and must refuse that client's gradients/updates at ingestion time. The default posture is fail-closed: if a client is on the isolation list, that client cannot influence the model.</p><h5>Runtime Blocklist Enforcement</h5><p>The blocklist should live in persistent storage (for example, a database table or etcd key). Every time the server receives a new update or a participation request, it checks the blocklist first and immediately rejects any client that appears there.</p><pre><code># File: isolate/blocklist_enforcement.py\nimport json\nfrom typing import Set\n\n# Example persistent store: a JSON file, DB table, etc.\n# In production, load this from a secure central store, not a local file.\nISOLATION_LIST_PATH = \"/etc/federated/isolation_list.json\"\n\n\ndef load_isolation_list() -> Set[str]:\n    try:\n        with open(ISOLATION_LIST_PATH, \"r\", encoding=\"utf-8\") as f:\n            data = json.load(f)\n            # data is expected like: {\"isolated_clients\": [\"client_Z\", \"client_Q\"]}\n            return set(data.get(\"isolated_clients\", []))\n    except FileNotFoundError:\n        return set()\n\n\ndef is_client_blocked(client_id: str, isolation_set: Set[str]) -> bool:\n    return client_id in isolation_set\n\n\ndef accept_client_update(client_id: str, update_vector, isolation_set: Set[str]) -> bool:\n    \"\"\"\n    Returns True if the server should accept this client's update,\n    False if the client is isolated and must be rejected (fail-closed).\n    \"\"\"\n    if is_client_blocked(client_id, isolation_set):\n        print(f\"Client {client_id} is isolated. Rejecting update.\")\n        return False\n    return True\n\n# Example usage in aggregation pipeline:\n# isolation_set = load_isolation_list()\n# for (client_id, update_vector) in incoming_updates:\n#     if not accept_client_update(client_id, update_vector, isolation_set):\n#         continue  # skip this malicious/suspended client entirely\n#     process_update(update_vector)\n</code></pre><p><strong>Action:</strong> Maintain a persistent isolation list (blocklist) of client IDs that are considered malicious. On every round of training or unlearning, load this list and enforce it programmatically at ingestion time. If a client is on the list, its updates are never applied. The system fails closed by default.</p>"
                }
            ],
            "toolsOpenSource": [
                "TensorFlow Federated (TFF)",
                "Flower (Federated Learning Framework)",
                "PySyft (OpenMined)",
                "NVIDIA FLARE",
                "scikit-learn (for clustering/anomaly detection)",
                "PyTorch",
                "TensorFlow",
                "SPIFFE/SPIRE (for workload identity attestation and signed workload identities)"
            ],
            "toolsCommercial": [
                "Enterprise Federated Learning Platforms (Owkin, Substra, IBM)",
                "MLOps Platforms with Federated Learning capabilities (Amazon SageMaker)",
                "AI Security Platforms (Protect AI, HiddenLayer)"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0020 Poison Training Data",
                        "AML.T0019 Publish Poisoned Datasets",
                        "AML.T0018 Manipulate AI Model (malicious FL participants directly manipulate the model via updates)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Data Poisoning (L2)",
                        "Data Poisoning (Training Phase) (L1)",
                        "Backdoor Attacks (L1) (FL poisoning can introduce model backdoors)",
                        "Supply Chain Attacks (Cross-Layer) (FL participants form part of the training supply chain)"
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
                        "ML08:2023 Model Skewing (FL poisoning skews model via feedback loop manipulation)"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "N/A"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.013 Data Poisoning",
                        "NISTAML.023 Backdoor Poisoning",
                        "NISTAML.024 Targeted Poisoning",
                        "NISTAML.011 Model Poisoning (Availability)",
                        "NISTAML.026 Model Poisoning (Integrity) (isolating malicious FL participants prevents integrity-targeted poisoning)",
                        "NISTAML.021 Clean-label Backdoor"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-6.1 Training Data Poisoning",
                        "AISubtech-9.2.2 Backdoors and Trojans"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "DP: Data Poisoning (isolating malicious FL participants prevents data poisoning)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Datasets 3.1: Data poisoning (isolating malicious participants prevents training data poisoning)",
                        "Datasets 3.3: Label flipping (isolating malicious participants prevents label flipping attacks)",
                        "Model 7.1: Backdoor machine learning / Trojaned model (isolating malicious FL clients prevents backdoor insertion)"
                    ]
                }
            ]
        },
        {
            "id": "AID-I-007",
            "name": "Client-Side AI Execution Isolation",
            "pillar": ["app"],
            "phase": ["operation"],
            "description": "This technique focuses on containing a compromised or malicious client-side model, preventing it from accessing sensitive data from other browser tabs, local application context, or the operating system. It addresses the security challenges of AI models that execute in untrusted environments like a user's web browser, Electron shell, hybrid mobile app, or native mobile runtime. This assumes the model or model runtime may already be tampered with or coerced (e.g. prompt-injected, modified weights, wrapped with hostile JS). The goal is not to \"fix\" the model but to strictly confine its blast radius using sandboxing, least capability, and controlled IPC.",
            "toolsOpenSource": [
                "WebAssembly runtimes (Wasmtime, Wasmer, browser WebAssembly runtime)",
                "TensorFlow.js, ONNX Runtime Web",
                "Web Workers (Browser API)",
                "Browser postMessage() channel (structured clone IPC for sandboxed components)",
                "Sandboxed iframes (HTML5 iframe with sandbox attribute)",
                "Content Security Policy (CSP) headers"
            ],
            "toolsCommercial": [
                "Mobile OS sandboxing (iOS App Sandbox, Android Application Sandbox)",
                "Enterprise Mobile Device Management (MDM) solutions with app sandboxing / clipboard control / data loss prevention"
            ],
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0025 Exfiltration via Cyber Means (from client device)",
                        "AML.T0037 Data from Local System (stealing browser/app state, session tokens, local storage)",
                        "AML.T0053 AI Agent Tool Invocation (client-side isolation prevents compromised model from invoking host tools)",
                        "AML.T0077 LLM Response Rendering (client-side sandboxing contains render-time attacks from model output)",
                        "AML.T0112.000 Machine Compromise: Local AI Agent (client-side isolation constrains a compromised local agent before it can become full machine compromise)"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Data Exfiltration (L2) (from the client)",
                        "Lateral Movement (Cross-Layer) (isolation prevents compromised client model from accessing other apps)",
                        "Compromised Framework Components (L3) (isolating hostile client-side JS/WASM runtimes)",
                        "Data Leakage (Cross-Layer) (sandboxing prevents cross-app data exposure)",
                        "Agent Tool Misuse (L7) (client-side sandboxing prevents tool misuse by compromised client model)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM02:2025 Sensitive Information Disclosure (blocking direct access to other DOM state / tokens / org data)",
                        "LLM05:2025 Improper Output Handling (preventing model-produced HTML/JS from gaining privileged DOM execution)"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": [
                        "ML06:2023 AI Supply Chain Attacks (containing a malicious downloaded client-side model/runtime so it cannot pivot)"
                    ]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI05:2026 Unexpected Code Execution (RCE)",
                        "ASI02:2026 Tool Misuse and Exploitation (client-side isolation prevents tool misuse by compromised model)",
                        "ASI03:2026 Identity and Privilege Abuse (client-side isolation prevents identity/privilege abuse by compromised model)"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.039 Compromising connected resources",
                        "NISTAML.038 Data Extraction"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-8.2 Data Exfiltration / Exposure",
                        "AISubtech-8.2.2 LLM Data Leakage",
                        "AISubtech-12.1.3 Unsafe System / Browser / File Execution",
                        "AITech-12.1 Tool Exploitation (sandboxing prevents tool exploitation by client-side model)",
                        "AITech-14.1 Unauthorized Access"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "MXF: Model Exfiltration (client-side isolation prevents model exfiltration from device)",
                        "SDD: Sensitive Data Disclosure (client-side sandboxing prevents data leakage to other browser tabs or apps)",
                        "IIC: Insecure Integrated Component (client-side isolation restricts compromised model capabilities)",
                        "RA: Rogue Actions (client-side sandbox prevents rogue model from accessing host system)"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Model 7.2: Model assets leak (client-side isolation prevents on-device model asset leakage)",
                        "Agents - Core 13.11: Unexpected RCE and Code Attacks (client-side sandboxing prevents code execution on host)",
                        "Agents - Tools MCP Server 13.23: Data Exfiltration (CSP and sandbox restrictions block client-side exfiltration)",
                        "Agents - Tools MCP Client 13.32: Client-Side Code Execution",
                        "Agents - Tools MCP Client 13.30: Client-Side Data Leakage (client-side isolation prevents local data leakage)"
                    ]
                }
            ],
            "implementationGuidance": [
                {
                    "implementation": "Execute AI models in a dedicated Web Worker.",
                    "howTo": "<h5>Concept:</h5><p>A Web Worker runs JavaScript in a background thread with no direct access to the DOM, forms, cookies, or UI state. Moving the model into a worker prevents a compromised model from scraping sensitive data rendered in the main page or from directly modifying the UI. All interaction happens through a controlled message channel.</p><h5>Step 1: Worker script that owns the model</h5><pre><code>// File: worker.js\n\n// Load AI runtime libraries inside the worker, not in the main page context\nimportScripts('https://cdn.jsdelivr.net/npm/@tensorflow/tfjs');\n\nlet model = null;\n\nself.onmessage = async (event) => {\n  const msg = event.data;\n\n  // Basic allowlist on message types to avoid unexpected commands\n  if (!['load', 'predict'].includes(msg.type)) {\n    self.postMessage({ status: 'error', error: 'Unsupported message type' });\n    return;\n  }\n\n  try {\n    if (msg.type === 'load') {\n      model = await tf.loadLayersModel(msg.modelPath);\n      self.postMessage({ status: 'loaded' });\n    } else if (msg.type === 'predict' && model) {\n      const inputTensor = tf.tensor(msg.input);\n      const outputTensor = model.predict(inputTensor);\n      const prediction = await outputTensor.data();\n      self.postMessage({ status: 'complete', prediction });\n    }\n  } catch (err) {\n    self.postMessage({ status: 'error', error: String(err) });\n  }\n};\n</code></pre><h5>Step 2: Main thread talks to worker via postMessage</h5><pre><code>// File: main.js\n\nconst inferenceWorker = new Worker('worker.js');\n\ninferenceWorker.onmessage = (event) => {\n  const msg = event.data;\n  if (msg.status === 'loaded') {\n    console.log('Model loaded in isolated worker.');\n    inferenceWorker.postMessage({ type: 'predict', input: [1, 2, 3, 4] });\n  } else if (msg.status === 'complete') {\n    console.log('Prediction from worker:', msg.prediction);\n  } else if (msg.status === 'error') {\n    console.error('Worker error:', msg.error);\n  }\n};\n\n// Trigger model load in the isolated worker (not in window scope)\ninferenceWorker.postMessage({ type: 'load', modelPath: './model/model.json' });\n</code></pre><p><strong>Action:</strong> Always run model load + inference inside a Web Worker. Do not hand the model direct handles to DOM, cookies, storage, or other tabs. Use a minimal, validated message schema for communication via <code>postMessage</code>.</p>"
                },
                {
                    "implementation": "Run untrusted models or their UI components in a sandboxed iframe.",
                    "howTo": "<h5>Concept:</h5><p>An <code>&lt;iframe&gt;</code> with a restrictive <code>sandbox</code> attribute creates a separate browsing context with sharply reduced privileges. You can render untrusted model-driven UI (chat box, visualization, explanation panel) in that iframe. The iframe cannot read the parent DOM, cannot reach cookies in the parent origin (unless you explicitly weaken it), and can be denied network, top-level navigation, form submission, etc. This prevents a hostile or poisoned model output from executing arbitrary script in the privileged parent page.</p><h5>Example: sandboxed iframe with minimal capabilities</h5><pre><code>&lt;!-- File: index.html --&gt;\n&lt;h2&gt;Main Application Content&lt;/h2&gt;\n&lt;p&gt;This main page holds sensitive app state, tokens, etc. The untrusted AI widget will NOT run here.&lt;/p&gt;\n\n&lt;iframe\n  id=\"ai-widget-frame\"\n  src=\"/ai-widget/widget.html\"\n  sandbox=\"allow-scripts\"\n  style=\"width:400px; height:300px; border:1px solid #ccc;\"\n&gt;&lt;/iframe&gt;\n\n&lt;script&gt;\n  const iframe = document.getElementById('ai-widget-frame');\n\n  // Send non-sensitive input to the sandboxed AI widget.\n  iframe.contentWindow.postMessage({\n    type: 'inferenceRequest',\n    prompt: 'Summarize this public text:'\n  }, '*');\n\n  // Receive responses from the sandboxed widget.\n  window.addEventListener('message', (event) =&gt; {\n    // Optional: enforce origin allowlist in production\n    const data = event.data;\n    if (data &amp;&amp; data.type === 'inferenceResult') {\n      console.log('AI iframe result:', data.output);\n    }\n  });\n&lt;/script&gt;\n</code></pre><p><strong>Key rule:</strong> Do <em>not</em> directly inject model-produced HTML/JS into your privileged DOM via <code>innerHTML</code>. Instead, render that untrusted UI inside the sandboxed iframe. Allow only the minimum needed sandbox flags (e.g. <code>allow-scripts</code>) and avoid <code>allow-same-origin</code> unless you fully understand the privacy and cookie implications.</p><p><strong>Action:</strong> Treat the iframe as the only place untrusted model output is allowed to render and execute. Communicate with it only via <code>postMessage</code> using a strict, typed message contract.</p>"
                },
                {
                    "implementation": "Leverage WebAssembly (WASM) runtimes for a capabilities-based sandbox.",
                    "howTo": "<h5>Concept:</h5><p>WebAssembly executes in a sandboxed virtual machine. By default, it cannot access network, filesystem, clipboard, camera, or DOM unless you explicitly hand it those capabilities via the import object. That import boundary becomes your policy enforcement point: you can decide exactly what privileged actions (if any) the model logic can perform, log them, throttle them, or deny them entirely.</p><h5>Run a WASM module with no capabilities granted</h5><pre><code>// File: run_wasm_in_browser.js\n\nasync function runSandboxedWasm() {\n  const wasmBytes = await fetch('./model_inference.wasm').then(res =&gt; res.arrayBuffer());\n\n  // Empty importObject = no host capabilities. The model code can only do math.\n  const importObject = {};\n\n  const { instance } = await WebAssembly.instantiate(wasmBytes, importObject);\n\n  // Call an exported pure function. It cannot touch DOM, cookies, etc.\n  const result = instance.exports.run_inference(/* your args here */);\n  console.log('Inference from WASM sandbox:', result);\n}\n\nrunSandboxedWasm();\n</code></pre><p><strong>Hardening tip:</strong> If you <em>must</em> allow I/O (for example, limited network fetches), expose a tiny, audited function in <code>importObject</code> (like <code>sendRedactedTelemetry()</code>) instead of giving raw fetch or filesystem access. That small shim becomes the choke point where you can redact secrets, rate-limit, and log usage for forensics.</p><p><strong>Action:</strong> Ship the model (or sensitive model kernels) as WASM. Instantiate it with an intentionally minimal <code>importObject</code>. Treat that import boundary as your enforcement layer: nothing outside that allowlist exists to the model.</p>"
                },
                {
                    "implementation": "Utilize Content Security Policy (CSP) to restrict model data exfiltration and script execution.",
                    "howTo": "<h5>Concept:</h5><p>Content Security Policy (CSP) lets you define which network endpoints scripts in this page are allowed to talk to (<code>connect-src</code>), which scripts can run (<code>script-src</code>), and more. A strict CSP makes it much harder for a compromised in-browser model to exfiltrate sensitive data to an attacker-controlled domain, or to inject arbitrary remote scripts.</p><h5>Example CSP header</h5><pre><code>Content-Security-Policy: \n  default-src 'self'; \n  script-src 'self' https://cdn.jsdelivr.net; \n  connect-src 'self' https://api.my-trusted-domain.com; \n  img-src 'self' data:; \n  frame-ancestors 'none';\n</code></pre><p>This policy says:\n<ul>\n<li>Only load scripts from self and a known CDN.</li>\n<li>Only allow outbound fetch/WebSocket/XHR to <code>self</code> and your trusted API endpoint.</li>\n<li>Disallow being iframed elsewhere (<code>frame-ancestors 'none'</code>), which helps protect your privileged parent app from clickjacking or hostile embedding.</li>\n</ul><h5>Meta tag fallback (if you cannot set headers)</h5><pre><code>&lt;head&gt;\n  &lt;meta http-equiv=\"Content-Security-Policy\"\n        content=\"default-src 'self'; connect-src 'self' https://api.my-trusted-domain.com; script-src 'self' https://cdn.jsdelivr.net;\"&gt;\n&lt;/head&gt;\n</code></pre><p><strong>Detection tip:</strong> CSP can also emit violation reports (via <code>report-to</code> / <code>report-uri</code>). Treat repeated CSP violations from a given session as a potential sign of a compromised model trying to leak data.</p><p><strong>Action:</strong> Enforce CSP on any page that hosts a client-side model. Use <code>connect-src</code> as an allowlist of outbound egress targets. Monitor CSP violation reports to detect attempted exfiltration or unexpected script loads.</p>"
                },
                {
                    "implementation": "Enforce a minimal, allowlisted native bridge between the AI runtime and device/system capabilities (mobile, Electron, hybrid apps).",
                    "howTo": "<h5>Concept:</h5><p>On mobile and hybrid desktop apps (React Native, Capacitor, Electron, etc.), the AI model often runs in a JS or WASM sandbox but can still reach powerful native APIs through a bridge layer (filesystem, microphone, corporate tokens, VPN configs, clipboard). A malicious or hijacked model could try to call those bridge APIs to exfiltrate data or escalate privileges. The defense is to force all privileged actions through a single, allowlisted gateway module and refuse anything else by default.</p><h5>Example: restricted bridge in an Electron-style preload</h5><pre><code>// File: preload.js (runs in isolated context)\nconst { contextBridge, ipcRenderer } = require('electron');\n\n// Only expose a very small, audited surface to the AI runtime.\ncontextBridge.exposeInMainWorld('secureBridge', {\n  getRedactedScreenshot: async () => {\n    // Ask main process for a redacted screenshot instead of raw screen pixels.\n    return ipcRenderer.invoke('get-redacted-screenshot');\n  },\n  sendTelemetry: async (msg) => {\n    // Allowlisted telemetry path, can be rate-limited and logged in main.\n    if (typeof msg !== 'string' || msg.length > 2000) {\n      throw new Error('Telemetry message rejected');\n    }\n    return ipcRenderer.invoke('send-telemetry', msg);\n  }\n});\n</code></pre><h5>Usage in untrusted AI code</h5><pre><code>// File: ai_runtime.js (untrusted / model-controlled layer)\n\nasync function tryExfiltrateSensitiveData() {\n  // The model CANNOT just read files or system secrets directly.\n  // It only sees window.secureBridge, which is minimal and audited.\n  const screenshot = await window.secureBridge.getRedactedScreenshot();\n  await window.secureBridge.sendTelemetry('[summary only]\\n' + screenshot.summary);\n}\n</code></pre><p><strong>Action:</strong> In mobile / Electron / hybrid apps, do NOT let the AI runtime call arbitrary native APIs. Instead, expose a narrowly scoped, audited bridge object with an allowlist of safe functions. Enforce input validation, redaction, and rate limiting at that bridge boundary. Treat anything not on the allowlist as denied by default (fail-closed).</p>"
                }
            ]
        },
        {
            "id": "AID-I-008",
            "name": "Task-Scoped Browser Session & Origin Isolation for Agents",
            "description": "Isolate browser-using agents at the session, profile, and origin boundary so malicious web content, injected workflows, and stateful browsing artifacts cannot persist across tasks or trust zones. This technique covers browser contexts, profiles, cookies, local storage, IndexedDB, cache, history, downloads, clipboard, and other browser-managed state surfaces that agentic browsing can accidentally reuse across unrelated tasks.<br/><br/><strong>Coverage includes:</strong><ul><li>Ephemeral browser context lifecycle and storage partitioning per task or trust zone.</li><li>Cross-origin read/write segmentation with step-up confirmation for sensitive actions.</li><li>Quarantine of downloads, clipboard transfers, and magic-link style authentication flows.</li></ul><strong>Scope boundary clarifications:</strong><ul><li><strong>vs AID-H-020:</strong> AID-H-020's current sub-techniques secure the fetch path and content-demotion path: which URLs may be requested, and how fetched HTML is sanitized before reaching the LLM. This technique secures the browser session and state surfaces themselves \u2014 profiles, contexts, cookies, storage, and history \u2014 which AID-H-020 does not cover.</li><li><strong>vs AID-I-001.003:</strong> AID-I-001.003 governs sandbox-level isolation for tool execution environments such as microVMs or gVisor-backed workloads. This technique governs browser-context-level isolation inside whatever sandbox or container the browser runs in, because browser engines manage their own cookies, storage, cache, and history surfaces that sandbox isolation alone does not partition.</li><li><strong>vs AID-I-004 family:</strong> AID-I-004 governs agent memory and conversational state such as in-memory context, Redis-backed session state, vector memory, and file-backed identity state. This technique governs browser-managed state surfaces such as BrowserContext, cookies, localStorage, IndexedDB, downloads, and history. Both use task-bounded segmentation patterns, but they protect different artifacts owned by different runtime subsystems.</li></ul>",
            "defendsAgainst": [
                {
                    "framework": "MITRE ATLAS",
                    "items": [
                        "AML.T0051.001 LLM Prompt Injection: Indirect",
                        "AML.T0080 AI Agent Context Poisoning",
                        "AML.T0100 AI Agent Clickbait"
                    ]
                },
                {
                    "framework": "MAESTRO",
                    "items": [
                        "Integration Risks (L7)",
                        "Data Exfiltration (L2)",
                        "Agent Tool Misuse (L7)",
                        "Compromised Agents (L7)"
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10 2025",
                    "items": [
                        "LLM01:2025 Prompt Injection",
                        "LLM02:2025 Sensitive Information Disclosure",
                        "LLM06:2025 Excessive Agency"
                    ]
                },
                {
                    "framework": "OWASP ML Top 10 2023",
                    "items": ["N/A"]
                },
                {
                    "framework": "OWASP Agentic AI Top 10 2026",
                    "items": [
                        "ASI01:2026 Agent Goal Hijack",
                        "ASI03:2026 Identity and Privilege Abuse",
                        "ASI06:2026 Memory & Context Poisoning",
                        "ASI10:2026 Rogue Agents"
                    ]
                },
                {
                    "framework": "NIST Adversarial Machine Learning 2025",
                    "items": [
                        "NISTAML.015 Indirect Prompt Injection",
                        "NISTAML.018 Prompt Injection",
                        "NISTAML.036 Leaking information from user interactions",
                        "NISTAML.039 Compromising connected resources"
                    ]
                },
                {
                    "framework": "Cisco Integrated AI Security and Safety Framework",
                    "items": [
                        "AITech-1.2 Indirect Prompt Injection",
                        "AITech-4.2 Context Boundary Attacks",
                        "AISubtech-4.2.2 Session Boundary Violation",
                        "AITech-8.2 Data Exfiltration / Exposure",
                        "AITech-12.1 Tool Exploitation"
                    ]
                },
                {
                    "framework": "Google Secure AI Framework 2.0 - Risks",
                    "items": [
                        "PIJ: Prompt Injection",
                        "SDD: Sensitive Data Disclosure",
                        "IIC: Insecure Integrated Component",
                        "RA: Rogue Actions"
                    ]
                },
                {
                    "framework": "Databricks AI Security Framework 3.0",
                    "items": [
                        "Agents - Core 13.2: Tool Misuse",
                        "Agents - Core 13.3: Privilege Compromise",
                        "Agents - Tools MCP Client 13.34: Session and State Management Failures"
                    ]
                }
            ],
            "subTechniques": [
                {
                    "id": "AID-I-008.001",
                    "name": "Ephemeral Browser Context Lifecycle & Storage Partitioning",
                    "pillar": ["app", "infra", "data"],
                    "phase": ["building", "operation"],
                    "description": "Launch a fresh browser context for each task or trust zone, partition all browser-managed state surfaces (cookies, localStorage, IndexedDB, cache, history) by origin and trust set, and destroy the context deterministically when the task ends. This prevents browsing residue, authenticated sessions, and cached resources from leaking across tasks or being reused by unrelated origins.<br/><br/><strong>Scope boundary clarifications:</strong><ul><li><strong>vs AID-H-018.004:</strong> AID-H-018.004 makes agent short-term memory (prompt state, Redis session context) ephemeral per session or task. This sub-technique applies the same ephemeral-per-task principle to browser profile state managed by the browser engine itself.</li><li><strong>vs AID-I-004.001:</strong> AID-I-004.001 isolates volatile agent runtime context such as in-memory prompt state or Redis-backed session context. This sub-technique isolates browser-managed state surfaces owned by the browser engine: cookies, localStorage, IndexedDB, cache, downloads, and navigation history.</li></ul>",
                    "toolsOpenSource": [
                        "Playwright",
                        "Chromium",
                        "Browserless",
                        "Firefox Multi-Account Containers"
                    ],
                    "toolsCommercial": [
                        "Browserbase",
                        "Cloudflare Browser Isolation",
                        "Menlo Security"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0100 AI Agent Clickbait",
                                "AML.T0080 AI Agent Context Poisoning",
                                "AML.T0086 Exfiltration via AI Agent Tool Invocation"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Compromised Agents (L7)",
                                "Data Exfiltration (L2)",
                                "Integration Risks (L7)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM01:2025 Prompt Injection",
                                "LLM02:2025 Sensitive Information Disclosure"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": ["N/A"]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI03:2026 Identity and Privilege Abuse",
                                "ASI06:2026 Memory & Context Poisoning"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.036 Leaking information from user interactions",
                                "NISTAML.038 Data Extraction"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-4.2 Context Boundary Attacks",
                                "AISubtech-4.2.2 Session Boundary Violation",
                                "AITech-8.2 Data Exfiltration / Exposure"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "SDD: Sensitive Data Disclosure",
                                "RA: Rogue Actions"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Tools MCP Client 13.30: Client-Side Data Leakage",
                                "Agents - Tools MCP Client 13.34: Session and State Management Failures"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Create a fresh browser context for every agent task or trust-zone transition, bind it to a task ID, and destroy it deterministically on task completion with residue verification.",
                            "howTo": "<h5>Concept:</h5><p>A browser-using agent must never attach to the user's long-lived daily profile or a shared team profile. Every task gets a fresh <code>BrowserContext</code> that is destroyed when the task ends. This is the single most impactful browser-isolation control because Playwright's <code>BrowserContext</code> already partitions cookies, localStorage, IndexedDB, cache, and service workers automatically &mdash; if you get the lifecycle right, origin-level partitioning comes for free.</p><h5>Step 1: Create a fresh context per task and bind it to the task ID</h5><p>At the start of every agent task, create a new <code>BrowserContext</code> with no inherited state. Tag it with the task ID and trust-zone label so audit logs can correlate every network request back to a specific task.</p><pre><code>// File: browser/ephemeral_context.js\nimport { chromium } from 'playwright';\n\nexport async function createTaskContext(browser, { taskId, trustZone }) {\n  const context = await browser.newContext({\n    storageState: undefined,       // no inherited cookies or localStorage\n    serviceWorkers: 'block',       // block SW persistence across tasks\n    permissions: [],                // start with no granted permissions\n    userAgent: `AIDefendAgent/${taskId}`,\n  });\n\n  // Tag the context for audit correlation.\n  context._taskId = taskId;\n  context._trustZone = trustZone;\n  context._createdAt = Date.now();\n\n  return context;\n}\n</code></pre><h5>Step 2: Destroy the context deterministically on task end</h5><p>Whether the task succeeds, fails, or is escalated, the context must be closed. Use a <code>try/finally</code> pattern so a thrown exception cannot leave a context alive. After closing, verify no cookies or storage keys survived by attempting to re-read from the closed context (Playwright will throw, confirming disposal).</p><pre><code>// File: browser/task_runner.js\nimport { createTaskContext } from './ephemeral_context.js';\n\nexport async function runBrowserTask(browser, taskId, trustZone, taskFn) {\n  const context = await createTaskContext(browser, { taskId, trustZone });\n  try {\n    const page = await context.newPage();\n    return await taskFn(page, context);\n  } finally {\n    await context.close();\n    // Residue verification: confirm the context is truly gone.\n    try {\n      await context.cookies();\n      throw new Error(`Context for task ${taskId} survived close()`);\n    } catch (e) {\n      if (!e.message.includes('has been closed')) throw e;\n      // Expected: context is disposed.\n    }\n  }\n}\n</code></pre><h5>Step 3: Integration test &mdash; prove no state leaks between tasks</h5><p>Ship a test that runs two sequential tasks, sets a cookie in the first, and asserts the second task's context cannot see it. This test should run in CI so regressions are caught before deployment.</p><pre><code>// File: test/ephemeral_context.test.js\nimport { chromium } from 'playwright';\nimport { runBrowserTask } from '../browser/task_runner.js';\nimport assert from 'node:assert/strict';\n\nconst browser = await chromium.launch();\n\n// Task 1: set a cookie.\nawait runBrowserTask(browser, 'task-1', 'zone-a', async (page) =&gt; {\n  await page.goto('https://httpbin.org/cookies/set/secret/hunter2');\n});\n\n// Task 2: verify the cookie is NOT visible.\nawait runBrowserTask(browser, 'task-2', 'zone-a', async (page) =&gt; {\n  await page.goto('https://httpbin.org/cookies');\n  const body = await page.textContent('body');\n  assert.ok(!body.includes('hunter2'), 'Cookie from task-1 must not leak to task-2');\n});\n\nawait browser.close();\nconsole.log('PASS: no state leakage between ephemeral contexts');\n</code></pre><p><strong>Action:</strong> Wrap every browser task in a <code>createTaskContext</code> / <code>try-finally-close</code> lifecycle. Ship the residue verification test to CI. After this is in place, an auditor can confirm (a) every task correlates to a unique context ID in the audit log, (b) no context outlives its task, and (c) the CI test proves no cross-task state leakage.</p>"
                        },
                        {
                            "implementation": "Define trust-set boundaries for origins and enforce state clearing or context rotation whenever a task crosses from one trust set to another.",
                            "howTo": "<h5>Concept:</h5><p>Even within a single task, a browser agent may visit origins belonging to different trust sets (e.g., an internal wiki and a public vendor site). If both origins share the same <code>BrowserContext</code>, cookies set by the vendor site are visible when the agent navigates back to the internal wiki. The fix is either one context per trust set (preferred) or explicit state clearing on trust-boundary crossings.</p><h5>Step 1: Declare a trust-set manifest that maps origins to trust zones</h5><p>Maintain a versioned manifest (JSON or YAML) that groups origins into trust sets. This manifest is consumed by the context launcher (see the first guidance) and by the routing guard in AID-I-008.002 if both sub-techniques are deployed together.</p><pre><code>// File: policy/trust_set_manifest.json\n{\n  \"version\": \"2026.04\",\n  \"trustSets\": {\n    \"internal\": [\n      \"https://wiki.internal.corp\",\n      \"https://tickets.internal.corp\",\n      \"https://git.internal.corp\"\n    ],\n    \"vendor\": [\n      \"https://console.aws.amazon.com\",\n      \"https://portal.azure.com\"\n    ],\n    \"public\": [\n      \"*\"\n    ]\n  },\n  \"defaultTrustSet\": \"public\"\n}\n</code></pre><h5>Step 2: Create or switch <code>BrowserContext</code> on trust-boundary crossing</h5><p>When the agent's next navigation targets an origin in a different trust set than the current context, do NOT reuse the context. Either create a new context for the new trust set (and close the old one), or &mdash; if the task requires returning to the previous trust set &mdash; park the old context and resume it later without carrying state from the new trust set.</p><pre><code>// File: browser/trust_set_router.js\nimport fs from 'node:fs';\nimport { createTaskContext } from './ephemeral_context.js';\n\nconst manifest = JSON.parse(fs.readFileSync('./policy/trust_set_manifest.json', 'utf8'));\n\nfunction classifyOrigin(origin) {\n  for (const [zone, origins] of Object.entries(manifest.trustSets)) {\n    if (origins.includes(origin) || origins.includes('*')) return zone;\n  }\n  return manifest.defaultTrustSet;\n}\n\nexport async function getContextForOrigin(browser, taskId, targetOrigin, contextPool) {\n  const trustSet = classifyOrigin(targetOrigin);\n\n  if (contextPool.has(trustSet)) {\n    return { context: contextPool.get(trustSet), trustSet, reused: true };\n  }\n\n  const context = await createTaskContext(browser, { taskId, trustZone: trustSet });\n  contextPool.set(trustSet, context);\n  return { context, trustSet, reused: false };\n}\n\nexport async function closeAllContexts(contextPool) {\n  for (const [zone, ctx] of contextPool) {\n    await ctx.close();\n  }\n  contextPool.clear();\n}\n</code></pre><h5>Step 3: Log every trust-boundary crossing for audit</h5><p>Whenever the router creates a new context or switches between pooled contexts, emit a structured log entry so auditors can verify that no cross-trust-set state reuse occurred.</p><pre><code>// File: browser/trust_boundary_audit.js\nexport function logTrustBoundaryCrossing({\n  taskId,\n  previousTrustSet,\n  newTrustSet,\n  targetOrigin,\n  contextReused\n}) {\n  const entry = {\n    event: 'trust_boundary_crossing',\n    taskId,\n    previousTrustSet,\n    newTrustSet,\n    targetOrigin,\n    contextReused,\n    timestamp: new Date().toISOString()\n  };\n  // Append to structured audit log (same log sink as AID-I-008.002 step-up audit).\n  process.stdout.write(JSON.stringify(entry) + '\\n');\n}\n</code></pre><p><strong>Action:</strong> Load the trust-set manifest at agent startup, route every navigation through <code>getContextForOrigin</code>, and emit a crossing log on every trust-set transition. After this is in place, an auditor can independently (a) review the trust-set manifest, (b) verify no context was reused across trust sets by replaying the crossing log, and (c) confirm all contexts were closed at task end via the lifecycle audit from the first guidance.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-008.002",
                    "name": "Cross-Origin Read/Write Segmentation with Step-Up Confirmation",
                    "pillar": ["app"],
                    "phase": ["building", "operation"],
                    "description": "Separate browsing permissions by origin and effect type. Read-only origins may be inspected without authorization, but state-changing actions on sensitive or previously unseen origins must trigger explicit step-up confirmation before execution.<br/><br/><strong>Distinct from AID-D-015.002</strong>, which defines the general step-up or out-of-band confirmation mechanism for high-risk actions such as fund transfers, IAM changes, deletions, or sensitive exports. This sub-technique applies that same mechanism with browser-specific trigger conditions: cross-origin transitions, previously unseen origins, and state-changing actions on sensitive web targets.",
                    "toolsOpenSource": [
                        "Playwright",
                        "Envoy (ext_authz for broker-agnostic suspension)",
                        "Slack Bolt SDK",
                        "Redis (for distributed pending-approvals broker)",
                        "Open Policy Agent (OPA)"
                    ],
                    "toolsCommercial": [
                        "Browserbase",
                        "Auth0 (step-up MFA for approver identity)",
                        "PagerDuty (alternate approval / escalation channel)"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0051.001 LLM Prompt Injection: Indirect",
                                "AML.T0101 Data Destruction via AI Agent Tool Invocation"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Agent Tool Misuse (L7)",
                                "Integration Risks (L7)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM06:2025 Excessive Agency"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": ["N/A"]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI01:2026 Agent Goal Hijack",
                                "ASI02:2026 Tool Misuse and Exploitation",
                                "ASI09:2026 Human-Agent Trust Exploitation (step-up confirmation forces user verification before agent commits to a manipulated cross-origin action)"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.039 Compromising connected resources"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-12.1 Tool Exploitation",
                                "AITech-14.2 Abuse of Delegated Authority"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "RA: Rogue Actions",
                                "IIC: Insecure Integrated Component"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Core 13.2: Tool Misuse",
                                "Agents - Core 13.6: Intent Breaking & Goal Manipulation"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Classify origins into read-only and read-write trust sets, and intercept all state-changing requests with a Playwright route handler that blocks cross-origin writes until a step-up confirmation clears them.",
                            "howTo": "<h5>Concept:</h5><p>The browser agent must not autonomously move from reading one origin to mutating another just because a page suggested it. The enforcement point is the network layer: every outbound request is classified by (origin, HTTP method, target), and any cross-origin state-changing call (POST/PUT/PATCH/DELETE) on a read-only or previously-unseen origin is paused until a broker records an explicit approval.</p><h5>Step 1: Declare an origin policy manifest</h5><p>Keep the trust-set classification in a versioned JSON manifest that ships alongside the agent runtime. Read-only origins can be inspected freely; read-write origins accept writes for the same task; sensitive origins always require step-up regardless of prior activity.</p><pre><code>// File: policy/origin_manifest.json\n{\n  \"version\": \"2026.04.09\",\n  \"readOnly\": [\n    \"https://docs.internal.corp\",\n    \"https://wiki.internal.corp\",\n    \"https://status.vendor.com\"\n  ],\n  \"readWrite\": [\n    \"https://tickets.internal.corp\"\n  ],\n  \"sensitive\": [\n    \"https://admin.internal.corp\",\n    \"https://payments.vendor.com\",\n    \"https://console.aws.amazon.com\"\n  ],\n  \"defaultAction\": \"require_stepup\"\n}\n</code></pre><h5>Step 2: Install a Playwright route() handler that classifies every request</h5><p>Use <code>page.route()</code> to intercept outbound traffic. Safe verbs (GET/HEAD/OPTIONS) on read-only origins pass through. Any state-changing verb, or any request targeting a sensitive origin, is suspended and handed to the step-up broker. A denied or timed-out approval aborts the request with a normalized error so the agent can decide whether to retry under a different plan.</p><pre><code>// File: browser/install_origin_guard.js\nimport fs from 'node:fs';\nimport { URL } from 'node:url';\n\nconst WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);\nconst manifest = JSON.parse(fs.readFileSync('./policy/origin_manifest.json', 'utf8'));\n\nfunction classifyOrigin(targetOrigin) {\n  if (manifest.sensitive.includes(targetOrigin)) return 'sensitive';\n  if (manifest.readWrite.includes(targetOrigin)) return 'read_write';\n  if (manifest.readOnly.includes(targetOrigin)) return 'read_only';\n  return 'unseen';\n}\n\nexport async function installOriginGuard(page, {\n  taskId,\n  sourceOrigin,\n  requestStepUp,\n  audit\n}) {\n  await page.route('**/*', async (route) =&gt; {\n    const request = route.request();\n    const targetOrigin = new URL(request.url()).origin;\n    const method = request.method().toUpperCase();\n    const classification = classifyOrigin(targetOrigin);\n    const isWrite = WRITE_METHODS.has(method);\n    const crossOrigin = targetOrigin !== sourceOrigin;\n\n    // Safe path: same-origin reads, or cross-origin reads on explicitly read-only targets.\n    if (!isWrite &amp;&amp; (classification === 'read_only' || !crossOrigin)) {\n      return route.continue();\n    }\n\n    // Writes to a known read-write target that the task already started on.\n    if (isWrite &amp;&amp; classification === 'read_write' &amp;&amp; !crossOrigin) {\n      audit({ taskId, targetOrigin, method, decision: 'same_origin_write' });\n      return route.continue();\n    }\n\n    // Anything else (cross-origin write, sensitive target, unseen origin) is suspended.\n    const decision = await requestStepUp({\n      taskId,\n      sourceOrigin,\n      targetOrigin,\n      method,\n      url: request.url(),\n      classification,\n      postData: request.postData()?.slice(0, 512) ?? null\n    });\n\n    audit({ taskId, targetOrigin, method, classification, decision: decision.verdict });\n\n    if (decision.verdict === 'approve') {\n      return route.continue();\n    }\n    return route.abort('blockedbyclient');\n  });\n}\n</code></pre><h5>Step 3: Wire the broker into the agent runner</h5><p>The agent controller owns <code>requestStepUp</code>. Its job is to normalize the request into a human-reviewable card (method, source origin, target origin, truncated body preview) and call out to either an automated policy engine (see the second implementation guidance below) or a human confirmation channel. Never auto-approve cross-origin writes inside the agent loop.</p><p><strong>Action:</strong> Load the origin manifest at context creation, install the route guard before any navigation, and forward every classified write to the step-up broker. Record each decision for audit.</p>"
                        },
                        {
                            "implementation": "Normalize every suspended write into a standard confirmation card and resolve it through an asynchronous approval broker with timeout-default-deny, idempotent resume, and a tamper-evident audit chain.",
                            "howTo": "<h5>Scope:</h5><p>This guidance is broker-agnostic. It applies to any enforcement layer that can produce a request-fact payload and block while waiting for a decision &mdash; the Playwright route guard from the first guidance, an Envoy <code>ext_authz</code> filter, a tool-call gate inside an agent runtime, or any custom interceptor. The independently provable outcome is: every suspended write becomes a normalized card with a bounded lifetime, every decision carries a recorded approver identity, and every record is chained so silent tampering is detectable.</p><h5>Concept:</h5><p>Once a write is suspended, three things must be true before it is allowed to resume: (1) a human (or automated decision layer &mdash; see the next implementation guidance) has seen the same normalized view of the action regardless of where the suspension came from, (2) the broker defaults to <em>deny</em> if no decision arrives within the configured window so a forgotten approval cannot silently auto-approve, and (3) a retry or double-click cannot commit the same action twice because resume is keyed on a stable <code>requestId</code>. All three are broker-level properties and do not depend on any specific interception mechanism.</p><h5>Step 1: Define the normalized confirmation card schema</h5><p>Every suspended write is normalized into a single shape so humans, automated policy engines, and downstream audit systems all see the same fields regardless of the suspension source. The card MUST carry an idempotency <code>requestId</code>, explicit <code>expiresAt</code> for default-deny on timeout, source and target origin, HTTP method, truncated URL, and a redacted body preview. Redaction happens at card construction time, not at display time, so the raw secret is never handed to an approval channel.</p><pre><code>// File: broker/confirmation_card.js\nexport function buildConfirmationCard({\n  requestId,\n  taskId,\n  agentId,\n  sourceOrigin,\n  targetOrigin,\n  method,\n  url,\n  postData,\n  timeoutMs = 120000\n}) {\n  const now = Date.now();\n  return {\n    schemaVersion: '2026.04',\n    requestId,\n    taskId,\n    agentId,\n    sourceOrigin,\n    targetOrigin,\n    method,\n    url: url.length &gt; 400 ? url.slice(0, 397) + '...' : url,\n    bodyPreview: redactSensitive(postData).slice(0, 512),\n    createdAt: new Date(now).toISOString(),\n    expiresAt: new Date(now + timeoutMs).toISOString()\n  };\n}\n\nfunction redactSensitive(text) {\n  if (!text) return '';\n  return text\n    .replace(/(password|token|authorization|secret|api[_-]?key)\\s*[:=]\\s*\"?[^\"\\s,}]+/gi, '$1=[REDACTED]')\n    .replace(/\\beyJ[A-Za-z0-9._-]+\\b/g, '[REDACTED_JWT]')\n    .replace(/\\b\\d{13,19}\\b/g, '[REDACTED_LONG_NUMBER]');\n}\n</code></pre><h5>Step 2: Implement the async broker with timeout default-deny and idempotent resume</h5><p>The broker keeps a map of pending approvals keyed by <code>requestId</code>. When a suspension arrives, the broker records the resolver and starts a timer. If the timer fires first, the promise resolves as <code>deny</code> with reason <code>timeout</code> &mdash; never silently approve on timeout, because a forgotten approval must fail closed. If a reviewer responds, the matching resolver fires once and the entry is removed; any subsequent resume call with the same <code>requestId</code> is a no-op, so retries, double-clicks, and replayed webhooks cannot commit the same write twice.</p><pre><code>// File: broker/approval_broker.js\nconst pending = new Map();\n\nexport function suspendForApproval(card) {\n  return new Promise((resolve) =&gt; {\n    const timer = setTimeout(() =&gt; {\n      if (pending.has(card.requestId)) {\n        pending.delete(card.requestId);\n        resolve({ verdict: 'deny', reason: 'timeout', approverId: null });\n      }\n    }, new Date(card.expiresAt).getTime() - Date.now());\n\n    pending.set(card.requestId, { resolve, timer, card });\n  });\n}\n\nexport function resumeApproval(requestId, verdict, approverId, reason) {\n  const entry = pending.get(requestId);\n  if (!entry) {\n    // Idempotent: a second resume (retry, double-click, replayed webhook) is a no-op.\n    return { accepted: false, reason: 'not_pending' };\n  }\n  clearTimeout(entry.timer);\n  pending.delete(requestId);\n  entry.resolve({ verdict, reason, approverId });\n  return { accepted: true };\n}\n\nexport function listPending() {\n  return Array.from(pending.values()).map((e) =&gt; e.card);\n}\n</code></pre><p>For multi-instance deployments, back <code>pending</code> with Redis so any broker replica can resume an approval, and use a Redis <code>SET NX</code> on the <code>requestId</code> inside <code>resumeApproval</code> to keep the idempotency guarantee across replicas.</p><h5>Step 3: Surface the card on a Slack approval channel</h5><p>Post each card as a Slack Block Kit message with explicit Approve and Deny buttons. The button action payload MUST carry the <code>requestId</code> so the webhook handler can call <code>resumeApproval</code> idempotently. Capture the Slack user ID as the <code>approverId</code> for the audit record. Never approve via free-text messages &mdash; only the signed button actions count as a decision, and the Slack signing secret verification is what binds the approver's identity to the recorded verdict.</p><pre><code>// File: channel/slack_approval.js\nimport { App } from '@slack/bolt';\nimport { resumeApproval } from '../broker/approval_broker.js';\nimport { appendAuditEntry } from './audit_log.js';\n\nconst app = new App({\n  token: process.env.SLACK_BOT_TOKEN,\n  signingSecret: process.env.SLACK_SIGNING_SECRET\n});\n\nexport async function postCardToSlack(channelId, card) {\n  await app.client.chat.postMessage({\n    channel: channelId,\n    text: `Agent step-up required: ${card.method} ${card.targetOrigin}`,\n    blocks: [\n      { type: 'header', text: { type: 'plain_text', text: 'Agent step-up confirmation' } },\n      {\n        type: 'section',\n        fields: [\n          { type: 'mrkdwn', text: `*Request ID:*\\n${card.requestId}` },\n          { type: 'mrkdwn', text: `*Agent:*\\n${card.agentId}` },\n          { type: 'mrkdwn', text: `*Method:*\\n${card.method}` },\n          { type: 'mrkdwn', text: `*Source origin:*\\n${card.sourceOrigin}` },\n          { type: 'mrkdwn', text: `*Target origin:*\\n${card.targetOrigin}` },\n          { type: 'mrkdwn', text: `*Expires at:*\\n${card.expiresAt}` }\n        ]\n      },\n      {\n        type: 'section',\n        text: { type: 'mrkdwn', text: `*URL:* \\`${card.url}\\`\\n*Body preview:* \\`${card.bodyPreview}\\`` }\n      },\n      {\n        type: 'actions',\n        block_id: `stepup-${card.requestId}`,\n        elements: [\n          { type: 'button', style: 'primary', text: { type: 'plain_text', text: 'Approve' }, action_id: 'stepup_approve', value: card.requestId },\n          { type: 'button', style: 'danger',  text: { type: 'plain_text', text: 'Deny'    }, action_id: 'stepup_deny',    value: card.requestId }\n        ]\n      }\n    ]\n  });\n}\n\napp.action('stepup_approve', async ({ ack, body, action }) =&gt; {\n  await ack();\n  const outcome = resumeApproval(action.value, 'approve', body.user.id, 'human_approved');\n  await appendAuditEntry({ requestId: action.value, approverId: body.user.id, verdict: 'approve', reason: 'human_approved', accepted: outcome.accepted });\n});\n\napp.action('stepup_deny', async ({ ack, body, action }) =&gt; {\n  await ack();\n  const outcome = resumeApproval(action.value, 'deny', body.user.id, 'human_denied');\n  await appendAuditEntry({ requestId: action.value, approverId: body.user.id, verdict: 'deny', reason: 'human_denied', accepted: outcome.accepted });\n});\n</code></pre><h5>Step 4: Append every decision to a tamper-evident audit chain</h5><p>The audit log is the primary evidence that a step-up actually happened. Store each entry append-only, keyed by <code>requestId</code>, with the approver identity and decision reason. Chain each entry with an HMAC over the previous entry's hash so a later reviewer can detect silent tampering: any deleted or modified row breaks the chain. Keep the chain secret in a secrets manager, never in the log file itself.</p><pre><code>// File: channel/audit_log.js\nimport fs from 'node:fs/promises';\nimport crypto from 'node:crypto';\n\nconst AUDIT_PATH = '/srv/aidefend/audit/stepup.log';\nconst AUDIT_SECRET = process.env.STEPUP_AUDIT_SECRET;\nlet lastChainHash = null;\n\nasync function loadLastChainHash() {\n  try {\n    const raw = await fs.readFile(AUDIT_PATH, 'utf8');\n    const lines = raw.trim().split('\\n').filter(Boolean);\n    if (lines.length === 0) return null;\n    return JSON.parse(lines[lines.length - 1]).chainHash;\n  } catch {\n    return null;\n  }\n}\n\nexport async function appendAuditEntry(entry) {\n  if (lastChainHash === null) {\n    lastChainHash = await loadLastChainHash();\n  }\n  const payload = {\n    ...entry,\n    loggedAt: new Date().toISOString(),\n    previousChainHash: lastChainHash\n  };\n  const chainHash = crypto\n    .createHmac('sha256', AUDIT_SECRET)\n    .update(JSON.stringify(payload))\n    .digest('hex');\n  const line = JSON.stringify({ ...payload, chainHash }) + '\\n';\n  await fs.appendFile(AUDIT_PATH, line, { mode: 0o640 });\n  lastChainHash = chainHash;\n}\n</code></pre><p><strong>Action:</strong> Normalize every suspended write into the confirmation card schema, hand it to the async broker with an explicit <code>expiresAt</code>, surface it on a signed Slack (or equivalent button-driven) channel, and record every decision on the chained audit log. After this is in place, an auditor can independently (a) diff the card schema against live traffic, (b) replay the Slack archive to confirm every approval came from a signed button action, (c) verify the audit chain HMAC end-to-end, and (d) count pending approvals at any time &mdash; without reading the enforcement layer's source code.</p>"
                        },
                        {
                            "implementation": "Externalize the step-up decision to an Open Policy Agent (OPA) Rego bundle so any broker can evaluate each suspended write against a versioned, unit-tested policy independently of the agent and broker source.",
                            "howTo": "<h5>Scope:</h5><p>This guidance is an optional automation layer that sits <em>inside</em> the step-up broker from the previous guidance. A minimal broker always asks a human; adding OPA lets you pre-classify the easy cases &mdash; auto-approve same-origin writes, auto-deny attempts against read-only targets &mdash; so human reviewers only see genuinely ambiguous requests. Because the policy lives outside the agent runtime and outside the broker itself, it can be reviewed, versioned, unit-tested, and rolled back as an independent policy-as-code artifact. Any step-up broker that can POST request facts to an HTTP endpoint can adopt this bundle without changing its interception mechanism.</p><h5>Concept:</h5><p>Hard-coding cross-origin confirmation logic inside the broker is brittle and hard to audit. Externalize the decision to OPA: the broker captures the request facts, posts them to OPA, and OPA returns whether the action should auto-approve, require human step-up, or be denied outright. OPA gives you a versioned, testable, policy-as-code artifact that security can review, approve, and roll back independently of the broker and agent code.</p><h5>Step 1: Write the Rego policy</h5><p>The policy takes the origin classification and HTTP method as input and returns a verdict plus a reason. Same-origin writes to a read-write target auto-approve; cross-origin writes to a sensitive or unseen origin always require human step-up; writes targeting a read-only origin are an explicit policy violation and are denied outright. The default verdict is <code>deny</code> so any input shape the policy did not anticipate fails closed.</p><pre><code># File: policy/cross_origin_stepup.rego\npackage aidefend.browser.stepup\n\nimport future.keywords.if\nimport future.keywords.in\n\ndefault verdict := {\"decision\": \"deny\", \"reason\": \"default_deny\"}\n\nwrite_methods := {\"POST\", \"PUT\", \"PATCH\", \"DELETE\"}\n\nverdict := {\"decision\": \"allow\", \"reason\": \"same_origin_write\"} if {\n    input.method in write_methods\n    input.classification == \"read_write\"\n    input.source_origin == input.target_origin\n}\n\nverdict := {\"decision\": \"stepup\", \"reason\": \"cross_origin_sensitive\"} if {\n    input.method in write_methods\n    input.classification == \"sensitive\"\n}\n\nverdict := {\"decision\": \"stepup\", \"reason\": \"unseen_origin_write\"} if {\n    input.method in write_methods\n    input.classification == \"unseen\"\n}\n\nverdict := {\"decision\": \"stepup\", \"reason\": \"cross_origin_write\"} if {\n    input.method in write_methods\n    input.classification == \"read_write\"\n    input.source_origin != input.target_origin\n}\n\nverdict := {\"decision\": \"deny\", \"reason\": \"readonly_target_write_attempt\"} if {\n    input.method in write_methods\n    input.classification == \"read_only\"\n}\n</code></pre><h5>Step 2: Run OPA as a sidecar and call it from the broker</h5><p>Start OPA in server mode with the policy bundle loaded, then have the broker POST each suspended request to <code>/v1/data/aidefend/browser/stepup/verdict</code>. When OPA returns <code>allow</code> or <code>deny</code>, the broker resolves immediately; when OPA returns <code>stepup</code>, the broker hands off to its human confirmation channel (see the previous implementation guidance for a Slack-based channel). The broker never synthesizes its own decision &mdash; it either echoes OPA or waits for a human.</p><pre><code># Run OPA as a local decision service\nopa run --server --addr :8181 policy/cross_origin_stepup.rego\n</code></pre><pre><code>// File: broker/opa_decision.js\nimport fetch from 'node-fetch';\n\nconst OPA_URL = 'http://127.0.0.1:8181/v1/data/aidefend/browser/stepup/verdict';\n\nexport function makeOpaDecider({ humanConfirm, audit }) {\n  return async function decide(requestFacts) {\n    const opaResponse = await fetch(OPA_URL, {\n      method: 'POST',\n      headers: { 'content-type': 'application/json' },\n      body: JSON.stringify({ input: requestFacts })\n    });\n    const { result } = await opaResponse.json();\n    audit({ stage: 'opa', requestFacts, verdict: result });\n\n    if (result.decision === 'allow') {\n      return { verdict: 'approve', reason: result.reason, approverId: 'opa_bundle' };\n    }\n    if (result.decision === 'deny') {\n      return { verdict: 'deny', reason: result.reason, approverId: 'opa_bundle' };\n    }\n    // stepup: hand off to the broker's human confirmation channel.\n    return humanConfirm(requestFacts, result.reason);\n  };\n}\n</code></pre><h5>Step 3: Unit-test the policy with <code>opa test</code> and gate deploys on it</h5><p>Ship Rego unit tests alongside the policy so a change to the step-up rules cannot land without CI verifying the decision table. The same inputs the broker sends in production should be covered, and the CI job for the policy repository must fail the build on any <code>opa test</code> failure. Rollback is a git revert of the bundle &mdash; not a code change to the broker.</p><pre><code># File: policy/cross_origin_stepup_test.rego\npackage aidefend.browser.stepup\n\ntest_same_origin_rw_allows if {\n    verdict.decision == \"allow\" with input as {\n        \"method\": \"POST\",\n        \"classification\": \"read_write\",\n        \"source_origin\": \"https://tickets.internal.corp\",\n        \"target_origin\": \"https://tickets.internal.corp\"\n    }\n}\n\ntest_cross_origin_sensitive_requires_stepup if {\n    verdict.decision == \"stepup\" with input as {\n        \"method\": \"POST\",\n        \"classification\": \"sensitive\",\n        \"source_origin\": \"https://docs.internal.corp\",\n        \"target_origin\": \"https://admin.internal.corp\"\n    }\n}\n\ntest_readonly_target_write_denied if {\n    verdict.decision == \"deny\" with input as {\n        \"method\": \"PUT\",\n        \"classification\": \"read_only\",\n        \"source_origin\": \"https://tickets.internal.corp\",\n        \"target_origin\": \"https://wiki.internal.corp\"\n    }\n}\n\ntest_unknown_classification_defaults_deny if {\n    verdict.decision == \"deny\" with input as {\n        \"method\": \"POST\",\n        \"classification\": \"bogus\",\n        \"source_origin\": \"https://a\",\n        \"target_origin\": \"https://b\"\n    }\n}\n</code></pre><p><strong>Action:</strong> Externalize every cross-origin step-up decision to a versioned OPA policy bundle, gate deploys on <code>opa test</code>, enable OPA decision logging, and only escalate to the human channel when the policy explicitly returns <code>stepup</code>. After this is in place, an auditor can independently (a) read the Rego policy as a single source of truth for automated decisions, (b) replay OPA decision logs against the current bundle version, (c) prove policy tests pass in CI, and (d) verify that the broker code contains no decision logic of its own &mdash; all without reading any enforcement-layer source.</p>"
                        }
                    ]
                },
                {
                    "id": "AID-I-008.003",
                    "name": "Download / Clipboard / Magic-Link Quarantine",
                    "pillar": ["app", "data"],
                    "phase": ["building", "operation"],
                    "description": "Treat downloads, clipboard operations, and magic-link style authentication flows as quarantine-required state transitions. These channels should not be auto-opened, auto-pasted, or auto-followed inside a privileged browser task without explicit policy and cleanup.",
                    "toolsOpenSource": [
                        "Playwright",
                        "ClamAV",
                        "YARA"
                    ],
                    "toolsCommercial": [
                        "Cloudflare Browser Isolation",
                        "VirusTotal Enterprise"
                    ],
                    "defendsAgainst": [
                        {
                            "framework": "MITRE ATLAS",
                            "items": [
                                "AML.T0011.003 User Execution: Malicious Link",
                                "AML.T0100 AI Agent Clickbait"
                            ]
                        },
                        {
                            "framework": "MAESTRO",
                            "items": [
                                "Data Exfiltration (L2)",
                                "Integration Risks (L7)"
                            ]
                        },
                        {
                            "framework": "OWASP LLM Top 10 2025",
                            "items": [
                                "LLM05:2025 Improper Output Handling"
                            ]
                        },
                        {
                            "framework": "OWASP ML Top 10 2023",
                            "items": ["N/A"]
                        },
                        {
                            "framework": "OWASP Agentic AI Top 10 2026",
                            "items": [
                                "ASI02:2026 Tool Misuse and Exploitation",
                                "ASI03:2026 Identity and Privilege Abuse"
                            ]
                        },
                        {
                            "framework": "NIST Adversarial Machine Learning 2025",
                            "items": [
                                "NISTAML.039 Compromising connected resources"
                            ]
                        },
                        {
                            "framework": "Cisco Integrated AI Security and Safety Framework",
                            "items": [
                                "AITech-8.2 Data Exfiltration / Exposure",
                                "AISubtech-12.1.3 Unsafe System / Browser / File Execution"
                            ]
                        },
                        {
                            "framework": "Google Secure AI Framework 2.0 - Risks",
                            "items": [
                                "SDD: Sensitive Data Disclosure",
                                "RA: Rogue Actions"
                            ]
                        },
                        {
                            "framework": "Databricks AI Security Framework 3.0",
                            "items": [
                                "Agents - Tools MCP Client 13.28: UI/UX Deception",
                                "Agents - Tools MCP Client 13.30: Client-Side Data Leakage"
                            ]
                        }
                    ],
                    "implementationGuidance": [
                        {
                            "implementation": "Quarantine browser downloads until they are scanned, approved, and reopened in a clean context.",
                            "howTo": "<h5>Concept:</h5><p>A browser-using agent should never auto-open a downloaded file inside the same privileged task context that requested it. Downloads are an out-of-band execution and exfiltration path, so every file should land in a quarantine location first, be scanned, and only then be released into a separate approved area.</p><h5>Step 1: Force downloads into a quarantine directory</h5><p>Create the browser context with downloads enabled, but point all saved files at a server-side quarantine path. Do not hand the agent a direct OS-level \"open\" action for newly downloaded content.</p><pre><code>// File: browser/download_quarantine.js\nimport fs from 'node:fs/promises';\nimport path from 'node:path';\nimport { mkdirSync } from 'node:fs';\nimport { spawnSync } from 'node:child_process';\n\nconst QUARANTINE_DIR = '/srv/agent-download-quarantine';\nconst RELEASE_DIR = '/srv/agent-approved-downloads';\nconst YARA_RULESET = '/etc/yara/downloads.yar';\n\nmkdirSync(QUARANTINE_DIR, { recursive: true });\nmkdirSync(RELEASE_DIR, { recursive: true });\n\nfunction scanWithClamAV(filePath) {\n  const result = spawnSync('clamscan', ['--no-summary', filePath], { encoding: 'utf8' });\n  return result.status === 0;\n}\n\nfunction scanWithYara(filePath) {\n  const result = spawnSync('yara', ['-r', YARA_RULESET, filePath], { encoding: 'utf8' });\n  if (result.error) {\n    throw result.error;\n  }\n  return result.stdout.trim() === '';\n}\n\nexport async function quarantineDownload(download, taskId) {\n  const safeName = `${taskId}-${download.suggestedFilename().replace(/[^a-zA-Z0-9._-]/g, '_')}`;\n  const quarantinePath = path.join(QUARANTINE_DIR, safeName);\n\n  await download.saveAs(quarantinePath);\n\n  const clean = scanWithClamAV(quarantinePath) && scanWithYara(quarantinePath);\n  if (!clean) {\n    return { status: 'blocked', quarantinePath };\n  }\n\n  const releasePath = path.join(RELEASE_DIR, safeName);\n  await fs.rename(quarantinePath, releasePath);\n  return { status: 'approved', releasePath };\n}\n</code></pre><h5>Step 2: Release only after scan and policy approval</h5><p>Wire the quarantine handler into the automation layer so the file is never auto-opened after download. Only return a release path after malware scanning, content-type checks, and any task-specific policy review have passed.</p><p><strong>Action:</strong> Treat every browser download as untrusted until proven clean. Save it to quarantine, scan it, record the scan result, and only reopen it from a clean location or a fresh browser context after explicit approval.</p>"
                        },
                        {
                            "implementation": "Block silent clipboard reuse across tasks and require approval before cross-origin paste or clipboard import.",
                            "howTo": "<h5>Concept:</h5><p>The system clipboard is a hidden cross-task transport. If a browser agent can silently reuse clipboard data across sites or tasks, it can leak credentials, session tokens, or sensitive customer data without needing a visible navigation. The safe pattern is to replace implicit clipboard reuse with a task-scoped clipboard broker that requires approval for cross-origin import.</p><h5>Step 1: Keep clipboard data in a task-scoped broker, not the global OS clipboard</h5><p>Record copied data as task metadata and attach source origin information. Deny direct reuse when the paste target belongs to another task or origin unless a policy or human explicitly approves it.</p><pre><code>// File: browser/clipboard_policy.js\nconst clipboardStore = new Map();\n\nexport function recordClipboardCopy({ taskId, origin, text }) {\n  clipboardStore.set(taskId, {\n    origin,\n    text,\n    createdAt: Date.now()\n  });\n}\n\nexport async function requestClipboardImport({\n  sourceTaskId,\n  targetTaskId,\n  targetOrigin,\n  approveTransfer\n}) {\n  const entry = clipboardStore.get(sourceTaskId);\n  if (!entry) {\n    throw new Error('No clipboard payload recorded for source task');\n  }\n\n  const sameTask = sourceTaskId === targetTaskId;\n  const sameOrigin = entry.origin === targetOrigin;\n\n  if (!sameTask || !sameOrigin) {\n    const approved = await approveTransfer({\n      sourceTaskId,\n      targetTaskId,\n      sourceOrigin: entry.origin,\n      targetOrigin,\n      preview: entry.text.slice(0, 120)\n    });\n\n    if (!approved) {\n      throw new Error('Clipboard import denied by policy');\n    }\n  }\n\n  return entry.text;\n}\n</code></pre><h5>Step 2: Intercept paste and materialize only approved content</h5><p>Do not let the browser task read from the global clipboard directly. Instead, intercept paste events and resolve them through the policy broker so cross-origin or cross-task transfers can be reviewed.</p><pre><code>// File: browser/install_clipboard_guard.js\nimport { requestClipboardImport } from './clipboard_policy.js';\n\nexport async function installClipboardGuard(page, taskId, pageOrigin, approveTransfer) {\n  await page.exposeBinding('requestApprovedClipboardImport', async () =&gt; {\n    return requestClipboardImport({\n      sourceTaskId: taskId,\n      targetTaskId: taskId,\n      targetOrigin: pageOrigin,\n      approveTransfer\n    });\n  });\n\n  await page.addInitScript(() =&gt; {\n    window.addEventListener('paste', (event) =&gt; {\n      event.preventDefault();\n      window.requestApprovedClipboardImport().then((approvedText) =&gt; {\n        const target = event.target;\n        if (target &amp;&amp; typeof target.setRangeText === 'function') {\n          const start = target.selectionStart ?? 0;\n          const end = target.selectionEnd ?? start;\n          target.setRangeText(approvedText, start, end, 'end');\n        }\n      }).catch(() =&gt; {\n        // Intentionally drop denied clipboard imports.\n      });\n    });\n  });\n}\n</code></pre><p><strong>Action:</strong> Replace implicit clipboard reuse with a task-aware clipboard broker. Same-task, same-origin paste can stay fast; any cross-origin or cross-task clipboard import must be denied by default unless policy or a human explicitly approves it.</p>"
                        },
                        {
                            "implementation": "Treat magic-link and auth-bearing link flows as approval-required authentication transitions in a dedicated browser context.",
                            "howTo": "<h5>Concept:</h5><p>Magic links, OAuth callbacks, password-reset URLs, and token-bearing invite flows often carry authority in the URL itself. If a browser agent auto-follows them inside a privileged task, it can accidentally complete authentication, leak a token to another origin, or bind the session to the wrong task. Handle these links as explicit authentication transitions, not ordinary clicks.</p><h5>Step 1: Classify token-bearing or auth-completing links before navigation</h5><p>Before the browser task follows a link, inspect the destination. Treat links containing auth callback paths or security-sensitive query keys as approval-required.</p><pre><code>// File: browser/auth_link_gate.js\nconst AUTH_QUERY_KEYS = ['token', 'code', 'id_token', 'access_token', 'magic', 'invite'];\nconst AUTH_PATH_PATTERN = /magic|verify|signin|login|oauth|callback|reset-password/i;\n\nexport function isApprovalRequiredAuthLink(rawUrl) {\n  const url = new URL(rawUrl);\n  return AUTH_QUERY_KEYS.some((key) =&gt; url.searchParams.has(key)) || AUTH_PATH_PATTERN.test(url.pathname);\n}\n</code></pre><h5>Step 2: Open approved auth links in a dedicated browser context</h5><p>If policy allows the transition, complete it in a fresh browser context that is separate from the current task's normal browsing state. This prevents the task from silently reusing an already-privileged session and keeps auth state from bleeding across unrelated work.</p><pre><code>// File: browser/open_auth_link.js\nimport { isApprovalRequiredAuthLink } from './auth_link_gate.js';\n\nexport async function openApprovedAuthLink(browser, rawUrl, requestApproval) {\n  if (!isApprovalRequiredAuthLink(rawUrl)) {\n    throw new Error('Link is not classified as an approval-required auth transition');\n  }\n\n  const approved = await requestApproval({\n    url: rawUrl,\n    reason: 'Token-bearing or magic-link authentication flow detected'\n  });\n\n  if (!approved) {\n    throw new Error('Authentication transition denied');\n  }\n\n  const authContext = await browser.newContext({\n    storageState: undefined,\n    serviceWorkers: 'block',\n    permissions: []\n  });\n\n  const authPage = await authContext.newPage();\n  await authPage.goto(rawUrl, { waitUntil: 'domcontentloaded' });\n  return { authContext, authPage };\n}\n</code></pre><p><strong>Action:</strong> Never let a browser agent auto-follow magic links or token-bearing redirects in its existing privileged task context. Classify them first, require explicit approval, and complete the transition only inside a dedicated browser context with separate state.</p>"
                        }
                    ]
                }
            ]
        }
    ]
};
