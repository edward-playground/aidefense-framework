#!/usr/bin/env node
/**
 * AIDEFEND Framework Dataset Generator
 *
 * Reads tactic JS files from tactics/ directory and generates:
 * - data/data.json - Complete dataset with techniques, strategies, and tools
 *
 * Keywords are structured into two categories:
 * - attack: Attack vectors, surfaces, indicators, outcomes, threat scenarios
 * - defense: Defense mechanisms, techniques, controls implemented
 *
 * Usage: node scripts/generate-dataset.js
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TACTICS_DIR = path.join(__dirname, '..', 'tactics');
const OUTPUT_DIR = path.join(__dirname, '..', 'data');

// Tactic file mapping (filename -> tactic ID)
const TACTIC_FILES = [
  { file: 'model.js', id: 'model', exportName: 'modelTactic' },
  { file: 'harden.js', id: 'harden', exportName: 'hardenTactic' },
  { file: 'detect.js', id: 'detect', exportName: 'detectTactic' },
  { file: 'isolate.js', id: 'isolate', exportName: 'isolateTactic' },
  { file: 'deceive.js', id: 'deceive', exportName: 'deceiveTactic' },
  { file: 'evict.js', id: 'evict', exportName: 'evictTactic' },
  { file: 'restore.js', id: 'restore', exportName: 'restoreTactic' },
];

/**
 * Parse a JavaScript file containing an exported tactic object
 */
function parseTacticFile(filePath, exportName) {
  const content = fs.readFileSync(filePath, 'utf-8');

  const regex = new RegExp(`export\\s+const\\s+${exportName}\\s*=\\s*`);
  const match = content.match(regex);

  if (!match) {
    throw new Error(`Could not find export '${exportName}' in ${filePath}`);
  }

  const startPos = match.index + match[0].length;

  // Extract the object by matching braces
  let depth = 0;
  let inString = false;
  let stringChar = null;
  let escaped = false;
  let objectEnd = -1;

  for (let i = startPos; i < content.length; i++) {
    const char = content[i];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === '\\') {
      escaped = true;
      continue;
    }

    if (inString) {
      if (char === stringChar) {
        inString = false;
        stringChar = null;
      }
      continue;
    }

    if (char === '"' || char === "'" || char === '`') {
      inString = true;
      stringChar = char;
      continue;
    }

    if (char === '{') {
      depth++;
    } else if (char === '}') {
      depth--;
      if (depth === 0) {
        objectEnd = i + 1;
        break;
      }
    }
  }

  if (objectEnd === -1) {
    throw new Error(`Could not parse object in ${filePath}`);
  }

  const objectStr = content.slice(startPos, objectEnd);

  try {
    const parsed = new Function(`return ${objectStr}`)();
    return parsed;
  } catch (e) {
    throw new Error(`Failed to parse object in ${filePath}: ${e.message}`);
  }
}

/**
 * Stopwords to filter out - common words that don't help with matching
 */
const STOPWORDS = new Set([
  'the', 'and', 'for', 'that', 'with', 'this', 'from', 'are', 'was', 'were',
  'been', 'being', 'have', 'has', 'had', 'does', 'did', 'will', 'would',
  'could', 'should', 'may', 'might', 'must', 'shall', 'can', 'need',
  'into', 'through', 'during', 'before', 'after', 'above', 'below',
  'between', 'under', 'again', 'further', 'then', 'once', 'here', 'there',
  'when', 'where', 'why', 'how', 'all', 'each', 'every', 'both', 'few',
  'more', 'most', 'other', 'some', 'such', 'only', 'own', 'same', 'than',
  'too', 'very', 'just', 'also', 'now', 'over', 'these', 'those',
  'which', 'while', 'what', 'about', 'against', 'because', 'including',
  'includes', 'include', 'within', 'without', 'across', 'along', 'among',
  'around', 'using', 'used', 'uses', 'based', 'ensure', 'ensures',
  'provide', 'provides', 'providing', 'create', 'creates', 'creating',
  'allow', 'allows', 'allowing', 'enable', 'enables', 'enabling',
  'make', 'makes', 'making', 'take', 'takes', 'taking', 'given', 'gives',
  'help', 'helps', 'helping', 'support', 'supports', 'supporting',
  'require', 'requires', 'requiring', 'involve', 'involves', 'involving',
  'specific', 'specifically', 'particular', 'particularly', 'general',
  'generally', 'typically', 'usually', 'often', 'always', 'never',
  'well', 'even', 'still', 'already', 'especially', 'either', 'neither',
  'whether', 'however', 'therefore', 'thus', 'hence', 'accordingly',
  'furthermore', 'moreover', 'although', 'though', 'unless', 'until',
  'upon', 'onto', 'toward', 'towards', 'beside', 'besides', 'beyond',
  'like', 'unlike', 'near', 'nearly', 'next', 'since', 'whereas',
  'whereby', 'wherein', 'wherever', 'whenever', 'whoever', 'whatever',
  'whichever', 'however', 'nonetheless', 'nevertheless', 'otherwise',
  'instead', 'rather', 'simply', 'merely', 'exactly', 'precisely',
  'directly', 'indirectly', 'effectively', 'efficiently', 'properly',
  'correctly', 'accurately', 'appropriately', 'adequately', 'sufficiently',
  'significantly', 'substantially', 'considerably', 'extensively',
  'comprehensively', 'systematically', 'automatically', 'manually',
  'potentially', 'possibly', 'probably', 'likely', 'unlikely',
  'necessary', 'essential', 'critical', 'important', 'relevant',
  'appropriate', 'suitable', 'applicable', 'available', 'accessible',
  'possible', 'capable', 'able', 'unable', 'responsible', 'accountable',
  'related', 'associated', 'connected', 'linked', 'tied', 'bound',
  'various', 'multiple', 'several', 'numerous', 'many', 'much',
  'certain', 'definite', 'clear', 'obvious', 'apparent', 'evident',
  'different', 'similar', 'same', 'identical', 'unique', 'distinct',
  'common', 'frequent', 'rare', 'occasional', 'regular', 'consistent',
  'complete', 'full', 'entire', 'whole', 'total', 'overall', 'partial',
  'initial', 'final', 'primary', 'secondary', 'main', 'major', 'minor',
  'first', 'second', 'third', 'last', 'previous', 'following', 'subsequent',
  'current', 'present', 'existing', 'former', 'latter', 'recent', 'new',
  'old', 'early', 'late', 'long', 'short', 'high', 'low', 'large', 'small',
  'big', 'little', 'great', 'good', 'bad', 'best', 'worst', 'better', 'worse',
  'right', 'wrong', 'true', 'false', 'real', 'actual', 'virtual', 'physical',
]);

/**
 * Generic terms to exclude - these don't add semantic value
 */
const EXCLUDE_GENERIC = new Set([
  // Vendor/tool names (don't describe what technique does)
  'google', 'microsoft', 'amazon', 'azure', 'aws', 'nvidia', 'ibm', 'meta',
  'pytorch', 'tensorflow', 'numpy', 'pandas', 'scikit-learn', 'keras',
  'mlflow', 'kubeflow', 'databricks', 'datadog', 'splunk', 'elastic',
  'openai', 'anthropic', 'huggingface', 'langchain', 'llamaindex',
  // Too generic
  'enterprise', 'cloud', 'open', 'custom', 'based', 'platform', 'service',
  'solution', 'tool', 'tools', 'framework', 'library', 'module',
  // Framework names (already in defendsAgainst)
  'owasp', 'mitre', 'atlas', 'maestro', 'nist',
]);

// ============================================================================
// ATTACK KEYWORDS - What attacks/threats this technique addresses
// ============================================================================

/**
 * Attack-related multi-word phrases
 * These describe attack vectors, surfaces, indicators, outcomes, threat scenarios
 */
const ATTACK_PHRASES = [
  // Attack types/techniques (comprehensive)
  'prompt injection', 'indirect prompt injection', 'direct prompt injection',
  'jailbreak attack', 'jailbreak attempt', 'data poisoning', 'training data poisoning',
  'model extraction', 'model theft', 'model stealing', 'weight extraction',
  'model inversion', 'membership inference', 'attribute inference',
  'adversarial attack', 'adversarial example', 'adversarial perturbation',
  'backdoor attack', 'trojan attack', 'neural trojan', 'sleeper agent',
  'evasion attack', 'replay attack', 'gradient attack', 'inference attack',
  'man in the middle', 'mitm attack', 'interception attack',
  'denial of service', 'resource exhaustion', 'compute exhaustion',
  'sponge attack', 'slowloris attack', 'token exhaustion',
  // Supply chain & dependency attacks
  'supply chain attack', 'supply chain compromise', 'dependency confusion',
  'typosquatting', 'package hijacking', 'malicious package',
  'compromised dependency', 'vulnerable dependency', 'outdated dependency',
  'model hub attack', 'pretrained model attack', 'fine-tuning attack',
  // Attack vectors (HOW attacks reach the system)
  'malicious input', 'crafted input', 'adversarial input', 'untrusted data',
  'external content', 'user input', 'unvalidated input', 'unsanitized input',
  'api abuse', 'api exploitation', 'tool abuse', 'tool misuse',
  'plugin abuse', 'extension abuse', 'third party risk', 'vendor risk',
  'social engineering', 'phishing', 'spear phishing', 'credential theft',
  'session hijacking', 'token theft', 'api key theft',
  // Attack surfaces (WHAT parts are vulnerable)
  'training pipeline', 'data pipeline', 'inference endpoint', 'model endpoint',
  'model weights', 'model parameters', 'model architecture', 'hyperparameters',
  'embedding store', 'vector database', 'vector store', 'knowledge base',
  'rag pipeline', 'retrieval pipeline', 'indexing pipeline',
  'agent tools', 'agent actions', 'function calling', 'tool execution',
  'code execution', 'arbitrary code', 'remote code execution',
  'system prompt', 'system instruction', 'context window', 'token limit',
  'memory buffer', 'conversation history', 'chat history',
  // Data & privacy attacks
  'data exfiltration', 'data theft', 'data leakage', 'data breach',
  'information disclosure', 'sensitive data exposure', 'pii exposure', 'pii leakage',
  'training data extraction', 'memorization attack', 'regurgitation attack',
  'privacy violation', 'confidentiality breach',
  // Access & privilege attacks
  'privilege escalation', 'unauthorized access', 'access violation',
  'lateral movement', 'pivoting', 'persistence', 'foothold',
  'account takeover', 'identity theft', 'impersonation attack',
  // Model integrity attacks
  'model corruption', 'model degradation', 'model drift',
  'output manipulation', 'response manipulation', 'bias injection',
  'fairness attack', 'discrimination attack',
  // Business/operational attacks
  'intellectual property theft', 'ip theft', 'competitive intelligence',
  'business logic abuse', 'fraud', 'financial fraud',
  'reputation damage', 'brand damage', 'misinformation', 'disinformation',
  // Threat actors & scenarios
  'insider threat', 'malicious insider', 'external attacker', 'external threat',
  'nation state', 'apt', 'advanced persistent threat',
  'automated attack', 'bot attack', 'coordinated attack', 'targeted attack',
  'opportunistic attack', 'mass attack', 'spray attack',
  // Attack indicators
  'anomalous queries', 'anomalous behavior', 'unusual patterns', 'suspicious activity',
  'repeated failures', 'brute force', 'high volume', 'rate abuse',
  'out of distribution', 'distribution shift', 'unexpected behavior',
  'performance degradation', 'accuracy degradation', 'quality degradation',
];

/**
 * Attack-related single keywords
 */
const ATTACK_KEYWORDS = new Set([
  // Attack actions (verbs)
  'injection', 'inject', 'jailbreak', 'jailbreaking', 'jailbroken',
  'poisoning', 'poisoned', 'poison', 'contaminate', 'contaminated',
  'backdoor', 'backdoored', 'trojan', 'trojaned',
  'evasion', 'evade', 'evading', 'bypass', 'bypassing', 'circumvent',
  'exploit', 'exploiting', 'exploitation', 'exploited',
  'abuse', 'abusing', 'abused', 'misuse', 'misusing',
  'extraction', 'extract', 'extracting', 'exfiltration', 'exfiltrate',
  'leakage', 'leak', 'leaking', 'disclosure', 'disclose',
  'exposure', 'expose', 'exposing', 'exposed',
  'stealing', 'steal', 'theft', 'stolen',
  'breach', 'breached', 'breaching',
  'compromise', 'compromised', 'compromising',
  'manipulation', 'manipulate', 'manipulating', 'manipulated',
  'tampering', 'tamper', 'tampered',
  'corruption', 'corrupt', 'corrupted', 'corrupting',
  'degradation', 'degrade', 'degraded', 'degrading',
  'impersonation', 'impersonate', 'impersonating',
  'spoofing', 'spoof', 'spoofed',
  'forgery', 'forge', 'forged',
  'hijacking', 'hijack', 'hijacked',
  'takeover', 'overtake',
  'attack', 'attacker', 'attacking', 'attacked',
  'threat', 'threaten', 'threatening',
  'intrusion', 'intrude', 'intruder',
  'penetration', 'penetrate',
  'subvert', 'subversion', 'subverted',
  'undermine', 'undermining',
  // Attack characteristics (adjectives)
  'malicious', 'maliciously', 'malware',
  'adversarial', 'adversary', 'adversaries',
  'hostile', 'untrusted', 'untrustworthy',
  'rogue', 'unauthorized', 'illegitimate',
  'fraudulent', 'fraud', 'deceptive', 'deception',
  'harmful', 'dangerous', 'risky',
  'suspicious', 'anomalous', 'abnormal',
  // Attack targets (nouns)
  'weights', 'weight', 'parameters', 'parameter',
  'gradients', 'gradient', 'embeddings', 'embedding',
  'vectors', 'vector', 'representations',
  'prompts', 'prompt', 'tokens', 'token',
  'context', 'memory', 'state', 'cache',
  'credentials', 'credential', 'secrets', 'secret',
  'keys', 'key', 'certificates', 'certificate',
  'assets', 'artifact', 'artifacts',
  // Vulnerability indicators
  'vulnerable', 'vulnerability', 'vulnerabilities',
  'weakness', 'weaknesses', 'flaw', 'flaws',
  'gap', 'gaps', 'hole', 'holes',
  'exposed', 'unprotected', 'unsecured',
  'misconfigured', 'misconfiguration',
  'insecure', 'insecurity',
  'risk', 'risks', 'risky',
]);

// ============================================================================
// DEFENSE KEYWORDS - What defense mechanisms this technique implements
// ============================================================================

/**
 * Defense-related multi-word phrases
 * These describe defense mechanisms, controls, techniques implemented
 */
const DEFENSE_PHRASES = [
  // Input/Output controls
  'input validation', 'input sanitization', 'input filtering',
  'output filtering', 'output validation', 'output sanitization',
  'content filtering', 'content moderation', 'content policy',
  'prompt filtering', 'prompt validation', 'prompt sanitization',
  // Rate/Resource controls
  'rate limiting', 'request throttling', 'quota management', 'resource limiting',
  'token limiting', 'context limiting', 'budget enforcement',
  // Access controls
  'access control', 'access management', 'identity management',
  'authentication', 'multi-factor authentication', 'authorization',
  'identity verification', 'credential management', 'session management',
  'role-based access', 'attribute-based access', 'least privilege',
  'privilege separation', 'privilege management', 'permission management',
  // Encryption/Cryptography
  'encryption at rest', 'encryption in transit', 'end-to-end encryption',
  'key management', 'secret management', 'certificate management',
  'cryptographic signing', 'digital signature', 'integrity verification',
  'hash verification', 'checksum verification',
  // Detection/Monitoring
  'anomaly detection', 'threat detection', 'intrusion detection',
  'behavior analysis', 'behavioral monitoring', 'pattern detection',
  'security monitoring', 'real-time monitoring', 'continuous monitoring',
  'performance monitoring', 'drift detection', 'deviation detection',
  'audit logging', 'activity logging', 'forensic logging', 'security logging',
  'event correlation', 'log analysis', 'alert management',
  // Isolation/Containment
  'network isolation', 'network segmentation', 'micro-segmentation',
  'process isolation', 'container isolation', 'workload isolation',
  'sandboxing', 'sandbox execution', 'isolated execution',
  'air-gapped', 'air gap', 'data isolation', 'tenant isolation',
  'blast radius', 'failure isolation', 'fault isolation',
  // Architecture/Design
  'zero trust', 'defense in depth', 'security by design',
  'secure architecture', 'secure design', 'threat modeling',
  'attack surface reduction', 'attack surface management',
  // Recovery/Resilience
  'incident response', 'disaster recovery', 'business continuity',
  'backup and restore', 'data backup', 'model backup',
  'rollback capability', 'version rollback', 'state rollback',
  'failover', 'redundancy', 'high availability', 'fault tolerance',
  'model versioning', 'checkpoint recovery', 'state restoration',
  'graceful degradation', 'circuit breaker',
  // Hardening
  'security hardening', 'system hardening', 'configuration hardening',
  'vulnerability management', 'vulnerability scanning', 'vulnerability assessment',
  'patch management', 'security patching', 'secure configuration',
  'secure defaults', 'secure baseline',
  // Governance/Compliance
  'policy enforcement', 'security policy', 'compliance monitoring',
  'risk assessment', 'risk management', 'security governance',
  'change management', 'approval workflow', 'review process',
  'audit trail', 'compliance audit', 'security audit',
  // AI-specific defenses
  'adversarial training', 'robust training', 'adversarial robustness',
  'differential privacy', 'privacy preservation', 'data anonymization',
  'federated learning', 'secure aggregation', 'privacy-preserving',
  'homomorphic encryption', 'secure computation', 'trusted execution',
  'model watermarking', 'model fingerprinting', 'ownership verification',
  'provenance tracking', 'lineage tracking', 'data lineage',
  'guardrail', 'guardrails', 'safety guardrail', 'output guardrail',
  'safety filter', 'harm filter', 'toxicity filter',
  'human-in-the-loop', 'human oversight', 'human review',
  'model registry', 'artifact registry', 'version control',
  // Inventory/Visibility
  'asset inventory', 'asset management', 'asset discovery',
  'dependency mapping', 'dependency tracking', 'supply chain visibility',
  'configuration management', 'configuration baseline',
  // Deception
  'honeypot', 'honey token', 'canary token', 'decoy',
  'deception technology', 'trap', 'tripwire',
];

/**
 * Defense-related single keywords
 */
const DEFENSE_KEYWORDS = new Set([
  // Defense actions (verbs)
  'validate', 'validation', 'validating', 'validated',
  'sanitize', 'sanitization', 'sanitizing', 'sanitized',
  'filter', 'filtering', 'filtered',
  'block', 'blocking', 'blocked',
  'deny', 'denying', 'denied',
  'reject', 'rejecting', 'rejected',
  'quarantine', 'quarantining', 'quarantined',
  'isolate', 'isolation', 'isolating', 'isolated',
  'contain', 'containment', 'containing', 'contained',
  'encrypt', 'encryption', 'encrypting', 'encrypted',
  'decrypt', 'decryption', 'decrypting', 'decrypted',
  'hash', 'hashing', 'hashed',
  'sign', 'signing', 'signed', 'signature',
  'authenticate', 'authentication', 'authenticating', 'authenticated',
  'authorize', 'authorization', 'authorizing', 'authorized',
  'verify', 'verification', 'verifying', 'verified',
  'certify', 'certification', 'certifying', 'certified',
  'monitor', 'monitoring', 'monitored',
  'detect', 'detection', 'detecting', 'detected',
  'alert', 'alerting', 'alerted',
  'audit', 'auditing', 'audited',
  'log', 'logging', 'logged',
  'trace', 'tracing', 'traced',
  'track', 'tracking', 'tracked',
  'scan', 'scanning', 'scanned',
  'inspect', 'inspection', 'inspecting', 'inspected',
  'analyze', 'analysis', 'analyzing', 'analyzed',
  'assess', 'assessment', 'assessing', 'assessed',
  'evaluate', 'evaluation', 'evaluating', 'evaluated',
  'patch', 'patching', 'patched',
  'update', 'updating', 'updated',
  'remediate', 'remediation', 'remediating', 'remediated',
  'mitigate', 'mitigation', 'mitigating', 'mitigated',
  'backup', 'backing', 'backed',
  'restore', 'restoration', 'restoring', 'restored',
  'recover', 'recovery', 'recovering', 'recovered',
  'rollback', 'rolling',
  'revert', 'reverting', 'reverted',
  'failover', 'failback',
  'harden', 'hardening', 'hardened',
  'secure', 'securing', 'secured',
  'protect', 'protection', 'protecting', 'protected',
  'defend', 'defense', 'defending', 'defended',
  'prevent', 'prevention', 'preventing', 'prevented',
  'enforce', 'enforcement', 'enforcing', 'enforced',
  'control', 'controlling', 'controlled',
  'govern', 'governance', 'governing', 'governed',
  'comply', 'compliance', 'complying', 'compliant',
  'inventory', 'inventorying', 'inventoried',
  'catalog', 'cataloging', 'cataloged',
  'document', 'documentation', 'documenting', 'documented',
  'baseline', 'baselining', 'baselined',
  'benchmark', 'benchmarking', 'benchmarked',
  // Defense components (nouns)
  'firewall', 'firewalls',
  'gateway', 'gateways',
  'proxy', 'proxies',
  'waf', 'ids', 'ips', 'siem', 'soar',
  'sandbox', 'sandboxes',
  'container', 'containers',
  'enclave', 'enclaves',
  'vault', 'vaults',
  'hsm',
  'guardrail', 'guardrails',
  'safeguard', 'safeguards',
  'constraint', 'constraints',
  'policy', 'policies',
  'rule', 'rules',
  'whitelist', 'blacklist', 'allowlist', 'denylist',
  'blocklist', 'safelist',
  'threshold', 'thresholds',
  'limit', 'limits', 'quota', 'quotas',
  'budget', 'budgets',
  // Defense properties (adjectives)
  'secure', 'secured', 'safe', 'safety',
  'trusted', 'trustworthy', 'trust',
  'robust', 'robustness',
  'resilient', 'resilience', 'resiliency',
  'reliable', 'reliability',
  'available', 'availability',
  'integrity',
  'confidential', 'confidentiality',
  'private', 'privacy',
  'anonymous', 'anonymized', 'anonymization',
  // Access control terms
  'rbac', 'abac', 'acl', 'iam', 'pam',
  'sso', 'mfa', '2fa', 'totp',
  'oauth', 'oidc', 'saml', 'ldap',
  'permission', 'permissions',
  'privilege', 'privileges',
  'role', 'roles',
  'scope', 'scopes',
  'token', 'tokens',
  'session', 'sessions',
  'credential', 'credentials',
  // Cryptographic terms
  'cryptographic', 'cryptography', 'crypto',
  'tls', 'ssl', 'https',
  'pki', 'ca',
  'certificate', 'certificates', 'cert', 'certs',
  'key', 'keys',
  'secret', 'secrets',
  'hmac', 'aes', 'rsa', 'ecdsa',
  // Visibility/inventory terms
  'visibility', 'observable', 'observability',
  'discoverable', 'discovery',
  'traceable', 'traceability',
  'accountable', 'accountability',
  'sbom', 'sca', 'sast', 'dast',
  'provenance', 'lineage', 'attestation',
  'registry', 'registries',
  'repository', 'repositories',
  'versioning', 'versioned',
  'checkpoint', 'checkpoints',
  'snapshot', 'snapshots',
]);

/**
 * Infer attack keywords based on defense technique type/context
 * Maps defense concepts to attacks they protect against
 */
const DEFENSE_TO_ATTACK_MAP = {
  // Defense concepts -> Related attacks
  'inventory': ['unauthorized access', 'asset discovery', 'reconnaissance', 'shadow ai'],
  'mapping': ['lateral movement', 'reconnaissance', 'attack surface', 'exposure'],
  'dependency': ['supply chain attack', 'dependency confusion', 'vulnerable dependency', 'compromised'],
  'provenance': ['data poisoning', 'tampering', 'supply chain attack', 'untrusted data'],
  'lineage': ['data poisoning', 'tampering', 'manipulation', 'corruption'],
  'versioning': ['rollback attack', 'tampering', 'corruption', 'unauthorized modification'],
  'integrity': ['tampering', 'corruption', 'manipulation', 'forgery', 'unauthorized modification'],
  'cryptographic': ['tampering', 'forgery', 'man in the middle', 'interception'],
  'vetting': ['supply chain attack', 'malicious', 'untrusted', 'compromised', 'backdoor'],
  'baseline': ['drift', 'anomalous behavior', 'deviation', 'degradation', 'manipulation'],
  'documentation': ['misconfiguration', 'misuse', 'unauthorized', 'compliance violation'],
  'explainability': ['bias injection', 'manipulation', 'deception', 'hidden behavior'],
  'sanitization': ['injection', 'malicious input', 'poisoning', 'exploit', 'xss', 'sqli'],
  'validation': ['injection', 'malicious input', 'bypass', 'exploit', 'invalid input'],
  'filtering': ['injection', 'malicious content', 'harmful output', 'data exfiltration'],
  'rate limiting': ['denial of service', 'resource exhaustion', 'brute force', 'abuse'],
  'throttling': ['denial of service', 'resource exhaustion', 'abuse', 'flooding'],
  'access control': ['unauthorized access', 'privilege escalation', 'lateral movement'],
  'authentication': ['impersonation', 'credential theft', 'unauthorized access', 'spoofing'],
  'authorization': ['privilege escalation', 'unauthorized access', 'bypass'],
  'encryption': ['data exfiltration', 'interception', 'man in the middle', 'eavesdropping'],
  'isolation': ['lateral movement', 'privilege escalation', 'containment escape', 'breakout'],
  'sandboxing': ['code execution', 'escape', 'breakout', 'privilege escalation'],
  'monitoring': ['evasion', 'stealth attack', 'persistent threat', 'undetected'],
  'detection': ['evasion', 'bypass', 'stealth', 'obfuscation', 'hiding'],
  'anomaly': ['zero-day', 'novel attack', 'unknown threat', 'evasion'],
  'audit': ['repudiation', 'tampering', 'unauthorized', 'forensic evasion'],
  'logging': ['repudiation', 'tampering', 'cover tracks', 'log injection'],
  'backup': ['ransomware', 'data destruction', 'corruption', 'availability attack'],
  'recovery': ['ransomware', 'data destruction', 'denial of service', 'corruption'],
  'rollback': ['corruption', 'poisoning', 'tampering', 'malicious update'],
  'hardening': ['exploitation', 'vulnerability', 'misconfiguration', 'attack surface'],
  'guardrail': ['jailbreak', 'bypass', 'harmful output', 'policy violation'],
  'moderation': ['harmful content', 'toxic output', 'policy violation', 'abuse'],
  'federated': ['poisoning', 'model corruption', 'byzantine attack', 'malicious participant'],
  'differential privacy': ['membership inference', 'data extraction', 'privacy attack'],
  'watermarking': ['model theft', 'model extraction', 'ip theft', 'unauthorized use'],
  'fingerprinting': ['model theft', 'unauthorized distribution', 'ip theft'],
  'deception': ['reconnaissance', 'attacker', 'intrusion', 'probing'],
  'honeypot': ['attacker', 'intrusion', 'reconnaissance', 'lateral movement'],
  'decoy': ['attacker', 'misdirection', 'reconnaissance'],
};

/**
 * Extract ATTACK keywords from technique
 * Sources: description, implementation strategies (threat context mentioned)
 * NOT from defendsAgainst (that's already structured data)
 */
function extractAttackKeywords(technique) {
  const keywords = new Set();

  const name = (technique.name || '').toLowerCase();
  const description = (technique.description || '').toLowerCase();

  // Combine text sources (excluding defendsAgainst per user request)
  const strategies = (technique.implementationStrategies || [])
    .map(s => typeof s === 'string' ? s : s.strategy || s.name || '')
    .join(' ')
    .toLowerCase();

  const allText = `${name} ${description} ${strategies}`;

  // 1. Extract attack phrases (multi-word)
  for (const phrase of ATTACK_PHRASES) {
    if (allText.includes(phrase)) {
      keywords.add(phrase);
    }
  }

  // 2. Extract attack single keywords
  const words = allText.replace(/[^a-z0-9\s-]/g, ' ').split(/\s+/);
  for (const word of words) {
    if (word.length > 2 && ATTACK_KEYWORDS.has(word) && !STOPWORDS.has(word)) {
      keywords.add(word);
    }
  }

  // 3. Extract contextual attack terms from description patterns
  const attackPatterns = [
    /against\s+(\w+(?:\s+\w+)?)\s*(?:attacks?)?/gi,
    /prevent(?:s|ing)?\s+(\w+(?:\s+\w+)?)/gi,
    /protect(?:s|ing)?\s+(?:against\s+)?(\w+(?:\s+\w+)?)/gi,
    /mitigat(?:e|es|ing)\s+(\w+(?:\s+\w+)?)/gi,
    /defend(?:s|ing)?\s+against\s+(\w+(?:\s+\w+)?)/gi,
    /vulnerab(?:le|ility)\s+to\s+(\w+(?:\s+\w+)?)/gi,
    /risk\s+of\s+(\w+(?:\s+\w+)?)/gi,
    /threat\s+of\s+(\w+(?:\s+\w+)?)/gi,
    /detect(?:s|ing)?\s+(\w+(?:\s+\w+)?)\s*(?:attacks?|attempts?)?/gi,
    /block(?:s|ing)?\s+(\w+(?:\s+\w+)?)/gi,
  ];

  for (const pattern of attackPatterns) {
    let match;
    const textCopy = allText; // Reset for each pattern
    pattern.lastIndex = 0;
    while ((match = pattern.exec(textCopy)) !== null) {
      const term = match[1].trim().toLowerCase();
      if (term.length > 2 && !STOPWORDS.has(term) && !EXCLUDE_GENERIC.has(term)) {
        // Check if it's a known attack term or phrase
        if (ATTACK_KEYWORDS.has(term) || ATTACK_PHRASES.some(p => p.includes(term))) {
          keywords.add(term);
        }
      }
    }
  }

  // 4. FALLBACK: Infer attack keywords from defense concepts in technique name/description
  if (keywords.size < 10) {
    for (const [defenseConcept, attackTerms] of Object.entries(DEFENSE_TO_ATTACK_MAP)) {
      if (allText.includes(defenseConcept)) {
        for (const attackTerm of attackTerms) {
          keywords.add(attackTerm);
          if (keywords.size >= 15) break;
        }
      }
      if (keywords.size >= 15) break;
    }
  }

  // 5. FALLBACK: Add generic attack terms based on technique category
  if (keywords.size < 8) {
    // Check what kind of technique this is based on ID prefix
    const id = technique.id || '';
    if (id.includes('-M-')) {
      // Model/visibility techniques
      ['reconnaissance', 'shadow ai', 'unauthorized access', 'misconfiguration', 'exposure'].forEach(t => keywords.add(t));
    } else if (id.includes('-H-')) {
      // Hardening techniques
      ['exploitation', 'vulnerability', 'attack surface', 'misconfiguration', 'bypass'].forEach(t => keywords.add(t));
    } else if (id.includes('-D-')) {
      // Detection techniques
      ['evasion', 'stealth attack', 'obfuscation', 'anomalous behavior', 'intrusion'].forEach(t => keywords.add(t));
    } else if (id.includes('-I-')) {
      // Isolation techniques
      ['lateral movement', 'privilege escalation', 'breakout', 'escape', 'containment bypass'].forEach(t => keywords.add(t));
    } else if (id.includes('-DV-')) {
      // Deception techniques
      ['reconnaissance', 'attacker', 'intrusion', 'probing', 'enumeration'].forEach(t => keywords.add(t));
    } else if (id.includes('-E-')) {
      // Eviction techniques
      ['persistence', 'backdoor', 'malware', 'compromise', 'intrusion'].forEach(t => keywords.add(t));
    } else if (id.includes('-R-')) {
      // Restore techniques
      ['corruption', 'data destruction', 'ransomware', 'availability attack', 'integrity attack'].forEach(t => keywords.add(t));
    }
  }

  // Return up to 15 keywords, sorted by relevance (phrases first, then single words)
  const phrases = Array.from(keywords).filter(k => k.includes(' '));
  const singles = Array.from(keywords).filter(k => !k.includes(' '));

  return [...phrases, ...singles].slice(0, 15);
}

/**
 * Tactic-to-defense concept mapping
 * Used as fallback to ensure sufficient defense keywords
 */
const TACTIC_DEFENSE_MAP = {
  'model': ['inventory', 'visibility', 'mapping', 'documentation', 'baseline', 'catalog', 'discovery', 'assessment', 'governance'],
  'harden': ['hardening', 'protection', 'prevention', 'secure', 'robust', 'resilient', 'mitigation', 'defense', 'control'],
  'detect': ['detection', 'monitoring', 'alerting', 'analysis', 'anomaly', 'inspection', 'observability', 'logging', 'audit'],
  'isolate': ['isolation', 'containment', 'segmentation', 'sandbox', 'separation', 'boundary', 'quarantine', 'enclave'],
  'deceive': ['deception', 'honeypot', 'decoy', 'trap', 'misdirection', 'canary', 'tripwire', 'lure'],
  'evict': ['eviction', 'removal', 'remediation', 'cleanup', 'eradication', 'purge', 'elimination', 'termination'],
  'restore': ['restoration', 'recovery', 'backup', 'rollback', 'checkpoint', 'failover', 'resilience', 'continuity'],
};

/**
 * Extract DEFENSE keywords from technique
 * Sources: technique name, description, implementation strategies
 */
function extractDefenseKeywords(technique) {
  const keywords = new Set();

  const name = (technique.name || '').toLowerCase();
  const description = (technique.description || '').toLowerCase();

  // Get strategies
  const strategies = (technique.implementationStrategies || [])
    .map(s => typeof s === 'string' ? s : s.strategy || s.name || '')
    .join(' ')
    .toLowerCase();

  const allText = `${name} ${description} ${strategies}`;

  // 1. Extract meaningful words from technique NAME (defines this defense)
  const nameWords = name.replace(/[^a-z0-9\s-]/g, ' ').split(/\s+/).filter(w => w.length > 2);
  for (const word of nameWords) {
    if (!STOPWORDS.has(word) && !EXCLUDE_GENERIC.has(word)) {
      keywords.add(word);
    }
  }

  // 2. Extract defense phrases (multi-word)
  for (const phrase of DEFENSE_PHRASES) {
    if (allText.includes(phrase)) {
      keywords.add(phrase);
    }
  }

  // 3. Extract defense single keywords
  const words = allText.replace(/[^a-z0-9\s-]/g, ' ').split(/\s+/);
  for (const word of words) {
    if (word.length > 2 && DEFENSE_KEYWORDS.has(word) && !STOPWORDS.has(word) && !EXCLUDE_GENERIC.has(word)) {
      keywords.add(word);
    }
  }

  // 4. Extract tool-agnostic defense concepts from tools and description
  const toolConcepts = [
    { pattern: /model\s*registry/i, concept: 'model registry' },
    { pattern: /artifact\s*registry/i, concept: 'artifact registry' },
    { pattern: /secret\s*manag/i, concept: 'secret management' },
    { pattern: /key\s*manag/i, concept: 'key management' },
    { pattern: /vulnerability\s*scan/i, concept: 'vulnerability scanning' },
    { pattern: /container\s*scan/i, concept: 'container scanning' },
    { pattern: /static\s*analysis/i, concept: 'static analysis' },
    { pattern: /dynamic\s*analysis/i, concept: 'dynamic analysis' },
    { pattern: /penetration\s*test/i, concept: 'penetration testing' },
    { pattern: /code\s*review/i, concept: 'code review' },
    { pattern: /threat\s*model/i, concept: 'threat modeling' },
    { pattern: /risk\s*assess/i, concept: 'risk assessment' },
    { pattern: /security\s*audit/i, concept: 'security audit' },
    { pattern: /access\s*control/i, concept: 'access control' },
    { pattern: /identity\s*manag/i, concept: 'identity management' },
    { pattern: /policy\s*enforce/i, concept: 'policy enforcement' },
    { pattern: /compliance\s*monitor/i, concept: 'compliance monitoring' },
    { pattern: /incident\s*response/i, concept: 'incident response' },
    { pattern: /anomaly\s*detect/i, concept: 'anomaly detection' },
    { pattern: /intrusion\s*detect/i, concept: 'intrusion detection' },
    { pattern: /data\s*validation/i, concept: 'data validation' },
    { pattern: /input\s*validation/i, concept: 'input validation' },
    { pattern: /output\s*filter/i, concept: 'output filtering' },
    { pattern: /rate\s*limit/i, concept: 'rate limiting' },
    { pattern: /network\s*segment/i, concept: 'network segmentation' },
    { pattern: /zero\s*trust/i, concept: 'zero trust' },
    { pattern: /least\s*privilege/i, concept: 'least privilege' },
    { pattern: /defense\s*in\s*depth/i, concept: 'defense in depth' },
    { pattern: /secure\s*by\s*design/i, concept: 'secure by design' },
    { pattern: /human[\s-]*in[\s-]*the[\s-]*loop/i, concept: 'human-in-the-loop' },
    { pattern: /differential\s*privacy/i, concept: 'differential privacy' },
    { pattern: /federated\s*learning/i, concept: 'federated learning' },
    { pattern: /adversarial\s*train/i, concept: 'adversarial training' },
  ];

  const toolsText = [
    ...(technique.toolsOpenSource || []),
    ...(technique.toolsCommercial || []),
  ].join(' ').toLowerCase();

  for (const { pattern, concept } of toolConcepts) {
    if (pattern.test(toolsText) || pattern.test(allText)) {
      keywords.add(concept);
    }
  }

  // 5. Extract action verbs that indicate defense activities
  const defenseActionPatterns = [
    /implement(?:s|ing)?\s+(\w+(?:\s+\w+)?)/gi,
    /establish(?:es|ing)?\s+(\w+(?:\s+\w+)?)/gi,
    /maintain(?:s|ing)?\s+(\w+(?:\s+\w+)?)/gi,
    /enforce(?:s|ing)?\s+(\w+(?:\s+\w+)?)/gi,
    /apply(?:ing)?\s+(\w+(?:\s+\w+)?)/gi,
  ];

  for (const pattern of defenseActionPatterns) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(allText)) !== null) {
      const term = match[1].trim().toLowerCase();
      if (term.length > 2 && DEFENSE_KEYWORDS.has(term.split(' ')[0])) {
        keywords.add(term.split(' ')[0]);
      }
    }
  }

  // 6. FALLBACK: Add tactic-based defense keywords if we have too few
  if (keywords.size < 10) {
    const id = technique.id || '';
    let tacticId = '';

    if (id.includes('-M-')) tacticId = 'model';
    else if (id.includes('-H-')) tacticId = 'harden';
    else if (id.includes('-D-')) tacticId = 'detect';
    else if (id.includes('-I-')) tacticId = 'isolate';
    else if (id.includes('-DV-')) tacticId = 'deceive';
    else if (id.includes('-E-')) tacticId = 'evict';
    else if (id.includes('-R-')) tacticId = 'restore';

    if (tacticId && TACTIC_DEFENSE_MAP[tacticId]) {
      for (const concept of TACTIC_DEFENSE_MAP[tacticId]) {
        keywords.add(concept);
        if (keywords.size >= 15) break;
      }
    }
  }

  // 7. FALLBACK: Add generic defense properties if still too few
  if (keywords.size < 8) {
    ['security', 'protection', 'control', 'management', 'governance', 'policy', 'compliance'].forEach(term => {
      keywords.add(term);
    });
  }

  // Return up to 15 keywords, sorted by relevance (phrases first, then single words)
  const phrases = Array.from(keywords).filter(k => k.includes(' '));
  const singles = Array.from(keywords).filter(k => !k.includes(' '));

  return [...phrases, ...singles].slice(0, 15);
}

/**
 * Extract structured keywords (attack + defense categories)
 */
function extractKeywords(technique) {
  return {
    attack: extractAttackKeywords(technique),
    defense: extractDefenseKeywords(technique),
  };
}

/**
 * Transform a sub-technique from source format to target format
 */
function transformSubTechnique(subTech) {
  const transformed = {
    id: subTech.id,
    name: subTech.name,
    description: subTech.description || '',
    pillar: Array.isArray(subTech.pillar) ? subTech.pillar : [subTech.pillar].filter(Boolean),
    phase: Array.isArray(subTech.phase) ? subTech.phase : [subTech.phase].filter(Boolean),
    // Only include strategy names, not the full howTo content
    implementationStrategies: (subTech.implementationStrategies || []).map(
      strat => strat.strategy || strat.name || ''
    ).filter(Boolean),
    toolsOpenSource: subTech.toolsOpenSource || [],
    toolsCommercial: subTech.toolsCommercial || [],
    defendsAgainst: subTech.defendsAgainst || [],
  };
  // Extract structured keywords
  transformed.keywords = extractKeywords(transformed);
  return transformed;
}

/**
 * Transform a technique from source format to target format
 */
function transformTechnique(tech, tacticId) {
  // Get pillar/phase from technique level, or aggregate from all sub-techniques
  const techPillar = tech.pillar;
  const techPhase = tech.phase;
  const subs = tech.subTechniques || [];

  let pillar, phase;

  if (techPillar) {
    // Standalone technique (Pattern B) — preserve full array
    pillar = Array.isArray(techPillar) ? techPillar : [techPillar].filter(Boolean);
  } else if (subs.length > 0) {
    // Parent technique (Pattern A) — aggregate deduplicated union from all sub-techniques
    const allPillars = new Set();
    subs.forEach(s => {
      const p = s.pillar;
      if (Array.isArray(p)) p.forEach(v => allPillars.add(v));
      else if (p) allPillars.add(p);
    });
    pillar = allPillars.size > 0 ? [...allPillars] : [derivePillarFromId(tech.id)];
  } else {
    pillar = [derivePillarFromId(tech.id)];
  }

  if (techPhase) {
    phase = Array.isArray(techPhase) ? techPhase : [techPhase].filter(Boolean);
  } else if (subs.length > 0) {
    const allPhases = new Set();
    subs.forEach(s => {
      const p = s.phase;
      if (Array.isArray(p)) p.forEach(v => allPhases.add(v));
      else if (p) allPhases.add(p);
    });
    phase = allPhases.size > 0 ? [...allPhases] : ['operation'];
  } else {
    phase = ['operation'];
  }

  // Get implementation strategies from technique level if present
  const techStrategies = (tech.implementationStrategies || []).map(
    strat => strat.strategy || strat.name || ''
  ).filter(Boolean);

  const transformed = {
    id: tech.id,
    name: tech.name,
    description: tech.description || '',
    pillar,
    phase,
    defendsAgainst: tech.defendsAgainst || [],
    implementationStrategies: techStrategies,
    toolsOpenSource: tech.toolsOpenSource || [],
    toolsCommercial: tech.toolsCommercial || [],
    subTechniques: (tech.subTechniques || []).map(transformSubTechnique),
    url: 'https://aidefend.net',
  };
  // Extract structured keywords
  transformed.keywords = extractKeywords(transformed);
  return transformed;
}

/**
 * Fallback pillar when a technique has no pillar field.
 * Tactic codes (D, H, I, etc.) are orthogonal to pillar values
 * (data, model, infra, app), so no mapping is possible — return
 * a safe default and warn so the gap is visible.
 */
function derivePillarFromId(id) {
  console.warn(`[generate-dataset] WARNING: technique ${id} has no pillar — using fallback 'app'`);
  return 'app';
}

/**
 * Transform a tactic from source format to target format
 */
function transformTactic(tacticData, tacticId) {
  return {
    id: tacticId,
    name: tacticData.name,
    description: tacticData.purpose || tacticData.description || '',
    techniques: (tacticData.techniques || []).map(tech =>
      transformTechnique(tech, tacticId)
    ),
  };
}

/**
 * Calculate SHA256 checksum
 */
function sha256(content) {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Main function
 */
async function main() {
  console.log('AIDEFEND Dataset Generator v2.0');
  console.log('================================');
  console.log('Keywords: Structured (attack/defense categories)\n');

  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  const tactics = [];
  let totalTechniques = 0;
  let totalSubTechniques = 0;
  let totalStrategies = 0;
  let totalAttackKeywords = 0;
  let totalDefenseKeywords = 0;

  // Process each tactic file
  for (const { file, id, exportName } of TACTIC_FILES) {
    const filePath = path.join(TACTICS_DIR, file);

    if (!fs.existsSync(filePath)) {
      console.warn(`Warning: ${file} not found, skipping...`);
      continue;
    }

    console.log(`Processing ${file}...`);

    try {
      const tacticData = parseTacticFile(filePath, exportName);
      const transformed = transformTactic(tacticData, id);
      tactics.push(transformed);

      const techCount = transformed.techniques.length;
      const subCount = transformed.techniques.reduce(
        (sum, t) => sum + t.subTechniques.length, 0
      );
      const stratCount = transformed.techniques.reduce(
        (sum, t) => sum + t.implementationStrategies.length +
          t.subTechniques.reduce((s, sub) => s + sub.implementationStrategies.length, 0),
        0
      );

      // Count keywords
      const attackKwCount = transformed.techniques.reduce(
        (sum, t) => sum + t.keywords.attack.length +
          t.subTechniques.reduce((s, sub) => s + sub.keywords.attack.length, 0),
        0
      );
      const defenseKwCount = transformed.techniques.reduce(
        (sum, t) => sum + t.keywords.defense.length +
          t.subTechniques.reduce((s, sub) => s + sub.keywords.defense.length, 0),
        0
      );

      totalTechniques += techCount;
      totalSubTechniques += subCount;
      totalStrategies += stratCount;
      totalAttackKeywords += attackKwCount;
      totalDefenseKeywords += defenseKwCount;

      console.log(`  -> ${transformed.name}: ${techCount} techniques, ${subCount} sub-techniques`);
      console.log(`     Keywords: ${attackKwCount} attack, ${defenseKwCount} defense`);
    } catch (e) {
      console.error(`Error processing ${file}: ${e.message}`);
    }
  }

  // Create dataset
  const now = new Date().toISOString();
  const dataset = {
    version: {
      schemaVersion: '2.0',
      dataVersion: now.split('T')[0].replace(/-/g, '.'),
      generatedAt: now,
      source: 'bundled',
      keywordStructure: 'categorized',
    },
    tactics,
  };

  // Serialize
  const content = JSON.stringify(dataset, null, 2);
  const checksum = sha256(content);

  // Write data.json
  const dataPath = path.join(OUTPUT_DIR, 'data.json');
  fs.writeFileSync(dataPath, content);

  console.log('\n================================');
  console.log('Generation complete!\n');
  console.log(`Tactics: ${tactics.length}`);
  console.log(`Techniques: ${totalTechniques}`);
  console.log(`Sub-techniques: ${totalSubTechniques}`);
  console.log(`Implementation strategies: ${totalStrategies}`);
  console.log(`\nKeywords:`);
  console.log(`  Attack keywords: ${totalAttackKeywords}`);
  console.log(`  Defense keywords: ${totalDefenseKeywords}`);
  console.log(`  Total: ${totalAttackKeywords + totalDefenseKeywords}`);
  console.log(`\nOutput: ${dataPath}`);
  console.log(`Size: ${(content.length / 1024).toFixed(1)} KB`);
  console.log(`Checksum: ${checksum.slice(0, 16)}...`);
}

main().catch(console.error);
