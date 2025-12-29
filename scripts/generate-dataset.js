#!/usr/bin/env node
/**
 * AIDEFEND Framework Dataset Generator
 *
 * Reads tactic JS files from tactics/ directory and generates:
 * - data/data.json - Complete dataset with techniques, strategies, and tools
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
 * Important multi-word phrases in AI security domain
 * These are matched as complete phrases before single-word extraction
 */
const IMPORTANT_PHRASES = [
  // Attack types
  'prompt injection', 'jailbreak attack', 'data poisoning', 'model extraction',
  'model stealing', 'model inversion', 'membership inference', 'adversarial attack',
  'supply chain', 'backdoor attack', 'trojan attack', 'evasion attack',
  'data exfiltration', 'privilege escalation', 'denial of service',
  // Defense techniques
  'input validation', 'output filtering', 'rate limiting', 'access control',
  'content filtering', 'anomaly detection', 'threat detection', 'intrusion detection',
  'security monitoring', 'audit logging', 'incident response',
  // AI/ML concepts
  'machine learning', 'deep learning', 'neural network', 'large language model',
  'vector database', 'knowledge base', 'training data', 'fine tuning',
  'retrieval augmented', 'function calling', 'tool use', 'agent framework',
  'model registry', 'model serving', 'feature store',
  // Security concepts
  'zero trust', 'defense in depth', 'least privilege', 'data classification',
  'encryption at rest', 'encryption in transit', 'key management',
  // Compliance/Frameworks
  'owasp', 'mitre atlas', 'nist', 'iso 27001',
];

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
 * TOO_COMMON keywords - these appear in almost every technique and are not distinctive
 * We should avoid adding these unless they're in the technique name
 */
const TOO_COMMON = new Set([
  'ai', 'ml', 'model', 'models', 'data', 'security', 'system', 'systems',
  'attack', 'attacks', 'risk', 'risks', 'threat', 'threats',
  'owasp', 'mitre', 'atlas', 'maestro', 'nist',  // Framework names appear in every defendsAgainst
  'detection', 'monitoring', 'protection', 'defense',
  'training', 'validation', 'testing', 'datasets',
]);

/**
 * HIGH_VALUE keywords - specific terms that are distinctive and useful for matching
 */
const HIGH_VALUE_KEYWORDS = new Set([
  // Specific attack types
  'injection', 'jailbreak', 'jailbreaking', 'adversarial', 'malicious',
  'poisoning', 'backdoor', 'trojan', 'evasion', 'exfiltration',
  'extraction', 'stealing', 'leakage', 'disclosure', 'exposure',
  'exploit', 'exploits', 'breach', 'compromise', 'compromised',
  // Specific defense techniques
  'sanitization', 'filtering', 'moderation', 'guardrail', 'guardrails',
  'sandbox', 'sandboxing', 'isolation', 'containment', 'quarantine',
  'firewall', 'gateway', 'proxy', 'authentication', 'authorization',
  'encryption', 'decryption', 'hashing', 'signing', 'verification',
  'rbac', 'abac', 'acl', 'permissions', 'privileges', 'credentials',
  'audit', 'auditing', 'logging', 'tracing', 'observability',
  // AI-specific terms
  'llm', 'nlp', 'gpt', 'bert', 'transformer', 'neural',
  'prompt', 'prompts', 'embedding', 'embeddings',
  'inference', 'fine-tuning', 'finetuning', 'pretraining',
  'token', 'tokens', 'tokenizer', 'tokenization', 'context',
  'vector', 'vectors', 'semantic', 'similarity', 'retrieval', 'rag',
  'agent', 'agents', 'agentic', 'autonomous',
  'chatbot', 'assistant', 'copilot', 'generative',
  // Tools (specific names)
  'openai', 'anthropic', 'langchain', 'llamaindex', 'huggingface',
  'pytorch', 'tensorflow', 'keras', 'scikit',
  'pinecone', 'weaviate', 'chromadb', 'milvus', 'qdrant', 'faiss',
  'kubernetes', 'docker', 'container', 'microservice',
  'mlflow', 'kubeflow', 'mlops', 'pipeline',
  // Data-specific
  'pii', 'sensitive', 'confidential', 'private', 'personal', 'secret',
  'classification', 'labeling', 'annotation', 'preprocessing',
  'sbom', 'sca', 'cve', 'cwe',
  // Action words that indicate specific activities
  'inventory', 'mapping', 'cataloging', 'discovery', 'scanning',
  'profiling', 'fingerprinting', 'enumeration', 'reconnaissance',
  'hardening', 'patching', 'remediation', 'mitigation',
  'rollback', 'recovery', 'restoration', 'backup',
  'throttling', 'limiting', 'blocking', 'filtering',
]);

/**
 * Extract keywords from a technique object
 * Priority: 1) Name keywords, 2) Important phrases, 3) Tool names, 4) High-value terms
 * Avoids: Too common terms that appear in every technique
 */
function extractKeywords(technique) {
  const keywords = new Set();

  const name = (technique.name || '').toLowerCase();
  const description = (technique.description || '').toLowerCase();
  const text = `${name} ${description}`;

  // 1. PRIORITY: Extract meaningful words from technique NAME (most distinctive)
  const nameWords = name.replace(/[^a-z0-9\s-]/g, ' ').split(/\s+/).filter(w => w.length > 2);
  for (const word of nameWords) {
    // Add name words even if they're in TOO_COMMON (they define this technique)
    if (!STOPWORDS.has(word)) {
      keywords.add(word);
    }
  }

  // 2. Extract important multi-word phrases from text
  for (const phrase of IMPORTANT_PHRASES) {
    if (text.includes(phrase)) {
      keywords.add(phrase);
    }
  }

  // 3. Extract tool names (very specific and useful)
  const allTools = [
    ...(technique.toolsOpenSource || []),
    ...(technique.toolsCommercial || []),
  ];
  for (const tool of allTools) {
    // Extract first word/name from tool entry
    const toolName = tool.split(/[,\s(]/)[0].toLowerCase().trim();
    if (toolName.length > 2 && !STOPWORDS.has(toolName) && !TOO_COMMON.has(toolName)) {
      keywords.add(toolName);
    }
  }

  // 4. Extract HIGH_VALUE keywords from description (but not TOO_COMMON ones)
  const descWords = description.replace(/[^a-z0-9\s-]/g, ' ').split(/\s+/);
  for (const word of descWords) {
    if (HIGH_VALUE_KEYWORDS.has(word) && !TOO_COMMON.has(word)) {
      keywords.add(word);
    }
  }

  // 5. Extract from implementation strategies (high-value terms only)
  const strategies = technique.implementationStrategies || [];
  for (const strat of strategies) {
    const stratText = (typeof strat === 'string' ? strat : strat.strategy || strat.name || '').toLowerCase();

    // Check for important phrases
    for (const phrase of IMPORTANT_PHRASES) {
      if (stratText.includes(phrase)) {
        keywords.add(phrase);
      }
    }

    // Extract high-value keywords
    const stratWords = stratText.replace(/[^a-z0-9\s-]/g, ' ').split(/\s+/);
    for (const word of stratWords) {
      if (HIGH_VALUE_KEYWORDS.has(word) && !TOO_COMMON.has(word)) {
        keywords.add(word);
      }
    }
  }

  // 6. Extract from defendsAgainst - only important phrases from items, NOT framework names
  const defendsAgainst = technique.defendsAgainst || [];
  for (const defense of defendsAgainst) {
    for (const item of defense.items || []) {
      const itemLower = item.toLowerCase();
      for (const phrase of IMPORTANT_PHRASES) {
        if (itemLower.includes(phrase)) {
          keywords.add(phrase);
        }
      }
    }
  }

  // 7. If we still have few keywords, add significant unique words from description
  if (keywords.size < 8) {
    for (const word of descWords) {
      if (word.length > 6 && !STOPWORDS.has(word) && !TOO_COMMON.has(word) && keywords.size < 12) {
        keywords.add(word);
      }
    }
  }

  // Return as array, limited to 15 keywords (quality over quantity)
  return Array.from(keywords).slice(0, 15);
}

/**
 * Transform a sub-technique from source format to target format
 */
function transformSubTechnique(subTech) {
  const transformed = {
    id: subTech.id,
    name: subTech.name,
    description: subTech.description || '',
    pillar: Array.isArray(subTech.pillar) ? subTech.pillar[0] : subTech.pillar,
    phase: Array.isArray(subTech.phase) ? subTech.phase[0] : subTech.phase,
    // Only include strategy names, not the full howTo content
    implementationStrategies: (subTech.implementationStrategies || []).map(
      strat => strat.strategy || strat.name || ''
    ).filter(Boolean),
    toolsOpenSource: subTech.toolsOpenSource || [],
    toolsCommercial: subTech.toolsCommercial || [],
    defendsAgainst: subTech.defendsAgainst || [],
  };
  // Extract keywords using the full technique object (for tools, strategies, etc.)
  transformed.keywords = extractKeywords(transformed);
  return transformed;
}

/**
 * Transform a technique from source format to target format
 */
function transformTechnique(tech, tacticId) {
  // Get pillar/phase from technique level or first sub-technique
  const techPillar = tech.pillar;
  const techPhase = tech.phase;
  const firstSub = tech.subTechniques?.[0];

  let pillar = techPillar
    ? (Array.isArray(techPillar) ? techPillar[0] : techPillar)
    : (firstSub?.pillar?.[0] || derivePillarFromId(tech.id));

  let phase = techPhase
    ? (Array.isArray(techPhase) ? techPhase[0] : techPhase)
    : (firstSub?.phase?.[0] || 'operation');

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
    url: `https://aidefend.dev/techniques/${tech.id}`,
  };
  // Extract keywords using the full technique object (for tools, strategies, etc.)
  transformed.keywords = extractKeywords(transformed);
  return transformed;
}

/**
 * Derive pillar from technique ID
 */
function derivePillarFromId(id) {
  const match = id.match(/AID-(\w+)-/);
  if (match) {
    const code = match[1];
    const pillarMap = {
      'D': 'detect',
      'H': 'harden',
      'I': 'isolate',
      'M': 'model',
      'DV': 'deceive',
      'E': 'evict',
      'R': 'restore',
    };
    return pillarMap[code] || 'app';
  }
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
  console.log('AIDEFEND Dataset Generator');
  console.log('==========================\n');

  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  const tactics = [];
  let totalTechniques = 0;
  let totalSubTechniques = 0;
  let totalStrategies = 0;

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

      totalTechniques += techCount;
      totalSubTechniques += subCount;
      totalStrategies += stratCount;

      console.log(`  -> ${transformed.name}: ${techCount} techniques, ${subCount} sub-techniques, ${stratCount} strategies`);
    } catch (e) {
      console.error(`Error processing ${file}: ${e.message}`);
    }
  }

  // Create dataset
  const now = new Date().toISOString();
  const dataset = {
    version: {
      schemaVersion: '1.0',
      dataVersion: now.split('T')[0].replace(/-/g, '.'),
      generatedAt: now,
      source: 'bundled',
    },
    tactics,
  };

  // Serialize
  const content = JSON.stringify(dataset, null, 2);
  const checksum = sha256(content);

  // Write data.json
  const dataPath = path.join(OUTPUT_DIR, 'data.json');
  fs.writeFileSync(dataPath, content);

  console.log('\n==========================');
  console.log('Generation complete!\n');
  console.log(`Tactics: ${tactics.length}`);
  console.log(`Techniques: ${totalTechniques}`);
  console.log(`Sub-techniques: ${totalSubTechniques}`);
  console.log(`Implementation strategies: ${totalStrategies}`);
  console.log(`\nOutput: ${dataPath}`);
  console.log(`Size: ${(content.length / 1024).toFixed(1)} KB`);
  console.log(`Checksum: ${checksum.slice(0, 16)}...`);
}

main().catch(console.error);
