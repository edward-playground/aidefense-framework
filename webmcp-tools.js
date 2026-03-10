/**
 * AIDEFEND WebMCP Tools — Public Framework Knowledge API
 * 
 * Registers browser-accessible tools via the emerging WebMCP API
 * (W3C Web Machine Learning Community Group draft), enabling AI agents
 * to query the AIDEFEND AI security defense framework.
 * 
 * PUBLIC FRAMEWORK — These tools expose read-only access to the
 * AIDEFEND open-source AI security defense knowledge base.
 * The first version focuses on 5 core query tools for stability
 * and simplicity. Additional tools may be added in future versions.
 * 
 * Tools registered:
 *   1. search_techniques       — Keyword search across techniques
 *   2. get_technique_detail    — Full detail lookup by ID
 *   3. get_implementation_guide — Implementation strategies + tools
 *   4. find_defenses_by_threat — Threat → defense mapping
 *   5. get_framework_stats     — Summary statistics
 * 
 * @see https://aidefend.net
 * @see https://webmachinelearning.github.io/webmcp/
 * @version 1.0.0
 */

// Pin to a specific version — do not use @latest
// Before deploying, verify the latest stable version at https://www.npmjs.com/package/@mcp-b/global
// Record tested/verified versions here
import 'https://esm.sh/@mcp-b/global@1.5.0';

// Guard check: verify API availability after polyfill loads
if (!navigator.modelContext || typeof navigator.modelContext.registerTool !== 'function') {
    console.warn('[AIDEFEND WebMCP] navigator.modelContext not available. WebMCP tools will not be registered.');
} else {
    // Only dynamically import data and register tools after the guard passes
    const { aidefendData } = await import('./main.js');

    // =========================================================================
    //  Helper Functions
    // =========================================================================

    /**
     * Strip HTML tags and return plain text with preserved structure.
     * Converts block-level tags to newlines before DOM text extraction,
     * so code blocks in <pre> and list items retain readable formatting.
     */
    function stripHtml(html) {
        if (!html) return '';
        // Replace block-level tags with newlines before extracting text
        let processed = html
            .replace(/<br\s*\/?>/gi, '\n')
            .replace(/<\/(?:p|div|li|h[1-6]|tr|pre)>/gi, '\n')
            .replace(/<\/(?:td|th)>/gi, '\t');
        const div = document.createElement('div');
        div.innerHTML = processed;
        const text = div.textContent || div.innerText || '';
        // Collapse excessive blank lines but preserve single newlines
        return text.replace(/\n{3,}/g, '\n\n').trim();
    }

    /**
     * Check if a defendsAgainst item is meaningful (not N/A).
     */
    function isValidItem(item) {
        return item && item !== 'N/A' && !item.startsWith('N/A ');
    }

    /**
     * Normalize text for search: strip HTML and lowercase.
     */
    function normalizeForSearch(text) {
        if (!text) return '';
        return stripHtml(text).toLowerCase();
    }

    /**
     * Heuristic: does this query look like a threat ID?
     * Matches patterns like: AML.T0051, LLM01, LLM01:2025, MAES-03, NIST.AML.018
     */
    function looksLikeId(query) {
        return /^[A-Z]{2,}[\.\-:]/i.test(query.trim()) || /^[A-Z]+\d+/i.test(query.trim());
    }

    /**
     * Two-mode threat matching against a defendsAgainst array.
     * 
     * If query looks like an ID:
     *   Tier 1: Exact ID match (query matches the ID portion of the item)
     *   Tier 2: Prefix match (query is a prefix of the item's ID portion)
     *           e.g., "LLM01" matches "LLM01:2025 Prompt Injection"
     * 
     * If query looks like a keyword:
     *   Tier 3: Substring search (case-insensitive)
     *           e.g., "prompt injection" matches items containing those words
     * 
     * Returns: { matched: boolean, tier: 1|2|3|null, matches: Array<{framework, item}> }
     */
    function matchThreat(defendsAgainst, query) {
        const q = query.trim().toLowerCase();
        const isId = looksLikeId(query);
        const results = { tier1: [], tier2: [], tier3: [] };

        for (const mapping of (defendsAgainst || [])) {
            for (const item of (mapping.items || [])) {
                if (!isValidItem(item)) continue;
                const itemLower = item.toLowerCase();
                const itemIdPart = itemLower.split(' ')[0];

                if (isId) {
                    // Tier 1: Exact ID match
                    if (itemIdPart === q || itemLower === q) {
                        results.tier1.push({ framework: mapping.framework, item });
                    }
                    // Tier 2: Query is prefix of item ID (but not reverse)
                    else if (itemIdPart.startsWith(q)) {
                        results.tier2.push({ framework: mapping.framework, item });
                    }
                } else {
                    // Tier 3: Keyword substring
                    if (itemLower.includes(q)) {
                        results.tier3.push({ framework: mapping.framework, item });
                    }
                }
            }
        }

        if (results.tier1.length > 0) return { matched: true, tier: 1, matches: results.tier1 };
        if (results.tier2.length > 0) return { matched: true, tier: 2, matches: results.tier2 };
        if (results.tier3.length > 0) return { matched: true, tier: 3, matches: results.tier3 };
        return { matched: false, tier: null, matches: [] };
    }

    /**
     * Filter defendsAgainst, removing N/A items and empty frameworks.
     * Returns a clean object keyed by framework name.
     */
    function cleanDefendsAgainst(defendsAgainst) {
        const result = {};
        for (const mapping of (defendsAgainst || [])) {
            const validItems = (mapping.items || []).filter(isValidItem);
            if (validItems.length > 0) {
                result[mapping.framework] = validItems;
            }
        }
        return result;
    }

    // =========================================================================
    //  Build Indexes (once at module load time)
    // =========================================================================

    const FRAMEWORK_KEYS = [
        'MITRE ATLAS',
        'MAESTRO',
        'OWASP LLM Top 10 2025',
        'OWASP ML Top 10 2023',
        'OWASP Agentic AI Top 10 2026',
        'NIST Adversarial Machine Learning 2025',
        'Cisco Integrated AI Security and Safety Framework'
    ];

    /** Flat array of all techniques, enriched with tacticName, _searchText, isLeaf */
    const allTechniques = (aidefendData.tactics || []).flatMap(tactic =>
        (tactic.techniques || []).map(tech => ({
            ...tech,
            tacticName: tactic.name,
            _searchText: normalizeForSearch((tech.name || '') + ' ' + (tech.description || '')),
            isLeaf: !tech.subTechniques || tech.subTechniques.length === 0
        }))
    );

    /** Flat array of all sub-techniques, enriched with parent info */
    const allSubTechniques = (aidefendData.tactics || []).flatMap(tactic =>
        (tactic.techniques || []).flatMap(tech =>
            (tech.subTechniques || []).map(sub => ({
                ...sub,
                techniqueId: tech.id,
                techniqueName: tech.name,
                tacticName: tactic.name,
                _searchText: normalizeForSearch((sub.name || '') + ' ' + (sub.description || ''))
            }))
        )
    );

    /**
     * All leaf nodes = the smallest-granularity defense units.
     * If a technique has subTechniques → use subTechniques as leaves.
     * If a technique has no subTechniques → the technique itself is a leaf.
     */
    const allLeafNodes = (aidefendData.tactics || []).flatMap(tactic =>
        (tactic.techniques || []).flatMap(tech => {
            if (tech.subTechniques && tech.subTechniques.length > 0) {
                return tech.subTechniques.map(sub => ({
                    ...sub,
                    techniqueId: tech.id,
                    techniqueName: tech.name,
                    tacticName: tactic.name
                }));
            }
            // Technique itself is a leaf
            return [{
                ...tech,
                techniqueId: tech.id,
                techniqueName: tech.name,
                tacticName: tactic.name
            }];
        })
    );

    // =========================================================================
    //  safeRegisterTool Wrapper
    // =========================================================================

    let registeredCount = 0;
    let skippedCount = 0;

    function safeRegisterTool(toolDef) {
        try {
            navigator.modelContext.registerTool(toolDef);
            registeredCount++;
        } catch (e) {
            if (e.name === 'InvalidStateError') {
                console.warn(`[AIDEFEND WebMCP] Tool "${toolDef.name}" already registered, skipping.`);
                skippedCount++;
            } else {
                throw e;
            }
        }
    }

    // =========================================================================
    //  Tool 1: search_techniques
    // =========================================================================

    safeRegisterTool({
        name: 'search_techniques',
        description: "Search the AIDEFEND AI security defense framework by keyword. Searches across technique and sub-technique names and descriptions. Returns matching IDs, names, parent tactic, and sub-technique counts. Use this as the starting point to explore AIDEFEND's 200+ defensive techniques across 7 tactics (Model, Harden, Detect, Isolate, Deceive, Evict, Restore). Note: framework content is in English. If the user's query is in another language, translate it to English before calling this tool.",
        annotations: {
            readOnlyHint: true,
            idempotentHint: true
        },
        inputSchema: {
            type: 'object',
            properties: {
                query: {
                    type: 'string',
                    description: "Search keyword in English, e.g. 'prompt injection', 'model scanning', 'adversarial'. IMPORTANT: The framework content is in English. If the user query is in another language (e.g., Traditional Chinese), MUST translate the keywords into English before calling this tool.",
                    minLength: 2,
                    maxLength: 200
                },
                maxResults: {
                    type: 'integer',
                    description: 'Maximum results to return per category (techniques and sub-techniques). Default: 10, max: 30',
                    default: 10,
                    minimum: 1,
                    maximum: 30
                }
            },
            required: ['query']
        },
        execute: async (args) => {
            try {
                const query = (args.query || '').trim().toLowerCase();
                const maxResults = Math.min(Math.max(args.maxResults || 10, 1), 30);

                // Search techniques
                const techMatches = allTechniques.filter(t => t._searchText.includes(query));
                const techResults = techMatches.slice(0, maxResults).map(t => ({
                    id: t.id,
                    name: t.name,
                    tactic: t.tacticName,
                    subTechniqueCount: (t.subTechniques || []).length
                }));

                // Search sub-techniques
                const subMatches = allSubTechniques.filter(s => s._searchText.includes(query));
                const subResults = subMatches.slice(0, maxResults).map(s => ({
                    id: s.id,
                    name: s.name,
                    parentTechniqueId: s.techniqueId,
                    parentTechniqueName: s.techniqueName,
                    tactic: s.tacticName
                }));

                const result = {
                    query: args.query,
                    techniques: techResults,
                    subTechniques: subResults,
                    totalTechniqueMatches: techMatches.length,
                    totalSubTechniqueMatches: subMatches.length
                };

                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            } catch (error) {
                return { content: [{ type: 'text', text: JSON.stringify({ error: `Search failed: ${error.message}. Please try a different query.` }, null, 2) }] };
            }
        }
    });

    // =========================================================================
    //  Tool 2: get_technique_detail
    // =========================================================================

    safeRegisterTool({
        name: 'get_technique_detail',
        description: "Get full details of an AIDEFEND technique or sub-technique by its ID. Returns description, threat mappings across 7 security frameworks (MITRE ATLAS, OWASP LLM/ML/Agentic Top 10, MAESTRO, NIST AML, Cisco), pillar/phase classification, and sub-technique list.",
        annotations: {
            readOnlyHint: true,
            idempotentHint: true
        },
        inputSchema: {
            type: 'object',
            properties: {
                id: {
                    type: 'string',
                    description: "Technique ID (e.g. 'AID-M-001') or sub-technique ID (e.g. 'AID-M-001.001')",
                    pattern: '^AID-[A-Z]{1,2}-\\d{3}(\\.\\d{3})?$'
                }
            },
            required: ['id']
        },
        execute: async (args) => {
            try {
                const queryId = (args.id || '').trim().toUpperCase();

                // Search in techniques first
                const tech = allTechniques.find(t => t.id.toUpperCase() === queryId);
                if (tech) {
                    if (tech.isLeaf) {
                        // Leaf technique (no subTechniques) — include pillar, phase
                        const result = {
                            id: tech.id,
                            name: tech.name,
                            entityType: 'technique',
                            isLeaf: true,
                            tactic: tech.tacticName,
                            description: stripHtml(tech.description),
                            pillar: tech.pillar || [],
                            phase: tech.phase || [],
                            defendsAgainst: cleanDefendsAgainst(tech.defendsAgainst),
                            subTechniques: []
                        };
                        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                    } else {
                        // Parent technique with subTechniques
                        const result = {
                            id: tech.id,
                            name: tech.name,
                            entityType: 'technique',
                            isLeaf: false,
                            tactic: tech.tacticName,
                            description: stripHtml(tech.description),
                            defendsAgainst: cleanDefendsAgainst(tech.defendsAgainst),
                            subTechniques: (tech.subTechniques || []).map(s => ({
                                id: s.id,
                                name: s.name
                            }))
                        };
                        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                    }
                }

                // Search in sub-techniques
                const sub = allSubTechniques.find(s => s.id.toUpperCase() === queryId);
                if (sub) {
                    const result = {
                        id: sub.id,
                        name: sub.name,
                        entityType: 'subTechnique',
                        parentTechniqueId: sub.techniqueId,
                        parentTechniqueName: sub.techniqueName,
                        tactic: sub.tacticName,
                        pillar: sub.pillar || [],
                        phase: sub.phase || [],
                        description: stripHtml(sub.description),
                        defendsAgainst: cleanDefendsAgainst(sub.defendsAgainst)
                    };
                    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                }

                // Not found
                return { content: [{ type: 'text', text: JSON.stringify({
                    error: `Technique "${args.id}" not found. AIDEFEND IDs follow the pattern AID-{Tactic Letter}-{Number} (e.g. AID-M-001) or AID-{Tactic Letter}-{Number}.{SubNumber} (e.g. AID-M-001.001). Tactic letters: M=Model, H=Harden, D=Detect, I=Isolate, DV=Deceive, E=Evict, R=Restore. Use search_techniques to find the correct ID.`
                }, null, 2) }] };
            } catch (error) {
                return { content: [{ type: 'text', text: JSON.stringify({ error: `Lookup failed: ${error.message}` }, null, 2) }] };
            }
        }
    });

    // =========================================================================
    //  Tool 3: get_implementation_guide
    // =========================================================================

    safeRegisterTool({
        name: 'get_implementation_guide',
        description: "Get practical implementation guidance for an AIDEFEND defense: step-by-step strategies with optional code examples, plus recommended open-source and commercial tools. Accepts technique ID (e.g. AID-H-001) or sub-technique ID (e.g. AID-H-001.002). Use mode='full' for detailed code examples.",
        annotations: {
            readOnlyHint: true,
            idempotentHint: true
        },
        inputSchema: {
            type: 'object',
            properties: {
                id: {
                    type: 'string',
                    description: 'Technique or sub-technique ID',
                    pattern: '^AID-[A-Z]{1,2}-\\d{3}(\\.\\d{3})?$'
                },
                mode: {
                    type: 'string',
                    description: "Output detail level. 'summary' returns strategy text only (shorter, fewer tokens). 'full' includes howTo details with code examples (longer but more actionable).",
                    enum: ['summary', 'full'],
                    default: 'summary'
                }
            },
            required: ['id']
        },
        execute: async (args) => {
            try {
                const queryId = (args.id || '').trim().toUpperCase();
                const mode = args.mode || 'summary';

                // Search in sub-techniques first
                const sub = allSubTechniques.find(s => s.id.toUpperCase() === queryId);
                if (sub) {
                    const strategies = (sub.implementationStrategies || []).map(s => {
                        const entry = { strategy: s.strategy };
                        if (mode === 'full' && s.howTo) {
                            entry.details = stripHtml(s.howTo);
                        }
                        return entry;
                    });

                    const result = {
                        id: sub.id,
                        name: sub.name,
                        tactic: sub.tacticName,
                        pillar: sub.pillar || [],
                        phase: sub.phase || [],
                        strategies,
                        toolsOpenSource: sub.toolsOpenSource || [],
                        toolsCommercial: sub.toolsCommercial || []
                    };
                    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                }

                // Search in techniques (leaf techniques may have implementationStrategies)
                const tech = allTechniques.find(t => t.id.toUpperCase() === queryId);
                if (tech) {
                    // If the technique has subTechniques but no implementationStrategies itself,
                    // guide the user to query individual sub-techniques
                    if (!tech.isLeaf && !(tech.implementationStrategies && tech.implementationStrategies.length > 0)) {
                        const subList = (tech.subTechniques || []).map(s => ({ id: s.id, name: s.name }));
                        return { content: [{ type: 'text', text: JSON.stringify({
                            id: tech.id,
                            name: tech.name,
                            tactic: tech.tacticName,
                            message: `This technique has ${subList.length} sub-techniques. Implementation guidance is available at the sub-technique level. Query each sub-technique ID for specific implementation strategies.`,
                            subTechniques: subList
                        }, null, 2) }] };
                    }

                    // Leaf technique or technique with its own implementationStrategies
                    const strategies = (tech.implementationStrategies || []).map(s => {
                        const entry = { strategy: s.strategy };
                        if (mode === 'full' && s.howTo) {
                            entry.details = stripHtml(s.howTo);
                        }
                        return entry;
                    });

                    const result = {
                        id: tech.id,
                        name: tech.name,
                        tactic: tech.tacticName,
                        pillar: tech.pillar || [],
                        phase: tech.phase || [],
                        strategies,
                        toolsOpenSource: tech.toolsOpenSource || [],
                        toolsCommercial: tech.toolsCommercial || []
                    };
                    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                }

                // Not found
                return { content: [{ type: 'text', text: JSON.stringify({
                    error: `Technique "${args.id}" not found. Use search_techniques to find the correct ID. AIDEFEND IDs follow the pattern AID-{Letter}-{Number} or AID-{Letter}-{Number}.{SubNumber}.`
                }, null, 2) }] };
            } catch (error) {
                return { content: [{ type: 'text', text: JSON.stringify({ error: `Implementation guide lookup failed: ${error.message}` }, null, 2) }] };
            }
        }
    });

    // =========================================================================
    //  Tool 4: find_defenses_by_threat
    // =========================================================================

    safeRegisterTool({
        name: 'find_defenses_by_threat',
        description: "Find AIDEFEND defenses for a specific threat. Accepts threat IDs from any framework (e.g. 'AML.T0051', 'LLM01', 'LLM01:2025') or keywords (e.g. 'prompt injection', 'supply chain'). Uses smart matching: exact IDs matched first, then prefix/family, then keyword search. Note: framework content is in English. Translate non-English threat keywords to English before calling this tool.",
        annotations: {
            readOnlyHint: true,
            idempotentHint: true
        },
        inputSchema: {
            type: 'object',
            properties: {
                threat: {
                    type: 'string',
                    description: "Threat ID or keyword in English. Examples: 'AML.T0051', 'LLM01', 'prompt injection', 'supply chain', 'model poisoning'. IMPORTANT: The framework content is in English. Translate any non-English queries into English before calling this tool.",
                    minLength: 2,
                    maxLength: 200
                },
                maxResults: {
                    type: 'integer',
                    description: 'Maximum results per category. Default: 15, max: 30',
                    default: 15,
                    minimum: 1,
                    maximum: 30
                }
            },
            required: ['threat']
        },
        execute: async (args) => {
            try {
                const threat = args.threat || '';
                const maxResults = Math.min(Math.max(args.maxResults || 15, 1), 30);

                // Collect matching techniques (deduplicated by id + framework)
                const techHits = [];
                const techSeen = new Set();
                for (const tech of allTechniques) {
                    const result = matchThreat(tech.defendsAgainst, threat);
                    if (result.matched) {
                        // Group matches by framework for this technique
                        const byFramework = {};
                        for (const m of result.matches) {
                            if (!byFramework[m.framework]) byFramework[m.framework] = [];
                            byFramework[m.framework].push(m.item);
                        }
                        for (const [framework, items] of Object.entries(byFramework)) {
                            const key = `${tech.id}|${framework}`;
                            if (!techSeen.has(key)) {
                                techSeen.add(key);
                                techHits.push({
                                    id: tech.id,
                                    name: tech.name,
                                    tactic: tech.tacticName,
                                    matchedFramework: framework,
                                    matchedItems: items,
                                    _tier: result.tier
                                });
                            }
                        }
                    }
                }

                // Collect matching sub-techniques (deduplicated)
                const subHits = [];
                const subSeen = new Set();
                for (const sub of allSubTechniques) {
                    const result = matchThreat(sub.defendsAgainst, threat);
                    if (result.matched) {
                        const byFramework = {};
                        for (const m of result.matches) {
                            if (!byFramework[m.framework]) byFramework[m.framework] = [];
                            byFramework[m.framework].push(m.item);
                        }
                        for (const [framework, items] of Object.entries(byFramework)) {
                            const key = `${sub.id}|${framework}`;
                            if (!subSeen.has(key)) {
                                subSeen.add(key);
                                subHits.push({
                                    id: sub.id,
                                    name: sub.name,
                                    parentTechniqueId: sub.techniqueId,
                                    tactic: sub.tacticName,
                                    matchedFramework: framework,
                                    matchedItems: items,
                                    _tier: result.tier
                                });
                            }
                        }
                    }
                }

                // Determine overall match tier for label
                const allTiers = [...techHits, ...subHits].map(h => h._tier);
                const bestTier = allTiers.length > 0 ? Math.min(...allTiers) : null;
                const tierLabel = bestTier === 1 ? 'exact_id' : bestTier === 2 ? 'prefix_family' : bestTier === 3 ? 'keyword' : 'none';

                // Strip internal _tier before returning
                const techOutput = techHits.slice(0, maxResults).map(({ _tier, ...rest }) => rest);
                const subOutput = subHits.slice(0, maxResults).map(({ _tier, ...rest }) => rest);

                const totalMatches = techHits.length + subHits.length;

                const response = {
                    query: threat,
                    matchTier: tierLabel,
                    techniques: techOutput,
                    subTechniques: subOutput,
                    totalMatches,
                    truncated: techHits.length > maxResults || subHits.length > maxResults
                };

                return { content: [{ type: 'text', text: JSON.stringify(response, null, 2) }] };
            } catch (error) {
                return { content: [{ type: 'text', text: JSON.stringify({ error: `Threat lookup failed: ${error.message}. Try a different threat ID or keyword.` }, null, 2) }] };
            }
        }
    });

    // =========================================================================
    //  Tool 5: get_framework_stats
    // =========================================================================

    safeRegisterTool({
        name: 'get_framework_stats',
        description: "Summary statistics of the AIDEFEND framework: total tactics, techniques, sub-techniques, breakdown per tactic, defense counts mapped to each external security framework, distribution across technology pillars and AI lifecycle phases, and tool counts. Useful for presentations, proposals, executive briefings, and understanding the framework's scope.",
        annotations: {
            readOnlyHint: true,
            idempotentHint: true
        },
        inputSchema: {
            type: 'object',
            properties: {},
            required: []
        },
        execute: async () => {
            try {
                const tactics = (aidefendData.tactics || []);
                const tacticNames = tactics.map(t => t.name);

                // Per-tactic breakdown
                const tacticsBreakdown = tactics.map(tactic => {
                    const techniques = tactic.techniques || [];
                    const subCount = techniques.reduce((sum, t) => sum + (t.subTechniques || []).length, 0);
                    return {
                        tactic: tactic.name,
                        techniqueCount: techniques.length,
                        subTechniqueCount: subCount
                    };
                });

                const totalTechniques = allTechniques.length;
                const totalSubTechniques = allSubTechniques.length;

                // Mapped defense count by framework
                // Count unique technique/sub-technique IDs that have at least one non-N/A mapping to each framework
                const mappedDefenseCountByFramework = {};
                for (const fk of FRAMEWORK_KEYS) {
                    const ids = new Set();
                    for (const tech of allTechniques) {
                        for (const mapping of (tech.defendsAgainst || [])) {
                            if (mapping.framework === fk && (mapping.items || []).some(isValidItem)) {
                                ids.add(tech.id);
                            }
                        }
                    }
                    for (const sub of allSubTechniques) {
                        for (const mapping of (sub.defendsAgainst || [])) {
                            if (mapping.framework === fk && (mapping.items || []).some(isValidItem)) {
                                ids.add(sub.id);
                            }
                        }
                    }
                    mappedDefenseCountByFramework[fk] = ids.size;
                }

                // Pillar distribution: count leaf nodes per pillar
                const pillarDistribution = { data: 0, model: 0, infra: 0, app: 0 };
                for (const leaf of allLeafNodes) {
                    for (const p of (leaf.pillar || [])) {
                        if (!pillarDistribution.hasOwnProperty(p)) {
                            pillarDistribution[p] = 0;
                        }
                        pillarDistribution[p]++;
                    }
                }

                // Phase distribution: count leaf nodes per phase
                const phaseDistribution = { scoping: 0, building: 0, validation: 0, operation: 0, response: 0, improvement: 0 };
                for (const leaf of allLeafNodes) {
                    for (const ph of (leaf.phase || [])) {
                        if (!phaseDistribution.hasOwnProperty(ph)) {
                            phaseDistribution[ph] = 0;
                        }
                        phaseDistribution[ph]++;
                    }
                }

                // Unique tool counts
                const openSourceTools = new Set();
                const commercialTools = new Set();
                for (const leaf of allLeafNodes) {
                    for (const t of (leaf.toolsOpenSource || [])) openSourceTools.add(t);
                    for (const t of (leaf.toolsCommercial || [])) commercialTools.add(t);
                }

                const result = {
                    frameworkVersion: 'AIDEFEND v1.0',
                    totalTactics: tacticNames.length,
                    tactics: tacticNames,
                    totalTechniques,
                    totalSubTechniques,
                    tacticsBreakdown,
                    mappedDefenseCountByFramework,
                    pillarDistribution,
                    phaseDistribution,
                    totalUniqueOpenSourceTools: openSourceTools.size,
                    totalUniqueCommercialTools: commercialTools.size
                };

                return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
            } catch (error) {
                return { content: [{ type: 'text', text: JSON.stringify({ error: `Stats generation failed: ${error.message}` }, null, 2) }] };
            }
        }
    });

    // =========================================================================
    //  Registration Complete
    // =========================================================================

    console.log(`[AIDEFEND WebMCP] registered: ${registeredCount}, skipped: ${skippedCount}`);
}
