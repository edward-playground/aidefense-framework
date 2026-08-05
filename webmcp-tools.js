/**
 * AIDEFEND WebMCP Tools — Public Framework Knowledge API
 * 
 * Registers browser-accessible tools via the emerging WebMCP API
 * (W3C Web Machine Learning Community Group draft), enabling AI agents
 * to query the AIDEFEND AI security defense framework.
 * 
 * PUBLIC FRAMEWORK — These tools expose read-only access to the
 * AIDEFEND openly licensed AI security defense knowledge base.
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
 * @version 1.4.0
 */

import { frameworkMigrations } from './framework-migrations.js';
import { buildThreatQueryPlan, mergeThreatHits } from './webmcp-query.js';

// The page loads an integrity-pinned, self-contained WebMCP runtime before
// importing this module. Native implementations can satisfy the same guard.
if (!document.modelContext || typeof document.modelContext.registerTool !== 'function') {
    console.warn('[AIDEFEND WebMCP] document.modelContext not available. WebMCP tools will not be registered.');
} else {
    // Only dynamically import data and register tools after the guard passes
    const { aidefendData } = await import('./main.js');
    const { aidefendVersion } = await import('./aidefend-intro.js');

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

    function cleanScopeBoundary(scopeBoundary) {
        if (!scopeBoundary || typeof scopeBoundary.responsibility !== 'string') {
            return null;
        }
        return {
            responsibility: scopeBoundary.responsibility.trim(),
            relatedTechniques: (Array.isArray(scopeBoundary.relatedTechniques)
                ? scopeBoundary.relatedTechniques
                : []
            ).map(related => ({
                id: related.id,
                comparison: related.comparison
            }))
        };
    }

    function scopeBoundarySearchText(scopeBoundary) {
        const boundary = cleanScopeBoundary(scopeBoundary);
        if (!boundary) return '';
        return [
            boundary.responsibility,
            ...boundary.relatedTechniques.flatMap(related => [related.id, related.comparison])
        ].join(' ');
    }

    /**
     * Heuristic: does this query look like a threat ID?
     * Matches patterns like: AML.T0051, LLM01, LLM01:2026, MAES-03, NIST.AML.018
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
     *           e.g., "LLM01" matches "LLM01:2026 Prompt Injection"
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

    function collectThreatHits(entities, threat, classify) {
        const hits = [];
        const seen = new Set();
        for (const entity of entities) {
            const result = matchThreat(entity.defendsAgainst, threat);
            if (!result.matched) continue;
            const byFramework = {};
            for (const match of result.matches) {
                if (!byFramework[match.framework]) byFramework[match.framework] = [];
                byFramework[match.framework].push(match.item);
            }
            for (const [framework, items] of Object.entries(byFramework)) {
                const key = `${entity.id}|${framework}`;
                if (seen.has(key)) continue;
                seen.add(key);
                hits.push({
                    id: entity.id,
                    name: entity.name,
                    tactic: entity.tacticName,
                    ...classify(entity),
                    matchedFramework: framework,
                    matchedItems: items,
                    _tier: result.tier
                });
            }
        }
        return hits;
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

    function canonicalToolName(value) {
        return String(value || '')
            .trim()
            .replace(/\s+\([^)]*\)\s*$/, '')
            .trim();
    }

    // =========================================================================
    //  Build Indexes (once at module load time)
    // =========================================================================

    const FRAMEWORK_KEYS = [
        'MITRE ATLAS',
        'MAESTRO',
        frameworkMigrations.frameworks.owasp_llm.activeLabel,
        'OWASP ML Top 10 2023',
        'OWASP Top 10 for Agentic Applications 2026',
        'NIST Adversarial Machine Learning 2025',
        'Cisco Integrated AI Security and Safety Framework',
        'Google Secure AI Framework 2.0 - Risks',
        'Databricks AI Security Framework 3.0'
    ];

    /** Flat array of all techniques, enriched with tacticName, _searchText, isLeaf */
    const allTechniques = (aidefendData.tactics || []).flatMap(tactic =>
        (tactic.techniques || []).map(tech => ({
            ...tech,
            tacticName: tactic.name,
            _searchText: normalizeForSearch(
                (tech.name || '') + ' ' + (tech.description || '') + ' ' +
                scopeBoundarySearchText(tech.scopeBoundary)
            ),
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
                _searchText: normalizeForSearch(
                    (sub.name || '') + ' ' + (sub.description || '') + ' ' +
                    scopeBoundarySearchText(sub.scopeBoundary)
                )
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

    const parentFamilies = allTechniques.filter(technique => !technique.isLeaf);
    const standaloneTechniques = allTechniques.filter(technique => technique.isLeaf);
    const allTaxonomyEntities = [...allTechniques, ...allSubTechniques];
    const taxonomyRowCount = allTechniques.length + allSubTechniques.length;
    const actionableControlCount = allLeafNodes.length;

    function resolveAidefendId(rawId) {
        return { queryId: String(rawId || '').trim().toUpperCase() };
    }

    // =========================================================================
    //  safeRegisterTool Wrapper
    // =========================================================================

    let registeredCount = 0;
    let skippedCount = 0;

    async function safeRegisterTool(toolDef) {
        try {
            await document.modelContext.registerTool(toolDef);
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

    await safeRegisterTool({
        name: 'search_techniques',
        description: `Search the AIDEFEND AI security defense framework by keyword. Searches ${taxonomyRowCount} taxonomy entities: ${parentFamilies.length} non-actionable parent families plus ${actionableControlCount} actionable standalone/sub-technique controls across 7 tactics. Results identify whether an entity is a parent family or an actionable control. Framework content is in English; translate non-English queries before calling this tool.`,
        annotations: {
            readOnlyHint: true
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
                    entityType: t.isLeaf ? 'standaloneTechnique' : 'parentFamily',
                    isActionable: t.isLeaf,
                    subTechniqueCount: (t.subTechniques || []).length
                }));

                // Search sub-techniques
                const subMatches = allSubTechniques.filter(s => s._searchText.includes(query));
                const subResults = subMatches.slice(0, maxResults).map(s => ({
                    id: s.id,
                    name: s.name,
                    parentTechniqueId: s.techniqueId,
                    parentTechniqueName: s.techniqueName,
                    tactic: s.tacticName,
                    entityType: 'subTechnique',
                    isActionable: true
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

    await safeRegisterTool({
        name: 'get_technique_detail',
        description: "Get full details of an AIDEFEND technique or sub-technique by its ID. Returns description, optional structured scope boundary, threat mappings across 9 security frameworks (MITRE ATLAS, MAESTRO, the OWASP Top 10 frameworks for LLM, ML, and Agentic Applications, NIST AML, Cisco, Google SAIF 2.0, and Databricks DASF 3.0), pillar/phase classification, and sub-technique list.",
        annotations: {
            readOnlyHint: true
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
                const resolved = resolveAidefendId(args.id);
                const { queryId } = resolved;

                // Search in techniques first
                const tech = allTechniques.find(t => t.id.toUpperCase() === queryId);
                if (tech) {
                    if (tech.isLeaf) {
                        // Leaf technique (no subTechniques) — include pillar, phase
                        const result = {
                            id: tech.id,
                            name: tech.name,
                            entityType: 'standaloneTechnique',
                            isActionable: true,
                            isLeaf: true,
                            tactic: tech.tacticName,
                            description: stripHtml(tech.description),
                            ...(tech.scopeBoundary ? {
                                scopeBoundary: cleanScopeBoundary(tech.scopeBoundary)
                            } : {}),
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
                            entityType: 'parentFamily',
                            isActionable: false,
                            isLeaf: false,
                            mappingSemantics: 'derivedChildUnionForNavigation',
                            tactic: tech.tacticName,
                            description: stripHtml(tech.description),
                            ...(tech.scopeBoundary ? {
                                scopeBoundary: cleanScopeBoundary(tech.scopeBoundary)
                            } : {}),
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
                        isActionable: true,
                        parentTechniqueId: sub.techniqueId,
                        parentTechniqueName: sub.techniqueName,
                        tactic: sub.tacticName,
                        pillar: sub.pillar || [],
                        phase: sub.phase || [],
                        description: stripHtml(sub.description),
                        ...(sub.scopeBoundary ? {
                            scopeBoundary: cleanScopeBoundary(sub.scopeBoundary)
                        } : {}),
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

    await safeRegisterTool({
        name: 'get_implementation_guide',
        description: "Get practical implementation guidance for an AIDEFEND defense: step-by-step strategies with optional code examples, plus recommended OSI open-source, source-available/open-weight, and commercial/hosted tools. Accepts technique ID (e.g. AID-H-001) or sub-technique ID (e.g. AID-H-001.002). Use mode='full' for detailed code examples.",
        annotations: {
            readOnlyHint: true
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
                const resolved = resolveAidefendId(args.id);
                const { queryId } = resolved;
                const mode = args.mode || 'summary';

                // Search in sub-techniques first
                const sub = allSubTechniques.find(s => s.id.toUpperCase() === queryId);
                if (sub) {
                    const strategies = (sub.implementationGuidance || []).map(s => {
                        const entry = { id: s.id, implementation: s.implementation };
                        if (mode === 'full' && s.howTo) {
                            entry.details = stripHtml(s.howTo);
                        }
                        return entry;
                    });

                    const result = {
                        id: sub.id,
                        name: sub.name,
                        entityType: 'subTechnique',
                        isActionable: true,
                        tactic: sub.tacticName,
                        pillar: sub.pillar || [],
                        phase: sub.phase || [],
                        strategies,
                        toolsOpenSource: sub.toolsOpenSource || [],
                        toolsSourceAvailable: sub.toolsSourceAvailable || [],
                        toolsCommercial: sub.toolsCommercial || []
                    };
                    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                }

                // Search in techniques (leaf techniques may have implementationGuidance)
                const tech = allTechniques.find(t => t.id.toUpperCase() === queryId);
                if (tech) {
                    // If the technique has subTechniques but no implementationGuidance itself,
                    // guide the user to query individual sub-techniques
                    if (!tech.isLeaf && !(tech.implementationGuidance && tech.implementationGuidance.length > 0)) {
                        const subList = (tech.subTechniques || []).map(s => ({ id: s.id, name: s.name }));
                        const result = {
                            id: tech.id,
                            name: tech.name,
                            tactic: tech.tacticName,
                            entityType: 'parentFamily',
                            isActionable: false,
                            message: `This technique has ${subList.length} sub-techniques. Implementation guidance is available at the sub-technique level. Query each sub-technique ID for specific implementation guidance.`,
                            subTechniques: subList
                        };
                        return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
                    }

                    // Leaf technique or technique with its own implementationGuidance
                    const strategies = (tech.implementationGuidance || []).map(s => {
                        const entry = { id: s.id, implementation: s.implementation };
                        if (mode === 'full' && s.howTo) {
                            entry.details = stripHtml(s.howTo);
                        }
                        return entry;
                    });

                    const result = {
                        id: tech.id,
                        name: tech.name,
                        entityType: 'standaloneTechnique',
                        isActionable: true,
                        tactic: tech.tacticName,
                        pillar: tech.pillar || [],
                        phase: tech.phase || [],
                        strategies,
                        toolsOpenSource: tech.toolsOpenSource || [],
                        toolsSourceAvailable: tech.toolsSourceAvailable || [],
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

    await safeRegisterTool({
        name: 'find_defenses_by_threat',
        description: "Find AIDEFEND mappings for a specific threat. Returns actionable standalone/sub-technique controls separately from non-actionable parent-family context, so a family is never presented as an implementable control. Parent-family mappings are a derived union of reviewed child mappings for navigation, not independent control claims. Accepts exact or prefix framework IDs and English mapping-name keywords; exact IDs are preferred. OWASP LLM references default to the current edition, and explicit 2025 IDs or legacy names are migrated by risk concept rather than by rank. Malformed explicit editions and queries containing multiple OWASP LLM concepts return resolution metadata instead of being guessed. A mapping expresses a reviewed defensive relationship, not certification that a control is deployed or effective in the caller's environment.",
        annotations: {
            readOnlyHint: true
        },
        inputSchema: {
            type: 'object',
            properties: {
                threat: {
                    type: 'string',
                    description: "Threat ID or keyword in English. Examples: 'AML.T0051', 'LLM01', 'LLM03:2025 Supply Chain', 'prompt injection', 'supply chain', 'model poisoning'. OWASP LLM 2025 references are accepted and resolved to their 2026 semantic successor. IMPORTANT: The framework content is in English. Translate any non-English queries into English before calling this tool.",
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

                const queryPlan = buildThreatQueryPlan(threat);
                const { resolution, canonicalThreat } = queryPlan;

                const classifyParent = () => ({ entityType: 'parentFamily', isActionable: false });
                const classifyActionable = entity => ({
                    entityType: entity.id === entity.techniqueId ? 'standaloneTechnique' : 'subTechnique',
                    isActionable: true,
                    ...(entity.id === entity.techniqueId ? {} : {
                        parentTechniqueId: entity.techniqueId,
                        parentTechniqueName: entity.techniqueName
                    })
                });

                const parentFamilyHits = mergeThreatHits(
                    ...queryPlan.queries.map(query => collectThreatHits(parentFamilies, query, classifyParent))
                );
                const actionableControlHits = mergeThreatHits(
                    ...queryPlan.queries.map(query => collectThreatHits(allLeafNodes, query, classifyActionable))
                );

                // Determine overall match tier for label
                const allTiers = [...actionableControlHits, ...parentFamilyHits].map(hit => hit._tier);
                const bestTier = allTiers.length > 0 ? Math.min(...allTiers) : null;
                const tierLabel = bestTier === 1 ? 'exact_id' : bestTier === 2 ? 'prefix_family' : bestTier === 3 ? 'keyword' : 'none';

                // Strip internal _tier before returning
                const actionableOutput = actionableControlHits.slice(0, maxResults).map(({ _tier, ...rest }) => rest);
                const familyOutput = parentFamilyHits.slice(0, maxResults).map(({ _tier, ...rest }) => rest);

                const totalMatches = actionableControlHits.length + parentFamilyHits.length;

                const response = {
                    query: threat,
                    ...(resolution ? {
                        ...(canonicalThreat ? { resolvedQuery: canonicalThreat } : {}),
                        resolution
                    } : {}),
                    matchTier: tierLabel,
                    actionableControls: actionableOutput,
                    parentFamilies: familyOutput,
                    parentFamilyMappingSemantics: 'derivedChildUnionForNavigation',
                    totalMatches,
                    actionableMatchCount: actionableControlHits.length,
                    parentFamilyMatchCount: parentFamilyHits.length,
                    truncated: actionableControlHits.length > maxResults || parentFamilyHits.length > maxResults
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

    await safeRegisterTool({
        name: 'get_framework_stats',
        description: "Population-explicit AIDEFEND statistics: taxonomy rows, top-level techniques, non-actionable parent families, standalone techniques, sub-techniques, actionable controls, mapping coverage for both all entities and actionable controls, leaf-only pillar/phase distributions, and canonical distinct-tool counts.",
        annotations: {
            readOnlyHint: true
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
                    const parentCount = techniques.filter(t => (t.subTechniques || []).length > 0).length;
                    const standaloneCount = techniques.length - parentCount;
                    return {
                        tactic: tactic.name,
                        topLevelTechniqueCount: techniques.length,
                        parentFamilyCount: parentCount,
                        standaloneTechniqueCount: standaloneCount,
                        subTechniqueCount: subCount,
                        taxonomyRowCount: techniques.length + subCount,
                        actionableControlCount: standaloneCount + subCount
                    };
                });

                const mappedEntityCountByFramework = {};
                const mappedActionableControlCountByFramework = {};
                for (const fk of FRAMEWORK_KEYS) {
                    const mappedEntities = new Set();
                    const mappedActionable = new Set();
                    for (const entity of allTaxonomyEntities) {
                        for (const mapping of (entity.defendsAgainst || [])) {
                            if (mapping.framework === fk && (mapping.items || []).some(isValidItem)) {
                                mappedEntities.add(entity.id);
                            }
                        }
                    }
                    for (const control of allLeafNodes) {
                        for (const mapping of (control.defendsAgainst || [])) {
                            if (mapping.framework === fk && (mapping.items || []).some(isValidItem)) {
                                mappedActionable.add(control.id);
                            }
                        }
                    }
                    mappedEntityCountByFramework[fk] = mappedEntities.size;
                    mappedActionableControlCountByFramework[fk] = mappedActionable.size;
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
                const sourceAvailableTools = new Set();
                const commercialTools = new Set();
                for (const leaf of allLeafNodes) {
                    for (const t of (leaf.toolsOpenSource || [])) openSourceTools.add(canonicalToolName(t));
                    for (const t of (leaf.toolsSourceAvailable || [])) sourceAvailableTools.add(canonicalToolName(t));
                    for (const t of (leaf.toolsCommercial || [])) commercialTools.add(canonicalToolName(t));
                }

                const result = {
                    frameworkVersion: `AIDEFEND v${aidefendVersion}`,
                    totalTactics: tacticNames.length,
                    tactics: tacticNames,
                    totalTaxonomyRows: taxonomyRowCount,
                    totalTopLevelTechniques: allTechniques.length,
                    totalParentFamilies: parentFamilies.length,
                    totalStandaloneTechniques: standaloneTechniques.length,
                    totalSubTechniques: allSubTechniques.length,
                    totalActionableControls: actionableControlCount,
                    tacticsBreakdown,
                    mappedEntityCountByFramework,
                    mappedActionableControlCountByFramework,
                    parentFamilyMappingSemantics: 'derivedChildUnionForNavigation; never independently scored',
                    pillarDistribution: { population: 'actionableControls', counts: pillarDistribution },
                    phaseDistribution: { population: 'actionableControls', counts: phaseDistribution },
                    toolCountPopulation: 'actionableControls; canonical product/project name before any role or license annotation',
                    totalUniqueOpenSourceTools: openSourceTools.size,
                    totalUniqueSourceAvailableTools: sourceAvailableTools.size,
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
