/**
 * Public framework edition and semantic migration registry.
 *
 * Identifier migration never carries an AIDEFEND mapping forward. Each active
 * mapping is reviewed against the target edition's actual risk definition.
 */
export const frameworkMigrations = {
    schemaVersion: "1.0",
    registryVersion: "2026-08-05",
    contract: "AIDEFEND framework edition and semantic migration registry",
    frameworks: {
        owasp_llm: {
            stableKey: "owasp_llm",
            activeEdition: "2026",
            activeLabel: "OWASP LLM Top 10 2026",
            officialTitle: "OWASP Top 10 for LLM Applications 2026",
            sourceUrl: "https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/",
            sourceArtifact: {
                release: "v1.0",
                downloadUrl: "https://genai.owasp.org/download/56791/",
                fileName: "OWASP-GenAI-LLM-Top-10-2026-v1.0.pdf",
                mediaType: "application/pdf",
                bytes: 2402520,
                pageCount: 122,
                sha256: "EF87993A4E50AE9D83B41FF7A3D3E6320A82DFA8D4EC6BF98D0CE264B2E6108E",
                publicationDate: null,
                publicationDateStatus: "not set in the v1.0 PDF"
            },
            sourceLicense: {
                spdxExpression: "CC-BY-SA-4.0",
                licenseUrl: "https://creativecommons.org/licenses/by-sa/4.0/legalcode",
                attribution: "OWASP Top 10 for LLM Applications 2026, OWASP Foundation / OWASP GenAI Security Project",
                scope: "OWASP-derived identifiers, names, edition metadata, and normalized risk summaries",
                changesMade: "Risk summaries are paraphrased and normalized for the AIDEFEND catalog; presentation is reformatted; AIDEFEND mapping decisions, migration analysis, and resolver behavior are independently authored."
            },
            editions: {
                "2025": {
                    label: "OWASP LLM Top 10 2025",
                    status: "superseded",
                    successorEdition: "2026"
                },
                "2026": {
                    label: "OWASP LLM Top 10 2026",
                    status: "current",
                    artifactRelease: "v1.0"
                }
            },
            resolutionPolicy: {
                omittedEdition: "resolve against the current edition",
                latestEdition: "resolve against the current edition",
                explicitCurrentId: "return the current canonical item",
                explicitSupersededId: "resolve by the declared semantic successor, never by same-rank number",
                legacyName: "resolve by the named risk concept and return its current successor",
                bareId: "treat the rank as belonging to the current edition",
                nonPaddedRank: "normalize LLM1 through LLM9 to the canonical two-digit rank before resolution",
                editionContext: "treat an edition in a recognized OWASP LLM label, or an adjacent OWASP year context, as explicit for an otherwise bare LLM rank",
                malformedOrUnsupportedEdition: "return structured invalid metadata; never reinterpret it as a current bare rank",
                multipleConcepts: "return structured ambiguity with current canonical candidates; never choose by catalog order",
                unversionedIdNameConflict: "a recognized current or legacy risk name identifies the concept; return the current successor and report normalization",
                versionedIdNameConflict: "a recognized risk name identifies the concept even when a versioned rank conflicts; return the named concept's current successor and report normalization",
                mappingCarryForward: "never automatic; AIDEFEND mappings require target-edition semantic review"
            },
            responseContract: {
                canonicalEdition: "2026",
                canonicalIdFormat: "LLMdd:2026",
                metadataField: "resolution",
                metadataValues: ["canonical", "migrated", "normalized", "fallback_latest", "ambiguous", "invalid"]
            },
            activeItems: [
                {
                    id: "LLM01:2026",
                    rank: 1,
                    name: "Prompt Injection",
                    description: "Untrusted or unintended content in any modality or context source changes model behavior, including content delivered through retrieval, tool output, persistent memory, images, audio, or video."
                },
                {
                    id: "LLM02:2026",
                    rank: 2,
                    name: "Sensitive Information Disclosure",
                    description: "Confidential, regulated, privileged, or proprietary data is exposed through answers, tool arguments, reasoning traces, retrieved chunks, logs, embeddings, multimodal output, or inference side channels."
                },
                {
                    id: "LLM03:2026",
                    rank: 3,
                    name: "Excessive Agency",
                    description: "Unexpected or manipulated model output causes damaging action because an application grants excessive tool functionality, permissions, or autonomy."
                },
                {
                    id: "LLM04:2026",
                    rank: 4,
                    name: "Supply Chain",
                    description: "Compromise, substitution, vulnerability, or ungoverned trust in third-party data, models, adapters, packages, transformation pipelines, deployment platforms, or on-device artifacts undermines the LLM application."
                },
                {
                    id: "LLM05:2026",
                    rank: 5,
                    name: "Data and Model Poisoning",
                    description: "Manipulated data or model artifacts create durable harmful behavior, bias, backdoors, or exploitable weaknesses during training, fine-tuning, retrieval, feedback, persistent memory, or model transformation."
                },
                {
                    id: "LLM06:2026",
                    rank: 6,
                    name: "Unbounded Consumption",
                    description: "Missing resource controls permit excessive inference, token, reasoning, multimodal, session, queue, tool, or infrastructure consumption that harms availability, creates unsustainable cost, or enables model cloning."
                },
                {
                    id: "LLM07:2026",
                    rank: 7,
                    name: "Misinformation",
                    description: "Incorrect, incomplete, unsupported, or misleading model output appears credible enough to drive a harmful human decision, workflow, or agent action."
                },
                {
                    id: "LLM08:2026",
                    rank: 8,
                    name: "Hidden Context Exposure",
                    description: "Hidden instructions or operational context are extracted, inferred, or reconstructed in a way that reveals secrets, policy logic, tool schemas, trust boundaries, or other details that materially increase attacker capability."
                },
                {
                    id: "LLM09:2026",
                    rank: 9,
                    name: "Vector and Embedding Weaknesses",
                    description: "Embedding geometry or similarity-search mechanics enable cross-tenant inference, inversion, retrieval poisoning or jamming, membership inference, semantic-cache poisoning, or multimodal retrieval manipulation."
                },
                {
                    id: "LLM10:2026",
                    rank: 10,
                    name: "Improper Output Handling",
                    description: "Model output is insufficiently validated, sanitized, encoded, or constrained before a downstream component interprets, renders, executes, stores, or transmits it."
                }
            ],
            migrations: [
                {
                    from: { edition: "2025", id: "LLM01:2025", name: "Prompt Injection" },
                    to: { edition: "2026", id: "LLM01:2026", name: "Prompt Injection" },
                    relation: "same-risk-expanded",
                    changeTypes: ["scope-expanded"],
                    note: "The 2026 risk explicitly adds cross-modal delivery, tool output, persistent memory, cross-session propagation, and trusted-backend surfaces.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM02:2025", name: "Sensitive Information Disclosure" },
                    to: { edition: "2026", id: "LLM02:2026", name: "Sensitive Information Disclosure" },
                    relation: "same-risk-expanded",
                    changeTypes: ["scope-expanded"],
                    note: "The 2026 risk explicitly includes tool arguments, reasoning traces, embeddings, telemetry, derived artifacts, and observable inference side channels.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM03:2025", name: "Supply Chain" },
                    to: { edition: "2026", id: "LLM04:2026", name: "Supply Chain" },
                    relation: "same-risk-expanded-and-re-ranked",
                    changeTypes: ["rank-changed", "scope-expanded"],
                    note: "The risk moved from rank 3 to rank 4 and now explicitly treats promoted artifacts, adapters, conversion, merge, quantization, and on-device delivery as first-class supply-chain surfaces.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM04:2025", name: "Data and Model Poisoning" },
                    to: { edition: "2026", id: "LLM05:2026", name: "Data and Model Poisoning" },
                    relation: "same-risk-expanded-and-re-ranked",
                    changeTypes: ["rank-changed", "scope-expanded"],
                    note: "The risk moved from rank 4 to rank 5 and more explicitly covers fine-tuning subversion, feedback loops, persistent memory, and inference artifacts.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM05:2025", name: "Improper Output Handling" },
                    to: { edition: "2026", id: "LLM10:2026", name: "Improper Output Handling" },
                    relation: "same-risk-expanded-and-re-ranked",
                    changeTypes: ["rank-changed", "scope-expanded"],
                    note: "The risk moved from rank 5 to rank 10 and now explicitly includes unsafe generated code, terminal/control-character sinks, and automatic outbound rendering.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM06:2025", name: "Excessive Agency" },
                    to: { edition: "2026", id: "LLM03:2026", name: "Excessive Agency" },
                    relation: "same-risk-re-ranked",
                    changeTypes: ["rank-changed", "boundary-clarified"],
                    note: "The risk moved from rank 6 to rank 3 and clarifies excessive functionality, permissions, autonomy, user-context preservation, complete mediation, and damage-limiting controls.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM07:2025", name: "System Prompt Leakage" },
                    to: { edition: "2026", id: "LLM08:2026", name: "Hidden Context Exposure" },
                    relation: "renamed-and-rescoped-successor",
                    changeTypes: ["rank-changed", "renamed", "scope-expanded", "security-boundary-changed"],
                    note: "The successor is broader than system-prompt leakage. It covers extraction, inference, or reconstruction of model-visible hidden operational context and assumes that context is discoverable; it does not imply that every former mapping remains valid.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM08:2025", name: "Vector and Embedding Weaknesses" },
                    to: { edition: "2026", id: "LLM09:2026", name: "Vector and Embedding Weaknesses" },
                    relation: "same-risk-rescoped-and-re-ranked",
                    changeTypes: ["rank-changed", "boundary-tightened", "scope-expanded"],
                    note: "The risk moved from rank 8 to rank 9 and now requires an embedding-geometry or similarity-search mechanism, while expanding treatment of inversion, jamming, membership inference, caches, and multimodal embeddings.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM09:2025", name: "Misinformation" },
                    to: { edition: "2026", id: "LLM07:2026", name: "Misinformation" },
                    relation: "same-risk-expanded-and-re-ranked",
                    changeTypes: ["rank-changed", "scope-expanded"],
                    note: "The risk moved from rank 9 to rank 7 and emphasizes incorrect, incomplete, unsupported, or misleading output that is trusted and acted upon.",
                    mappingCarryForward: "requires-semantic-review"
                },
                {
                    from: { edition: "2025", id: "LLM10:2025", name: "Unbounded Consumption" },
                    to: { edition: "2026", id: "LLM06:2026", name: "Unbounded Consumption" },
                    relation: "same-risk-expanded-and-re-ranked",
                    changeTypes: ["rank-changed", "scope-expanded"],
                    note: "The risk moved from rank 10 to rank 6 and now explicitly includes thinking-token exhaustion, multimodal cost, agent/tool fan-out, hard spending caps, and model cloning through resource abuse.",
                    mappingCarryForward: "requires-semantic-review"
                }
            ]
        }
    }
};

function normalizeConceptName(value) {
    return String(value || "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, " ")
        .trim();
}

/**
 * Resolve current, unversioned, and superseded OWASP LLM references without
 * confusing a 2025 rank with the different risk occupying that rank in 2026.
 */
export function resolveOwaspLlmReference(rawReference) {
    const input = String(rawReference || "").trim();
    if (!input) return null;

    const catalog = frameworkMigrations.frameworks.owasp_llm;
    const currentById = new Map(catalog.activeItems.map(item => [item.id.toUpperCase(), item]));
    const migrationByOldId = new Map(catalog.migrations.map(item => [item.from.id.toUpperCase(), item]));
    const supportedEditions = Object.keys(catalog.editions);
    const idTokenPattern = /\bLLM(\d+)(?::([a-z0-9_-]+))?(?=$|[\s/(),;\[\]{}&?]|\.(?=$|\s|LLM))/ig;
    const idTokens = [...input.matchAll(idTokenPattern)];
    const llmIdLikeStarts = new Set(
        [...input.matchAll(/(?<![a-z0-9])LLM\d+/ig)].map(match => match.index)
    );
    const containsLlmIdLikeText = llmIdLikeStarts.size > 0;
    const containsRecognizedFrameworkLabel = /\bOWASP\s+(?:LLM(?:\s+TOP\s+10)?|TOP\s+10\s+FOR\s+(?:LLM|LARGE\s+LANGUAGE\s+MODEL)\s+APPLICATIONS)\b/i.test(input);
    const contextInput = input.replace(idTokenPattern, " ");
    const editionContexts = new Set();
    const editionContextPatterns = [
        /\bOWASP\s+LLM(?:\s+TOP\s+10)?\s*\(?\s*(20\d{2})(?![a-z0-9.]|\.\d)\s*\)?/ig,
        /\bOWASP\s+TOP\s+10\s+FOR\s+LLM\s+APPLICATIONS\s*\(?\s*(20\d{2})(?![a-z0-9.]|\.\d)\s*\)?/ig,
        /\bOWASP\s+TOP\s+10\s+FOR\s+LARGE\s+LANGUAGE\s+MODEL\s+APPLICATIONS\s*\(?\s*(20\d{2})(?![a-z0-9.]|\.\d)\s*\)?/ig,
        /\bOWASP\s*\(?\s*(20\d{2})(?![a-z0-9.]|\.\d)\s*\)?/ig
    ];
    for (const pattern of editionContextPatterns) {
        for (const match of contextInput.matchAll(pattern)) editionContexts.add(match[1]);
    }
    const hasOwaspSignal = containsRecognizedFrameworkLabel || containsLlmIdLikeText || editionContexts.size > 0;
    const editionTokenPattern = /(?<![a-z0-9])20\d{2}(?=$|[\s/(),;\[\]{}&?]|\.(?=$|\s|LLM))/ig;
    const editionTokens = [...contextInput.matchAll(editionTokenPattern)];
    if (hasOwaspSignal) {
        for (const match of editionTokens) editionContexts.add(match[0]);
    }

    const invalid = reason => ({
        status: "invalid",
        input,
        frameworkKey: catalog.stableKey,
        reason,
        supportedEditions,
        canonicalIdFormat: catalog.responseContract.canonicalIdFormat
    });

    if (/\bLLM\d+:(?=\s|$|[^a-z0-9_-])/i.test(input)) {
        return invalid("The OWASP LLM edition suffix is empty or malformed.");
    }
    const parsedIdStarts = new Set(idTokens.map(match => match.index));
    if ([...llmIdLikeStarts].some(start => !parsedIdStarts.has(start))) {
        return invalid("At least one OWASP LLM identifier is malformed or joined with an unsupported delimiter; use separate LLMdd, LLMdd:latest, or supported four-digit edition references.");
    }
    if (hasOwaspSignal) {
        const parsedEditionStarts = new Set(editionTokens.map(match => match.index));
        const editionLikeStarts = new Set(
            [...contextInput.matchAll(/(?<![a-z0-9])20[a-z0-9][a-z0-9._-]*/ig)].map(match => match.index)
        );
        if ([...editionLikeStarts].some(start => !parsedEditionStarts.has(start))) {
            return invalid("At least one OWASP LLM edition context is malformed or joined with an unsupported delimiter.");
        }
    }
    if (editionContexts.size > 1) {
        return invalid("The query contains conflicting OWASP LLM edition contexts.");
    }
    const contextEdition = editionContexts.values().next().value || null;
    if (contextEdition && !supportedEditions.includes(contextEdition)) {
        return invalid(`OWASP LLM edition context ${JSON.stringify(contextEdition)} is not supported.`);
    }
    const hasStandaloneLatest = /\blatest\b/i.test(contextInput);
    if (hasStandaloneLatest && contextEdition && contextEdition !== catalog.activeEdition) {
        return invalid("The latest OWASP LLM edition conflicts with a superseded surrounding edition context.");
    }

    const resolvedIdTokens = [];
    for (const match of idTokens) {
        const rankText = match[1];
        if (!/^(?:[1-9]|0[1-9]|10)$/.test(rankText)) {
            return invalid(`OWASP LLM rank ${JSON.stringify(rankText)} has malformed zero padding or width.`);
        }
        const rank = Number(rankText);
        const suffix = match[2]?.toLowerCase() || null;
        if (!Number.isInteger(rank) || rank < 1 || rank > 10) {
            return invalid(`OWASP LLM rank ${JSON.stringify(match[1])} is outside the supported Top 10 catalog.`);
        }
        if (suffix && suffix !== "latest" && !supportedEditions.includes(suffix)) {
            return invalid(`OWASP LLM edition ${JSON.stringify(match[2])} is not supported.`);
        }
        if (contextEdition && suffix === "latest" && contextEdition !== catalog.activeEdition) {
            return invalid("The latest OWASP LLM edition conflicts with a superseded surrounding edition context.");
        }
        if (contextEdition && suffix && suffix !== "latest" && suffix !== contextEdition) {
            return invalid("The explicit OWASP LLM identifier edition conflicts with the surrounding edition context.");
        }

        const bareId = `LLM${String(rank).padStart(2, "0")}`;
        const effectiveEdition = suffix === "latest"
            ? catalog.activeEdition
            : (suffix || contextEdition || null);
        const explicitId = effectiveEdition && suffix !== "latest"
            ? `${bareId}:${effectiveEdition}`.toUpperCase()
            : null;
        let current;
        let source = null;
        let tokenStatus;
        let note;

        if (!explicitId) {
            current = currentById.get(`${bareId}:${catalog.activeEdition}`.toUpperCase()) || null;
            tokenStatus = "fallback_latest";
            note = "A bare or latest OWASP LLM rank is resolved against the current edition.";
        } else if (currentById.has(explicitId)) {
            current = currentById.get(explicitId);
            tokenStatus = "canonical";
            note = "The query uses a current, versioned OWASP LLM identifier.";
        } else if (migrationByOldId.has(explicitId)) {
            const migration = migrationByOldId.get(explicitId);
            source = migration.from;
            current = currentById.get(migration.to.id.toUpperCase());
            tokenStatus = "migrated";
            note = migration.note;
        } else {
            return invalid(`OWASP LLM identifier ${explicitId} is not declared in the current or superseded catalog.`);
        }

        resolvedIdTokens.push({
            raw: match[0],
            explicitId,
            source,
            current,
            status: tokenStatus,
            note
        });
    }

    let inputName = normalizeConceptName(contextInput);
    const frameworkPhrases = new Set([
        catalog.activeLabel,
        catalog.officialTitle,
        ...Object.values(catalog.editions).map(edition => edition.label),
        "OWASP Top 10 for Large Language Model Applications",
        "OWASP Top 10 for LLM Applications",
        "OWASP LLM Top 10",
        "OWASP LLM",
        "OWASP"
    ].map(normalizeConceptName));
    for (const phrase of [...frameworkPhrases].sort((left, right) => right.length - left.length)) {
        if (!phrase) continue;
        const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        inputName = inputName.replace(new RegExp(`(?:^|\\s)${escaped}(?=\\s|$)`, "g"), " ");
    }
    inputName = normalizeConceptName(inputName)
        .replace(/(?:^|\s)20\d{2}(?=\s|$)/g, " ")
        .replace(/(?:^|\s)(?:latest|from|edition|version)(?=\s|$)/g, " ");
    inputName = normalizeConceptName(inputName);

    const conceptDefinitions = [];
    for (const item of catalog.activeItems) {
        conceptDefinitions.push({
            name: normalizeConceptName(item.name),
            current: item,
            source: null,
            kind: "current"
        });
    }
    for (const migration of catalog.migrations) {
        conceptDefinitions.push({
            name: normalizeConceptName(migration.from.name),
            current: currentById.get(migration.to.id.toUpperCase()),
            source: migration.from,
            kind: "legacy",
            note: migration.note
        });
    }

    const matchedDefinitions = [];
    const coveredCharacters = Array(inputName.length).fill(false);
    for (const definition of [...conceptDefinitions].sort((left, right) => right.name.length - left.name.length)) {
        if (!definition.name) continue;
        const escaped = definition.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const pattern = new RegExp(`(?:^|\\s)(${escaped})(?=\\s|$)`, "g");
        for (const match of inputName.matchAll(pattern)) {
            const start = match.index + match[0].length - match[1].length;
            const end = start + match[1].length;
            matchedDefinitions.push(definition);
            for (let index = start; index < end; index += 1) coveredCharacters[index] = true;
        }
    }
    const uncoveredName = normalizeConceptName(
        [...inputName].map((character, index) => coveredCharacters[index] ? " " : character).join("")
    );
    const uncoveredTokens = uncoveredName ? uncoveredName.split(/\s+/) : [];
    const conceptTextIsFullyCovered = uncoveredTokens.every(token => token === "and" || token === "or");
    const acceptedDefinitions = conceptTextIsFullyCovered ? matchedDefinitions : [];

    const currentNameTargets = new Map();
    for (const definition of acceptedDefinitions.filter(item => item.kind === "current")) {
        currentNameTargets.set(definition.current.id, {
            current: definition.current,
            source: null,
            kind: "current"
        });
    }
    const legacyNameTargets = new Map();
    const legacyNameTargetsByEdition = new Map();
    for (const definition of acceptedDefinitions.filter(item => item.kind === "legacy")) {
        const target = {
            current: definition.current,
            source: definition.source,
            kind: "legacy",
            note: definition.note
        };
        legacyNameTargets.set(definition.current.id, target);
        const editionTargets = legacyNameTargetsByEdition.get(definition.source.edition) || new Map();
        editionTargets.set(definition.current.id, target);
        legacyNameTargetsByEdition.set(definition.source.edition, editionTargets);
    }

    let nameTargets;
    if (contextEdition === catalog.activeEdition) {
        if (currentNameTargets.size === 0 && legacyNameTargets.size > 0) {
            return invalid("The recognized risk name belongs to a superseded OWASP LLM edition, not the declared current edition.");
        }
        nameTargets = currentNameTargets;
    } else if (contextEdition) {
        nameTargets = legacyNameTargetsByEdition.get(contextEdition) || new Map();
        if (nameTargets.size === 0 && currentNameTargets.size > 0) {
            return invalid(`The recognized risk name is not declared in the OWASP LLM ${contextEdition} edition.`);
        }
    } else {
        nameTargets = new Map([...legacyNameTargets, ...currentNameTargets]);
    }

    const idTargetIds = new Set(resolvedIdTokens.map(token => token.current.id));
    const nameTargetIds = new Set(nameTargets.keys());
    if (idTargetIds.size > 1 || nameTargetIds.size > 1) {
        const candidateIds = new Set([...idTargetIds, ...nameTargetIds]);
        return {
            status: "ambiguous",
            input,
            frameworkKey: catalog.stableKey,
            candidates: [...candidateIds]
                .sort((left, right) => {
                    const leftItem = currentById.get(left.toUpperCase());
                    const rightItem = currentById.get(right.toUpperCase());
                    return (leftItem?.rank || 0) - (rightItem?.rank || 0)
                        || left.localeCompare(right);
                })
                .map(id => currentById.get(id.toUpperCase()))
                .filter(Boolean)
                .map(item => ({
                    framework: catalog.activeLabel,
                    edition: catalog.activeEdition,
                    id: item.id,
                    name: item.name,
                    label: `${item.id} ${item.name}`
                })),
            reason: "The query contains multiple OWASP LLM identifiers or risk names that resolve to different current concepts. Specify one risk concept; no rank is guessed."
        };
    }

    const idToken = resolvedIdTokens[0] || null;
    const nameTarget = nameTargets.values().next().value || null;

    let status;
    let source = null;
    let current = null;
    let reason;

    const recognizedNameTarget = nameTarget?.current || null;
    const idNameConflict = Boolean(
        idToken
        && recognizedNameTarget
        && recognizedNameTarget.id !== idToken.current.id
    );

    if (idNameConflict) {
        current = recognizedNameTarget;
        source = nameTarget.source;
        status = "normalized";
        reason = `The identifier/name conflict resolves by risk concept: the identifier points to ${idToken.current.id}, while the recognized name identifies ${recognizedNameTarget.id}; the named concept's current canonical successor is returned.`;
    } else if (idToken?.explicitId) {
        status = idToken.status;
        source = idToken.source;
        current = idToken.current;
        reason = idToken.note;
    } else if (idToken && nameTarget) {
        current = nameTarget.current;
        status = nameTarget.kind === "legacy" ? "migrated" : "normalized";
        source = nameTarget.source;
        reason = idToken.current.id === nameTarget.current.id
            ? "The unversioned identifier and recognized risk name resolve to the current canonical item."
            : `The unversioned rank and risk name conflict; the recognized risk concept resolves to ${nameTarget.current.id} rather than carrying the old rank forward.`;
    } else if (idToken) {
        status = idToken.status;
        source = idToken.source;
        current = idToken.current;
        reason = idToken.note;
    } else if (nameTarget) {
        source = nameTarget.source;
        current = nameTarget.current;
        status = nameTarget.kind === "legacy" ? "migrated" : "normalized";
        reason = nameTarget.note || "The recognized risk name resolves to the current canonical item.";
    } else {
        if (containsRecognizedFrameworkLabel) {
            return invalid("The query names the OWASP LLM framework but does not identify one recognized risk concept.");
        }
        return null;
    }

    const canonical = {
        frameworkKey: catalog.stableKey,
        framework: catalog.activeLabel,
        edition: catalog.activeEdition,
        id: current.id,
        name: current.name,
        label: `${current.id} ${current.name}`
    };
    return {
        status,
        input,
        ...(idNameConflict ? {
            inputNameConflict: {
                normalizedInputName: inputName,
                identifierTarget: `${idToken.current.id} ${idToken.current.name}`,
                recognizedNameTarget: `${recognizedNameTarget.id} ${recognizedNameTarget.name}`,
                resolvedBy: "recognized-risk-name"
            }
        } : {}),
        ...(resolvedIdTokens.length > 1 ? {
            coResolvedReferences: resolvedIdTokens.map(token => token.raw)
        } : {}),
        ...(source ? { migratedFrom: { ...source, label: `${source.id} ${source.name}` } } : {}),
        canonical,
        reason
    };
}

export default frameworkMigrations;
