# AIDEFEND™ — AI Defense Framework

[![Code License: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg?style=for-the-badge)](LICENSE)
[![Content License: CC BY 4.0](https://img.shields.io/badge/content-CC_BY_4.0-lightgrey.svg?style=for-the-badge)](LICENSE-CONTENT)
[![Version](https://img.shields.io/badge/version-1.20260724-0ea5e9.svg?style=for-the-badge)](aidefend-intro.js)
[![Live Demo](https://img.shields.io/badge/live-aidefend.net-brightgreen.svg?style=for-the-badge)](https://aidefend.net)

AIDEFEND is an open, implementation-oriented knowledge base of defensive controls for AI, machine-learning, LLM, multimodal, RAG, and agentic systems. It organizes defenses by security function, protected component, lifecycle phase, and the external threat frameworks they address.

- **Live framework:** https://aidefend.net
- **MCP and REST service:** https://github.com/edward-playground/aidefend-mcp

## Current release

Version `1.20260724` contains:

- **357** taxonomy entries
  - 57 parent technique families
  - 35 actionable standalone techniques
  - 265 actionable leaf sub-techniques
- **300** actionable defensive controls
- **355** reviewed structured scope boundaries, with two entries intentionally requiring none
- **851** implementation-guidance entries
- **8,371** mapping items across nine external AI security frameworks
  - 5,772 actionable-control claims
  - 2,599 derived parent-family navigation entries
- **667** explicit justified `N/A` decisions
- Four exploration views: Tactics, Pillars, Phases, and Frameworks
- A generated JSON dataset for external tools and integrations
- Browser-side WebMCP tools for agent-assisted framework lookup

Counts are generated from the current `tactics/*.js` source files and should be refreshed when the framework changes.

The optional WebMCP integration activates only when the browser exposes the supported `document.modelContext` surface. The framework website continues to operate normally when that experimental browser API is unavailable; in that case, no WebMCP tools are registered.

## Framework coverage

Every actionable AIDEFEND control is mapped against the following framework set:

1. MITRE ATLAS
2. MAESTRO
3. OWASP Top 10 for LLM Applications 2025
4. OWASP Machine Learning Security Top 10 2023
5. OWASP Top 10 for Agentic Applications 2026
6. NIST Adversarial Machine Learning 2025
7. Cisco Integrated AI Security and Safety Framework
8. Google Secure AI Framework 2.0 risks
9. Databricks AI Security Framework 3.0

A mapping indicates a defensible relationship between a threat or risk and an AIDEFEND control. It is not a certification claim, an implementation attestation, or evidence that a specific deployment is secure.

Mapping relevance is reviewed at the actionable standalone-technique or leaf-sub-technique level. A non-actionable parent family's mapping list is the de-duplicated union of its reviewed child mappings for navigation and reverse lookup only; it must not be used as implementation evidence or control credit.

## Explore the framework

### Tactics

Organizes defenses by security function:

- Model
- Harden
- Detect
- Isolate
- Deceive
- Evict
- Restore

### Pillars

Organizes controls by the component they protect:

- Data
- Model
- Infrastructure
- Application

### Phases

Places controls in the AI-system lifecycle:

- Scoping
- Building
- Validation
- Operation
- Response
- Improvement

### Frameworks

Provides a reverse view from external threat-framework entries to the corresponding AIDEFEND defenses.

## Public data

The generated dataset is available at [`data/data.json`](data/data.json). A compact navigation index is available at [`data/tactics-index.json`](data/tactics-index.json).

The source of truth for AIDEFEND-authored framework content is `tactics/*.js`. Do not edit generated JSON files directly.

Generation intentionally strips source-only `howTo` detail, warnings, and other authoring fields according to the dataset-generation rules. Consumers must not assume that generated JSON is a complete mirror of the tracked tactic source.

The public dataset uses additive schema 2.3. Its top-level `version.dataVersion` is derived from the AIDEFEND release version, while `version.generatedAt` records the UTC generation timestamp. The compact tactics index carries its own schema version and the same generation timestamp.

Schema 2.3 adds the optional `scopeBoundary` object for structured responsibility and adjacent-technique comparisons; consumers reading older data should treat an absent `scopeBoundary` as no structured boundary metadata. Schema 2.2 added `implementationGuidanceIds`, aligned one-to-one with the existing lightweight guidance strings. A guidance ID such as `AID-H-002.004-G004` is a stable implementation-method reference inside its owning actionable control; it is not a separate control, applicability result, evidence result, or score. Schema 2.1 added `toolsSourceAvailable`; consumers that also read 2.0 data should treat a missing `toolsSourceAvailable` property as an empty array.

Tool recommendations use three licensing and delivery categories: `toolsOpenSource` is limited to OSI-licensed software; `toolsSourceAvailable` covers non-OSI tooling and ends each entry with `(<exact license>; source-available)` or `(<exact license>; open-weight)`; and `toolsCommercial` covers proprietary or vendor-hosted offerings. Standards, datasets, specifications, documentation, methodologies, and papers are not classified as tools.

## Local use

The website is static. Open `index.html` directly in a modern browser or serve the repository with any static web server.

For example:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`.

## Public dataset generation

Requirements:

- Node.js 22.7 or newer
- No runtime npm dependencies

```bash
npm run generate
npm run count
npm run generate -- --check
```

`npm run generate` regenerates the public dataset from the tracked tactic source and validates the tracked keyword lock and technique hierarchy. `npm run generate -- --check` performs the same public validation without rewriting tracked outputs. Neither command runs the maintainer's private release-audit or external-framework reference workflow.

The complete official release process includes additional maintainer-only source-freshness, mapping, semantic-boundary, content-quality, and Frameworks View synchronization checks. Those internal review assets are intentionally not part of the public repository.

## Repository structure

```text
tactics/                 AIDEFEND framework source of truth
data/                    Generated public datasets and keyword lock
scripts/                 Public dataset generation and count tools
js/, css/                Main website implementation and vendored browser libraries
kids/                    AIDEFEND Kids experience and vendored browser libraries
index.html               Main static application
webmcp-tools.js          Browser-side WebMCP query tools
```

## Security and implementation notice

AIDEFEND provides defensive control objectives, implementation patterns, examples, mappings, and verification guidance. Environment-specific thresholds, products, trust boundaries, regulatory obligations, and operational approval requirements must be evaluated by qualified practitioners before production deployment.

Example code is educational implementation guidance, not a drop-in guarantee of security. Validate it against the exact platform version, deployment architecture, threat model, and organizational policy in which it will run.

If you believe the website or published artifacts contain a security vulnerability, use GitHub's private **Report a vulnerability** channel when it is available. Otherwise, open a minimal public issue requesting a private contact path and do not include exploit details, credentials, or sensitive evidence in that issue.

## Licensing

AIDEFEND uses a deliberate split-license model:

- **Software and website implementation code:** Apache License 2.0 — see [`LICENSE`](LICENSE)
- **Original framework content and data:** Creative Commons Attribution 4.0 International — see [`LICENSE-CONTENT`](LICENSE-CONTENT)
- **Detailed scope and attribution:** [`LICENSING.md`](LICENSING.md)
- **AIDEFEND names, marks, logos, and badges:** not granted for unrestricted brand use — see [`TRADEMARKS.md`](TRADEMARKS.md)
- **Bundled third-party components and data:** retain their upstream terms — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)

Suggested content attribution:

> AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.

Licensing does not grant permission to imply affiliation, certification, approval, or endorsement by AIDEFEND or any referenced framework owner.

## Acknowledgments and independence

AIDEFEND synthesizes defensive knowledge and references identifiers or concepts from MITRE ATLAS, MITRE D3FEND, MITRE ATT&CK, MAESTRO, OWASP, NIST, Cisco, Google, and Databricks resources.

AIDEFEND is an independent project. It is not affiliated with, endorsed by, sponsored by, or officially connected to The MITRE Corporation, the Cloud Security Alliance, OWASP, NIST, Cisco, Google, or Databricks.

See the framework website and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for relevant source and license notices.

## Maintainer

AIDEFEND is led by **Edward Lee**. Connect on [LinkedIn](https://www.linkedin.com/in/go-edwardlee/).
