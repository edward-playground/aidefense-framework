# AIDEFEND™ — AI Defense Framework

[![Code License: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg?style=for-the-badge)](LICENSE)
[![Content License: CC BY 4.0](https://img.shields.io/badge/content-CC_BY_4.0-lightgrey.svg?style=for-the-badge)](LICENSE-CONTENT)
[![Version](https://img.shields.io/badge/version-1.20260911-0ea5e9.svg?style=for-the-badge)](aidefend-intro.js)
[![Live Demo](https://img.shields.io/badge/live-aidefend.net-brightgreen.svg?style=for-the-badge)](https://aidefend.net)

AIDEFEND is an open, implementation-oriented knowledge base of defensive controls for AI, machine-learning, LLM, multimodal, RAG, and agentic systems. It organizes defenses by security function, protected component, lifecycle phase, and the external security references they address.

- **Live framework:** https://aidefend.net
- **MCP and REST service:** https://github.com/edward-playground/aidefend-mcp

## Current source version

Version `1.20260911` provides:

- **307 actionable defensive controls**: 35 standalone techniques and 272 leaf sub-techniques
- implementation guidance, production-oriented examples, verification guidance, and explicit scope boundaries
- assessment against nine external AI security frameworks and risk catalogs
- four exploration views: Tactics, Pillars, Phases, and Frameworks
- generated JSON datasets for external tools and integrations
- optional browser-side WebMCP tools for read-only framework lookup

Parent families are not implementation controls and do not receive independent control credit. Implementation-guidance entries are methods within their owning actionable control, not additional controls.

The optional WebMCP module loads the self-contained `@mcp-b/global@4.0.0` IIFE from `unpkg.com` with a pinned SHA-384 Subresource Integrity value, then registers tools only when `document.modelContext.registerTool` is available. A compatible native browser implementation bypasses the polyfill. Core framework browsing and the public datasets do not depend on WebMCP; when the runtime or API is unavailable, no WebMCP tools are registered.

## Framework coverage

Every actionable AIDEFEND control is assessed against the following external reference set. Each assessment contains one or more canonical relationships or an explicit `N/A` when no defensible direct relationship applies.

1. MITRE ATLAS
2. MAESTRO
3. OWASP LLM Top 10 2026
4. OWASP ML Top 10 2023
5. OWASP Top 10 for Agentic Applications 2026
6. NIST Adversarial Machine Learning 2025
7. Cisco Integrated AI Security and Safety Framework v2.0
8. Google Secure AI Framework 2.0 - Risks
9. Databricks AI Security Framework 3.0

A mapping indicates a defensible relationship between a threat or risk and an AIDEFEND control. It is not a certification claim, an implementation attestation, or evidence that a specific deployment is secure.

Mapping relevance is reviewed at the actionable standalone-technique or leaf-sub-technique level. A non-actionable parent family's mapping list is the de-duplicated union of its reviewed child mappings for navigation and reverse lookup only; it must not be used as implementation evidence or control credit.

## Explore the framework

| View | Organizes defenses by |
|---|---|
| **Tactics** | Security function: Model, Harden, Detect, Isolate, Deceive, Evict, Restore |
| **Pillars** | Protected component: Data, Model, Infrastructure, Application |
| **Phases** | Lifecycle stage: Scoping, Building, Validation, Operation, Response, Improvement |
| **Frameworks** | Reverse lookup from external threat or risk entries to corresponding AIDEFEND defenses |

## Public data

The generated dataset is available at [`data/data.json`](data/data.json). A compact navigation index is available at [`data/tactics-index.json`](data/tactics-index.json). The additive [`data/framework-migrations.json`](data/framework-migrations.json) registry identifies the current framework edition and semantic successors for superseded identifiers; it does not carry AIDEFEND mappings forward without a target-edition review.

The source of truth for AIDEFEND-authored framework content is `tactics/*.js`. Do not edit generated JSON files directly.

Generation intentionally strips source-only `howTo` detail, warnings, and other authoring fields according to the dataset-generation rules. Consumers must not assume that generated JSON is a complete mirror of the tracked tactic source.

The public dataset uses additive schema 2.3. `version.dataVersion` is derived from the AIDEFEND source version, and `version.generatedAt` records the UTC generation time. The compact tactics index carries its own schema version and the same generation timestamp.

`scopeBoundary` is optional structured boundary metadata. `implementationGuidanceIds` align one-to-one with the lightweight guidance strings; a guidance ID such as `AID-H-002.004-G004` identifies an implementation method inside its owning control and is not a separate control or assessment result. Consumers of older data should treat a missing `toolsSourceAvailable` field as an empty array and ignore unknown additive fields.

Tool recommendations use three licensing and delivery categories: `toolsOpenSource` is limited to OSI-licensed software; `toolsSourceAvailable` covers non-OSI tooling and ends each entry with `(<exact license>; source-available)` or `(<exact license>; open-weight)`; and `toolsCommercial` covers proprietary or vendor-hosted offerings. Standards, datasets, specifications, documentation, methodologies, and papers are not classified as tools.

## Local use

The website is static. Serve the repository with any local static web server:

For example:

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`.

The core framework data, DOMPurify, and Tailwind browser bundle are stored locally. The pages request Google Fonts, the main page also requests Google Analytics, and the optional WebMCP module loads its exact-version, integrity-pinned runtime from `unpkg.com`. Blocking those third-party origins does not remove the local framework data, but it can disable WebMCP, analytics, or hosted fonts.

## Public dataset generation

Requirements:

- Node.js 22.7 or newer
- No package installation is required

```bash
npm run generate
npm run count
npm run generate -- --check
```

`npm run generate` regenerates the public dataset from the tracked tactic source and validates the public keyword lock and technique hierarchy. `npm run generate -- --check` performs the same validation without rewriting tracked outputs. These public commands do not run the maintainer-only source-freshness, mapping, semantic-boundary, or external-reference review workflow.

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

## Release versions and automatic tags

To publish a new Framework version:

1. Set the same `1.YYYYMMDD` version in `package.json` and `aidefend-intro.js`.
2. Run `npm run generate`, review the content and generated changes, and commit them together.
3. Push or merge to `main`. The release workflow runs the repository tests, verifies generated outputs, and creates the annotated `v1.YYYYMMDD` tag on the exact validated commit.

Each version is published once. Later commits with the same version preserve its
original tag; a content release needs a new version. The current date format
supports one release version per calendar day. Existing tags are never moved,
overwritten, or deleted, and version rollback or conflicting tag targets fail
the workflow. If validation fails, fix the issue and retry the workflow on
`main`; no tag is created until validation passes. To inspect the proposed tag
without publishing, run `node scripts/release-tag.mjs` in a complete checkout
with the remote tags fetched.

Pull requests run validation with read-only permissions. Only the subsequent
main-branch publication job receives `contents: write`, using GitHub's temporary
token without an additional repository secret. Automated tag pushes do not
trigger another GitHub Actions workflow through `GITHUB_TOKEN`; future tag-based
deployment workflows must be connected explicitly. The website continues to
deploy from `main`. This automation creates Git tags, not GitHub Release pages,
npm packages, Engine promotions, or semantic-review approvals.

## Security and implementation notice

AIDEFEND provides defensive control objectives, implementation patterns, examples, mappings, and verification guidance. Environment-specific thresholds, products, trust boundaries, regulatory obligations, and operational approval requirements must be evaluated by qualified practitioners before production deployment.

Example code is educational implementation guidance, not a drop-in guarantee of security. Validate it against the exact platform version, deployment architecture, threat model, and organizational policy in which it will run.

To report a vulnerability, follow [`SECURITY.md`](SECURITY.md). Use GitHub private vulnerability reporting when available; never place exploit details, credentials, personal data, or sensitive evidence in a public issue.

## Licensing

AIDEFEND uses a deliberate split-license model:

- **Software and website implementation code:** Apache License 2.0 — see [`LICENSE`](LICENSE)
- **Original framework content and data:** Creative Commons Attribution 4.0 International — see [`LICENSE-CONTENT`](LICENSE-CONTENT)
- **Detailed scope and attribution:** [`LICENSING.md`](LICENSING.md)
- **AIDEFEND names, marks, logos, and badges:** not granted for unrestricted brand use — see [`TRADEMARKS.md`](TRADEMARKS.md)
- **Bundled third-party components and data:** retain their upstream terms — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)

Suggested content attribution:

> AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.

When sharing modified content, also provide a link to CC BY 4.0 and indicate that changes were made. See [`LICENSING.md`](LICENSING.md) for the complete repository scope and attribution requirements.

Licensing does not grant permission to imply affiliation, certification, approval, or endorsement by AIDEFEND or any referenced framework owner.

## Acknowledgments and independence

AIDEFEND synthesizes defensive knowledge and references identifiers or concepts from MITRE ATLAS, MITRE D3FEND, MITRE ATT&CK, MAESTRO, OWASP, NIST, Cisco, Google, and Databricks resources.

AIDEFEND is an independent project. It is not affiliated with, endorsed by, sponsored by, or officially connected to The MITRE Corporation, the Cloud Security Alliance, OWASP, NIST, Cisco, Google, or Databricks.

External names, identifiers, titles, and other third-party material remain subject to their respective owners' rights. AIDEFEND's licenses apply only to AIDEFEND-authored code, content, and data as defined in [`LICENSING.md`](LICENSING.md). See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for bundled third-party software and redistributed data notices.

## Cisco AI Security and Safety Framework v2

Cisco mappings use the current v2.0.0 taxonomy announced on September 9, 2026: 19 objectives, 41 techniques, and 115 subtechniques. The Frameworks View retains Cisco objective names and uses AIDEFEND-authored summaries of their child techniques. Mapping decisions follow the complete official technique/subtechnique record and each AIDEFEND control's deployment mechanism. Definitions are primary; Cisco's own examples and standards mappings can clarify ambiguous scope, without creating transitive equivalence between frameworks. Shared keywords or an objective heading alone do not establish defense coverage.

The current catalog and source provenance are available in [`cisco-framework.js`](cisco-framework.js) and generated [`data/cisco-framework.json`](data/cisco-framework.json). Cisco's framework key remains stable; identifiers and names represent v2 only. The migration registry and WebMCP resolver report the current edition for bare IDs, reject unsupported editions and retired IDs, and report ID/name conflicts instead of silently interpreting a v1 concept as v2. Historical conflict metadata does not restore v1 mappings or automatically select a successor.

Parent-family mappings are derived child unions for navigation. All nine framework views list and count only actionable controls that actually match the selected threat group. Full and High describe relevance within the defense's stated scope, not verified deployment. Repairable implementation defects are tracked separately from relevance; a missing primary defense mechanism still cannot earn coverage from a title or tool name.

Official sources: [Cisco v2 announcement](https://blogs.cisco.com/ai/security-framework-v2) and [Cisco taxonomy](https://learn-cloudsecurity.cisco.com/ai-security-framework).

## Maintainer

AIDEFEND is led by **Edward Lee**. Connect on [LinkedIn](https://www.linkedin.com/in/go-edwardlee/).
