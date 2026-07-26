# Security policy

## Supported scope

Security reports are accepted for:

- the current `main` branch of this repository;
- the website currently published at `https://aidefend.net`;
- AIDEFEND-authored website code, generated public datasets, and browser-side WebMCP integration;
- bundled or remotely loaded dependencies when their use by AIDEFEND creates a security issue; and
- implementation examples whose unsafe behavior could reasonably expose users who follow the published guidance.

Older snapshots, unofficial forks, modified datasets, downstream services, and third-party products are not maintained by this project. Report vulnerabilities in a third-party product to its owner unless the issue is caused by how AIDEFEND integrates or represents that product.

## What should be reported privately

Please use the private reporting process for issues such as:

- executable website or browser-side vulnerabilities;
- unauthorized data access, sensitive-data exposure, or credential disclosure;
- supply-chain or artifact-integrity problems affecting published AIDEFEND files;
- a WebMCP tool behavior that crosses its documented read-only boundary;
- a reproducible security flaw in published implementation code that could create an unsafe deployment; or
- any issue whose public disclosure would provide a practical exploitation path before a fix is available.

Mapping disagreements, taxonomy proposals, broken links, wording corrections, and non-sensitive documentation defects can be reported through a normal GitHub issue.

## How to report a vulnerability

1. If GitHub shows a **Report a vulnerability** button for this repository, use the repository's [private vulnerability reporting form](https://github.com/edward-playground/aidefense-framework/security/advisories/new).
2. If private vulnerability reporting is unavailable, open a minimal public issue titled `[Security contact request]` and ask for a private contact path.
3. Do not include exploit details, working payloads, credentials, personal data, customer information, or other sensitive evidence in a public issue.

In the private report, include what you can of the following:

- the affected URL, file, control or guidance ID, version, and commit;
- the security impact and required preconditions;
- concise reproduction steps or a minimal proof of concept;
- whether the issue affects the live website, repository content, or both;
- any known mitigation or suggested fix; and
- any disclosure deadline or coordination constraint.

Use redacted or synthetic data whenever possible.

## Coordinated handling

The maintainer will review credible reports and coordinate validation, remediation, and disclosure as circumstances allow. This volunteer project does not promise a fixed response or remediation time.

Please allow a reasonable opportunity to investigate before publishing exploit details. AIDEFEND may request additional evidence, determine that an issue belongs to an upstream project, or treat a report as a non-security content correction when it does not create a practical security impact.

## Testing boundaries

Security research must stay within systems, accounts, and data you own or are explicitly authorized to test. Do not:

- access, alter, retain, or disclose another person's data;
- disrupt the public website or degrade service availability;
- use social engineering, credential attacks, or destructive testing;
- test third-party services without their authorization; or
- continue testing after confirming a vulnerability when further activity would increase impact.

This policy does not authorize activity that would otherwise be unlawful or violate third-party terms.

## No security guarantee or bounty

AIDEFEND is a defensive knowledge base, not a certification or a guarantee that a particular deployment is secure. Published examples must be validated against the exact platform version, architecture, threat model, and organizational policy before production use.

No bug bounty, payment, or safe-harbor commitment is offered unless the maintainer explicitly agrees to it in writing before the relevant activity.
