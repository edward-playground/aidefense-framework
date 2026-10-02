# Third-party notices

This repository redistributes, or its pages optionally load, the following third-party software and data. These components are not relicensed as original AIDEFEND work.

## DOMPurify 3.4.16

Files:

- `js/purify.min.js`
- `kids/purify.min.js`

Source: https://github.com/cure53/DOMPurify/tree/3.4.16

Package: `dompurify@3.4.16`

Package integrity:

```text
sha512-sqo+pNp3qRhCIpbgRi1y8Tgk27Bo2Ry7w0dC1NBeNTdZChWjz9Xb/KOoZbRP/R6pQZ80Qw8YhXw13hWWBbMRnQ==
```

Vendored file SHA-256:

```text
2C90A9B46D6463F26038A29B686E82BC91DE01FDAC9D5229E7CFE3B360134EA2  js/purify.min.js
2C90A9B46D6463F26038A29B686E82BC91DE01FDAC9D5229E7CFE3B360134EA2  kids/purify.min.js
```

Copyright Cure53 and other contributors. DOMPurify is offered under `(MPL-2.0 OR Apache-2.0)`; this distribution uses the Apache-2.0 option. The Apache-2.0 license text is available in [`LICENSE`](LICENSE).

## Tailwind CSS 3.4.17 browser bundle

Files:

- `js/tailwindcss.js`
- `kids/tailwindcss.js`

Source: https://github.com/tailwindlabs/tailwindcss

Vendored file SHA-256:

```text
176E894661AA9CDC9A5CBA6C720044CBBF7B8BD80D1C9A142A7C24B1B6C50D15  js/tailwindcss.js
176E894661AA9CDC9A5CBA6C720044CBBF7B8BD80D1C9A142A7C24B1B6C50D15  kids/tailwindcss.js
```

MIT License

Copyright (c) Tailwind Labs, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## @mcp-b/global 4.0.0 optional browser runtime

The main page can load the package's self-contained browser IIFE from:

```text
https://unpkg.com/@mcp-b/global@4.0.0/dist/index.iife.js
```

The exact-version URL is protected by this SHA-384 Subresource Integrity value:

```text
sha384-1ilb0+KiPCJ4wTvm97cC3KX527AS59JIfvfEryVeXbY6mwBCxEAI4u9FEgxnjgX5
```

Exact package release: https://www.npmjs.com/package/@mcp-b/global/v/4.0.0

Source repository: https://github.com/WebMCP-org/npm-packages/tree/main/packages/global

Package: `@mcp-b/global@4.0.0`

MIT License

Copyright (c) 2025 mcp-b contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## MITRE ATLAS data

The Frameworks View contains metadata derived from MITRE ATLAS data version 2026.09.

`integration-catalogs.js` and the generated `data/integration/threat-catalogs/mitre-atlas.json` and `data/integration/threat-control-joins.json` contain ATLAS technique identifiers, names, tactic membership and parent/sub-technique relationships from the same data version. Technique descriptions are not reproduced in those files.

Source artifact: https://github.com/mitre-atlas/atlas-data/blob/3259f388d19cbcca11bacf12a0ef97f4198f711b/dist/v6/ATLAS-2026.09.yaml

Source revision: `3259f388d19cbcca11bacf12a0ef97f4198f711b`

Source artifact SHA-256: `935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688`

Copyright 2021-2026 MITRE. MITRE ATLAS data is licensed under the Apache License, Version 2.0. The Apache-2.0 license text is available in [`LICENSE`](LICENSE).

MITRE, MITRE ATT&CK, MITRE ATLAS, and MITRE D3FEND are trademarks of The MITRE Corporation. Use of MITRE material does not imply endorsement.

## OWASP Top 10 for LLM Applications 2026

OWASP-derived identifiers, names, edition metadata, and normalized risk summaries appear in:

- `framework-migrations.js`
- generated `data/framework-migrations.json`
- the OWASP LLM Frameworks View in `index.html`
- generated `data/integration/threat-catalogs/owasp-llm-top-10-2026.json` and `data/integration/threat-control-joins.json` (identifiers, ranks and names only)

Official source: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/

Version-pinned artifact: https://genai.owasp.org/download/56857/

The numeric download id on genai.owasp.org has changed before (56791 became 56857 without a content change); the artifact SHA-256 below is the pin, and a request without browser headers may receive an HTML page instead of the PDF.

Artifact release: `v1.0`

Artifact SHA-256:

```text
EF87993A4E50AE9D83B41FF7A3D3E6320A82DFA8D4EC6BF98D0CE264B2E6108E
```

Attribution: OWASP Top 10 for LLM Applications 2026, OWASP Foundation / OWASP GenAI Security Project.

The source document is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/legalcode) (`CC-BY-SA-4.0`). The public AIDEFEND files do not bundle the complete source PDF or reproduce its full prose.

Changes made: AIDEFEND preserves the official risk identifiers and names, paraphrases and normalizes short risk summaries for its public catalog, adapts presentation formatting, and adds independently authored mapping decisions, migration analysis, and resolver behavior. OWASP-derived portions retain the upstream license; AIDEFEND-authored portions are identified separately. These changes do not imply OWASP endorsement.

## OWASP Machine Learning Security Top 10 (2023)

OWASP-derived identifiers and names appear in `integration-catalogs.js`, the generated `data/integration/threat-catalogs/owasp-ml-top-10-2023.json` and `data/integration/threat-control-joins.json`, the OWASP ML Frameworks View in `index.html`, and the `defendsAgainst` mappings in `tactics/*.js` and `data/data.json`.

Official source: https://owasp.org/www-project-machine-learning-security-top-10/ (project site: https://mltop10.info/)

Copyright 2003-2023 The OWASP Foundation. The source is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/) (`CC-BY-SA-4.0`), as stated on the project notice page. The public AIDEFEND files reproduce identifiers, ranks and names only, not the source prose. AIDEFEND mapping decisions are independently authored and do not imply OWASP endorsement.

## OWASP Top 10 for Agentic Applications 2026

OWASP-derived identifiers and names appear in `integration-catalogs.js`, the generated `data/integration/threat-catalogs/owasp-agentic-top-10-2026.json` and `data/integration/threat-control-joins.json`, the OWASP Agentic Frameworks View in `index.html`, and the `defendsAgainst` mappings in `tactics/*.js` and `data/data.json`.

Official source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

Attribution: OWASP Top 10 for Agentic Applications 2026, OWASP Foundation / OWASP GenAI Security Project.

The OWASP GenAI Security Project site states that, unless otherwise specified, its content is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/) (`CC-BY-SA-4.0`). The public AIDEFEND files reproduce identifiers, ranks and names only, not the source prose. AIDEFEND mapping decisions are independently authored and do not imply OWASP endorsement.

# Cisco Integrated AI Security and Safety Framework v2

`cisco-framework.js` and generated `data/cisco-framework.json` contain current v2.0.0 identifiers, names, and hierarchy derived from Cisco's [public taxonomy](https://learn-cloudsecurity.cisco.com/ai-security-framework), announced [September 9, 2026](https://blogs.cisco.com/ai/security-framework-v2). Those identifiers, names, and other Cisco material remain subject to Cisco's rights and applicable terms. AIDEFEND authored the objective summaries and defense mappings; these are independent assessments and do not imply Cisco endorsement.

`framework-migrations.js` and generated `data/framework-migrations.json` also include Cisco edition and historical identifier/name conflict metadata. AIDEFEND authors the resolver behavior and bounded interpretations of ambiguous official records, considering Cisco's definitions, examples and standards mappings together. These interpretations are not Cisco corrections or automatic cross-framework equivalence.
