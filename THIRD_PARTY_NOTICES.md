# Third-party notices

This repository redistributes, or its pages optionally load, the following third-party software and data. These components are not relicensed as original AIDEFEND work.

## DOMPurify 3.4.11

Files:

- `js/purify.min.js`
- `kids/purify.min.js`

Source: https://github.com/cure53/DOMPurify/tree/3.4.11

Package: `dompurify@3.4.11`

Package integrity:

```text
sha512-zhlUV12GsaRzMsf9q5M254YhA4+VuF0fG+QFqu6aYpoGlKtz+w8//jBcGVYBgQkR5GHjUomejY84AV+/uPbWdw==
```

Vendored file SHA-256:

```text
45262DA1C9875F6DF7AE861DD8666C63D476BBD44F8C0C4CC52F05208EFBEC0D  js/purify.min.js
45262DA1C9875F6DF7AE861DD8666C63D476BBD44F8C0C4CC52F05208EFBEC0D  kids/purify.min.js
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

The Frameworks View contains metadata derived from MITRE ATLAS data version 2026.08.

Source artifact: https://github.com/mitre-atlas/atlas-data/blob/41d4f5ca4112f0e492ffaa3ebff07dc80a75afa5/dist/v6/ATLAS-2026.08.yaml

Source revision: `41d4f5ca4112f0e492ffaa3ebff07dc80a75afa5`

Source artifact SHA-256: `a8d32f676854cc57721c217ec5b39f07db518076dee4a6c1335df0a7bc8271a2`

Copyright 2021-2026 MITRE. MITRE ATLAS data is licensed under the Apache License, Version 2.0. The Apache-2.0 license text is available in [`LICENSE`](LICENSE).

MITRE, MITRE ATT&CK, MITRE ATLAS, and MITRE D3FEND are trademarks of The MITRE Corporation. Use of MITRE material does not imply endorsement.

## OWASP Top 10 for LLM Applications 2026

OWASP-derived identifiers, names, edition metadata, and normalized risk summaries appear in:

- `framework-migrations.js`
- generated `data/framework-migrations.json`
- the OWASP LLM Frameworks View in `index.html`

Official source: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/

Version-pinned artifact: https://genai.owasp.org/download/56791/

Artifact release: `v1.0`

Artifact SHA-256:

```text
EF87993A4E50AE9D83B41FF7A3D3E6320A82DFA8D4EC6BF98D0CE264B2E6108E
```

Attribution: OWASP Top 10 for LLM Applications 2026, OWASP Foundation / OWASP GenAI Security Project.

The source document is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International license](https://creativecommons.org/licenses/by-sa/4.0/legalcode) (`CC-BY-SA-4.0`). The public AIDEFEND files do not bundle the complete source PDF or reproduce its full prose.

Changes made: AIDEFEND preserves the official risk identifiers and names, paraphrases and normalizes short risk summaries for its public catalog, adapts presentation formatting, and adds independently authored mapping decisions, migration analysis, and resolver behavior. OWASP-derived portions retain the upstream license; AIDEFEND-authored portions are identified separately. These changes do not imply OWASP endorsement.

# Cisco Integrated AI Security and Safety Framework v2

`cisco-framework.js` and generated `data/cisco-framework.json` contain current v2.0.0 identifiers, names, and hierarchy derived from Cisco's [public taxonomy](https://learn-cloudsecurity.cisco.com/ai-security-framework), announced [September 9, 2026](https://blogs.cisco.com/ai/security-framework-v2). Those identifiers, names, and other Cisco material remain subject to Cisco's rights and applicable terms. AIDEFEND authored the objective summaries and defense mappings; these are independent assessments and do not imply Cisco endorsement.

`framework-migrations.js` and generated `data/framework-migrations.json` also include Cisco edition and historical identifier/name conflict metadata. AIDEFEND authors the resolver behavior and bounded interpretations of ambiguous official records, considering Cisco's definitions, examples and standards mappings together. These interpretations are not Cisco corrections or automatic cross-framework equivalence.
