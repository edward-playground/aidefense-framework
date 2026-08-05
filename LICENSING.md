# AIDEFEND licensing

AIDEFEND uses separate licenses for software and framework content. This file defines which license applies to each part of the repository.

## Software: Apache License 2.0

Unless a file contains a different notice, original executable code and website implementation code are licensed under the Apache License, Version 2.0. The full license is in [`LICENSE`](LICENSE).

This includes:

- `css/`
- `js/`, except vendored third-party files identified in `THIRD_PARTY_NOTICES.md`
- `kids/` implementation code, except vendored third-party files and AIDEFEND brand assets
- `scripts/`
- `index.html`, `kids.html`, `main.js`, and `webmcp-tools.js`, excluding embedded framework content, third-party material, and AIDEFEND marks

Copyright 2025-2026 Edward Lee.

## Framework content and data: CC BY 4.0

Original AIDEFEND framework content and data are licensed under the Creative Commons Attribution 4.0 International Public License. The full legal code is in [`LICENSE-CONTENT`](LICENSE-CONTENT).

This includes AIDEFEND-authored material in:

- `tactics/`
- `data/data.json`, `data/data-cache.json`, `data/tactics-index.json`, and AIDEFEND-authored migration analysis in `data/framework-migrations.json`
- `aidefend-intro.js`
- explanatory documentation in `README.md`

When sharing this material, attribute it as:

> AIDEFEND AI Defense Framework, created by Edward Lee, https://aidefend.net, licensed under CC BY 4.0.

Indicate material changes and retain a link to the license. CC BY 4.0 does not grant trademark rights or imply endorsement.

## Exclusions and third-party material

- The AIDEFEND name, AIDEFEND marks, logos, badges, and other brand identifiers are not licensed for unrestricted brand use. See [`TRADEMARKS.md`](TRADEMARKS.md).
- External framework names, descriptions, identifiers, and other third-party material remain subject to their respective owners' rights and licenses.
- OWASP-derived identifiers, names, edition metadata, and normalized risk summaries in `framework-migrations.js`, generated `data/framework-migrations.json`, and the Frameworks View retain the upstream CC BY-SA 4.0 terms described in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). The resolver implementation and AIDEFEND-authored migration contract remain covered by the applicable AIDEFEND software/content licenses.
- Bundled third-party software retains its upstream license. See [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- No license grants permission to claim affiliation with, endorsement by, or official status from AIDEFEND or any referenced framework owner.

If a file carries its own license notice, that file-specific notice controls for that file.
