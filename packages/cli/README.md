# @rightsroot/prm-cli

Offline verification for **PRM — Personal Rights Management** documents: policies, key event logs,
personal ledgers, and `.prmproof` evidence bundles. The specification lives at
[rightsroot.org/spec/prm](https://rightsroot.org/spec/prm); the source is
[Breezy-Point-Beach/prm](https://github.com/Breezy-Point-Beach/prm).

```
npx @rightsroot/prm-cli verify notice.prmproof
npx @rightsroot/prm-cli verify policy.json --kel kel.json --offline
```

Nothing here contacts RightsRoot, or any network. The package is a single self-contained file with
no dependencies, so what runs is exactly what was published.

Exit codes: `0` verified · `1` verified with warnings (for example, no timestamp evidence) · `2`
failed · `3` bad usage or malformed input.

RFC 3161 timestamp tokens in a bundle are **bound** to the bundle's tree head by this tool (the
imprint is checked); the authority's signature is left to you and standard tooling, because which
authorities you trust is your decision — see `verification/instructions.txt` inside any bundle.
