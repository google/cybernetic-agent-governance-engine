# Compatibility

## Tested in 0.1.0-alpha.0

- Node.js 22 on Linux
- npm workspaces and npm 10+
- TypeScript 5.8
- Direct TypeScript/JavaScript SDK use
- JSON stdin/stdout CLI use
- Local files on a single host filesystem
- Ed25519 keys supported by Node.js `crypto`

## Protocol-compatible in principle

Any language or agent host can integrate experimentally if it can construct protocol JSON, invoke the CLI, protect the policy/decision/receipt stores, and preserve exact UTF-8 byte offsets. Python, Go, Java, OpenAI, Anthropic, Google, LangChain, and Mastra adapters are not bundled or tested.

## Not supported or not tested

- Browsers, edge runtimes, Deno, or Bun
- Network filesystems for the receipt registry
- Multiple hosts sharing one receipt registry
- Windows and macOS release qualification
- Third-party semantic verification of whether evidence truly supports a claim

## Version matrix

| Package release | Protocol | Receipt | Node.js | Status |
| --- | --- | --- | --- | --- |
| 0.1.0-alpha.0 | 1-alpha | 2-alpha | 22+ | Current private alpha |

All workspace packages must use the same release version. Mixed versions are unsupported during alpha.
