# Governance and Support

Agent Integrity is currently maintainer-led. Maintainers decide releases, protocol changes, security responses, and contributor access. Significant behavior changes require tests, updated documentation, and review against the threat model.

GitHub issues are the public support channel after launch. Alpha support is best-effort; there is no uptime or response-time commitment. Security reports must follow `SECURITY.md` and should not be filed publicly.

The release process requires passing tests, real tarball inspection and clean installation, placeholder scanning, dependency audit, a clean working tree, and explicit maintainer approval. The tag-only npm workflow requests only repository read and OIDC identity-token permissions and publishes packages in dependency order. It remains intentionally inoperable until placeholders are replaced, npm scope ownership and trusted publishing are configured externally, and the documented security channels are operational. Repository visibility is a separate manual decision and is never changed by release scripts.
