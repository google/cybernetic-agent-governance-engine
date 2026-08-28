# @agent-integrity/sdk

Session construction and exact-response release controls for Node.js agent hosts.

```js
import { AgentIntegritySession, releaseVerifiedResponse } from "@agent-integrity/sdk";
```

Buffer drafts until verification finishes. Release only the `response` returned by a `PASS` release result. Do not stream model output around this boundary. See `examples/basic-agent` for runnable code.
