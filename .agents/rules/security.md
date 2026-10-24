- Prioritize static analysis (AST parsing, file reading) over dynamic execution.
- Never execute untrusted scripts or setup files.
- Flag any unsafe Python behaviors (e.g., shell=True, insecure deserialization) in a dedicated "Security Observability" section.

