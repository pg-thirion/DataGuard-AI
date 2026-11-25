# Security policy

## Threat model

DataGuard handles untrusted text. The browser runs detection in a dedicated worker, the Node adapter uses a bounded worker pool, and the local server serves an explicit asset allowlist. No request containing source text is necessary. There is no telemetry or database. Review is required before the UI enables its export controls or the guarded Node client invokes a provider callback. The browser is a user-operated tool, not an enforcement boundary against someone manually selecting or copying text.

Trusted: browser runtime, operating system, package source, organisation's review/audit/provider callbacks and deployment. Untrusted: all input text and any model response. A compromised browser extension, host or trusted callback is outside this control. The review callback must implement actual organisational approval, not always return true. The mandatory audit callback must persist only non-sensitive metadata in the organisation's approved audit system.

## Known gaps

Pattern detection misses some unlabelled names, addresses, novel encodings, split secrets and context-specific data. Normalisation handles compatibility forms and format characters but is not a complete Unicode or encoding security solution. Free-text detection is not NER. Binary documents, OCR, attachments, provider responses and streaming are unsupported. Source text and redacted output may persist in OS memory or clipboard. The code does not enforce network-level egress. Application teams must prevent bypassing the adapter.

## Production release gates

- Independent security review and successful browser end-to-end tests (the repository includes a Chromium security smoke test; expand it before deployment).
- Representative, authorised labelled corpus, measured category-level precision/recall and documented acceptance thresholds.
- Review/authentication, enterprise access controls and network-level deny-by-default egress at the integration boundary.
- TLS, deployment supply-chain integrity, monitoring of metadata-only failures and documented incident response.
- Privacy impact assessment, retention policy and organisational approval. No POPIA compliance claim.

Report vulnerabilities privately to the repository owner via GitHub's private vulnerability reporting if enabled. Never attach real customer records, credentials or raw scan logs. Use fictional reproduction data.
