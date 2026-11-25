# DataGuard AI

Local-first sensitive-data redaction and reviewed model egress for AI-assisted insurance and support workflows. Version 0.2 introduces isolated scanning, bounded resources, normalisation-aware detection and a fail-closed application adapter. This is a hardened reference implementation, not a certified production DLP product.

## Quick start

Requires Node.js 22 or newer and a modern browser. No third-party runtime dependencies or model API keys.

```sh
npm test
npm run evaluate
npm start
```

Open http://127.0.0.1:8080. Paste synthetic text, scan, review and export. The static server binds only to loopback. Do not expose it directly to the public internet.

```sh
node cli.mjs < input.txt > redacted.txt
node cli.mjs --report < input.txt
node cli.mjs --mask < input.txt
```

The CLI is a scanner, not an approval workflow. Reports include redacted text and metadata, not original matched spans. Unmatched sensitive content can remain.

## Integrate at the model boundary

```js
import { createGuardedClient } from './guard.mjs';

const guard = createGuardedClient({
  review: async ({ text, summary }) => {
    // Implement actual authenticated human/organisational approval.
    return await yourReviewWorkflow(text, summary);
  },
  audit: async event => {
    // Metadata only. Do not attach prompts or provider responses.
    await yourAuditSink(event);
  },
  send: async reviewedPrompt => {
    // Your approved model SDK invocation, using only reviewedPrompt.
    return await yourModelCall(reviewedPrompt);
  }
});
const response = await guard.submit(userInput);
```

The adapter scans in an isolated Node worker, validates residual detections, requires explicit boolean approval and requires and awaits an explicit audit callback before sending. Scan, review and audit errors prevent egress. The provider callback receives only the reviewed redacted text. Provider responses are not scanned. Configure deadlines and access control on review/audit/provider callbacks in your application. Do not bypass this adapter or log original text. The lower-level synchronous engine is for trusted callers and tests.

## Detection coverage

Personal: email (including common [at]/[dot] forms), South African/international phones, labelled names, addresses and birth dates, IPv4 and MAC addresses. Financial: checksum-valid cards, labelled cards even when invalid, bank accounts, IBAN-like strings, tax identifiers, CVV/PIN. Identity: South African ID checksum/date/citizenship validation and labelled identity numbers. Insurance: policy, claim, customer, member and passport identifiers. Credentials: common API key prefixes, JWTs, basic/bearer tokens, labelled secrets, connection credentials, URL secrets and private keys. Includes selected Afrikaans labels.

Compatibility characters, common dash variants and format characters are normalised for matching, with findings projected to original UTF-16 positions. Overlaps are merged and consistent placeholders scoped to one scan. No reverse map is returned. Unknown options are rejected. Inputs are capped at 200,000 UTF-16 units, matches at 10,000 and worker scans at 3 seconds by default. Node allows at most four active workers per process. Browser export controls require review and reset on edits. No outbound requests are required.

## Evaluation and tests

`npm test` runs engine regressions, worker/guard integration, CLI and HTTP security tests. `npm run evaluate` reports measured precision and recall on a tiny hand-authored synthetic corpus, including deliberate unsupported cases. These figures are not production accuracy estimates. CI is configured for Node 22 and 24, including a Chromium browser smoke test on Node 22. Run `npm run test:browser` locally with Chromium or set `CHROME_BIN`. No external model or real customer data is used.

## Deployment and assurance

Read [SECURITY.md](SECURITY.md) for the threat model, limitations and production release gates. Detection is heuristic and does not establish anonymity or POPIA compliance. This tool is not a network DLP gateway by itself; enforce the adapter at the application boundary and deny alternative egress. Independent testing and representative evaluation are required before handling live insurance data.

## Additional detection (policy v3)

Twenty new detector categories cover Stripe-style keys, package tokens, Twilio-style tokens, webhook secrets, cookies, recovery codes, OTPs, routing numbers, card expiry, labelled US SSNs, medical record identifiers, employee identifiers, vehicle identifiers, GPS coordinates, salary, labelled health information, driving licence numbers, labelled phone values, cloud connection secrets and SSH fingerprints. All patterns are heuristic; some intentionally favour privacy over precision.

## Version 0.3: structured payloads and policy enforcement

Select Plain text or Structured JSON in the browser or use `node cli.mjs --json < input.json`. JSON scanning recursively processes known sensitive field names, arrays, scalar values and keys. Sensitive fields are replaced wholesale, including nested objects. Safe numbers, booleans and nulls are preserved. Detected numeric identifiers become strings. JSON uses standard JSON.parse duplicate-key semantics; formatting and object types may change. Sensitive keys, prototype-related keys, unsafe numeric integers and excessive nesting are rejected. Structured findings omit source offsets.

Choose Redact and review, Block critical or Block any detection. Blocked scans return no content. CLI flags `--block-critical` and `--block-any` return exit code 2 when blocked. `--metadata` exports only counts, policy and category metadata. The browser supports local UTF-8 imports, risk summaries, severity filters, metadata downloads, keyboard scan shortcuts and inactivity clearing. CSV is treated as plain text, not a structured table.

The guarded client accepts `settings: {format: 'json', policy: 'block-critical', mode: 'mask'}`. Review, audit and provider deadlines are configurable. Callbacks receive an AbortSignal and must honour it. An expired provider call cannot be undone. Audit events have per-submission UUIDs. Metadata-only reports may still be sensitive in context; protect their storage.

The expanded Chromium smoke suite exercises local file import, JSON scanning, keyboard activation, severity filters, metadata generation, strict policy blocking and stale-result invalidation. Node integration tests include worker saturation, callback deadlines and static route allowlisting.
