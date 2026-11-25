# DataGuard AI

Local-first data loss prevention for AI prompts, support tickets and insurance workflows. A dependency-free, deterministic detector redacts sensitive spans before an application sends content to a model. This is a portfolio MVP, not a certified DLP product.

## Run locally

Requires Node.js 20+ for the CLI and tests, and a modern browser for the workbench.

```sh
npm test
npm start
```

Open http://127.0.0.1:8080. No API key or database is needed.

```sh
node cli.mjs < input.txt > redacted.txt
node cli.mjs --report < input.txt
node cli.mjs --mask < input.txt
```

The report contains redacted output, types, severity, offsets and replacement tokens, never original matched values. Unmatched sensitive data can remain.

## Integrate before model calls

```js
import { prepareForModel, redact } from './engine.mjs';

const { text, summary } = redact(userInput);
const reviewedPrompt = prepareForModel(userInput);
// Review according to your organisation's policy before passing
// reviewedPrompt to your model SDK. Do not send userInput.
```

All processing is in memory. Repeated identical values within a scan receive the same placeholder. Offsets use UTF-16 indices. Mask mode uses a generic placeholder. No reversible mapping is returned. Errors throw rather than returning the original input. The workbench does not send any requests to AI services.

## Coverage

- Personal: emails, South African and international phone patterns, labelled names, addresses, birth dates, IPv4 addresses.
- South African ID candidates: date, citizenship digit and Luhn validation.
- Financial: Luhn-valid payment cards, labelled bank accounts, IBAN-like strings, tax identifiers, CVV and card PIN.
- Insurance: labelled policy, claim and customer numbers, passport numbers.
- Credentials: common API key prefixes, bearer tokens, JWTs, labelled secrets, connection passwords and PEM private keys.

## Security and limitations

The browser policy blocks outbound connections from the app. The code has no analytics, storage, external dependencies or AI calls. The local server binds to loopback and only serves an explicit list of public assets. Never use real data in screenshots or public issue reports. The clipboard and operating system may retain copied output.

Pattern matching is incomplete: unlabelled people and addresses, Unicode obfuscation, unknown secret formats, context-dependent identifiers, images and binary files are not reliably handled. False positives and false negatives are possible. Tokenisation is not proof of anonymisation. The residual check is heuristic, not a safety guarantee. Category disabling weakens protection. Maximum scan size is 200,000 UTF-16 units and 10,000 candidate matches. Split larger inputs carefully, as secrets can cross chunk boundaries.

POPIA and other privacy regulations require organisational controls beyond redaction. Production integration should add human approval, access control, local named-entity recognition, calibrated evaluation on synthetic or authorised data, and a deny-by-default egress gateway. No compliance claim is made.

## Architecture

Browser or CLI → rule matching → overlap merging → per-scan tokenisation → redacted output + metadata → review → optional model integration.

`engine.mjs` is the shared pure redaction module. `app.mjs` renders results using text nodes, and `tests/redaction.test.mjs` contains regression fixtures. No provider SDK is necessary.
