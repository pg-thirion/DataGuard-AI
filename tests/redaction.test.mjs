import assert from 'node:assert/strict';
import {redact,prepareForModel} from '../engine.mjs';
const samples=[
  [
    "Email: demo@example.test. Again demo@example.test",
    "EMAIL",
    2
  ],
  [
    "Card: 4111 1111 1111 1111",
    "PAYMENT_CARD",
    1
  ],
  [
    "Card: 4111 1111 1111 1112",
    null,
    0
  ],
  [
    "Customer name: Jane Example\nPhone: +27 82 555 0199",
    "PERSON_NAME",
    1
  ],
  [
    "password: \"not a real secret\"",
    "CREDENTIAL",
    1
  ],
  [
    "account number: 1234567890",
    "BANK_ACCOUNT",
    1
  ],
  [
    "Authorization: Bearer demo.token_123456",
    "AUTH_TOKEN",
    1
  ],
  [
    "IP 192.0.2.1",
    "IP_ADDRESS",
    1
  ],
  [
    "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----",
    "PRIVATE_KEY",
    1
  ],
  [
    "Normal sentence about rainfall.",
    null,
    0
  ],
  [
    "DOB: 1990-01-01",
    "DATE_OF_BIRTH",
    1
  ],
  [
    "claim number: CLM-12345",
    "POLICY_NUMBER",
    1
  ],
  [
    "{\"password\":\"test-credential\"}",
    "CREDENTIAL",
    1
  ],
  [
    "name: Jane Example",
    "PERSON_NAME",
    1
  ],
  [
    "password: demo@example.test",
    "CREDENTIAL",
    1
  ]
];
function runChecks(){
 for(const [input,type,n] of samples){const r=redact(input);const found=type?r.findings.filter(f=>f.type===type).length:r.findings.length;if(found!==n)throw new Error("Unexpected "+type+": "+JSON.stringify(r));for(const f of r.findings){if(r.text.includes(input.slice(f.start,f.end)))throw new Error("Leak "+f.type);}}
 const r=redact("demo@example.test demo@example.test");if(r.findings[0].replacement!==r.findings[1].replacement)throw Error("Inconsistent token");
 if(redact("demo@example.test",{mode:"mask"}).text!=="[REDACTED]")throw Error("Mask failed");
 if(redact("demo@example.test",{disabled:["EMAIL"]}).findings.length)throw Error("Policy failed");
 if(prepareForModel("email: demo@example.test")!=="email: [EMAIL_1]")throw Error("Guard failed");
}
runChecks();
assert.throws(()=>redact(null),TypeError);
assert.throws(()=>redact('x'.repeat(200001)),RangeError);
assert.throws(()=>redact('x',{mode:'wrong'}),TypeError);
assert.equal(redact('email: demo@example.test').findings[0].start,7);
console.log('All DataGuard regression checks passed');
