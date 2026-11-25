import assert from 'node:assert/strict';
import test from 'node:test';
import {redact,prepareForModel} from '../engine.mjs';
// Generate synthetic token-shaped strings at runtime, never store credentials.
const fixtures=[
  [
    "STRIPE_KEY",
    [
      "sk",
      "_test_",
      "A",
      24
    ]
  ],
  [
    "PACKAGE_TOKEN",
    [
      "npm",
      "_",
      "A",
      30
    ]
  ],
  [
    "TWILIO_TOKEN",
    [
      "S",
      "K",
      "a",
      32
    ]
  ],
  [
    "WEBHOOK_SECRET",
    [
      "whsec",
      "_",
      "A",
      20
    ]
  ],
  [
    "SESSION_COOKIE",
    "Cookie: sid=fictional123; preference=private"
  ],
  [
    "RECOVERY_CODE",
    "recovery codes: ABC-XYZ-123"
  ],
  [
    "ONE_TIME_CODE",
    "OTP: 493821"
  ],
  [
    "ROUTING_NUMBER",
    "branch code: 123456"
  ],
  [
    "CARD_EXPIRY",
    "card expiry: 04/30"
  ],
  [
    "US_SSN",
    "ssn: 000-00-0000"
  ],
  [
    "MEDICAL_RECORD",
    "MRN: MR-DEMO-22"
  ],
  [
    "EMPLOYEE_ID",
    "employee id: EMP-123"
  ],
  [
    "VEHICLE_ID",
    "vehicle registration: CA 123 456"
  ],
  [
    "GPS_LOCATION",
    "GPS: -33.12345, 18.12345"
  ],
  [
    "SALARY",
    "salary: R 25,000"
  ],
  [
    "HEALTH_INFORMATION",
    "diagnosis: fictional condition"
  ],
  [
    "DRIVING_LICENCE",
    "driving licence number: DEMO-123"
  ],
  [
    "LABELLED_PHONE",
    "phone: 1234567"
  ],
  [
    "CLOUD_SECRET",
    [
      "Account",
      "Key=",
      "A",
      24
    ]
  ],
  [
    "SSH_FINGERPRINT",
    "ssh fingerprint: SHA256:AAAAABBBBB"
  ]
];
for(const [type,fixture] of fixtures)test('Detector: '+type,()=>{
  const input=Array.isArray(fixture)?fixture[0]+fixture[1]+fixture[2].repeat(fixture[3]):fixture;
  const result=redact(input);
  assert.ok(result.findings.some(f=>f.type===type),JSON.stringify(result.findings));
  for(const f of result.findings)assert.ok(!result.text.includes(input.slice(f.start,f.end)));
  assert.doesNotThrow(()=>prepareForModel(input));
});
