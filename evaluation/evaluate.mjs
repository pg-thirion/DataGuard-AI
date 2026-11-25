import {redact} from '../engine.mjs';
// Hand-authored synthetic smoke corpus, not a representative production dataset.
const cases=[
 ['Email: demo@example.test',['demo@example.test']],
 ['Please contact +27 82 555 0199',['+27 82 555 0199']],
 ['name: Jane Example',['Jane Example']],
 ['password: "fictional secret"',['fictional secret']],
 ['Card: 4111 1111 1111 1112',['4111 1111 1111 1112']],
 ['claim number: CLM-FAKE-123',['CLM-FAKE-123']],
 ['bank account: 1234567890',['1234567890']],
 ['demo\u200b@example.test',['demo\u200b@example.test']],
 ['DOB: 1990-01-01',['1990-01-01']],
 ['Customer name: Zoë Example',['Zoë Example']],
 ['Please review the quarterly report.',[]],
 ['The meeting starts at 09:30.',[]],
 ['Order contains three items.',[]],
 ['The rainfall was 12 mm.',[]],
 ['Jane Example visited Cape Town.',['Jane Example']],
 ['Contact demo [at] example [dot] test.',['demo [at] example [dot] test']]
];
let tp=0,fn=0,fp=0,clean=0;
for(const [input,expected] of cases){
 const result=redact(input);
 for(const secret of expected){const start=input.indexOf(secret),end=start+secret.length; if(result.findings.some(f=>f.start<=start&&f.end>=end))tp++;else fn++;}
 for(const f of result.findings){if(!expected.some(secret=>{const start=input.indexOf(secret);return f.start<=start&&f.end>=start+secret.length;}))fp++;}
 if(!expected.length&&!result.findings.length)clean++;
}
console.log(JSON.stringify({corpus:'synthetic smoke only',cases:cases.length,truePositives:tp,falseNegatives:fn,falsePositives:fp,cleanCases:clean,precision:tp/(tp+fp),recall:tp/(tp+fn)},null,2));
