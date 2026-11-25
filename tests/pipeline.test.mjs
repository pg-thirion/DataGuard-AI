import assert from 'node:assert/strict';
import test from 'node:test';
import {inspect,metadataReport,validateSettings} from '../pipeline.mjs';
test('nested JSON fields, consistent tokens and preserved types',()=>{
  const r=inspect(JSON.stringify({customer:{full_name:'Jane Example',email:'demo@example.test'},items:[{name:'Jane Example',amount:4,active:true},{name:'John Example',amount:5}],empty:null,password:{nested:'fictional secret'}}),{format:'json'});
  const p=JSON.parse(r.text);
  assert.equal(p.customer.full_name,p.items[0].name);
  assert.notEqual(p.items[0].name,p.items[1].name);
  assert.equal(p.items[0].amount,4);assert.equal(p.items[0].active,true);assert.equal(p.empty,null);
  assert.ok(!r.text.includes('fictional secret'));assert.ok(!r.text.includes('Jane Example'));
  assert.equal(r.findings.length,5);assert.ok(r.findings.every(f=>f.start===null));
});
test('arbitrary string and numeric fields',()=>{
  const r=inspect(JSON.stringify({description:'mail demo@example.test',reference:4111111111111111}),{format:'json'});
  assert.ok(!r.text.includes('demo@example.test'));assert.ok(!r.text.includes('4111111111111111'));assert.equal(r.summary.total,2);
});
test('mask and null semantics',()=>{
  const r=inspect('{"password":"demo","name":null}',{format:'json',mode:'mask'});
  assert.deepEqual(JSON.parse(r.text),{password:'[REDACTED]',name:null});
});
test('malformed JSON, sensitive keys, unsafe numbers, dangerous keys and nesting',()=>{
  for(const [input,code] of [['{','INVALID_JSON'],['{"demo@example.test":1}','SENSITIVE_KEY'],['{"__proto__":1}','UNSAFE_KEY'],['{"amount":9007199254740993}','UNSAFE_NUMBER'],['['.repeat(34)+'0'+']'.repeat(34),'STRUCTURE_LIMIT']])assert.throws(()=>inspect(input,{format:'json'}),{code});
});
test('strict policies suppress content',()=>{
  const a=inspect('password: fake-secret',{policy:'block-critical'});assert.equal(a.blocked,true);assert.equal(a.text,'');assert.equal(a.risk,'critical');
  assert.equal(inspect('demo@example.test',{policy:'block-critical'}).blocked,false);
  const c=inspect('demo@example.test',{policy:'block-any'});assert.equal(c.text,'');assert.equal(c.blocked,true);
  assert.equal(inspect('Safe plain text',{policy:'block-any'}).blocked,false);
});
test('risk and category breakdown',()=>{
  const r=inspect('demo@example.test demo@example.test');assert.equal(r.risk,'medium');assert.equal(r.breakdown.EMAIL,2);assert.equal(inspect('Normal prose').risk,'none-detected');
});
test('metadata report excludes sensitive values and content',()=>{
  const r=metadataReport(inspect('Customer name: Jane Example\npassword: fake-secret'));
  const s=JSON.stringify(r);assert.ok(!s.includes('Jane Example'));assert.ok(!s.includes('fake-secret'));assert.ok(!s.includes('replacement'));assert.ok(!Object.hasOwn(r,'text'));assert.equal(r.summary.total,2);
});
test('invalid settings rejected',()=>{
  for(const x of [null,[],{disabled:['EMAIL']},{format:'csv'},{policy:'allow'},{mode:'wrong'}])assert.throws(()=>validateSettings(x),{code:'INVALID_SETTINGS'});
});
test('Unicode keys and nested arrays',()=>{
  const r=inspect('{"items":[{"ｐａｓｓｗｏｒｄ":"demo-123"},{"first_name":"Jane"}]}',{format:'json'});assert.ok(!r.text.includes('demo-123'));assert.ok(!r.text.includes('Jane'));
});
