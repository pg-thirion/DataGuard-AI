import test from 'node:test';
import assert from 'node:assert/strict';
import {createGuardedClient,scan} from '../guard.mjs';
import {createApp} from '../server.mjs';
import {spawnSync} from 'node:child_process';
import {once} from 'node:events';

test('guard sends only reviewed redacted prompt; audit has no text',async()=>{
  const events=[];let calls=0;
  const client=createGuardedClient({review:async r=>{assert.equal(r.text,'email: [EMAIL_1]');return true;},audit:e=>events.push(e),send:async p=>{calls++;return p;}});
  assert.equal(await client.submit('email: demo@example.test'),'email: [EMAIL_1]');
  assert.equal(calls,1);assert.equal(events[0].outcome,'approved');assert.ok(!JSON.stringify(events).includes('example.test'));
});
test('denied review, audit error and scan error prevent egress',async()=>{
  let calls=0;const send=()=>{calls++;};
  for(const [review,audit,input,code] of [[()=>false,()=>{},'demo@example.test','REVIEW_REQUIRED'],[()=>true,()=>{throw Error('audit');},'demo@example.test','AUDIT_FAILED'],[()=>true,()=>{},'x'.repeat(200001),'INVALID_INPUT']]){
    await assert.rejects(createGuardedClient({review,audit,send}).submit(input),{code});
  }
  assert.equal(calls,0);
});
test('worker handles strict scans and rejects invalid input',async()=>{
  assert.equal((await scan('password: test-secret')).text,'password: [CREDENTIAL_1]');
  await assert.rejects(scan(null),{code:'INVALID_INPUT'});
  await assert.rejects(scan('x',{timeoutMs:1}),{code:'INVALID_POLICY'});
});
test('CLI fails without leaking original or malformed bytes',()=>{
  const r=spawnSync(process.execPath,['cli.mjs'],{input:Buffer.from([0xff]),encoding:'utf8'});
  assert.equal(r.status,1);assert.equal(r.stdout,'');
  const s=spawnSync(process.execPath,['cli.mjs'],{input:'demo@example.test',encoding:'utf8'});
  assert.equal(s.status,0);assert.equal(s.stdout,'[EMAIL_1]');
});
test('static server restricts host, methods, paths and egress',async()=>{
  const server=createApp();server.listen(0,'127.0.0.1');await once(server,'listening');
  const base='http://127.0.0.1:'+server.address().port;
  try{
    const r=await fetch(base);assert.equal(r.status,200);
    assert.match(r.headers.get('content-security-policy'),/connect-src 'none'/);
    assert.match(r.headers.get('content-security-policy'),/worker-src 'self'/);
    assert.equal(r.headers.get('cache-control'),'no-store');
    assert.equal((await fetch(base+'/guard.mjs')).status,404);
    assert.equal((await fetch(base+'/scan-worker.mjs')).status,200);
    assert.equal((await fetch(base,{method:'POST',body:'demo@example.test'})).status,405);
    assert.equal((await fetch(base,{headers:{host:'attacker.invalid'}})).status,421);
    assert.equal((await fetch(base,{method:'HEAD'})).status,200);
  }finally{server.close();server.closeAllConnections();}
});

test('audit adapter is mandatory and audit failure on denial is sanitised',async()=>{
  assert.throws(()=>createGuardedClient({review:()=>true,send:()=>{}}),{code:'INVALID_ADAPTER'});
  let sent=false;
  await assert.rejects(createGuardedClient({review:()=>false,audit:()=>{throw Error('private error');},send:()=>{sent=true;}}).submit('demo@example.test'),{code:'AUDIT_FAILED'});
  assert.equal(sent,false);
});

test('strict adapter blocks before review and egress with correlated audit',async()=>{
  let calls=0;const events=[];
  const client=createGuardedClient({settings:{policy:'block-any'},review:()=>{calls++;return true;},send:()=>{calls++;},audit:e=>events.push(e)});
  await assert.rejects(client.submit('demo@example.test'),{code:'POLICY_BLOCKED'});
  assert.equal(calls,0);assert.equal(events[0].outcome,'policy-blocked');assert.match(events[0].requestId,/^[a-f0-9-]{36}$/);
});
test('review deadline prevents provider call and logs failure',async()=>{
  let sent=false;const events=[];
  const c=createGuardedClient({reviewTimeoutMs:20,review:()=>new Promise(()=>{}),audit:e=>events.push(e),send:()=>{sent=true;}});
  await assert.rejects(c.submit('demo@example.test'),{code:'REVIEW_FAILED'});
  assert.equal(sent,false);assert.equal(events[0].outcome,'review-failed');
});
test('CLI structured JSON, metadata and blocking exit code',()=>{
  const r=spawnSync(process.execPath,['cli.mjs','--json'],{input:'{"name":"Jane Example","total":42}',encoding:'utf8'});
  assert.equal(r.status,0);assert.equal(JSON.parse(r.stdout).total,42);assert.ok(!r.stdout.includes('Jane Example'));
  const s=spawnSync(process.execPath,['cli.mjs','--block-any','--metadata'],{input:'demo@example.test',encoding:'utf8'});
  assert.equal(s.status,2);assert.equal(JSON.parse(s.stdout).blocked,true);assert.ok(!s.stdout.includes('example.test'));
});

test('four worker slots are bounded and reusable',async()=>{
  const pending=Array.from({length:4},()=>scan('demo@example.test'));
  await assert.rejects(scan('another@example.test'),{code:'BUSY'});
  const results=await Promise.all(pending);assert.equal(results.length,4);
  assert.ok(results.every(r=>r.text==='[EMAIL_1]'));
  assert.equal((await scan('Clean content')).text,'Clean content');
});
test('provider deadline signals cancellation',async()=>{
  let signal,events=[];
  const client=createGuardedClient({review:()=>true,audit:e=>events.push(e),sendTimeoutMs:20,send:(_text,s)=>{signal=s;return new Promise(()=>{});}});
  await assert.rejects(client.submit('demo@example.test'),{code:'PROVIDER_FAILED'});
  assert.equal(signal.aborted,true);assert.equal(events[0].outcome,'approved');
});
test('audit timeout blocks egress',async()=>{
  let sent=false,signal;
  const client=createGuardedClient({review:()=>true,auditTimeoutMs:20,audit:(_e,s)=>{signal=s;return new Promise(()=>{});},send:()=>{sent=true;}});
  await assert.rejects(client.submit('demo@example.test'),{code:'AUDIT_FAILED'});
  assert.equal(signal.aborted,true);assert.equal(sent,false);
});
test('HTTP allowlist serves pipeline module, rejects traversal and secret files',async()=>{
  const server=createApp();server.listen(0,'127.0.0.1');await once(server,'listening');
  const base='http://127.0.0.1:'+server.address().port;
  try{
    assert.equal((await fetch(base+'/pipeline.mjs')).status,200);
    for(const path of ['/.git/config','/tests/integration.test.mjs','/guard.mjs','/%2e%2e%2fREADME.md'])assert.equal((await fetch(base+path)).status,404);
  }finally{server.close();server.closeAllConnections();}
});
