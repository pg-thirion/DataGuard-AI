// Dependency-free Chromium end-to-end smoke test using the DevTools protocol.
// Launch only against synthetic fixtures in a temporary test profile.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createApp } from '../server.mjs';

const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(fn,description,timeout=10000){
  const end=Date.now()+timeout;
  while(Date.now()<end){
    try{const value=await fn();if(value)return value;}catch{}
    await sleep(100);
  }
  throw new Error('Timed out: '+description);
}
const executable=process.env.CHROME_BIN||['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'].find(existsSync);
if(!executable)throw new Error('Set CHROME_BIN to a Chromium-compatible executable');
const profile=await mkdtemp(join(tmpdir(),'dataguard-browser-'));
const server=createApp();
let browser,ws;
try{
  server.listen(0,'127.0.0.1');await once(server,'listening');
  const origin='http://127.0.0.1:'+server.address().port;
  const args=['--headless=new','--disable-gpu','--disable-dev-shm-usage','--disable-background-networking','--disable-sync','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'];
  // CI containers may not support Chromium's sandbox. This applies only to a synthetic test.
  if(process.getuid?.()===0||process.env.CI==='true')args.unshift('--no-sandbox');
  browser=spawn(executable,args,{stdio:'ignore'});
  let launchError;browser.once('error',error=>{launchError=error;});
  const port=await until(async()=>{
    if(launchError)throw launchError;
    const data=await readFile(join(profile,'DevToolsActivePort'),'utf8');
    return Number(data.split('\n')[0]);
  },'Chromium startup',15000);
  const target=await until(async()=>{
    const response=await fetch('http://127.0.0.1:'+port+'/json/list',{signal:AbortSignal.timeout(2000)});
    return (await response.json()).find(x=>x.type==='page');
  },'browser target');
  ws=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('WebSocket startup timeout')),5000);
    ws.addEventListener('open',()=>{clearTimeout(timer);resolve();},{once:true});
    ws.addEventListener('error',()=>{clearTimeout(timer);reject(new Error('WebSocket startup failed'));},{once:true});
  });
  let serial=0;
  const pending=new Map();
  ws.addEventListener('message',({data})=>{
    const msg=JSON.parse(data);const p=pending.get(msg.id);
    if(!p)return;pending.delete(msg.id);clearTimeout(p.timer);
    if(msg.error)p.reject(new Error('DevTools command failed'));else p.resolve(msg.result);
  });
  function cdp(method,params={}){
    return new Promise((resolve,reject)=>{
      const id=++serial;
      const timer=setTimeout(()=>{pending.delete(id);reject(new Error('DevTools timeout: '+method));},5000);
      pending.set(id,{resolve,reject,timer});
      try{ws.send(JSON.stringify({id,method,params}));}catch(error){clearTimeout(timer);pending.delete(id);reject(error);}
    });
  }
  async function js(expression){
    const r=await cdp('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
    if(r.exceptionDetails)throw new Error('Browser expression failed');
    return r.result.value;
  }
  await cdp('Page.enable');await cdp('Page.navigate',{url:origin});
  await until(()=>js("document.readyState==='complete' && !!document.querySelector('#policy div')"),'application startup');
  assert.equal(await js("document.querySelector('#copy').disabled"),true);
  assert.equal(await js("document.querySelector('#download').disabled"),true);
  await js("document.querySelector('#example').click();document.querySelector('#scan').click()");
  await until(()=>js("document.querySelector('#output').value.length>0"),'worker scan result');
  const output=await js("document.querySelector('#output').value");
  assert.match(output,/\[EMAIL_1\]/);assert.match(output,/\[CREDENTIAL_1\]/);
  assert.ok(!output.includes('jane@example.test'));assert.ok(!output.includes('fictional-demo-only'));
  assert.equal(await js("document.querySelector('#copy').disabled"),true);
  await js("document.querySelector('#review').click()");
  assert.equal(await js("document.querySelector('#copy').disabled"),false);
  assert.equal(await js("document.querySelector('#download').disabled"),false);
  await js("document.querySelector('#source').value='modified';document.querySelector('#source').dispatchEvent(new Event('input'))");
  assert.equal(await js("document.querySelector('#output').value"),'');
  assert.equal(await js("document.querySelector('#copy').disabled"),true);
  assert.equal(await js("document.querySelector('#review').checked"),false);
  const hostile='<img src=x onerror="window.__injected=1"> demo@example.test';
  await js("document.querySelector('#source').value="+JSON.stringify(hostile)+";document.querySelector('#source').dispatchEvent(new Event('input'));document.querySelector('#mode').value='mask';document.querySelector('#mode').dispatchEvent(new Event('change'));document.querySelector('#scan').click()");
  await until(()=>js("document.querySelector('#output').value.length>0"),'masked scan result');
  assert.match(await js("document.querySelector('#output').value"),/\[REDACTED\]/);
  assert.equal(await js("Boolean(window.__injected)"),false);
  assert.equal(await js("document.querySelectorAll('img[src=x]').length"),0);
  assert.equal(await js("fetch('/engine.mjs').then(()=>false,()=>true)"),true);
  await js("document.querySelector('#source').value='demo@example.test';document.querySelector('#source').dispatchEvent(new Event('input'));document.querySelector('#scan').click();document.querySelector('#clear').click()");
  await sleep(500);
  assert.equal(await js("document.querySelector('#output').value"),'');
  assert.equal(await js("document.querySelector('#copy').disabled"),true);
  console.log('Browser smoke checks passed: worker, CSP, review, stale output, mask and text rendering.');
}finally{
  if(ws)ws.close();
  if(browser&&browser.exitCode===null&&browser.signalCode===null){
    browser.kill('SIGKILL');
    await Promise.race([once(browser,'exit').catch(()=>{}),sleep(2000)]);
  }
  server.close();server.closeAllConnections();
  await rm(profile,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
