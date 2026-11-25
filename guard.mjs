import {Worker} from 'node:worker_threads';
import {MAX_INPUT} from './engine.mjs';
const MAX_ACTIVE=4;
let active=0;
export class GuardError extends Error {
  constructor(code){super(code);this.name='GuardError';this.code=code;}
}
export async function scan(input,{mode='token',timeoutMs=3000}={}){
  if(typeof input!=='string'||input.length>MAX_INPUT)throw new GuardError('INVALID_INPUT');
  if(!['token','mask'].includes(mode)||!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>10000)throw new GuardError('INVALID_POLICY');
  if(active>=MAX_ACTIVE)throw new GuardError('BUSY');
  active++;
  let worker,timer;
  try{
    return await new Promise((resolve,reject)=>{
      worker=new Worker(new URL('./node-worker.mjs',import.meta.url),{workerData:{input,mode},resourceLimits:{maxOldGenerationSizeMb:64,maxYoungGenerationSizeMb:16,stackSizeMb:4},execArgv:[]});
      timer=setTimeout(()=>reject(new GuardError('SCAN_TIMEOUT')),timeoutMs);
      worker.once('message',message=>message.ok?resolve(message.result):reject(new GuardError('SCAN_REJECTED')));
      worker.once('error',()=>reject(new GuardError('SCAN_FAILED')));
      worker.once('exit',()=>reject(new GuardError('SCAN_EXITED')));
    });
  }catch(err){throw err instanceof GuardError?err:new GuardError('SCAN_FAILED');}
  finally{clearTimeout(timer);try{if(worker)await worker.terminate();}finally{active--;}}
}
// Trusted application callbacks only. No original text or raw matched values are passed.
export function createGuardedClient({review,send,audit=()=>{}}){
  if(typeof review!=='function'||typeof send!=='function'||typeof audit!=='function')throw new GuardError('INVALID_ADAPTER');
  return Object.freeze({
    async submit(input){
      const result=await scan(input);
      const event=Object.freeze({policyVersion:result.policyVersion,summary:Object.freeze({...result.summary})});
      const reviewed=Object.freeze({text:result.text,...event});
      let approved;
      try{approved=await review(reviewed);}catch{throw new GuardError('REVIEW_FAILED');}
      if(approved!==true){await audit(Object.freeze({...event,outcome:'blocked'}));throw new GuardError('REVIEW_REQUIRED');}
      // Audit failure blocks egress. Only the immutable, reviewed prompt goes to the provider.
      try{await audit(Object.freeze({...event,outcome:'approved'}));}catch{throw new GuardError('AUDIT_FAILED');}
      try{return await send(result.text);}catch{throw new GuardError('PROVIDER_FAILED');}
    }
  });
}
