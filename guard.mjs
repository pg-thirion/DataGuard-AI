import {Worker} from 'node:worker_threads';
import {MAX_INPUT} from './engine.mjs';
import {validateSettings,metadataReport} from './pipeline.mjs';
import {randomUUID} from 'node:crypto';
const MAX_ACTIVE=4;
let active=0;
export class GuardError extends Error {
  constructor(code){super(code);this.name='GuardError';this.code=code;}
}
export async function scan(input,options={}){
  if(typeof input!=='string'||input.length>MAX_INPUT)throw new GuardError('INVALID_INPUT');
  if(!options||typeof options!=='object'||Array.isArray(options))throw new GuardError('INVALID_POLICY');
  const {timeoutMs=3000,...settings}=options;
  let mode,format,policy;try{({mode,format,policy}=validateSettings(settings));}catch{throw new GuardError('INVALID_POLICY');}
  if(!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>10000)throw new GuardError('INVALID_POLICY');
  if(active>=MAX_ACTIVE)throw new GuardError('BUSY');
  active++;
  let worker,timer;
  try{
    return await new Promise((resolve,reject)=>{
      worker=new Worker(new URL('./node-worker.mjs',import.meta.url),{workerData:{input,mode,format,policy},resourceLimits:{maxOldGenerationSizeMb:64,maxYoungGenerationSizeMb:16,stackSizeMb:4},execArgv:[]});
      timer=setTimeout(()=>reject(new GuardError('SCAN_TIMEOUT')),timeoutMs);
      worker.once('message',message=>message.ok?resolve(message.result):reject(new GuardError('SCAN_REJECTED')));
      worker.once('error',()=>reject(new GuardError('SCAN_FAILED')));
      worker.once('exit',()=>reject(new GuardError('SCAN_EXITED')));
    });
  }catch(err){throw err instanceof GuardError?err:new GuardError('SCAN_FAILED');}
  finally{clearTimeout(timer);try{if(worker)await worker.terminate();}finally{active--;}}
}
// Trusted callbacks receive no original input. A deadline cannot undo a started provider call.
async function deadline(callback,args,ms,code){
  const controller=new AbortController();let timer;
  try{return await Promise.race([Promise.resolve().then(()=>callback(...args,controller.signal)),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new GuardError(code));},ms);})]);}
  catch{throw new GuardError(code);}finally{clearTimeout(timer);}
}
export function createGuardedClient({review,send,audit,settings={},reviewTimeoutMs=30000,auditTimeoutMs=5000,sendTimeoutMs=30000}){
  if(typeof review!=='function'||typeof send!=='function'||typeof audit!=='function')throw new GuardError('INVALID_ADAPTER');
  const policy=Object.freeze(validateSettings(settings));
  for(const n of [reviewTimeoutMs,auditTimeoutMs,sendTimeoutMs])if(!Number.isInteger(n)||n<10||n>120000)throw new GuardError('INVALID_POLICY');
  return Object.freeze({
    async submit(input){
      const requestId=randomUUID();
      let result;
      try{result=await scan(input,policy);}catch(error){
        await deadline(audit,[Object.freeze({requestId,outcome:'scan-failed'})],auditTimeoutMs,'AUDIT_FAILED');
        throw error;
      }
      const meta=metadataReport(result);
      const event=Object.freeze({...meta,requestId,summary:Object.freeze(meta.summary),breakdown:Object.freeze(meta.breakdown)});
      const log=outcome=>deadline(audit,[Object.freeze({...event,outcome})],auditTimeoutMs,'AUDIT_FAILED');
      if(result.blocked){await log('policy-blocked');throw new GuardError('POLICY_BLOCKED');}
      let approved;
      try{approved=await deadline(review,[Object.freeze({text:result.text,...event})],reviewTimeoutMs,'REVIEW_FAILED');}
      catch(error){await log('review-failed');throw error;}
      if(approved!==true){await log('blocked');throw new GuardError('REVIEW_REQUIRED');}
      await log('approved');
      return deadline(send,[result.text],sendTimeoutMs,'PROVIDER_FAILED');
    }
  });
}
