import {parentPort,workerData} from 'node:worker_threads';
import {redact,verifyRedacted} from './engine.mjs';
try{const result=redact(workerData.input,{mode:workerData.mode});verifyRedacted(result);parentPort.postMessage({ok:true,result});}catch{parentPort.postMessage({ok:false});}
