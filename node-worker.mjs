import {parentPort,workerData} from 'node:worker_threads';
import {inspect} from './pipeline.mjs';
try{const {input,mode,format,policy}=workerData;parentPort.postMessage({ok:true,result:inspect(input,{mode,format,policy})});}catch{parentPort.postMessage({ok:false});}
