import {redact,verifyRedacted} from './engine.mjs';
self.onmessage=({data})=>{
  try{
    const result=redact(data.input,{mode:data.mode});
    verifyRedacted(result);
    self.postMessage({ok:true,result});
  }catch{self.postMessage({ok:false});}
};
