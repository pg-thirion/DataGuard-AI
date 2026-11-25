import {inspect} from './pipeline.mjs';
self.onmessage=({data})=>{try{self.postMessage({ok:true,result:inspect(data.input,{mode:data.mode,format:data.format,policy:data.policy})});}catch{self.postMessage({ok:false});}};
