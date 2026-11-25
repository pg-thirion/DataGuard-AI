import {mkdir,rm,copyFile} from 'node:fs/promises';
const output=new URL('./dist/',import.meta.url);
const assets=['index.html','style.css','app.mjs','engine.mjs','pipeline.mjs','scan-worker.mjs','icon.svg'];
await rm(output,{recursive:true,force:true});
await mkdir(output,{recursive:true});
await Promise.all(assets.map(name=>copyFile(new URL(name,import.meta.url),new URL(name,output))));
console.log('Built browser-only DataGuard AI');
