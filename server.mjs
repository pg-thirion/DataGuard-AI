import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
const files={'/':'index.html','/index.html':'index.html','/style.css':'style.css','/app.mjs':'app.mjs','/engine.mjs':'engine.mjs','/icon.svg':'icon.svg'};
const mime={html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',mjs:'text/javascript; charset=utf-8',svg:'image/svg+xml'};
createServer(async(req,res)=>{
res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
const path=req.url?.split('?')[0];if(req.method!=='GET'||!Object.hasOwn(files,path)){res.writeHead(404);res.end('Not found');return;}
try{const file=files[path];const data=await readFile(new URL(file,import.meta.url));res.setHeader('Content-Type',mime[file.split('.').pop()]);res.end(data);}catch{res.writeHead(500);res.end('Server error');}
}).listen(8080,'127.0.0.1',()=>console.log('DataGuard AI: http://127.0.0.1:8080'));
