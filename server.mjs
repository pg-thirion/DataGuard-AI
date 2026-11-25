import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
const files={'/':'index.html','/index.html':'index.html','/style.css':'style.css','/app.mjs':'app.mjs','/engine.mjs':'engine.mjs','/scan-worker.mjs':'scan-worker.mjs','/icon.svg':'icon.svg'};
const mime={html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',mjs:'text/javascript; charset=utf-8',svg:'image/svg+xml'};
export function createApp({allowedHosts=['127.0.0.1','localhost']}={}){
  const server=createServer({requestTimeout:5000,headersTimeout:5000,keepAliveTimeout:2000,maxHeaderSize:8192},async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','DENY');
    res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=()');
    res.setHeader('Cross-Origin-Opener-Policy','same-origin');res.setHeader('Cross-Origin-Resource-Policy','same-origin');
    res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'");
    if(!allowedHosts.some(h=>req.headers.host===h||new RegExp('^'+h.replaceAll('.','\\.')+':[0-9]{1,5}$').test(req.headers.host||''))){res.writeHead(421);res.end('Invalid host');return;}
    if(!['GET','HEAD'].includes(req.method)){res.setHeader('Allow','GET, HEAD');res.writeHead(405);res.end('Method not allowed');return;}
    const path=req.url?.split('?')[0];if(!Object.hasOwn(files,path)){res.writeHead(404);res.end('Not found');return;}
    try{const file=files[path],data=await readFile(new URL(file,import.meta.url));res.setHeader('Content-Type',mime[file.split('.').pop()]);res.setHeader('Content-Length',data.length);res.end(req.method==='HEAD'?undefined:data);}catch{res.writeHead(500);res.end('Server error');}
  });
  server.maxConnections=64;server.maxRequestsPerSocket=100;
  return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const server=createApp();server.listen(8080,'127.0.0.1',()=>console.log('DataGuard AI: http://127.0.0.1:8080'));
  for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{server.close();server.closeAllConnections();});
}
