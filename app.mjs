import {categories,MAX_INPUT} from './engine.mjs';
import {metadataReport} from './pipeline.mjs';
const $=id=>document.getElementById(id);
const source=$('source'),output=$('output'),findings=$('findings'),review=$('review');
const human=s=>s.toLowerCase().replaceAll('_',' ').replace(/^./,x=>x.toUpperCase());
let worker=null,timer=null,generation=0,ready=false,last=null,idle=null;
for(const c of categories){const item=document.createElement('div');item.textContent=human(c.type);item.className=c.severity;$('policy').append(item);}
function cancel(){generation++;if(worker)worker.terminate();worker=null;clearTimeout(timer);$('scan').disabled=false;}
function reset(){cancel();ready=false;last=null;$('report').disabled=true;$('risk').textContent='';$('counts').textContent='';review.checked=false;review.disabled=true;output.value='';findings.replaceChildren();for(const k of ['total','critical','high','medium'])$(k).textContent='0';$('copy').disabled=true;$('download').disabled=true;$('resultState').textContent='Not scanned';$('empty').hidden=false;$('empty').textContent='No scan results yet.';$('status').textContent='';$('length').textContent=source.value.length.toLocaleString()+' / '+MAX_INPUT.toLocaleString()+' characters • '+new TextEncoder().encode(source.value).length.toLocaleString()+' bytes';}
function gate(){const enabled=ready&&review.checked&&Boolean(output.value);$('copy').disabled=!enabled;$('download').disabled=!enabled;}
source.addEventListener('input',reset);for(const k of ['mode','format','egress'])$(k).addEventListener('change',reset);review.addEventListener('change',gate);
$('clear').addEventListener('click',()=>{source.value='';$('file').value='';reset();source.focus();});
$('example').addEventListener('click',()=>{$('format').value='text';source.value='Customer name: Jane Example\nEmail: jane@example.test\nPhone: +27 82 555 0199\nClaim number: CLM-2026-TEST\nBank account: 1234567890\nPayment card: 4111 1111 1111 1111\npassword: "fictional-demo-only"\nIP address: 192.0.2.10\n\nPlease summarise this synthetic support ticket.';reset();source.focus();});
$('file').addEventListener('change',async()=>{
  const file=$('file').files[0];$('file').value='';if(!file)return;reset();const job=generation;
  try{if(file.size>MAX_INPUT*4)throw Error();const text=new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer());if(job!==generation)return;if(text.length>MAX_INPUT||text.includes('\0'))throw Error();source.value=text;$('format').value=/\.json$/i.test(file.name)?'json':'text';reset();$('status').textContent='File imported locally. Scan before sharing.';}catch{if(job===generation)$('status').textContent='Import rejected: use a supported UTF-8 file within the limit.';}
});
function failed(message){cancel();ready=false;output.value='';$('status').textContent=message;}
function renderFindings(){
  findings.replaceChildren();if(!last)return;
  const filtered=last.findings.filter(f=>$('filter').value==='all'||f.severity===$('filter').value),frag=document.createDocumentFragment();
  for(const f of filtered.slice(0,500)){const tr=document.createElement('tr');for(const val of [human(f.type),f.severity,f.start===null?'Structured '+f.kind:String(f.start)+'–'+String(f.end),last.blocked?'Blocked':f.replacement]){const td=document.createElement('td');td.textContent=val;if(val===f.severity)td.className=f.severity;tr.append(td);}frag.append(tr);}
  findings.append(frag);$('empty').hidden=filtered.length>0;$('empty').textContent=last.findings.length?'No findings match this filter.':'No patterns matched. Manual review is still required.';
  if(filtered.length>500)$('empty').hidden=false,$('empty').textContent='Showing first 500 matching findings.';
}
$('filter').addEventListener('change',renderFindings);
$('scan').addEventListener('click',()=>{
  reset();if(!source.value.trim()){$('status').textContent='Enter content to scan.';return;}
  if(source.value.length>MAX_INPUT){failed('Input exceeds the scan limit.');return;}
  $('scan').disabled=true;$('status').textContent='Scanning locally…';
  const job=generation;
  try{
    worker=new Worker(new URL('./scan-worker.mjs',import.meta.url),{type:'module'});
    timer=setTimeout(()=>failed('Scan timed out. No output released.'),3000);
    worker.onerror=()=>{if(job===generation)failed('Scan failed. No output released.');};
    worker.onmessage=({data})=>{
      if(job!==generation)return;
      if(!data.ok){failed('Scan or residual check failed. No output released.');return;}
      cancel();const r=data.result;output.value=r.text;
      for(const [k,v] of Object.entries(r.summary))$(k).textContent=String(v);
      last=r;renderFindings();$('report').disabled=false;
      $('risk').textContent='Input risk: '+human(r.risk);$('counts').textContent=Object.entries(r.breakdown).map(([k,v])=>human(k)+': '+v).join(' • ');
      $('resultState').textContent=r.blocked?'Blocked by policy':'Scanned • review required';$('status').textContent=r.blocked?'Policy blocked export. No content released.':r.findings.length+' sensitive spans replaced. Review before export.';
      ready=!r.blocked;review.disabled=!ready;gate();
    };
    worker.postMessage({input:source.value,mode:$('mode').value,format:$('format').value,policy:$('egress').value});
  }catch{failed('Unable to start local scanner. No output released.');}
});
$('copy').addEventListener('click',async()=>{if(!ready||!review.checked)return;const job=generation;try{await navigator.clipboard.writeText(output.value);if(job===generation)$('status').textContent='Reviewed output copied.';}catch{if(job===generation)$('status').textContent='Clipboard unavailable. Use the reviewed download.';}});
$('download').addEventListener('click',()=>{if(!ready||!review.checked)return;const url=URL.createObjectURL(new Blob([output.value],{type:last.format==='json'?'application/json':'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=last.format==='json'?'dataguard-redacted.json':'dataguard-redacted.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('report').addEventListener('click',()=>{if(!last)return;const url=URL.createObjectURL(new Blob([JSON.stringify(metadataReport(last),null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='dataguard-metadata.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
function touch(){clearTimeout(idle);idle=setTimeout(()=>{source.value='';reset();$('status').textContent='Workspace cleared after inactivity.';},300000);}
document.addEventListener('keydown',e=>{touch();if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();if(!$('scan').disabled)$('scan').click();}});
document.addEventListener('pointerdown',touch);source.addEventListener('input',touch);
window.addEventListener('pagehide',()=>{clearTimeout(idle);source.value='';reset();});
window.addEventListener('pageshow',e=>{if(e.persisted){source.value='';reset();}touch();});
reset();
touch();
