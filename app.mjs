import {categories,MAX_INPUT} from './engine.mjs';
const $=id=>document.getElementById(id);
const source=$('source'),output=$('output'),findings=$('findings'),review=$('review');
const human=s=>s.toLowerCase().replaceAll('_',' ').replace(/^./,x=>x.toUpperCase());
let worker=null,timer=null,generation=0,ready=false;
for(const c of categories){const item=document.createElement('div');item.textContent=human(c.type);item.className=c.severity;$('policy').append(item);}
function cancel(){generation++;if(worker)worker.terminate();worker=null;clearTimeout(timer);$('scan').disabled=false;}
function reset(){cancel();ready=false;review.checked=false;review.disabled=true;output.value='';findings.replaceChildren();for(const k of ['total','critical','high','medium'])$(k).textContent='0';$('copy').disabled=true;$('download').disabled=true;$('resultState').textContent='Not scanned';$('empty').hidden=false;$('empty').textContent='No scan results yet.';$('status').textContent='';$('length').textContent=source.value.length.toLocaleString()+' / '+MAX_INPUT.toLocaleString()+' characters';}
function gate(){const enabled=ready&&review.checked&&Boolean(output.value);$('copy').disabled=!enabled;$('download').disabled=!enabled;}
source.addEventListener('input',reset);$('mode').addEventListener('change',reset);review.addEventListener('change',gate);
$('clear').addEventListener('click',()=>{source.value='';reset();source.focus();});
$('example').addEventListener('click',()=>{source.value='Customer name: Jane Example\nEmail: jane@example.test\nPhone: +27 82 555 0199\nClaim number: CLM-2026-TEST\nBank account: 1234567890\nPayment card: 4111 1111 1111 1111\npassword: "fictional-demo-only"\nIP address: 192.0.2.10\n\nPlease summarise this synthetic support ticket.';reset();source.focus();});
function failed(message){cancel();ready=false;output.value='';$('status').textContent=message;}
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
      const frag=document.createDocumentFragment();
      for(const f of r.findings.slice(0,500)){const tr=document.createElement('tr');for(const val of [human(f.type),f.severity,String(f.start)+'–'+String(f.end),f.replacement]){const td=document.createElement('td');td.textContent=val;if(val===f.severity)td.className=f.severity;tr.append(td);}frag.append(tr);}
      findings.append(frag);$('empty').hidden=r.findings.length>0;$('empty').textContent='No patterns matched. Manual review is still required.';
      $('resultState').textContent='Scanned • review required';$('status').textContent=r.findings.length+' sensitive spans replaced. '+(r.findings.length>500?'Showing the first 500 findings. ':'')+'Review before export.';
      ready=true;review.disabled=false;gate();
    };
    worker.postMessage({input:source.value,mode:$('mode').value});
  }catch{failed('Unable to start local scanner. No output released.');}
});
$('copy').addEventListener('click',async()=>{if(!ready||!review.checked)return;try{await navigator.clipboard.writeText(output.value);$('status').textContent='Reviewed output copied.';}catch{$('status').textContent='Clipboard unavailable. Use the reviewed download.';}});
$('download').addEventListener('click',()=>{if(!ready||!review.checked)return;const url=URL.createObjectURL(new Blob([output.value],{type:'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='dataguard-redacted.txt';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
window.addEventListener('pagehide',()=>{source.value='';reset();});
window.addEventListener('pageshow',e=>{if(e.persisted){source.value='';reset();}});
reset();
