// DataGuard AI: deterministic local redaction. No network or persistence.
function luhn(value) {
  const d=value.replace(/\D/g,""); let sum=0;
  for(let i=d.length-1,j=0;i>=0;i--,j++){let n=Number(d[i]);if(j%2)n=n*2>9?n*2-9:n*2;sum+=n;}
  return d.length>0&&sum%10===0;
}
function saId(value){
  const y=Number(value.slice(0,2)),m=Number(value.slice(2,4)),d=Number(value.slice(4,6));
  return [1900+y,2000+y].some(year=>{const date=new Date(Date.UTC(year,m-1,d));return date.getUTCMonth()===m-1&&date.getUTCDate()===d;})&&/[01]/.test(value[10])&&luhn(value);
}
const rules = [
["PRIVATE_KEY","critical",/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g,null,null],
["API_KEY","critical",/\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,null,null],
["JWT","critical",/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,null,null],
["CREDENTIAL","critical",/\b(?:password|passwd|pwd|api[_ -]?key|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|secret[_ -]?key|aws_secret_access_key)\s*["']?\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s,;}\]]+))/gi,[1,2,3],null],
["AUTH_TOKEN","critical",/\bBearer[ \t]+([A-Za-z0-9._~+/=-]{8,})/gi,[1],null],
["CONNECTION_SECRET","critical",/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|https?):\/\/[^\s:/@]+:([^\s/@]+)@/gi,[1],null],
["SA_ID","high",/\b\d{13}\b/g,null,saId],
["PAYMENT_CARD","high",/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,null,v=>{const d=v.replace(/\D/g,"");return d.length>=13&&d.length<=19&&!/^(\d)\1+$/.test(d)&&luhn(d);}],
["BANK_ACCOUNT","high",/\b(?:bank\s+account(?:\s+(?:number|no\.?))?|account\s+(?:number|no\.?)|account_number|iban)\s*["']?\s*[:=]\s*["']?([A-Z]{2}\d{2}[A-Z0-9 ]{8,30}|\d(?:[ -]?\d){5,17})/gi,[1],null],
["FINANCIAL_ID","high",/\b(?:cvv|cvc|card pin|tax(?:payer)? (?:number|id)|vat (?:number|no\.?))\s*["']?\s*[:=]\s*["']?(\d{3,15})\b/gi,[1],null],
["POLICY_NUMBER","high",/\b(?:policy|claim|passport|customer)\s+(?:number|no\.?|id)\s*["']?\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9/-]{3,30})/gi,[1],null],
["EMAIL","medium",/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+/gi,null,null],
["PHONE","medium",/(?<![\w\d])(?:\+27[ .-]?(?:\(0\)[ .-]?)?|0)[1-9]\d(?:[ .-]?\d){7}(?!\d)|(?<![\w\d])\+[1-9]\d{0,2}(?:[ .-]?\d){7,12}(?!\d)/g,null,null],
["IP_ADDRESS","medium",/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,null,v=>v.split(".").every(n=>Number(n)<=255)],
["PERSON_NAME","medium",/\b(?:full name|customer name|policyholder name|patient name|first name|last name|surname|name)\s*["']?\s*[:=]\s*["']?([\p{L}][\p{L}.'’ -]{1,79}?)(?=["'\r\n,;]|$)/giu,[1],null],
["ADDRESS","medium",/\b(?:street address|postal address|home address|address)\s*["']?\s*[:=]\s*["']?([^\r\n";]{4,160})/gi,[1],null],
["DATE_OF_BIRTH","medium",/\b(?:date of birth|dob|birth date)\s*["']?\s*[:=]\s*["']?(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})/gi,[1],null]
];
export function redact(input,options={}){
  if(typeof input!=="string")throw new TypeError("Input must be text");
  if(input.length>200000)throw new RangeError("Maximum input is 200,000 UTF-16 code units");
  if(options.mode!==undefined&&!["token","mask"].includes(options.mode))throw new TypeError("Invalid mode");
  const candidates=[], disabled=new Set(options.disabled||[]);
  const rank={critical:3,high:2,medium:1};
  for(const [type,severity,pattern,groups,validate] of rules){
    if(disabled.has(type))continue;
    const re=new RegExp(pattern.source,pattern.flags.includes("d")?pattern.flags:pattern.flags+"d");
    for(const match of input.matchAll(re)){
      const idx=groups?groups.find(i=>match[i]!==undefined):0;
      if(idx===undefined)continue;
      const value=match[idx], [start,end]=match.indices[idx];
      if(!value||validate&&!validate(value))continue;
      if(candidates.length>=10000)throw new RangeError("Too many matches; split the input");
      candidates.push({type,severity,start,end});
    }
  }
  // Merge overlapping spans instead of dropping a partially covered secret.
  candidates.sort((a,b)=>a.start-b.start||b.end-a.end||rank[b.severity]-rank[a.severity]);
  const spans=[];
  for(const c of candidates){
    const p=spans[spans.length-1];
    if(p&&c.start<p.end){
      p.end=Math.max(p.end,c.end);
      if(rank[c.severity]>rank[p.severity]){p.type=c.type;p.severity=c.severity;}
    }else spans.push({...c});
  }
  const counts={}, identities=new Map(),findings=[];let output="",cursor=0;
  for(const span of spans){
    const {type,severity,start,end}=span;
    const value=input.slice(start,end),key=type+"\0"+value;
    if(!identities.has(key)){counts[type]=(counts[type]||0)+1;identities.set(key,"["+type+"_"+counts[type]+"]");}
    const replacement=options.mode==="mask"?"[REDACTED]":identities.get(key);
    output+=input.slice(cursor,start)+replacement;cursor=end;
    findings.push({type,severity,start,end,replacement});
  }
  output+=input.slice(cursor);
  return {text:output,findings,summary:{total:findings.length,critical:findings.filter(x=>x.severity==="critical").length,high:findings.filter(x=>x.severity==="high").length,medium:findings.filter(x=>x.severity==="medium").length}};
}
export function prepareForModel(input){
  const result=redact(input);
  if(redact(result.text).findings.some(f=>!/\[(?:[A-Z_]+_\d+|REDACTED)\]/.test(result.text.slice(f.start,f.end))))throw new Error("Residual sensitive pattern detected; review manually");
  return result.text;
}
export const categories = rules.map(([type,severity])=>({type,severity}));
