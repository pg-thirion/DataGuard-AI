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
export const POLICY_VERSION = "3.0.0";
export const MAX_INPUT = 200000;
function normalise(input) {
  let text="";
  const starts=[],ends=[];
  for(let i=0;i<input.length;){
    const cp=String.fromCodePoint(input.codePointAt(i)), end=i+cp.length;
    const normal=cp.normalize("NFKC").replace(/[\p{Cf}\u00ad]/gu,"").replace(/[\u2010-\u2015\u2212]/g,"-");
    text+=normal;
    for(let j=0;j<normal.length;j++){starts.push(i);ends.push(end);}
    i=end;
  }
  if(text.length>MAX_INPUT*3)throw new RangeError("Normalised input exceeds limit");
  return {text,starts,ends};
}
const rules = [
["PRIVATE_KEY","critical",/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)/g,null,null],
["API_KEY","critical",/\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,null,null],
["WEB_SECRET","critical",/\b(?:token|signature|sig|key|password|secret|code)=([^&#\s"'<>]+)/gi,[1],null],
["JWT","critical",/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,null,null],
["CREDENTIAL","critical",/\b(?:password|passwd|pwd|api[_ -]?key|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|secret[_ -]?key|aws_secret_access_key|session[_ -]?token|authorization[_ -]?token|private[_ -]?key|wagwoord)\s*["']?\s*[:=]\s*(?:"((?:\\.|[^"\\\r\n])*)(?:"|(?=\r?\n|$))|'((?:\\.|[^'\\\r\n])*)(?:'|(?=\r?\n|$))|([^\s,;}]+))/gi,[1,2,3],null],
["AUTH_TOKEN","critical",/\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{4,})/gi,[1],null],
["CONNECTION_SECRET","critical",/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|https?|ftp|amqps?):\/\/([^\s/:@]+:[^\s/@]+)@/gi,[1],null],
["LABELLED_ID","high",/\b(?:south african id|national[_ ]id|identity[_ ]number|id[_ ]number|idnommer|identiteitsnommer|id)\s*["']?\s*[:=]\s*["']?([A-Z0-9](?:[ -]?[A-Z0-9]){5,})/gi,[1],null],
["LABELLED_CARD","high",/\b(?:(?:payment|credit|debit)[_ ]card(?:[_ ]number)?|card[_ ]number|card)\s*["']?\s*[:=]\s*["']?(\d(?:[ -]?\d){7,})/gi,[1],null],
["SA_ID","high",/\b\d{13}\b/g,null,saId],
["PAYMENT_CARD","high",/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,null,v=>{const d=v.replace(/\D/g,"");return d.length>=13&&d.length<=19&&!/^(\d)\1+$/.test(d)&&luhn(d);}],
["BANK_ACCOUNT","high",/\b(?:bank[_ ]account(?:[_ ](?:number|no\.?))?|account[_ ](?:number|no\.?)|iban|rekeningnommer)\s*["']?\s*[:=]\s*["']?([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){8,}|\d(?:[ -]?\d){3,})/gi,[1],null],
["FINANCIAL_ID","high",/\b(?:cvv|cvc|card pin|tax(?:payer)? (?:number|id)|vat (?:number|no\.?))\s*["']?\s*[:=]\s*["']?(\d{3,})\b/gi,[1],null],
["POLICY_NUMBER","high",/\b(?:(?:policy|claim|passport|customer|member|medical[_ ]aid)[_ ](?:number|no\.?|id)|polisnommer|eisnommer|paspoortnommer)\s*["']?\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9_/-]{1,})/gi,[1],null],
["OBFUSCATED_EMAIL","medium",/(?<![\w.])[A-Z0-9._%+-]{1,128}[ \t]{0,8}(?:\[at\]|\(at\))[ \t]{0,8}[A-Z0-9-]{1,63}(?:[ \t]{0,8}(?:\[dot\]|\(dot\)|\.)[ \t]{0,8}[A-Z0-9-]{1,63}){1,10}(?![\w-])/gi,null,null],
["EMAIL","medium",/(?<![A-Z0-9.!#$%&'*+/=?^_`{|}~-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,128}@[A-Z0-9-]{1,63}(?:\.[A-Z0-9-]{1,63}){1,10}(?![A-Z0-9-])/gi,null,null],
["PHONE","medium",/(?<![\w\d])(?:\+27[ .-]?(?:\(0\)[ .-]?)?|0)[1-9]\d(?:[ .-]?\d){7}(?!\d)|(?<![\w\d])\+[1-9]\d{0,2}(?:[ .-]?\d){7,12}(?!\d)/g,null,null],
["MAC_ADDRESS","medium",/\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi,null,null],
["IP_ADDRESS","medium",/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,null,v=>v.split(".").every(n=>Number(n)<=255)],
["PERSON_NAME","medium",/\b(?:full[_ ]name|customer[_ ]name|policyholder[_ ]name|patient[_ ]name|first[_ ]name|last[_ ]name|surname|name|naam|van)\s*["']?\s*[:=]\s*["']?([\p{L}][\p{L}\p{M}.'’ -]{1,}?)(?=["\r\n,;}]|$)/giu,[1],null],
["ADDRESS","medium",/\b(?:street[_ ]address|postal[_ ]address|home[_ ]address|address|adres)\s*["']?\s*[:=]\s*["']?([^\r\n";]{4,})/gi,[1],null],
["DATE_OF_BIRTH","medium",/\b(?:date[_ ]of[_ ]birth|dob|birth[_ ]date|geboortedatum)\s*["']?\s*[:=]\s*["']?(\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})/gi,[1],null],
["STRIPE_KEY","critical",/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{12,}\b/g,null,null],
["PACKAGE_TOKEN","critical",/\b(?:npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,})\b/g,null,null],
["TWILIO_TOKEN","critical",/\bSK[0-9a-fA-F]{32}\b/g,null,null],
["WEBHOOK_SECRET","critical",/\b(?:whsec_[A-Za-z0-9_-]{12,}|(?:webhook[_ ]secret|signing[_ ]secret)\s*[:=]\s*["']?([^\r\n"';,]+))/gi,[1,0],null],
["SESSION_COOKIE","critical",/\b(?:set-cookie|cookie|session[_ ]cookie)\s*:\s*([^\r\n]+)/gi,[1],null],
["RECOVERY_CODE","critical",/\b(?:recovery[_ ]codes?|backup[_ ]codes?|seed[_ ]phrase|mnemonic[_ ]phrase)\s*["']?\s*[:=]\s*["']?([^\r\n"';}]+)/gi,[1],null],
["ONE_TIME_CODE","critical",/\b(?:otp|one[- ]time (?:password|code)|verification[_ ]code|2fa[_ ]code)\s*["']?\s*[:=]\s*["']?([0-9]{4,12})\b/gi,[1],null],
["ROUTING_NUMBER","high",/\b(?:routing[_ ]number|sort[_ ]code|branch[_ ]code|takkode)\s*["']?\s*[:=]\s*["']?(\d(?:[ -]?\d){4,})/gi,[1],null],
["CARD_EXPIRY","high",/\b(?:card[_ ]expir(?:y|ation)(?:[_ ]date)?|card[_ ]exp|expiry[_ ]date)\s*["']?\s*[:=]\s*["']?(\d{1,2}[/-]\d{2,4})/gi,[1],null],
["US_SSN","high",/\b(?:ssn|social[_ ]security[_ ]number)\s*["']?\s*[:=]\s*["']?(\d{3}[ -]?\d{2}[ -]?\d{4})\b/gi,[1],null],
["MEDICAL_RECORD","high",/\b(?:medical[_ ]record[_ ](?:number|id)|patient[_ ]id|mrn)\s*["']?\s*[:=]\s*["']?([A-Z0-9][A-Z0-9_/-]*)/gi,[1],null],
["EMPLOYEE_ID","high",/\b(?:employee|staff|personnel)[_ ](?:id|number)\s*["']?\s*[:=]\s*["']?([A-Z0-9][A-Z0-9_/-]*)/gi,[1],null],
["VEHICLE_ID","medium",/\b(?:vin|vehicle[_ ]registration(?:[_ ]number)?|licen[cs]e[_ ]plate|registrasienommer)\s*["']?\s*[:=]\s*["']?([A-Z0-9][A-Z0-9 -]*)(?=["'\r\n,;}]|$)/gi,[1],null],
["GPS_LOCATION","medium",/\b(?:gps|coordinates|location[_ ]coordinates)\s*["']?\s*[:=]\s*["']?([+-]?\d{1,2}\.\d{3,}\s*,\s*[+-]?\d{1,3}\.\d{3,})/gi,[1],null],
["SALARY","high",/\b(?:salary|monthly[_ ]income|annual[_ ]income|gross[_ ]pay|net[_ ]pay|salaris)\s*["']?\s*[:=]\s*["']?((?:ZAR|USD|EUR|GBP|R|\$|£|€)?[ \t]*\d[\d ,.]*\d|\d)(?!\d)/gi,[1],null],
["HEALTH_INFORMATION","high",/\b(?:diagnosis|medical[_ ]condition|medication|diagnose)\s*["']?\s*[:=]\s*["']?([^\r\n"';}]+)/gi,[1],null],
["DRIVING_LICENCE","high",/\b(?:driver'?s?[_ ]licen[cs]e(?:[_ ]number)?|driving[_ ]licen[cs]e(?:[_ ]number)?)\s*["']?\s*[:=]\s*["']?([A-Z0-9][A-Z0-9/-]*)/gi,[1],null],
["LABELLED_PHONE","medium",/\b(?:telephone|phone|mobile|cellphone|telefoon|selfoon)(?:[_ ]number)?\s*["']?\s*[:=]\s*["']?(\+?\d(?:[ .()-]?\d){5,})/gi,[1],null],
["CLOUD_SECRET","critical",/\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*([^\s;,"']+)/gi,[1],null],
["SSH_FINGERPRINT","medium",/\b(?:ssh[_ ]fingerprint)\s*[:=]\s*["']?((?:SHA256:|MD5:)[A-Za-z0-9+/=:]+)\b/gi,[1],null],
];
export function redact(input,options={}){
  if(typeof input!=="string")throw new TypeError("Input must be text");
  if(input.length>MAX_INPUT)throw new RangeError("Maximum input is 200,000 UTF-16 code units");
  if(!options||typeof options!=="object"||Array.isArray(options))throw new TypeError("Invalid options");
  if(options.mode!==undefined&&!["token","mask"].includes(options.mode))throw new TypeError("Invalid mode");
  if(Object.keys(options).some(k=>!["mode","disabled"].includes(k)))throw new TypeError("Unknown option");
  if(options.disabled!==undefined&&(!Array.isArray(options.disabled)||options.disabled.some(t=>!rules.some(r=>r[0]===t))))throw new TypeError("Invalid category");
  const candidates=[], disabled=new Set(options.disabled||[]);
  const {text:normal,starts,ends}=normalise(input);
  const rank={critical:3,high:2,medium:1};
  for(const [type,severity,pattern,groups,validate] of rules){
    if(disabled.has(type))continue;
    const re=new RegExp(pattern.source,pattern.flags.includes("d")?pattern.flags:pattern.flags+"d");
    for(const match of normal.matchAll(re)){
      const idx=groups?groups.find(i=>match[i]!==undefined):0;
      if(idx===undefined)continue;
      const value=match[idx], [ns,ne]=match.indices[idx];
      const start=starts[ns],end=ends[ne-1];
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
      if(rank[c.severity]>rank[p.severity]||(rank[c.severity]===rank[p.severity]&&p.type==="LABELLED_ID"&&c.type!=="LABELLED_ID")){p.type=c.type;p.severity=c.severity;}
    }else spans.push({...c});
  }
  const counts={}, identities=new Map(),findings=[];let output="",cursor=0;
  for(const span of spans){
    const {type,severity,start,end}=span;
    const value=input.slice(start,end),key=type+"\0"+normalise(value).text;
    if(!identities.has(key)){counts[type]=(counts[type]||0)+1;identities.set(key,"["+type+"_"+counts[type]+"]");}
    const replacement=options.mode==="mask"?"[REDACTED]":identities.get(key);
    output+=input.slice(cursor,start)+replacement;cursor=end;
    findings.push({type,severity,start,end,replacement});
  }
  output+=input.slice(cursor);
  return {policyVersion:POLICY_VERSION,text:output,findings,summary:{total:findings.length,critical:findings.filter(x=>x.severity==="critical").length,high:findings.filter(x=>x.severity==="high").length,medium:findings.filter(x=>x.severity==="medium").length}};
}
export function verifyRedacted(result){
  if(!result||typeof result.text!=="string"||!Array.isArray(result.findings))throw new TypeError("Invalid scan result");
  if(/[\p{Cf}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(result.text))throw new Error("Unsupported control characters remain; review manually");
  // Only ignore residual matches wholly inside tokens actually generated by this scan.
  let delta=0;
  const generated=result.findings.map(f=>{
    const start=f.start+delta,end=start+f.replacement.length;
    delta+=f.replacement.length-(f.end-f.start);
    return {start,end};
  });
  let i=0;
  for(const f of redact(result.text).findings){
    while(i<generated.length&&generated[i].end<=f.start)i++;
    if(i===generated.length||f.start<generated[i].start||f.end>generated[i].end){
      throw new Error("Residual sensitive pattern detected; review manually");
    }
  }
  return result.text;
}
export function prepareForModel(input){return verifyRedacted(redact(input));}
export const categories = rules.map(([type,severity])=>({type,severity}));
