import {redact,verifyRedacted,MAX_INPUT,POLICY_VERSION} from './engine.mjs';
export const FORMATS=Object.freeze(['text','json']);
export const POLICIES=Object.freeze(['redact','block-critical','block-any']);
const fields=new Map();
for(const [type,keys] of Object.entries({
  CREDENTIAL:'password passwd pwd apikey clientsecret accesstoken refreshtoken secretkey privatekey sessiontoken authorization awssecretaccesskey secret token cookie setcookie accountkey sharedaccesskey otp recoverycode seedphrase',
  PERSON_NAME:'name fullname firstname lastname surname customername policyholdername patientname naam van',
  ADDRESS:'address homeaddress streetaddress postaladdress billingaddress shippingaddress adres',
  EMAIL:'email emailaddress customeremail',
  PHONE:'phone phonenumber mobile mobilenumber cellphone telephone telefoon selfoon',
  LABELLED_ID:'idnumber nationalid identitynumber southafricanid idnommer identiteitsnommer ssn socialsecuritynumber',
  LABELLED_CARD:'cardnumber creditcard creditcardnumber debitcard debitcardnumber paymentcard pan cvv cvc cardpin cardexpiry expirydate',
  BANK_ACCOUNT:'bankaccount bankaccountnumber accountnumber iban rekeningnommer routingnumber sortcode branchcode',
  FINANCIAL_ID:'taxnumber taxpayerid vatnumber',
  DATE_OF_BIRTH:'dob dateofbirth birthdate geboortedatum',
  POLICY_NUMBER:'policynumber policyid claimnumber claimid customernumber customerid membernumber passportnumber medicalaidnumber polisnommer eisnommer',
  MEDICAL_RECORD:'patientid medicalrecordnumber mrn',
  HEALTH_INFORMATION:'diagnosis diagnoses medication medicalcondition medicalhistory',
  SALARY:'salary monthlyincome annualincome grosspay netpay salaris',
  VEHICLE_ID:'vin vehicleregistration licenceplate licenseplate',
  EMPLOYEE_ID:'employeeid employeenumber staffnumber',
  GPS_LOCATION:'latitude longitude coordinates gps'
}))for(const key of keys.split(' '))fields.set(key,type);
const medium=new Set(['PERSON_NAME','ADDRESS','EMAIL','PHONE','DATE_OF_BIRTH','VEHICLE_ID','GPS_LOCATION']);
const severityOf=type=>type==='CREDENTIAL'?'critical':medium.has(type)?'medium':'high';
const keyForm=key=>key.normalize('NFKC').replace(/[\p{Cf}\s_-]/gu,'').toLowerCase();
export class PipelineError extends Error{
  constructor(code){super(code);this.name='PipelineError';this.code=code;}
}
export function validateSettings(options={}){
  if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(k=>!['mode','format','policy'].includes(k)))throw new PipelineError('INVALID_SETTINGS');
  const {mode='token',format='text',policy='redact'}=options;
  if(!['token','mask'].includes(mode)||!FORMATS.includes(format)||!POLICIES.includes(policy))throw new PipelineError('INVALID_SETTINGS');
  return {mode,format,policy};
}
function structure(input,mode){
  let value;try{value=JSON.parse(input);}catch{throw new PipelineError('INVALID_JSON');}
  const findings=[],summary={total:0,critical:0,high:0,medium:0};let nodes=0,token=0;
  const identities=new Map();
  function record(type,severity,value,kind){
    if(findings.length>=10000)throw new PipelineError('MATCH_LIMIT');
    const key=type+'\0'+JSON.stringify(value);
    if(!identities.has(key))identities.set(key,'['+type+'_J'+(++token)+']');
    const replacement=mode==='mask'?'[REDACTED]':identities.get(key);
    findings.push({type,severity,start:null,end:null,replacement,kind});
    summary.total++;summary[severity]++;
    return replacement;
  }
  function visit(v,depth,field){
    if(++nodes>10000||depth>32)throw new PipelineError('STRUCTURE_LIMIT');
    if(field&&v!==null)return record(field,severityOf(field),v,'field');
    if(v===null||typeof v==='boolean')return v;
    if(typeof v==='string'||typeof v==='number'){
      if(typeof v==='number'&&(!Number.isFinite(v)||(Number.isInteger(v)&&!Number.isSafeInteger(v))))throw new PipelineError('UNSAFE_NUMBER');
      const raw=String(v),r=redact(raw,{mode});verifyRedacted(r);
      if(!r.findings.length)return v;
      let text='',cursor=0;
      for(const f of r.findings){
        text+=raw.slice(cursor,f.start)+record(f.type,f.severity,raw.slice(f.start,f.end),'value');cursor=f.end;
      }
      return text+raw.slice(cursor);
    }
    if(Array.isArray(v))return v.map(item=>visit(item,depth+1));
    const out=Object.create(null);
    for(const [key,item] of Object.entries(v)){
      const canonical=keyForm(key);
      if(['proto','constructor','prototype'].includes(canonical))throw new PipelineError('UNSAFE_KEY');
      const r=redact(key,{mode:'mask'});verifyRedacted(r);
      if(r.findings.length)throw new PipelineError('SENSITIVE_KEY');
      out[key]=visit(item,depth+1,fields.get(canonical));
    }
    return out;
  }
  const text=JSON.stringify(visit(value,0),null,2);
  return {policyVersion:POLICY_VERSION,text,findings,summary};
}
export function inspect(input,options={}){
  if(typeof input!=='string'||input.length>MAX_INPUT)throw new PipelineError('INVALID_INPUT');
  const settings=validateSettings(options);
  const result=settings.format==='json'?structure(input,settings.mode):redact(input,{mode:settings.mode});
  if(settings.format==='text')verifyRedacted(result);
  if(result.text.length>MAX_INPUT*2)throw new PipelineError('OUTPUT_LIMIT');
  const {summary}=result;
  const blocked=settings.policy==='block-any'&&summary.total>0||settings.policy==='block-critical'&&summary.critical>0;
  const risk=summary.critical?'critical':summary.high?'high':summary.medium?'medium':'none-detected';
  const breakdown=Object.create(null);
  for(const f of result.findings)breakdown[f.type]=(breakdown[f.type]||0)+1;
  return {...result,...settings,risk,breakdown,blocked,text:blocked?'':result.text};
}
export function metadataReport(result){
  return {policyVersion:result.policyVersion,format:result.format,policy:result.policy,mode:result.mode,risk:result.risk,blocked:result.blocked,summary:{...result.summary},breakdown:{...result.breakdown}};
}
