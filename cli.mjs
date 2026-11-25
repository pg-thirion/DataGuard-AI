import {scan} from './guard.mjs';
import {MAX_INPUT} from './engine.mjs';
import {metadataReport} from './pipeline.mjs';
import {stdin,stdout,stderr} from 'node:process';
try{
  const args=process.argv.slice(2);
  const allowed=['--help','--mask','--report','--metadata','--json','--block-critical','--block-any'];
  if(args.some(a=>!allowed.includes(a))||args.includes('--report')&&args.includes('--metadata')||args.includes('--block-critical')&&args.includes('--block-any'))throw Error('INVALID_ARGUMENT');
  if(args.includes('--help'))stdout.write('Usage: node cli.mjs [--mask] [--report|--metadata] [--json] [--block-critical|--block-any] < input.txt\n');
  else{
    const chunks=[];let bytes=0;
    for await(const chunk of stdin){bytes+=chunk.length;if(bytes>MAX_INPUT*4)throw Error('INPUT_TOO_LARGE');chunks.push(chunk);}
    const input=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));
    const result=await scan(input,{mode:args.includes('--mask')?'mask':'token',format:args.includes('--json')?'json':'text',policy:args.includes('--block-any')?'block-any':args.includes('--block-critical')?'block-critical':'redact'});
    if(result.blocked){if(args.includes('--metadata'))stdout.write(JSON.stringify(metadataReport(result),null,2)+'\n');stderr.write('DataGuard: POLICY_BLOCKED\n');process.exitCode=2;}
    else stdout.write(args.includes('--metadata')?JSON.stringify(metadataReport(result),null,2)+'\n':args.includes('--report')?JSON.stringify(result,null,2)+'\n':result.text);
  }
}catch(e){stderr.write('DataGuard: '+(e.code&&/^[A-Z_]+$/.test(e.code)?e.code:'INPUT_OR_SCAN_FAILED')+'\n');process.exitCode=1;}
