import {scan} from './guard.mjs';
import {MAX_INPUT} from './engine.mjs';
import {stdin,stdout,stderr} from 'node:process';
try{
  const args=process.argv.slice(2);
  if(args.includes('--help'))stdout.write('Usage: node cli.mjs [--mask] [--report] < input.txt\n');
  else{
    if(args.some(a=>!['--mask','--report'].includes(a)))throw Error('INVALID_ARGUMENT');
    const chunks=[];let bytes=0;
    for await(const chunk of stdin){bytes+=chunk.length;if(bytes>MAX_INPUT*4)throw Error('INPUT_TOO_LARGE');chunks.push(chunk);}
    const input=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));
    const result=await scan(input,{mode:args.includes('--mask')?'mask':'token'});
    stdout.write(args.includes('--report')?JSON.stringify(result,null,2)+'\n':result.text);
  }
}catch(e){stderr.write('DataGuard: '+(e.code&&/^[A-Z_]+$/.test(e.code)?e.code:'INPUT_OR_SCAN_FAILED')+'\n');process.exitCode=1;}
