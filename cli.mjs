import {redact} from './engine.mjs';
import {stdin,stdout,stderr} from 'node:process';
try{
const args=process.argv.slice(2);
if(args.includes('--help')){stdout.write('Usage: node cli.mjs [--mask] [--report] < input.txt\n');}else{
if(args.some(a=>!['--mask','--report'].includes(a)))throw Error('Unknown argument');
stdin.setEncoding('utf8');let input='';for await(const chunk of stdin){input+=chunk;if(input.length>200000)throw Error('Input too large');}
const result=redact(input,{mode:args.includes('--mask')?'mask':'token'});
stdout.write(args.includes('--report')?JSON.stringify(result,null,2)+'\n':result.text);
}
}catch(e){stderr.write('DataGuard: '+e.message+'\n');process.exitCode=1;}
