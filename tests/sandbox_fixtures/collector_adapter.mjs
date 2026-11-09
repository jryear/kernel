// Host-only test preload. This file is not loaded by any production launch.
// The descriptor is supplied by the harness before sandbox supervisor startup.
import fs from 'node:fs';
import {observeDrain} from './collector_clock.mjs';
import cp from 'node:child_process';
import path from 'node:path';
import {PassThrough} from 'node:stream';
import {syncBuiltinESMExports} from 'node:module';
const fd=Number(process.env.KERNEL_TEST_COLLECTOR_FD);
const livePath=process.env.KERNEL_TEST_COLLECTOR_LIVE;
const suppress=process.env.KERNEL_TEST_COLLECTOR_SUPPRESS === '1';
delete process.env.KERNEL_TEST_COLLECTOR_FD;
delete process.env.KERNEL_TEST_COLLECTOR_LIVE;
delete process.env.KERNEL_TEST_COLLECTOR_SUPPRESS;
if (!Number.isInteger(fd) || fd < 3 || !livePath) throw Error('test collector host descriptor unavailable');
const live=fs.openSync(livePath,'wx',0o600);
const ackPath=path.join(path.dirname(livePath),'collector-write-ack.jsonl');
const clock=observeDrain(row=>fs.appendFileSync(ackPath,JSON.stringify({...row,at:Date.now()/1000})+'\n'));
const original=cp.spawn;
cp.spawn=function(file,args,options){
  const child=original.apply(this,arguments);
  if (String(file).split('/').pop() !== 'log' || !Array.isArray(args) || args[0] !== 'stream') return child;
  const predicate=String(args[args.indexOf('--predicate')+1]);
  const suffix=/eventMessage ENDSWITH "([^"]+)"/.exec(predicate)?.[1];
  if (!suffix) throw Error('test adapter could not bind srt session suffix');
  const real=child.stdout, mux=new PassThrough();
  child.stdout=mux;
  let liveLines='';
  real.on('data', data=>{
    fs.writeSync(live,data);
    // Preserve the collector banner; suppress only test-designated upstream
    // event bytes before they enter the subject stream and its counters.
    if (!suppress) mux.write(data);
    else {
      liveLines+=data.toString('utf8'); let n;
      while((n=liveLines.indexOf('\n'))>=0){const line=liveLines.slice(0,n+1);liveLines=liveLines.slice(n+1);
        if(line.includes('Filtering the log data using ')) mux.write(line);}
      if(liveLines.length>65536) throw Error('test collector upstream line limit exceeded');
    }
  });
  real.on('end',()=>mux.end());
  const control=fs.createReadStream(null,{fd,autoClose:false});
  let buffer='';
  control.on('data',data=>{
    buffer+=data.toString('utf8'); let n;
    while ((n=buffer.indexOf('\n'))>=0){
      const msg=JSON.parse(buffer.slice(0,n)); buffer=buffer.slice(n+1);
      if (msg.type!=='event' || typeof msg.line!=='string' || typeof msg.tag!=='string') throw Error('invalid host test frame');
      if(!mux.readableFlowing || mux.listenerCount('data')===0)throw Error('host collector boundary not flowing');
      const writtenAt=Date.now()/1000,writtenMono=clock.now();
      mux.write(msg.line+'\nCMD64_'+msg.tag+'_END_'+(msg.suffix ?? suffix)+'\n');
      setImmediate(()=>fs.appendFileSync(path.join(path.dirname(livePath),'collector-write-ack.jsonl'),JSON.stringify({type:'boundary_written',frame_id:msg.frame_id,written_at:writtenAt,written_mono:writtenMono,finish_at:clock.finish_at,deadline_mono:clock.deadline_mono,at:Date.now()/1000})+'\n'));
    }
  });
  child.on('close',()=>{control.destroy();fs.closeSync(live);});
  return child;
};
syncBuiltinESMExports();
