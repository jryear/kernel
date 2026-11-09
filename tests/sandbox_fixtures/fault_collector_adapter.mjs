// Host-only preload for disposable collector-path fault reproductions.
// Nothing in the candidate environment references this module or its pipe.
import fs from 'node:fs';
import cp from 'node:child_process';
import path from 'node:path';
import {PassThrough} from 'node:stream';
import {syncBuiltinESMExports} from 'node:module';
import {pathToFileURL} from 'node:url';

const fd=Number(process.env.KERNEL_TEST_COLLECTOR_FD);
const livePath=process.env.KERNEL_TEST_COLLECTOR_LIVE;
delete process.env.KERNEL_TEST_COLLECTOR_FD;
delete process.env.KERNEL_TEST_COLLECTOR_LIVE;
delete process.env.KERNEL_TEST_COLLECTOR_SUPPRESS;
if (!Number.isInteger(fd) || fd<3 || !livePath) throw Error('host collector descriptor unavailable');
const root=path.dirname(livePath);
// The test host chooses this parent directory before launch; the candidate
// cannot write outside its sandbox scratch or change the preload or descriptor.
const mode=path.basename(root).replace(/^fault-/, '');
const cases=new Set(['SUBSCRIPTION_DROP','SPOOL_OVERFLOW','COLLECTOR_DEATH',
 'AMBIGUOUS_EVENT_ID','CROSS_INVOCATION_EVENT','DRAIN_TIMEOUT',
 'LATE_RELEVANT_DENIAL','BURST_OVER_100_PERSISTED','DELAYED_AFTER_LEADER_EXIT']);
if (!cases.has(mode)) throw Error('unknown host fault fixture');
const auditPath=path.join(root,'fault-adapter-audit.jsonl');
const audit=(value)=>fs.appendFileSync(auditPath,JSON.stringify({...value,at:Date.now()/1000})+'\n');
const live=fs.openSync(livePath,'wx',0o600);

if (mode==='SUBSCRIPTION_DROP') {
  const modulePath=path.join(path.dirname(process.argv[1]),'node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-violation-store.js');
  const {SandboxViolationStore}=await import(pathToFileURL(modulePath).href);
  const original=SandboxViolationStore.prototype.subscribe;
  SandboxViolationStore.prototype.subscribe=function(listener) {
    let held=0;
    return original.call(this,(tail)=>{
      if(this.getTotalCount()===0){listener(tail);return;}
      held++;
      if(held<150)return;
      if(held===150)audit({type:'subscription_callbacks_held',held,total:this.getTotalCount(),tail:tail.length});
      listener(tail);
    });
  };
}
if (mode==='DRAIN_TIMEOUT') {
  // A controlled collector scheduling fault holds the real drain callback open
  // beyond its unchanged frozen deadline; it does not change the deadline.
  const timer=globalThis.setTimeout;
  globalThis.setTimeout=function(callback,ms,...args) {
    return timer(callback,ms===2000 ? 2600 : ms,...args);
  };
}
const spawn=cp.spawn;
cp.spawn=function(file,args,options){
  const child=spawn.apply(this,arguments);
  if (path.basename(String(file))!=='log' || !Array.isArray(args) || args[0]!=='stream') return child;
  const predicate=String(args[args.indexOf('--predicate')+1]);
  const suffix=/eventMessage ENDSWITH "([^"]+)"/.exec(predicate)?.[1];
  if (!suffix) throw Error('collector predicate suffix unavailable');
  const real=child.stdout,mux=new PassThrough();child.stdout=mux;
  let lines='';
  real.on('data',data=>{
    fs.writeSync(live,data); lines+=data.toString('utf8');let n;
    while((n=lines.indexOf('\n'))>=0){const line=lines.slice(0,n+1);lines=lines.slice(n+1);
      if(line.includes('Filtering the log data using '))mux.write(line);}
  });
  real.on('end',()=>mux.end());
  const input=fs.createReadStream(null,{fd,autoClose:false});let buffer='';
  input.on('data',data=>{
    buffer+=data.toString('utf8');let n;
    while((n=buffer.indexOf('\n'))>=0){
      const msg=JSON.parse(buffer.slice(0,n));buffer=buffer.slice(n+1);
      if(msg.type!=='event'||typeof msg.line!=='string'||typeof msg.tag!=='string')throw Error('bad host event');
      const prefix=msg.line.replace(/Sandbox: .*$/, 'Sandbox: ');
      const benign=(pid,tag=msg.tag,suf=suffix)=>`${prefix}Python(${pid}) deny(1) sysctl-read kern.iossupportversion\nCMD64_${tag}_END_${suf}\n`;
      const pid=/Sandbox: \w+\((\d+)\)/.exec(msg.line)?.[1];
      if (!pid) throw Error('host event subject pid missing');
      if(mode==='COLLECTOR_DEATH') {audit({type:'terminate_real_collector',pid:child.pid});child.kill('SIGKILL');continue;}
      if(mode==='SPOOL_OVERFLOW' || mode==='BURST_OVER_100_PERSISTED' || mode==='SUBSCRIPTION_DROP') {
        const count=mode==='SPOOL_OVERFLOW'?10001:150;
        const frame=benign(pid);audit({type:'write_benign_burst',count});
        mux.write(frame.repeat(count));continue;
      }
      if(mode==='AMBIGUOUS_EVENT_ID') {audit({type:'write_unknown_command_tag'});mux.write(msg.line+'\nCMD64_dW5rbm93bi10YWc=_END_'+suffix+'\n');continue;}
      if(mode==='CROSS_INVOCATION_EVENT') {
        const scratch=path.join(root,'operator-scratch');let prior;
        for(const name of fs.readdirSync(scratch)){
          const dir=path.join(scratch,name), receipt=path.join(dir,'sandbox-receipt.json'),prepared=path.join(dir,'prepared.json');
          if(fs.existsSync(receipt)&&fs.existsSync(prepared)){
            const r=JSON.parse(fs.readFileSync(receipt)),p=JSON.parse(fs.readFileSync(prepared));
            if(r.identity.phase==='base'){prior={r,p};break;}
          }
        }
        if(!prior)throw Error('sealed previous invocation unavailable');
        const oldpid=prior.r.assertions.cleanup.observed?.[0]?.pid;
        if(!oldpid)throw Error('prior observed subject unavailable');
        audit({type:'write_prior_benign_event',prior_run:prior.r.identity.run_id,oldpid});
        mux.write(benign(oldpid,prior.p.command_tag,prior.p.session_suffix));continue;
      }
      if(mode==='DRAIN_TIMEOUT'){
        process.stdin.once('data',()=>{
          audit({type:'schedule_after_unchanged_drain_deadline',delay_after_finish_ms:2100});
          setTimeout(()=>mux.write(benign(pid)),2100);
        });
        continue;
      }
      if(mode==='LATE_RELEVANT_DENIAL' || mode==='DELAYED_AFTER_LEADER_EXIT') {
        audit({type:'hold_for_supervisor_finish',case:mode});
        process.stdin.once('data',()=>{
          audit({type:'supervisor_finish_observed',case:mode});
          setTimeout(()=>{
            audit({type:mode==='DELAYED_AFTER_LEADER_EXIT'?'write_benign_delayed_event':'write_late_denial'});
            mux.write(mode==='DELAYED_AFTER_LEADER_EXIT'?benign(pid):msg.line+'\nCMD64_'+msg.tag+'_END_'+suffix+'\n');
          },10);
        });
        continue;
      }
      audit({type:'write_event',case:mode});mux.write(msg.line+'\nCMD64_'+msg.tag+'_END_'+suffix+'\n');
    }
  });
  child.on('close',()=>{input.destroy();fs.closeSync(live);});return child;
};
syncBuiltinESMExports();
