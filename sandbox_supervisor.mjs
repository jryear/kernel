// Trusted per-check supervisor. Proxy destinations are literal loopback only.
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {randomUUID, createHash} from 'node:crypto';
import {once} from 'node:events';
import childProcess from 'node:child_process';
import {syncBuiltinESMExports} from 'node:module';

const cfg = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const started = new Date().toISOString();
const declared = new Set(cfg.localhost_ports);
if (!Array.isArray(cfg.localhost_ports) || [...declared].some((p,i,a)=>!Number.isInteger(p)||p<1||p>65535||(i && a[i-1]>=p))) throw Error('invalid port declaration');
if (!cfg.env || typeof cfg.env !== 'object' || !cfg.filesystem || !path.isAbsolute(cfg.cwd)) throw Error('invalid trusted configuration');
const destination = (authority) => {
  const m = /^(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$/.exec(authority);
  if (!m || !declared.has(Number(m[2]))) return null;
  return {host: m[1] === '[::1]' ? '::1' : '127.0.0.1', port:Number(m[2])};
};
const sockets = new Set();
function track(socket) {
  sockets.add(socket);
  socket.once('close',()=>sockets.delete(socket));
  return socket;
}
function tunnel(client, target, head=Buffer.alloc(0), connected=()=>{}) {
  const upstream = track(net.connect(target.port,target.host));
  upstream.once('connect',()=>{connected();if(head.length) upstream.write(head);client.pipe(upstream);upstream.pipe(client);});
  upstream.on('error',()=>client.destroy()); client.on('error',()=>upstream.destroy());
  upstream.once('close',()=>client.destroy()); client.once('close',()=>upstream.destroy());
}
const web = http.createServer((req,res)=>{
  const m = /^http:\/\/(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})(\/[^#]*)?$/.exec(req.url || '');
  const dst = m && destination(`${m[1]}:${m[2]}`);
  if (!dst) {res.writeHead(403);res.end();return;}
  const headers = {...req.headers}; delete headers['proxy-authorization']; delete headers['proxy-connection'];
  const out = http.request({hostname:dst.host,port:dst.port,path:m[3]||'/',method:req.method,headers}, response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
  out.on('socket',track);
  out.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end();});req.pipe(out);
});
web.on('connection',track);
web.on('connect',(req,client,head)=>{const dst=destination(req.url||'');if(!dst){client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return;}tunnel(client,dst,head,()=>client.write('HTTP/1.1 200 Connection Established\r\n\r\n'));});
web.on('clientError',(_e,socket)=>socket.destroy());
const socks = net.createServer(socket=>{
  let stage=0, buffer=Buffer.alloc(0);
  socket.on('error',()=>socket.destroy());
  const fail=()=>socket.end(Buffer.from([5,2,0,1,0,0,0,0,0,0]));
  const consume=chunk=>{
    buffer=Buffer.concat([buffer,chunk]); if(buffer.length>4096){socket.destroy();return;}
    if(stage===0){if(buffer.length<2)return;const n=buffer[1];if(buffer.length<2+n)return;if(buffer[0]!==5||!buffer.subarray(2,2+n).includes(0)){socket.end(Buffer.from([5,255]));return;}buffer=buffer.subarray(2+n);socket.write(Buffer.from([5,0]));stage=1;}
    if(stage!==1||buffer.length<4)return;
    if(buffer[0]!==5||buffer[1]!==1||buffer[2]!==0){fail();return;}
    const atyp=buffer[3], size=atyp===1?4:atyp===4?16:0;
    if(!size){fail();return;}if(buffer.length<4+size+2)return;
    const addr=buffer.subarray(4,4+size);const host=atyp===1 && addr.equals(Buffer.from([127,0,0,1]))?'127.0.0.1':atyp===4 && addr.equals(Buffer.from([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]))?'::1':null;
    const port=buffer.readUInt16BE(4+size);if(!host||!declared.has(port)){fail();return;}
    const head=buffer.subarray(6+size);stage=2;socket.removeListener('data',consume);
    tunnel(socket,{host,port},head,()=>socket.write(Buffer.from([5,0,0,1,0,0,0,0,0,0])));
  };socket.on('data',consume);
});
socks.on('connection',track);
async function listen(server) {for(let i=0;i<20;i++){server.listen(0,'127.0.0.1');await once(server,'listening');if(!declared.has(server.address().port))return;await new Promise(r=>server.close(r));}throw Error('unable to allocate disjoint proxy');}
// srt's shell quote emits bare tokens or POSIX single quoted tokens with the
// standard quote-escape sequence. Parse strictly; never execute it to inspect.
function words(s){let out=[],v='',started=false,q=false;for(let i=0;i<s.length;i++){const c=s[i];if(q){if(c==="'")q=false;else v+=c;continue;}if(c==="'"){q=true;started=true;continue;}if(c==='"'&&s.slice(i,i+3)==='"\'"'){v+="'";i+=2;started=true;continue;}if(c===' '){if(started){out.push(v);v='';started=false;}continue;}if(!/[A-Za-z0-9_./:=@+,\-]/.test(c))throw Error('unexpected shell quoting');v+=c;started=true;}if(q)throw Error('unterminated quote');if(started)out.push(v);return out;}
function unwrap(w){if(!Array.isArray(w.argv)||w.argv.length!==3||w.argv[1]!=='-c')throw Error('unsupported wrapper');const a=words(w.argv[2]);const i=a.indexOf('/usr/bin/sandbox-exec');if(i<0||a[i+1]!=='-p'||a[i+3]!=='/bin/bash'||a[i+4]!=='-c'||i+6!==a.length)throw Error('unexpected sandbox wrapper');return {argv:a,profile:a[i+2],command_index:i+5};}
// Observe the library's own collector without replacing its delivery path. The
// observer sees only losses exposed in received chunks, not upstream omissions.
let monitorProcess, monitorCount=0, stoppingMonitor=false, collectorFault=null;
const monitor={pid:null,started:false,exit:null,closed:false,errors:[],argv:null};
const collectorTimestamps={spawned_at:null,stdout_first_at:null,banner_at:null,prepared_at:null,finish_at:null,closed_at:null};
const now=()=>Date.now()/1000;
let bannerText='', bannerSeen=false, signalBanner;
const bannerReady=new Promise(resolve=>{signalBanner=resolve;});
let rawFd, rawBytes=0, rawReceived=0;
const rawChunks=[];
const rawCapacity=8*1024*1024, rawHash=createHash('sha256');
const rawPath=cfg.collector_spool_path || path.join(path.dirname(cfg.result_path),'collector.raw');
let dropped=0, drainTimedOut=false, finishing=false, attribution='original_invocation', drainDeadline=null;
let commandId, expectedEncodedCommand, lateEvent=null, sessionSuffix=null;
const failCollector = message => {if (!collectorFault) collectorFault=message;};
function afterDrainDeadline() {
  if (drainDeadline!==null && performance.now()>=drainDeadline) {
    drainTimedOut=true;failCollector('collector data arrived after drain deadline');
  }
}
const originalSpawn=childProcess.spawn;
childProcess.spawn=function(file,args,options) {
  if (cfg.diagnostics==='enabled' && path.basename(String(file))==='log' && Array.isArray(args) && args[0]==='stream') {
    const index=args.indexOf('--predicate');
    const predicate=index>=0 && typeof args[index+1]==='string' ? args[index+1] : '';
    const match=/^\(eventMessage ENDSWITH "(_[A-Za-z0-9]+_SBX)"\)$/.exec(predicate);
    if (!match) throw Error('unexpected collector predicate');
    sessionSuffix=match[1];
    args=[...args]; args[index+1]=`(senderImagePath == "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox") AND ${predicate}`;
  }
  const child=originalSpawn.call(this,file,args,options);
  if (cfg.diagnostics==='enabled' && path.basename(String(file))==='log' && Array.isArray(args) && args[0]==='stream') {
    monitorCount++;
    if (monitorCount!==1) failCollector('multiple sandbox log collectors');
    monitorProcess=child; monitor.pid=child.pid || null; monitor.started=Boolean(child.pid);
    monitor.argv=[String(file),...args.map(String)];collectorTimestamps.spawned_at=now();
    child.on('error',error=>{if(monitor.errors.length<16)monitor.errors.push(String(error).slice(0,2048));failCollector('sandbox log collector error');});
    child.on('exit',(code,signal)=>{monitor.exit={code,signal};if(!stoppingMonitor)failCollector('sandbox log collector exited early');});
    child.on('close',()=>{monitor.closed=true;collectorTimestamps.closed_at=now();});
    child.stderr?.on('data',data=>{if(data.length){if(monitor.errors.length<16)monitor.errors.push(String(data).slice(0,2048));failCollector('sandbox log collector stderr');}});
    child.stdout?.on('data',data=>{
      if(data.length) afterDrainDeadline();
      if(data.length && collectorTimestamps.stdout_first_at===null)collectorTimestamps.stdout_first_at=now();
      rawReceived+=data.length;
      const rawStart=rawBytes, receivedEpoch=now();
      try {
        const available=Math.max(0,rawCapacity-rawBytes), writeData=data.subarray(0,available);
        let offset=0;
        while(offset<writeData.length){const written=fs.writeSync(rawFd,writeData,offset,writeData.length-offset);if(written<=0)throw Error('short raw collector write');rawHash.update(writeData.subarray(offset,offset+written));offset+=written;rawBytes+=written;}
        if(writeData.length!==data.length)failCollector('raw collector spool capacity exceeded');
        if (rawChunks.length>=20000) failCollector('raw collector chunk ledger capacity exceeded');
        else rawChunks.push({start:rawStart,end:rawBytes,received_epoch:receivedEpoch,arrival_phase:finishing?'drain':'active'});
      } catch(error) {failCollector('raw collector spool write failed: '+String(error));}
      if(!bannerSeen){
        bannerText=(bannerText+data.toString('utf8')).slice(-8192);
        if(bannerText.includes('Filtering the log data using ')){bannerSeen=true;collectorTimestamps.banner_at=now();signalBanner();}
      }
    });
  }
  return child;
};
syncBuiltinESMExports();
let manager, unsubscribe, events=[], spoolFd, persisted=0, received=0, supervisorError=null;
const spoolPath=cfg.spool_path || path.join(path.dirname(cfg.result_path),'diagnostic-events.jsonl');
const spoolHash=createHash('sha256');
// Expected-probe exemptions are decided by the trusted parent after it has
// bound the actual probe PID, process start, executable and time window.
function knownBenignDenial(event) {
  const match=/^.*\(\d+\) deny\(\d+\) (\S+) (.+)$/.exec(String(event.line || ''));
  if(!match)return false;
  const [,operation,resource]=match;
  return (operation==='sysctl-read' && resource==='kern.iossupportversion') ||
    (operation==='system-info' && resource==='vfs.disk-space') ||
    false;
}
function saveEvent(event) {
  afterDrainDeadline();
  if (events.length>=10000) {dropped++;failCollector('diagnostic spool capacity exceeded');return;}
  if (event.encodedCommand!==expectedEncodedCommand) attribution='ambiguous';
  if (finishing && !knownBenignDenial(event)) lateEvent='relevant_denial';
  event = {...event, received_epoch: now(), arrival_phase: finishing ? 'drain' : 'active'};
  const bytes=Buffer.from(JSON.stringify(event)+'\n');
  try {
    let offset=0;
    while(offset<bytes.length) {const written=fs.writeSync(spoolFd,bytes,offset,bytes.length-offset);if(written<=0)throw Error('short diagnostic spool write');offset+=written;}
    spoolHash.update(bytes); persisted++; events.push(event);
  } catch(error) {dropped++;failCollector('diagnostic spool write failed: '+String(error));}
}
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function within(promise,ms) {
  let timer;
  try {return await Promise.race([promise.then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),ms);})]);}
  finally {clearTimeout(timer);}
}
try {
  spoolFd=fs.openSync(spoolPath,'wx',0o600);
  if(cfg.diagnostics==='enabled')rawFd=fs.openSync(rawPath,'wx',0o600);
  await listen(web); await listen(socks);
  const proxy = (role,server)=>({role,host:'127.0.0.1',port:server.address().port,transport:'tcp',pid:process.pid,started,ready:server.listening,ownership_verified:server.listening});
  const proxies=[proxy('http',web),proxy('socks',socks)];
  const root=path.dirname(fileURLToPath(import.meta.url));
  ({SandboxManager:manager}=await import(pathToFileURL(path.join(root,'node_modules/@anthropic-ai/sandbox-runtime/dist/index.js')).href));
  const store=manager.getSandboxViolationStore();let last=0;
  unsubscribe=store.subscribe(tail=>{const total=store.getTotalCount(), count=total-last; if(count<=0)return; received+=count; if(count>tail.length){dropped+=count-tail.length;failCollector('diagnostic subscription lost events');}for(const event of tail.slice(-Math.min(count,tail.length)))saveEvent(event);last=total;});
  process.chdir(cfg.cwd);
  await manager.initialize({network:{allowedDomains:[],deniedDomains:[],strictAllowlist:true,allowLocalBinding:false,kernelLocalhostPorts:cfg.localhost_ports,httpProxyPort:proxies[0].port,socksProxyPort:proxies[1].port},filesystem:cfg.filesystem},undefined,cfg.diagnostics==='enabled');
  if(cfg.diagnostics==='enabled') {
    if(!monitor.started || monitorCount!==1 || monitor.exit || collectorFault || !await within(bannerReady,5000) || monitor.exit || collectorFault)
      throw Error('sandbox log collector startup banner unavailable');
  }
  commandId=randomUUID(); expectedEncodedCommand=Buffer.from(commandId).toString('base64');
  const ref=unwrap(await manager.wrapWithSandboxArgv(cfg.command,'/bin/bash',{network:{kernelLocalhostPorts:[]}},undefined,cfg.cwd,{commandId}));
  const actual=unwrap(await manager.wrapWithSandboxArgv(cfg.command,'/bin/bash',undefined,undefined,cfg.cwd,{commandId}));
  const prepared={profile:actual.profile,argv:actual.argv,env:cfg.env,command_index:actual.command_index,proxies,command_tag:expectedEncodedCommand,session_suffix:sessionSuffix,template_context:{reference_profile:ref.profile,localhost_ports:cfg.localhost_ports,proxies,generator_sha256:'9da44b6ea3c1bb3f90052118b237d328dd38c2d0ce2a70ef6160dd81a1d95400'}};
  fs.writeFileSync(cfg.prepared_path,JSON.stringify(prepared),{mode:0o600,flag:'wx'});
  collectorTimestamps.prepared_at=now();
  if(cfg.diagnostics==='enabled' && (!monitor.started || monitorCount!==1 || monitor.exit)) failCollector('sandbox log collector unavailable');
  await once(process.stdin,'data');
} catch(error) {supervisorError=String(error);failCollector('supervisor failure: '+supervisorError);process.exitCode=1;}
finally {
  collectorTimestamps.finish_at=now();
  finishing=true;
  // No connection may outlive the candidate cleanup boundary. Close accepted
  // and outgoing sockets before waiting for server close callbacks.
  for(const socket of sockets) socket.destroy();
  const closing=Promise.all([web,socks].map(server=>server.listening ? new Promise(resolve=>server.close(resolve)) : Promise.resolve()));
  if(!await within(closing,1000)) {drainTimedOut=true;failCollector('proxy shutdown timed out');}
  if(cfg.diagnostics==='enabled') {
    if(!monitorProcess || monitor.exit!==null || !monitor.started) failCollector('sandbox log collector not alive through finish');
    drainDeadline=performance.now()+2000;
    await delay(2000);
  }
  stoppingMonitor=true;
  try {if(manager)await manager.reset();} catch(error) {failCollector('sandbox manager reset failed: '+String(error));process.exitCode=1;}
  if(cfg.diagnostics==='enabled' && monitorProcess && !monitor.closed) {
    await within(once(monitorProcess,'close').catch(()=>{}),1000);
    if(!monitor.closed){
      drainTimedOut=true;failCollector('sandbox log collector shutdown timed out');
      try {monitorProcess.kill('SIGKILL');} catch(error) {monitor.errors.push(String(error).slice(0,2048));}
      await within(once(monitorProcess,'close').catch(()=>{}),500);
      if(!monitor.closed) process.exitCode=1;
    }
  }
  if(unsubscribe)unsubscribe();
  if(spoolFd!==undefined) {
    try {fs.fsyncSync(spoolFd);fs.closeSync(spoolFd);} catch(error) {failCollector('diagnostic spool finalization failed: '+String(error));}
  }
  if(rawFd!==undefined) {
    try {fs.fsyncSync(rawFd);fs.closeSync(rawFd);} catch(error) {failCollector('raw collector spool finalization failed: '+String(error));}
  }
  const rawSha256=rawHash.digest('hex');
  monitor.timestamps=collectorTimestamps;monitor.banner_seen=bannerSeen;
  const result={events,received,dropped,mode:cfg.diagnostics,complete:false,profile_sha256:null,error:supervisorError,
    collector_fault:collectorFault,drain_timed_out:drainTimedOut,attribution,late_event:lateEvent,
    spool_path:spoolPath,spool_sha256:spoolHash.digest('hex'),persisted,monitor,
    collector_persisted_bytes:rawBytes,collector_received_bytes:rawReceived,collector_spool_sha256:rawSha256,collector_capacity:rawCapacity,
    collector_raw:{path:cfg.diagnostics==='enabled'?rawPath:null,sha256:rawSha256,bytes:rawBytes,received_bytes:rawReceived,capacity:rawCapacity,banner_seen:bannerSeen,timestamps:collectorTimestamps,chunks:rawChunks}};
  try {fs.writeFileSync(cfg.result_path,JSON.stringify(result),{mode:0o600,flag:'wx'});} catch {process.exitCode=1;}
}
