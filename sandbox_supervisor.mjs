// Trusted per-check supervisor. Proxy destinations are literal loopback only.
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {randomUUID, createHash} from 'node:crypto';
import {once} from 'node:events';

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
function tunnel(client, target, head=Buffer.alloc(0), connected=()=>{}) {
  const upstream = net.connect(target.port,target.host);
  upstream.once('connect',()=>{connected();if(head.length) upstream.write(head);client.pipe(upstream);upstream.pipe(client);});
  upstream.on('error',()=>client.destroy()); client.on('error',()=>upstream.destroy());
}
const web = http.createServer((req,res)=>{
  const m = /^http:\/\/(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})(\/[^#]*)?$/.exec(req.url || '');
  const dst = m && destination(`${m[1]}:${m[2]}`);
  if (!dst) {res.writeHead(403);res.end();return;}
  const headers = {...req.headers}; delete headers['proxy-authorization']; delete headers['proxy-connection'];
  const out = http.request({hostname:dst.host,port:dst.port,path:m[3]||'/',method:req.method,headers}, response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
  out.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end();});req.pipe(out);
});
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
async function listen(server) {for(let i=0;i<20;i++){server.listen(0,'127.0.0.1');await once(server,'listening');if(!declared.has(server.address().port))return;await new Promise(r=>server.close(r));}throw Error('unable to allocate disjoint proxy');}
// srt's shell quote emits bare tokens or POSIX single quoted tokens with the
// standard quote-escape sequence. Parse strictly; never execute it to inspect.
function words(s){let out=[],v='',started=false,q=false;for(let i=0;i<s.length;i++){const c=s[i];if(q){if(c==="'")q=false;else v+=c;continue;}if(c==="'"){q=true;started=true;continue;}if(c==='"'&&s.slice(i,i+3)==='"\'"'){v+="'";i+=2;started=true;continue;}if(c===' '){if(started){out.push(v);v='';started=false;}continue;}if(!/[A-Za-z0-9_./:=@+,\-]/.test(c))throw Error('unexpected shell quoting');v+=c;started=true;}if(q)throw Error('unterminated quote');if(started)out.push(v);return out;}
function unwrap(w){if(!Array.isArray(w.argv)||w.argv.length!==3||w.argv[1]!=='-c')throw Error('unsupported wrapper');const a=words(w.argv[2]);const i=a.indexOf('/usr/bin/sandbox-exec');if(i<0||a[i+1]!=='-p'||a[i+3]!=='/bin/bash'||a[i+4]!=='-c'||i+6!==a.length)throw Error('unexpected sandbox wrapper');return {argv:a,profile:a[i+2],command_index:i+5};}
let manager, unsubscribe, events=[], dropped=0;
try {
  await listen(web); await listen(socks);
  const proxy = (role,server)=>({role,host:'127.0.0.1',port:server.address().port,transport:'tcp',pid:process.pid,started,ready:server.listening,ownership_verified:server.listening});
  const proxies=[proxy('http',web),proxy('socks',socks)];
  const root=path.dirname(fileURLToPath(import.meta.url));
  ({SandboxManager:manager}=await import(pathToFileURL(path.join(root,'node_modules/@anthropic-ai/sandbox-runtime/dist/index.js')).href));
  const store=manager.getSandboxViolationStore();let last=0;
  unsubscribe=store.subscribe(tail=>{const total=store.getTotalCount(), count=total-last; if(count<=0)return; if(count>tail.length)dropped+=count-tail.length;for(const event of tail.slice(-Math.min(count,tail.length))){if(events.length<10000)events.push(event);else dropped++;}last=total;});
  process.chdir(cfg.cwd);
  await manager.initialize({network:{allowedDomains:[],deniedDomains:[],strictAllowlist:true,allowLocalBinding:false,kernelLocalhostPorts:cfg.localhost_ports,httpProxyPort:proxies[0].port,socksProxyPort:proxies[1].port},filesystem:cfg.filesystem},undefined,cfg.diagnostics==='enabled');
  const commandId=randomUUID();
  const ref=unwrap(await manager.wrapWithSandboxArgv(cfg.command,'/bin/bash',{network:{kernelLocalhostPorts:[]}},undefined,cfg.cwd,{commandId}));
  const actual=unwrap(await manager.wrapWithSandboxArgv(cfg.command,'/bin/bash',undefined,undefined,cfg.cwd,{commandId}));
  const prepared={profile:actual.profile,argv:actual.argv,env:cfg.env,command_index:actual.command_index,proxies,template_context:{reference_profile:ref.profile,localhost_ports:cfg.localhost_ports,proxies,generator_sha256:'2b4d539624dde6067982722c9fe234ff7ba15b04ddb86ce5141c69ef40de2e5a'}};
  fs.writeFileSync(cfg.prepared_path,JSON.stringify(prepared),{mode:0o600,flag:'wx'});
  await once(process.stdin,'data');
} catch(error) {try{fs.writeFileSync(cfg.result_path,JSON.stringify({error:String(error),launched:false}),{mode:0o600});}catch{} process.exitCode=1;}
finally {if(unsubscribe)unsubscribe();if(manager)await manager.reset();for(const server of [web,socks])if(server.listening)await new Promise(r=>server.close(r));if(!fs.existsSync(cfg.result_path))fs.writeFileSync(cfg.result_path,JSON.stringify({events,dropped,mode:cfg.diagnostics,complete:false,profile_sha256:null}),{mode:0o600});}
