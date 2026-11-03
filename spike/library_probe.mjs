// Research driver: subscribe outside the sandbox before initialize/spawn.
import {SandboxManager, SandboxViolationStore} from '@anthropic-ai/sandbox-runtime';
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import {createHash, randomUUID} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
const [configPath, commandPath, outputPath] = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(configPath));
const commands = JSON.parse(fs.readFileSync(commandPath));
function hashes(paths) {return Object.fromEntries(paths.map(path=>[path, fs.existsSync(path)?createHash('sha256').update(fs.readFileSync(path)).digest('hex'):null]));}
const result = {path:'embedded', collectorSubscribedAt:Date.now(), cases:[]};
const store = SandboxManager.getSandboxViolationStore();
let events = [];
let lastTotal = 0;
const unsubscribe = store.subscribe(tail => {
  const total = store.getTotalCount();
  const delta = total - lastTotal;
  if (delta > 0) events.push(...tail.slice(-delta).map(event=>({...event, receivedAt:Date.now()})));
  lastTotal = total;
});
// Deterministic store exercise is distinct from actual OS denial delivery.
const synthetic = new SandboxViolationStore();
let seen = 0, previous = 0;
synthetic.subscribe(tail=>{const total=synthetic.getTotalCount(); seen += Math.max(0,total-previous); previous=total;});
for(let i=0;i<150;i++) synthetic.addViolation({line:`synthetic-${i}`,timestamp:new Date()});
result.syntheticStore = {injected:150, retained:synthetic.getCount(), total:synthetic.getTotalCount(), subscribed:seen};
try {
  result.initializeStartedAt = Date.now();
  await SandboxManager.initialize(config, undefined, true);
  result.initializeReturnedAt = Date.now();
  // initialize starts log stream but supplies no collector-ready acknowledgement.
  await delay(700);
  for (const entry of commands) {
    const commandId = randomUUID();
    const startIndex = events.length;
    const row = {case:entry.case, commandId, startedAt:Date.now(), protectedBefore:hashes(entry.protected)};
    try {
      const wrapped = await SandboxManager.wrapWithSandboxArgv(entry.command, '/bin/bash', undefined, undefined, entry.cwd, {commandId});
      await new Promise((resolve,reject)=>{
        const child=spawn(wrapped.argv[0],wrapped.argv.slice(1),{cwd:entry.cwd,env:wrapped.env,stdio:['ignore','pipe','pipe']});
        let stdout='',stderr='';
        child.stdout.on('data',chunk=>stdout+=chunk);
        child.stderr.on('data',chunk=>stderr+=chunk);
        const timer=setTimeout(()=>child.kill('SIGKILL'),15000);
        child.on('error',reject);
        child.on('close',(code,signal)=>{clearTimeout(timer); Object.assign(row,{code,signal,stdout,stderr,exitedAt:Date.now()}); resolve();});
      });
      row.eventsAtExit = events.length-startIndex;
      await delay(2000);
      row.eventsAfterDrain = events.length-startIndex;
      row.events = events.slice(startIndex);
      row.canaryDenialEvents = row.events.filter(event=>event.line.includes(entry.canaryPrefix) && event.line.includes('deny')).length;
      row.protectedAfter=hashes(entry.protected);
      row.protectedUnchanged=entry.protected.every(path=>row.protectedBefore[path]===row.protectedAfter[path]);
      row.retained = store.getCount();
      row.total = store.getTotalCount();
    } catch(error) {row.setupError=String(error);}
    result.cases.push(row);
  }
} catch(error) {result.setupError=String(error);}
finally {
  result.finalRetained=store.getCount();
  result.finalTotal=store.getTotalCount();
  result.subscribedEvents=events.length;
  unsubscribe();
  await SandboxManager.reset();
  result.completedAt=Date.now();
  fs.writeFileSync(outputPath,JSON.stringify(result,null,2));
}
