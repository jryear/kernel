// Host-only observation of the pinned supervisor's existing drain clock.
// Return every performance.now value unchanged; never alter its 2000ms deadline.
import fs from 'node:fs';
import path from 'node:path';
export function observeDrain(audit, extendClose=false) {
  const source=fs.readFileSync(process.argv[1],'utf8').split('\n');
  const lines=source.flatMap((line,index)=>line.includes('drainDeadline=performance.now()+2000;')?[index+1]:[]);
  if(lines.length!==1)throw Error('pinned supervisor drain assignment unavailable');
  const location=path.resolve(process.argv[1])+':'+lines[0]+':';
  const realNow=performance.now.bind(performance), timer=globalThis.setTimeout;
  const state={finish_at:null,drain_start_mono:null,deadline_mono:null,waiters:[],lateDelivered:false,releaseDrain:null};
  process.stdin.on('data',()=>{
    if(state.finish_at!==null)return;
    state.finish_at=Date.now()/1000;
    audit({type:'supervisor_finish_observed',finish_at:state.finish_at});
  });
  Object.defineProperty(performance,'now',{configurable:true,value:function(){
    const value=realNow();
    if(state.finish_at!==null && state.deadline_mono===null && new Error().stack.includes(location)) {
      state.drain_start_mono=value;state.deadline_mono=value+2000;
      audit({type:'drain_started',finish_at:state.finish_at,drain_start_mono:value,deadline_mono:state.deadline_mono,source_location:location});
      for(const resume of state.waiters.splice(0))resume();
    }
    return value;
  }});
  if(extendClose)globalThis.setTimeout=function(callback,ms,...args){
    // Only the pinned supervisor's drain delay is held open. The assigned
    // performance-clock deadline above is observed and remains unchanged.
    const isDrain=ms===2000 && state.deadline_mono!==null && new Error().stack.includes(path.resolve(process.argv[1])+':');
    if(!isDrain)return timer(callback,ms,...args);
    return timer(()=>{
      if(state.lateDelivered)callback(...args);
      else {state.releaseDrain=()=>callback(...args);audit({type:'drain_callback_held',deadline_mono:state.deadline_mono});}
    },ms);
  };
  state.acknowledgeLateWrite=()=>{state.lateDelivered=true;if(state.releaseDrain){const release=state.releaseDrain;state.releaseDrain=null;timer(release,0);}};
  state.now=realNow;
  return state;
}
