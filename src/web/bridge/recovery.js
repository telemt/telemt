(()=>{
'use strict';
const mediaType='application/vnd.telemt.web-recovery+json',maxBytes=1024,heartbeatMs=2500;
const exactKeys=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.slice().sort().join(',');
const integer=(value,min,max)=>Number.isSafeInteger(value)&&value>=min&&value<=max;
function parsePolicy(bytes){
 let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes))}catch(error){throw new Error('invalid recovery document')}
 if(!exactKeys(value,['v','bootstrap','limits','timeouts','negotiation'])||value.v!==1||!/^[A-Za-z0-9_-]{43}$/.test(value.bootstrap))throw new Error('invalid recovery document');
 const limits=value.limits,timeouts=value.timeouts,negotiation=value.negotiation;
 if(!exactKeys(limits,['carrier_batch_bytes','pending_bytes_per_session','pending_items_per_session','max_streams_per_session'])
  ||!integer(limits.carrier_batch_bytes,8,16777216)||!integer(limits.pending_bytes_per_session,limits.carrier_batch_bytes,4294967296)
  ||!integer(limits.pending_items_per_session,1,1048576)||!integer(limits.max_streams_per_session,1,16777215))throw new Error('invalid recovery limits');
 if(!exactKeys(timeouts,['long_poll_secs','bridge_request_secs','bridge_retry_secs','bridge_recovery_secs','websocket_open_secs','reconnect_grace_secs'])
  ||!integer(timeouts.long_poll_secs,1,3600)||!integer(timeouts.bridge_request_secs,1,60)||!integer(timeouts.bridge_retry_secs,1,300)
  ||!integer(timeouts.bridge_recovery_secs,1,60)||!integer(timeouts.websocket_open_secs,1,300)||!integer(timeouts.reconnect_grace_secs,1,3600))throw new Error('invalid recovery timeouts');
 if(!exactKeys(negotiation,['enabled','candidate_count','deadlines_secs','carrier_probe_coalesce_ms'])||typeof negotiation.enabled!=='boolean'
  ||!integer(negotiation.candidate_count,1,4)||!Array.isArray(negotiation.deadlines_secs)||negotiation.deadlines_secs.length!==4
  ||!negotiation.deadlines_secs.every((entry,index)=>integer(entry,1,3600)&&(index===0||entry>negotiation.deadlines_secs[index-1]))
  ||!integer(negotiation.carrier_probe_coalesce_ms,0,10))throw new Error('invalid recovery negotiation');
 return value;
}
function create(settings){
 let current=null,nextEpoch=1;
 const remaining=owner=>Math.max(0,Math.min(owner.wall-Date.now(),owner.monotonic-performance.now()));
 function stop(owner){
  if(owner.heartbeat)clearTimeout(owner.heartbeat);owner.heartbeat=null;
  if(owner.deadlineTimer)clearTimeout(owner.deadlineTimer);owner.deadlineTimer=null;
 }
 function heartbeat(owner){
  if(current!==owner||owner.controller.signal.aborted||owner.accepted)return;
  const left=remaining(owner);settings.status(left);
  if(left<=0){owner.controller.abort();return}owner.heartbeat=setTimeout(()=>heartbeat(owner),Math.min(heartbeatMs,left));
 }
 async function load(owner){
  const left=remaining(owner);if(left<=0)throw new Error('recovery deadline');
  const requestController=new AbortController(),abort=()=>requestController.abort();
  owner.controller.signal.addEventListener('abort',abort,{once:true});
  const timer=setTimeout(abort,Math.max(1,Math.min(settings.requestMs(),left)));
  try{
   const token=settings.token();
   const response=await fetch(settings.url(),{
    method:'GET',signal:requestController.signal,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
    headers:Object.assign({Accept:mediaType},token?{Authorization:'Bearer '+token}:{})
   });
   if(response.status!==200||response.headers.get('Content-Type')!==mediaType){settings.cancel(response);throw new Error('recovery representation rejected')}
   const bytes=await settings.read(response,maxBytes,false,requestController.signal);
   return parsePolicy(bytes);
  }finally{
   clearTimeout(timer);owner.controller.signal.removeEventListener('abort',abort);
  }
 }
 function activeBeforeDeadline(owner){
  if(current!==owner)return false;
  if(owner.accepted)return true;
  if(owner.controller.signal.aborted||remaining(owner)<=0)throw new Error('recovery deadline');
  return true;
 }
 async function run(owner,replay){
  heartbeat(owner);
  if(replay){
   try{
    if(!activeBeforeDeadline(owner))return false;
    await replay(owner.controller.signal,()=>remaining(owner),()=>{owner.accepted=true});
    if(!activeBeforeDeadline(owner))return false;
    settings.restored();return true;
   }catch(error){
    if(current!==owner)return false;
    if(!owner.accepted&&(owner.controller.signal.aborted||remaining(owner)<=0))throw new Error('recovery deadline');
    if(!settings.replaceable(error))throw error;
   }
  }
  if(!activeBeforeDeadline(owner))return false;
  const policy=await load(owner);
  if(!activeBeforeDeadline(owner))return false;
  await settings.replace(policy,owner.controller.signal,()=>remaining(owner),owner.epoch,()=>{owner.accepted=true});
  if(!activeBeforeDeadline(owner))return false;
  return true;
 }
 function recover(reason,replay){
  if(current)return current.promise;
  const budget=settings.budgetMs(),owner={epoch:nextEpoch++,controller:new AbortController(),heartbeat:null,deadlineTimer:null,promise:null,accepted:false};
  owner.wall=Date.now()+budget;owner.monotonic=performance.now()+budget;current=owner;
  owner.deadlineTimer=setTimeout(()=>{if(!owner.accepted)owner.controller.abort()},Math.max(1,remaining(owner)));
  owner.promise=run(owner,replay).catch(error=>{settings.terminal(settings.reason(error,reason));return false}).finally(()=>{stop(owner);if(current===owner)current=null});
  return owner.promise;
 }
 function cancel(){if(current){const owner=current;current=null;owner.controller.abort();stop(owner)}}
 return Object.freeze({recover,cancel,active:()=>current!==null,remaining:()=>current?remaining(current):0});
}
globalThis.TelemtBridgeRecovery=Object.freeze({create});
})();
