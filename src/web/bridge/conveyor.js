(()=>{'use strict';
// HTTP request ownership is separate from the native WINDOW credit protocol.
function create(settings){
 const channels=new Map(),window=settings.window,token=settings.token,downBudget=globalThis.TelemtBridgeDownlink.budget(settings.queueLimit);
 let closed=false,order=0,ready=settings.committed(),resolveReady;
 const readyPromise=new Promise(resolve=>{resolveReady=resolve});if(ready)resolveReady();
 const alive=channel=>!closed&&!channel.closed&&settings.alive(channel.lane);
 const remainingBudget=()=>settings.remaining?settings.remaining():Infinity;
 const markReady=()=>{if(!ready){ready=true;resolveReady();settings.commit()}};
 function waitReady(signal){
  if(ready)return Promise.resolve();
  return new Promise((resolve,reject)=>{const abort=()=>reject(new Error('carrier retired'));if(signal&&signal.aborted){abort();return}if(signal)signal.addEventListener('abort',abort,{once:true});readyPromise.then(()=>{if(signal)signal.removeEventListener('abort',abort);resolve()})});
 }
 function get(id,type){
  let channel=channels.get(id);if(channel)return channel;
  const lane=id===null?null:settings.lane(id,type);if(id!==null&&!lane)return null;
  channel={id,lane,pending:[],flights:new Map(),acks:new Set(),next:1,confirmed:0,cursor:'0',controller:null,polling:false,closed:false};
  channel.receiver=globalThis.TelemtBridgeDownlink.create({
   failure:settings.failure,alive:()=>alive(channel),cursor:()=>channel.cursor,lane:id,limit:settings.batchLimit,budget:downBudget,
   cancel:settings.cancel,ready:waitReady,deliver:settings.deliver,advance:next=>{channel.cursor=next},finished:()=>{if(lane)settings.finish(lane,false)}
  });channels.set(id,channel);return channel;
 }
 function enqueue(data,defer){
  if(closed)return;
  const entries=settings.lanes?settings.buffers.splitFrames(data):[{id:null,type:0,data}],touched=new Set();
  for(const entry of entries){
   const channel=get(entry.id,entry.type);if(!channel)continue;
   if(!settings.buffers.reserve(entry.data,channel.lane))throw settings.failure('capacity','carrier queue full');
   channel.pending.push(entry.data);touched.add(channel);
  }
  if(!defer)for(const channel of touched)pump(channel);
 }
 function checkAck(response,sequence){
  if(response.status!==204)throw settings.failure('http','uplink rejected');
  if(response.headers.get('X-Up-Ack')!==String(sequence))throw settings.failure('protocol','uplink acknowledgement rejected');
 }
 function acknowledge(channel,sequence,lease){
  if(!alive(channel)||channel.flights.get(sequence)!==lease)return;
  settings.buffers.settleBatch(lease);channel.flights.delete(sequence);channel.acks.add(sequence);
  while(channel.acks.delete(channel.confirmed+1))channel.confirmed++;
  markReady();settings.traffic(lease.total,0);pump(channel);
 }
 async function send(channel,sequence,lease){
  const headers={'X-Up-Seq':String(sequence)};if(channel.id!==null)headers['X-Lane-ID']=String(channel.id);
  if(window>1)headers['X-Telemt-Up-Confirmed']=String(channel.confirmed);
  const frozen=settings.options(settings.method,token,lease.body,headers,lease.controller.signal);
  try{
   while(alive(channel)&&!lease.cancelled){
    try{const response=await settings.request('/api/v1/up',frozen,remainingBudget,()=>ready?1:9);if(!alive(channel))return;checkAck(response,sequence);acknowledge(channel,sequence,lease);return}
    catch(error){
     if(!alive(channel)||lease.cancelled)return;
     if(!ready){settings.failed(error);return}
     let replayed=false;
     const recovered=await settings.recover(error,async(signal,remaining,accepted)=>{
      const response=await settings.request('/api/v1/up',Object.assign({},frozen,{signal}),remaining,2,undefined,accepted);
      if(!alive(channel)||lease.cancelled)return;if(remaining()<=0)throw settings.failure('timeout','recovery deadline');checkAck(response,sequence);accepted();replayed=true;acknowledge(channel,sequence,lease);
     });
     if(!recovered||!alive(channel)||replayed)return;
    }
   }
  }catch(error){if(alive(channel)&&!lease.cancelled)settings.failed(error)}
 }
 function pump(channel){
  while(alive(channel)&&channel.pending.length&&channel.next<=channel.confirmed+window){
   const lease=settings.buffers.takeBatch(channel.pending,channel.lane),sequence=channel.next++;
   lease.controller=new AbortController();lease.order=order++;channel.flights.set(sequence,lease);send(channel,sequence,lease);
   if(!channel.polling)poll(channel);
  }
 }
 async function poll(channel){
  if(channel.polling||!alive(channel))return;channel.polling=true;
  try{
   while(alive(channel)){
    const cursor=channel.cursor,headers={'X-Down-Cursor':cursor};if(channel.id!==null)headers['X-Lane-ID']=String(channel.id);
    channel.controller=new AbortController();const frozen=settings.options(settings.method,token,null,headers,channel.controller.signal);
    try{
     const response=await settings.request('/api/v1/down',frozen,remainingBudget,1,channel.receiver.read);
     if(!alive(channel))return;if(response.status!==200&&response.status!==204)throw settings.failure('http','downlink rejected');
     if(ready)settings.connected();
    }catch(error){
     if(!alive(channel))return;
     if(!ready){settings.failed(error);return}
     const recovered=await settings.recover(error,async(signal,remaining,accepted)=>{
      const response=await settings.request('/api/v1/down',Object.assign({},frozen,{signal}),remaining,2,channel.receiver.read,accepted);
      if(remaining()<=0)throw settings.failure('timeout','recovery deadline');
      if(response.status!==200&&response.status!==204)throw settings.failure('http','downlink replay rejected');
     });
     if(!recovered||!alive(channel))return;
    }
   }
  }catch(error){if(alive(channel))settings.failed(error)}
  finally{channel.polling=false;channel.controller=null}
 }
 function retire(channel,restore){
  channel.closed=true;if(channel.controller)channel.controller.abort();channel.receiver.close();
  const saved=[];
  for(const lease of channel.flights.values()){if(restore)saved.push({order:lease.order,data:lease.body});settings.buffers.cancelBatch(lease);}
  channel.flights.clear();channel.acks.clear();
  for(const data of channel.pending)if(restore)saved.push({order:order++,data});
  settings.buffers.releasePending(channel.pending,channel.lane);return saved;
 }
 return {enqueue,flush(){for(const channel of channels.values())pump(channel)},finish(lane){const channel=channels.get(lane.id);if(channel){channels.delete(lane.id);retire(channel,false)}},close(restore){
  if(closed)return [];closed=true;const saved=[];for(const channel of channels.values())saved.push(...retire(channel,restore));channels.clear();
  return saved.sort((a,b)=>a.order-b.order).map(entry=>entry.data);
 }};
}
globalThis.TelemtBridgeConveyor=Object.freeze({create});
})();
