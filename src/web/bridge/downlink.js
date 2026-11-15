(()=>{'use strict';
// Prefix ownership survives HTTP retries, but never a session or lane replacement.
function budget(limit){
 let used=0;const waiters=[];
 function wake(){for(const next of waiters.slice())next()}
 function acquire(size,signal){
  if(size>limit())return Promise.reject(new Error('downlink budget exceeded'));
  return new Promise((resolve,reject)=>{
   const remove=()=>{const at=waiters.indexOf(tryAcquire);if(at>=0)waiters.splice(at,1);if(signal)signal.removeEventListener('abort',abort)};
   const abort=()=>{remove();reject(new Error('downlink aborted'))};
   const tryAcquire=()=>{if(signal&&signal.aborted){abort();return}if(size<=limit()-used){remove();used+=size;let released=false;resolve(()=>{if(!released){released=true;used-=size;wake()}})}};
   waiters.push(tryAcquire);if(signal)signal.addEventListener('abort',abort,{once:true});tryAcquire();
  });
 }
 return {acquire,used:()=>used};
}
function create(settings){
 let transaction=null,closed=false;
 const protocol=message=>settings.failure('protocol',message);
 const current=signal=>!closed&&settings.alive()&&!(signal&&signal.aborted);
 const withinBudget=remaining=>{if(remaining&&remaining()<=0)throw settings.failure('timeout','recovery deadline')};
 function dispose(){if(transaction){transaction.release();transaction=null}}
 function shape(type,id,size){
  if(type===2)return id!==0&&size>0&&size<=1048576;
  if(type===3)return id!==0&&size===0;
  if(type===4)return id!==0&&size===4;
  if(type===5)return id===0&&size<=64;
  return type===31&&id===0&&size===0;
 }
 async function read(response,signal,remaining,accepted){
  withinBudget(remaining);
  if(!current(signal))throw new Error('downlink retired');
  if(response.status===204){
   settings.cancel(response);if(transaction)throw protocol('missing replay batch');
   const cursor=response.headers.get('X-Down-Cursor');
   if(cursor!==null&&cursor!==settings.cursor())throw protocol('changed empty cursor');
   withinBudget(remaining);
   if(accepted)accepted();
   if(response.headers.get('X-Lane-Closed')==='1')settings.finished();
   return new ArrayBuffer(0);
  }
  const next=response.headers.get('X-Down-Cursor')||'',base=settings.cursor();
  if(!/^[1-9]\d*$/.test(next)||BigInt(next)!==BigInt(base)+1n||BigInt(next)>18446744073709551615n)throw protocol('invalid downlink cursor');
  const length=response.headers.get('Content-Length');let declared=null;
  if(length!==null){if(!/^(0|[1-9]\d*)$/.test(length))throw protocol('invalid response length');declared=Number(length);if(!Number.isSafeInteger(declared)||declared===0||declared>settings.limit())throw protocol('response body overflow');}
  if(transaction&&(transaction.base!==base||transaction.next!==next||(transaction.declared!==null&&declared!==null&&transaction.declared!==declared)))throw protocol('changed replay metadata');
  if(!transaction){
   const capacity=declared===null?settings.limit():declared,release=await settings.budget.acquire(capacity,signal);
   try{withinBudget(remaining)}catch(error){release();throw error}
   if(!current(signal)){release();throw new Error('downlink retired');}
   transaction={base,next,declared,bytes:new Uint8Array(capacity),retained:0,delivered:0,release};
  }
  const owner=transaction;
  if(owner.declared===null&&declared!==null)owner.declared=declared;
  await settings.ready(signal);
  withinBudget(remaining);
  if(!current(signal)||transaction!==owner)throw new Error('downlink retired');
  if(!response.body)throw protocol('missing response body');
  const reader=response.body.getReader();let position=0,offset=0,frames=0,chunks=0,complete=false;
  try{
   for(;;){
    let part;try{part=await reader.read();}catch(error){throw settings.failure('network','response stream interrupted');}
    withinBudget(remaining);
    if(!current(signal)||transaction!==owner)throw new Error('downlink retired');
    if(part.done)break;
    const data=part.value;if(!(data instanceof Uint8Array)||++chunks>65536||data.byteLength>owner.bytes.byteLength-position)throw protocol('response body overflow');
    const compared=Math.min(data.byteLength,Math.max(0,owner.retained-position));
    for(let i=0;i<compared;i++)if(data[i]!==owner.bytes[position+i])throw protocol('changed replay prefix');
    owner.bytes.set(data.subarray(compared),position+compared);position+=data.byteLength;owner.retained=Math.max(owner.retained,position);
    while(position-offset>=8){
     const view=new DataView(owner.bytes.buffer,offset),type=view.getUint8(0),id=(view.getUint8(1)<<16)|(view.getUint8(2)<<8)|view.getUint8(3),size=view.getUint32(4),end=offset+8+size;
     if(!shape(type,id,size)||(settings.lane!==null&&id!==settings.lane)||end>owner.bytes.byteLength)throw protocol('invalid downlink frame');
     if(end>position)break;if(++frames>4096)throw protocol('too many downlink frames');
     if(type===4&&view.getUint32(8)===0)throw protocol('invalid WINDOW credit');
     if(end>owner.delivered){
      if(offset!==owner.delivered)throw protocol('invalid replay boundary');
      withinBudget(remaining);
      const frame=owner.bytes.slice(offset,end).buffer;
      settings.deliver(frame);owner.delivered=end;
     }
     offset=end;
    }
   }
   if(!position||offset!==position||position<owner.retained||(owner.declared!==null&&position!==owner.declared))throw protocol('incomplete downlink batch');
   withinBudget(remaining);if(accepted)accepted();settings.advance(next);complete=true;dispose();return new ArrayBuffer(0);
  }finally{
   if(!complete)try{const cancelled=reader.cancel();if(cancelled)cancelled.catch(()=>{});}catch(error){}
   reader.releaseLock();
  }
 }
 return {read,close(){closed=true;dispose()}};
}
globalThis.TelemtBridgeDownlink=Object.freeze({create,budget});
})();
