(()=>{'use strict';
const HEADER_BYTES=8,FRAME_BYTES=24,DEADLINE_MS=1000;
function encoded(type,nonce){const value=new Uint8Array(FRAME_BYTES);value[0]=type;value[7]=16;value.set(nonce,HEADER_BYTES);return value.buffer}
function inspect(value){
 if(!(value instanceof ArrayBuffer))return null;
 const bytes=new Uint8Array(value);let offset=0,count=0,control=null,malformed=false;const view=new DataView(value);
 while(offset<bytes.length){
  if(bytes.length-offset<HEADER_BYTES){malformed=true;break}
  const type=bytes[offset],id=(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3],size=view.getUint32(offset+4);
  if(type===6&&id===0){if(control)malformed=true;else control={offset,size}}
  const end=offset+HEADER_BYTES+size;if(end>bytes.length){malformed=true;break}
  count++;offset=end;
 }
 if(!control)return null;
 const exact=!malformed&&offset===bytes.length&&count===1&&control.offset===0&&control.size===16&&bytes.length===FRAME_BYTES;
 return {exact,nonce:exact?bytes.slice(HEADER_BYTES):null};
}
function create(settings){
 let active=null;
 function finish(owner,error){
  if(owner.finished)return;owner.finished=true;clearTimeout(owner.timer);owner.timer=null;
  if(owner.signal)owner.signal.removeEventListener('abort',owner.abort);if(active===owner)active=null;
  if(error)owner.reject(error);else owner.resolve(true);
 }
 function remaining(owner){return Math.max(0,Math.min(owner.wallDeadline-Date.now(),owner.monotonicDeadline-performance.now()))}
 function probe(entries,signal){
  if(active)return Promise.reject(new Error('resume probe already active'));
  if(!Array.isArray(entries)||!entries.length||!globalThis.crypto||typeof globalThis.crypto.getRandomValues!=='function')return Promise.reject(new Error('resume probe unavailable'));
  const owner={entries,signal,wallDeadline:Date.now()+DEADLINE_MS,monotonicDeadline:performance.now()+DEADLINE_MS,pending:new Map(),finished:false,timer:null,resolve:null,reject:null,abort:null};
  const result=new Promise((resolve,reject)=>{owner.resolve=resolve;owner.reject=reject});active=owner;
  owner.abort=()=>finish(owner,new Error('resume probe cancelled'));
  if(signal){signal.addEventListener('abort',owner.abort,{once:true});if(signal.aborted){owner.abort();return result}}
  owner.timer=setTimeout(()=>finish(owner,new Error('resume probe deadline')),Math.max(1,remaining(owner)));
  (async()=>{
   try{
    while(remaining(owner)>0){
     if(owner.finished||active!==owner)throw new Error('resume probe settled');
     if(!settings.current(entries))throw new Error('resume probe owner changed');
     if(entries.every(entry=>settings.ready(entry)))break;
     await settings.wait(Math.min(10,remaining(owner)),signal);
     if(owner.finished||active!==owner)throw new Error('resume probe settled');
    }
    if(owner.finished||active!==owner||remaining(owner)<=0||!settings.current(entries))throw new Error('resume probe deadline');
    for(const entry of entries){
     if(owner.finished||active!==owner||remaining(owner)<=0||!settings.current(entries))throw new Error('resume probe deadline');
     if(owner.pending.has(entry.socket))throw new Error('duplicate resume probe socket');
     const nonce=new Uint8Array(16);globalThis.crypto.getRandomValues(nonce);owner.pending.set(entry.socket,{nonce,epoch:entry.epoch});
    }
    if(!owner.pending.size)throw new Error('resume probe has no captured sockets');
    for(const entry of entries){
     if(owner.finished||active!==owner||remaining(owner)<=0||!settings.current(entries))throw new Error('resume probe expired before send');
     entry.socket.send(encoded(5,owner.pending.get(entry.socket).nonce));
    }
   }catch(error){finish(owner,error)}
  })();
  return result;
 }
 function receive(socket,value,epoch){
  const observed=inspect(value);if(!observed)return false;
  const owner=active,expected=owner&&owner.pending.get(socket);if(!owner)return true;
  const current=settings.current(owner.entries);
  if(!expected||expected.epoch!==epoch||!observed.exact||remaining(owner)<=0||!current){finish(owner,new Error('resume probe response rejected'));return true}
  if(expected.nonce.some((byte,index)=>byte!==observed.nonce[index])){finish(owner,new Error('resume probe nonce mismatch'));return true}
  owner.pending.delete(socket);
  if(!owner.pending.size){if(remaining(owner)<=0||!settings.current(owner.entries))finish(owner,new Error('resume probe expired'));else finish(owner,null)}
  return true;
 }
 return Object.freeze({probe,receive,active:()=>active!==null});
}
globalThis.TelemtBridgeResumeProbe=Object.freeze({create});
})();
