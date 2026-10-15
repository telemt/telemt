(()=>{'use strict';
function create(settings){
 let queuedBytes=0,queuedItems=0;
 const retiredLimit=4096,activeStreams=new Set(),retiredStreams=new Set(),retiredStreamOrder=[];
 function reserve(data,lane){
  const limits=settings.limits(),buffered=settings.buffered();
  if(!data.byteLength||data.byteLength>limits.queueBytes-queuedBytes-buffered||queuedItems>=limits.queueItems)return false;
  if(lane&&(data.byteLength>limits.laneBytes-lane.bytes-(lane.socket?lane.socket.bufferedAmount:0)||lane.items>=limits.laneItems))return false;
  queuedBytes+=data.byteLength;queuedItems++;if(lane){lane.bytes+=data.byteLength;lane.items++}return true;
 }
 function release(bytes,items,lane){
  if(bytes>queuedBytes||items>queuedItems||(lane&&(bytes>lane.bytes||items>lane.items)))throw new Error('queue accounting invariant');
  queuedBytes-=bytes;queuedItems-=items;if(lane){lane.bytes-=bytes;lane.items-=items}
 }
 function releasePending(values,lane){
  if(!values.length)return;let bytes=0;for(const value of values)bytes+=value.byteLength;
  const items=values.length;values.length=0;release(bytes,items,lane);
 }
 function frameBound(value,maxFrames,maxBytes){
  const view=new DataView(value);let offset=0,frames=0;
  while(offset<value.byteLength){
   if(value.byteLength-offset<8)throw new Error('invalid frame batch');
   const size=view.getUint32(offset+4),end=offset+8+size;
   if(size>1048576||end>value.byteLength)throw new Error('invalid frame');
   if(frames>0&&(frames>=maxFrames||end>maxBytes))break;
   frames++;offset=end;
  }
  if(!frames)throw new Error('empty frame batch');
  return {frames,bytes:offset};
 }
 function splitFrames(value){
  const view=new DataView(value),result=[];let offset=0;
  while(offset<value.byteLength){
   if(value.byteLength-offset<8||result.length>=4096)throw new Error('invalid frame batch');
   const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
   const size=view.getUint32(offset+4),end=offset+8+size;
   if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');
   result.push({type,id,data:offset===0&&end===value.byteLength?value:value.slice(offset,end)});offset=end;
  }
  if(!result.length)throw new Error('empty frame batch');return result;
 }
 function rememberStreamRetired(id){
  if(!id||retiredStreams.has(id))return;
  if(retiredStreamOrder.length===retiredLimit)retiredStreams.delete(retiredStreamOrder.shift());
  retiredStreams.add(id);retiredStreamOrder.push(id);
 }
 function acceptNativeFrames(data){
  const values=splitFrames(data),accepted=[];
  for(const value of values){
   if(retiredStreams.has(value.id)&&!activeStreams.has(value.id))continue;
   if(value.type===1){
    if(!activeStreams.has(value.id)&&activeStreams.size>=settings.maxStreams())throw settings.failure('capacity','stream capacity exhausted');
    activeStreams.add(value.id);accepted.push(value.data);continue;
   }
   if(value.type===3){activeStreams.delete(value.id);rememberStreamRetired(value.id)}
   accepted.push(value.data);
  }
  if(accepted.length===values.length)return data;if(!accepted.length)return null;
  let total=0;for(const value of accepted)total+=value.byteLength;
  const joined=new Uint8Array(total);let offset=0;
  for(const value of accepted){joined.set(new Uint8Array(value),offset);offset+=value.byteLength}
  return joined.buffer;
 }
 function observeServerFrames(data){
  for(const value of splitFrames(data))if(value.type===3){activeStreams.delete(value.id);rememberStreamRetired(value.id)}
 }
 function probeFrames(excludedRanges){
  const result=[];let scanned=0,pending=settings.pending(),batchLimit=settings.limits().batchBytes,more=false;
  for(let index=0;index<pending.length;index++){
   const source=pending[index],view=new DataView(source),ranges=excludedRanges.get(source)||[];let start=0,rangeIndex=0;
   while(start<source.byteLength){
    while(rangeIndex<ranges.length&&ranges[rangeIndex].end<=start)rangeIndex++;
    if(rangeIndex<ranges.length&&ranges[rangeIndex].start===start){start=ranges[rangeIndex++].end;continue}
    if(source.byteLength-start<8)throw new Error('invalid frame batch');
    const type=view.getUint8(start),id=(view.getUint8(start+1)<<16)|(view.getUint8(start+2)<<8)|view.getUint8(start+3);
    const size=view.getUint32(start+4),end=start+8+size,bytes=end-start;
    if((type===2&&!size)||size>1048576||end>source.byteLength)throw new Error('invalid frame');
    const frame={source,index,start,end,type,id};start=end;
    if(result.length>=4096||scanned+bytes>batchLimit){more=true;return {frames:result,more}}
    result.push(frame);scanned+=bytes;
   }
  }
  return {frames:result,more};
 }
 function findProbe(includeData,excludeSpans,targetID,targetType,collectAll){
  const excludedRanges=new Map();
  for(const span of excludeSpans||[]){const ranges=excludedRanges.get(span.source)||[];ranges.push(span);excludedRanges.set(span.source,ranges)}
  const scanned=probeFrames(excludedRanges),frames=scanned.frames;
  let first;const selected=[];let hasData;
  if(targetID!==undefined){
   first=frames.findIndex(frame=>frame.id===targetID&&frame.type===(targetType===undefined?2:targetType));
   if(first<0){
    if(!scanned.more)return null;
    const laneMode=settings.laneMode();for(const frame of frames)if(!laneMode||frame.id===targetID)selected.push(frame);
    if(!selected.length)return null;
    first=frames.indexOf(selected[0]);
   }
   let last=first;
   if(collectAll)for(let index=first+1;index<frames.length;index++)if(frames[index].id===targetID&&frames[index].type===(targetType===undefined?2:targetType))last=index;
   const laneMode=settings.laneMode();
   if(selected.length===0)for(let index=0;index<=last;index++)if(!laneMode||frames[index].id===targetID)selected.push(frames[index]);
   hasData=selected.some(frame=>frame.type===2);
  }else{
   first=frames.findIndex(frame=>frame.type===1||frame.type===2);if(first<0)return null;
   hasData=frames[first].type===2;
   if(settings.laneMode()){
   selected.push(frames[first]);
   if(includeData&&!hasData)for(let index=first+1;index<frames.length;index++)if(frames[index].id===frames[first].id){selected.push(frames[index]);if(frames[index].type===2){hasData=true;break}}
   }else{
    let last=first;
    if(includeData&&!hasData)for(let index=first+1;index<frames.length;index++){if(frames[index].id===frames[first].id&&frames[index].type===2){last=index;hasData=true;break}}
    for(let index=0;index<=(hasData?last:first);index++)selected.push(frames[index]);
   }
  }
  const spans=[];let total=0;
  for(const frame of selected){
   const previous=spans[spans.length-1];total+=frame.end-frame.start;
   if(previous&&previous.source===frame.source&&previous.end===frame.start)previous.end=frame.end;
   else spans.push({source:frame.source,index:frame.index,start:frame.start,end:frame.end});
  }
  const joined=new Uint8Array(total);let offset=0;
  for(const span of spans){const part=new Uint8Array(span.source,span.start,span.end-span.start);joined.set(part,offset);offset+=part.byteLength}
  return {spans,id:frames[first].id,data:joined.buffer,hasData,more:scanned.more};
 }
 function consumeProbe(probe){
  const pending=settings.pending(),groups=new Map();
  for(const span of probe.spans){if(pending[span.index]!==span.source)throw new Error('stale carrier probe');const values=groups.get(span.index)||[];values.push(span);groups.set(span.index,values)}
  const indexes=Array.from(groups.keys()).sort((left,right)=>right-left);
  for(const index of indexes){
   const source=pending[index],spans=groups.get(index).sort((left,right)=>left.start-right.start);let removed=0,offset=0;
   for(const span of spans){if(span.start<offset)throw new Error('overlapping carrier probe');removed+=span.end-span.start;offset=span.end}
   if(removed===source.byteLength){pending.splice(index,1);release(removed,1,null);continue}
   const merged=new Uint8Array(source.byteLength-removed);let write=0;offset=0;
   for(const span of spans){merged.set(new Uint8Array(source,offset,span.start-offset),write);write+=span.start-offset;offset=span.end}
   merged.set(new Uint8Array(source,offset),write);pending[index]=merged.buffer;release(removed,0,null);
  }
 }
 function canSendCandidate(laneID,socketBuffered,sendBytes){
  const limits=settings.limits();if(queuedBytes>limits.queueBytes)return 'capacity';
  if(queuedBytes+sendBytes>limits.queueBytes)return 'reserved';
  if(queuedBytes+settings.buffered()+sendBytes>limits.queueBytes)return 'buffered';
  if(laneID===null)return true;
  let laneBytes=0,laneItems=0;
  for(const source of settings.pending()){
   const view=new DataView(source);let offset=0;
   while(offset<source.byteLength){
    const id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3),size=view.getUint32(offset+4),end=offset+8+size;
    if(end>source.byteLength)throw new Error('invalid frame');
    if(id===laneID){laneBytes+=end-offset;laneItems++}offset=end;
   }
  }
  if(laneItems>limits.laneItems||laneBytes>limits.laneBytes)return 'capacity';
  if(laneBytes+sendBytes>limits.laneBytes)return 'reserved';
  return laneBytes+socketBuffered+sendBytes<=limits.laneBytes?true:'buffered';
 }
 function joinPending(values,lane){
  const batchLimit=settings.limits().batchBytes;let total=0,count=0,frames=0;
  while(count<values.length){
   const bound=frameBound(values[count],4096,batchLimit),whole=bound.bytes===values[count].byteLength;
   if(count===0&&!whole){
    const head=new Uint8Array(values[0],0,bound.bytes).slice();
    values[0]=values[0].slice(bound.bytes);queuedItems++;if(lane)lane.items++;
    return {body:head.buffer,total:bound.bytes,count:1};
   }
   if(count&&(total+values[count].byteLength>batchLimit||frames+bound.frames>4096))break;
   total+=values[count].byteLength;frames+=bound.frames;count++;
  }
  const joined=new Uint8Array(total);let offset=0;
  for(const data of values.splice(0,count)){joined.set(new Uint8Array(data),offset);offset+=data.byteLength}
  return {body:joined.buffer,total,count};
 }
 function takeBatch(values,lane){return Object.assign(joinPending(values,lane),{lane,controller:null,cancelled:false,settled:false})}
 function settleBatch(lease){if(!lease||lease.settled)return false;lease.settled=true;release(lease.total,lease.count,lease.lane);return true}
 function cancelBatch(lease){if(!lease||lease.settled)return;lease.cancelled=true;if(lease.controller)lease.controller.abort();settleBatch(lease)}
 function closeFrame(id){const value=new Uint8Array(8);value[0]=3;value[1]=(id>>>16)&255;value[2]=(id>>>8)&255;value[3]=id&255;return value.buffer}
 function retireStream(id){activeStreams.delete(id);rememberStreamRetired(id)}
 function retireAllStreams(){const ids=Array.from(activeStreams);activeStreams.clear();for(const id of ids)rememberStreamRetired(id);return ids}
 function clearStreams(){activeStreams.clear();retiredStreams.clear();retiredStreamOrder.length=0}
 function assertEmpty(){if(queuedBytes!==0||queuedItems!==0)throw new Error('queue accounting leak')}
 return Object.freeze({reserve,release,releasePending,frameBound,splitFrames,acceptNativeFrames,observeServerFrames,findProbe,consumeProbe,canSendCandidate,takeBatch,settleBatch,cancelBatch,closeFrame,retireStream,retireAllStreams,clearStreams,assertEmpty});
}
globalThis.TelemtBridgeBuffers=Object.freeze({create});
})();
