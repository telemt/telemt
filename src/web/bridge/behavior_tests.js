'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

let stdinPage;
function renderedPage(sources={},overrides={}){
 if(process.argv.includes('--stdin')){
  if(stdinPage===undefined)stdinPage=fs.readFileSync(0,'utf8');
  let page=stdinPage;
  if(overrides.NEGOTIATION_ENABLED!==undefined)page=page.replace(/let negotiationEnabled=(?:true|false),/,`let negotiationEnabled=${overrides.NEGOTIATION_ENABLED},`);
  if(overrides.BATCH_LIMIT!==undefined)page=page.replace(/batchLimit=\d+/,`batchLimit=${overrides.BATCH_LIMIT}`);
  if(overrides.QUEUE_LIMIT!==undefined)page=page.replace(/queueLimit=\d+/,`queueLimit=${overrides.QUEUE_LIMIT}`);
  if(overrides.QUEUE_ITEMS!==undefined)page=page.replace(/queueItemLimit=\d+/,`queueItemLimit=${overrides.QUEUE_ITEMS}`);
  if(overrides.BRIDGE_RECOVERY_SECS!==undefined){const updated=page.replace(/let bridgeRecoveryMs=\d+\*1000/,`let bridgeRecoveryMs=${overrides.BRIDGE_RECOVERY_SECS}*1000`);assert.notEqual(updated,page,'stdin page exposes the test recovery timeout');page=updated}
  return page;
 }
 const read=name=>sources[name]===undefined?fs.readFileSync(path.join(__dirname,name),'utf8'):sources[name];
 let page=read('document.html');
 const modules={RESPONSE:'response',REQUEST:'request',BUFFER:'buffers',RECOVERY:'recovery',RESUME_PROBE:'resume_probe',CONVEYOR:'conveyor',DOWNLINK:'downlink'};
 page=page.replace('__DIAGNOSTIC_RUNTIME__','');
 for(const [key,file] of Object.entries(modules))if(page.includes('__'+key+'_RUNTIME__'))page=page.replace('__'+key+'_RUNTIME__',()=>read(file+'.js'));
 page=page.replace('__RUNTIME__',()=>read('runtime.js'));
 const values={RETRY_JITTER:'{enabled:false,min:0,max:250,peak:125,triangular:false}',BOOTSTRAP:'A'.repeat(43),HOST:'proxy.example.com',BASE_PREFIX:'',CARRIER_METHOD:'POST',NEGOTIATION_ENABLED:'true',CANDIDATE_COUNT:4,CARRIER_DEADLINES:'3,5,8,12',LONG_POLL_SECS:25,BRIDGE_REQUEST_SECS:10,BRIDGE_RETRY_SECS:90,BRIDGE_RECOVERY_SECS:15,WEBSOCKET_OPEN_SECS:15,RECONNECT_GRACE_SECS:120,CARRIER_PROBE_COALESCE_MS:0,BATCH_LIMIT:2097152,QUEUE_LIMIT:33554432,QUEUE_ITEMS:16384,MAX_STREAMS:1024,STATUS_FUNCTION:"state=>{if(port&&!closed)port.postMessage({t:'status',state})}",HELLO_TIMEOUT_CALLBACK:"()=>fail('timeout')",PAGEHIDE_CALLBACK:'()=>close(true)',...overrides}; return page.replace(/__([A-Z_]+)__/g,(all,key)=>key.startsWith('DIAGNOSTIC_')?'':String(values[key]??''));
}
function frame(type,id=0,payload=[]){
 const data=new Uint8Array(8+payload.length),view=new DataView(data.buffer);
 data[0]=type;data[1]=id>>>16;data[2]=id>>>8;data[3]=id;view.setUint32(4,payload.length);data.set(payload,8);return data.buffer;
}
function join(...frames){const data=new Uint8Array(frames.reduce((n,f)=>n+f.byteLength,0));let offset=0;for(const f of frames){data.set(new Uint8Array(f),offset);offset+=f.byteLength}return data.buffer}
async function flush(){for(let i=0;i<40;i++)await Promise.resolve()}
function environment(page,android=false){
 let now=1000,nextTimer=1;const timers=new Map(),events=new Map(),requests=[],received=[],webSockets=[];
 const port={onmessage:null,start(){},close(){},postMessage(value,transfer){received.push(structuredClone(value,{transfer:transfer||[]}))}};
 const context={ArrayBuffer,Uint8Array,DataView,TextDecoder,TextEncoder,URL,Headers,AbortController,ReadableStream,structuredClone,console,
  location:{hash:android?'#android='+'A'.repeat(43):'',pathname:'/',search:'?bridge=test'},history:{replaceState(){}},parent:{},
  performance:{now:()=>now},Date:class extends Date{static now(){return now}},document:{visibilityState:'visible',addEventListener(){}},
  addEventListener:(name,fn)=>events.set(name,fn),setTimeout:(fn,delay)=>{const id=nextTimer++;timers.set(id,{fn,at:now+delay});return id},clearTimeout:id=>timers.delete(id),
  fetch:(url,options)=>new Promise((resolve,reject)=>{const request={url,options,resolve,reject};requests.push(request);options.signal?.addEventListener('abort',()=>reject(new Error('aborted')),{once:true})}),
  WebSocket:class {
   static CONNECTING=0;static OPEN=1;static CLOSING=2;static CLOSED=3;
   constructor(url,protocol){this.url=url;this.protocol=protocol;this.readyState=0;this.bufferedAmount=0;this.sent=[];webSockets.push(this)}
   open(){if(this.readyState!==0)return;this.readyState=1;this.onopen?.()}
   send(data){if(this.readyState!==1)throw new Error('websocket is not open');if(this.throwOnSend===this.sent.length+1)throw new Error('synthetic send failure');this.sent.push(data.slice(0));this.bufferedAmount+=data.byteLength}
   message(data){this.onmessage?.({data:data.slice(0)})}
   close(){if(this.readyState===3)return;this.readyState=3;this.onclose?.()}
  }
 };
 if(android)context.TelegramWebProxy={onmessage:null,postMessage(value){received.push(typeof value==='string'?JSON.parse(value):structuredClone(value))}};
 vm.createContext(context);
 for(const match of page.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g))vm.runInContext(match[1],context);
 if(!android)events.get('message')({source:context.parent,origin:'http://127.0.0.1:12345',data:{t:'tproxy-init',v:1},ports:[port]});
 const send=data=>android?context.TelegramWebProxy.onmessage({data}):port.onmessage({data});
 const pending=suffix=>requests.filter(r=>r.url.endsWith(suffix)&&!r.answered);
 const answer=(request,status,body=null,headers={})=>{request.answered=true;request.resolve({status,headers:new Headers(headers),body:body===null?null:new ReadableStream({start(c){c.enqueue(new Uint8Array(body));c.close()}})})};
 return {context,port,send,pending,answer,received,requests,webSockets,now:()=>now,schedule:(fn,delay)=>context.setTimeout(fn,delay),async tick(ms){const until=now+ms;for(;;){const entry=[...timers].filter(([,t])=>t.at<=until).sort((a,b)=>a[1].at-b[1].at)[0];if(!entry)break;now=entry[1].at;timers.delete(entry[0]);entry[1].fn();await flush()}now=until;await flush()},suspend(ms){now+=ms},async resume(){const until=now;for(;;){const entry=[...timers].filter(([,t])=>t.at<=until).sort((a,b)=>a[1].at-b[1].at)[0];if(!entry)break;timers.delete(entry[0]);entry[1].fn();await flush()}},close(){events.get('pagehide')();}};
}
async function session(page,carrier='https',window=1,android=false){
 const env=environment(page,android);env.send(frame(16,0,[1]));await flush();
 const request=env.pending('/api/v1/session')[0];assert.ok(request,'session requested');
 const headers={'X-Session-Token':'B'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':carrier,'X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional'};
 if(window!==null)headers['X-Telemt-Up-Window']=String(window);
 env.answer(request,200,frame(17),headers);await flush();return env;
}
const tests=[];
function test(name,run){tests.push({name,run})}
function ack(env,request){env.answer(request,204,null,{'X-Up-Ack':request.options.headers['X-Up-Seq']})}
function binary(env){return env.received.filter(value=>value instanceof ArrayBuffer&&new Uint8Array(value)[0]!==17)}
function streaming(env,request,next='1',length=null){
 let controller;const body=new ReadableStream({start(value){controller=value}}),headers={'X-Down-Cursor':next};if(length!==null)headers['Content-Length']=String(length);
 request.answered=true;request.resolve({status:200,headers:new Headers(headers),body});return controller;
}
test('Telemt overload hint retries at 250 ms with legacy and malformed fallback',async page=>{
 for(const android of [false,true])for(const carrier of ['https','https-lanes'])for(const [status,hint,retry,delay] of [
  [503,'250','1',250],[503,null,'1',1000],[503,'0','1',1000],
  [503,'0.25','1',1000],[503,'250, 250','1',1000],[503,'250','2',2000],[429,'250','1',1000]
 ]){
  const env=await session(page,carrier,4,android);env.send(frame(1,1));await flush();
  const original=env.pending('/api/v1/up')[0],headers={'Retry-After':retry};
  if(hint!==null)headers['X-Telemt-Retry-After-Ms']=hint;
  env.answer(original,status,null,headers);await flush();
  await env.tick(delay-1);assert.equal(env.pending('/api/v1/up').length,0,'retry must not run early');
  await env.tick(1);const replay=env.pending('/api/v1/up')[0];assert.ok(replay,'retry at selected deadline');
  assert.equal(replay.options.headers['X-Up-Seq'],original.options.headers['X-Up-Seq']);
  assert.deepEqual(new Uint8Array(replay.options.body),new Uint8Array(original.options.body));
  ack(env,replay);await flush();env.close();await flush();
 }
});
test('repeated 250 ms overload hints retain the nine-attempt limit',async page=>{
 const env=await session(page);env.send(frame(1,1));await flush();
 for(let attempt=1;attempt<=9;attempt++){
  const request=env.pending('/api/v1/up')[0];assert.ok(request,'bounded retry attempt '+attempt);
  env.answer(request,503,null,{'Retry-After':'1','X-Telemt-Retry-After-Ms':'250'});await flush();
  if(attempt<9)await env.tick(250);
 }
 await env.tick(250);
 assert.equal(env.requests.filter(r=>r.url.endsWith('/api/v1/up')).length,9);
 env.close();await flush();
});
test('closing the bridge cancels the 250 ms overload retry',async page=>{
 const env=await session(page);env.send(frame(1,1));await flush();
 env.answer(env.pending('/api/v1/up')[0],503,null,{'Retry-After':'1','X-Telemt-Retry-After-Ms':'250'});await flush();
 await env.tick(249);env.close();await flush();await env.tick(1000);
 assert.equal(env.requests.filter(r=>r.url.endsWith('/api/v1/up')).length,1);
});
test('retry jitter distributions, fallback, deadlines and page ownership',require('./retry_jitter_tests'));
test('configured jitter is added once to the Telemt delay',async page=>{
 page=page.replace('{enabled:false,min:0,max:250,peak:125,triangular:false}','{enabled:true,min:100,max:100,peak:100,triangular:false}');
 const env=await session(page);env.send(frame(1,1));await flush();
 env.answer(env.pending('/api/v1/up')[0],503,null,{'Retry-After':'1','X-Telemt-Retry-After-Ms':'250'});await flush();
 await env.tick(349);assert.equal(env.pending('/api/v1/up').length,0);
 await env.tick(1);assert.equal(env.pending('/api/v1/up').length,1);
 env.close();await flush();
});
test('already queued OPEN and DATA share the zero-wait startup request',async page=>{
 const env=await session(page);const body=join(frame(1,1),frame(2,1,[7,8]));env.send(body);await flush();
 assert.equal(env.pending('/api/v1/up')[0].options.body.byteLength,body.byteLength);env.close();await flush();
});
test('negotiated WebSocket candidates send later DATA before the empty ACK',async page=>{
 for(const android of [false,true])for(const carrier of ['websocket','websocket-lanes']){
  const env=await session(page,carrier,4,android);env.send(frame(1,1));await flush();
  const socket=env.webSockets[0];assert.ok(socket,carrier+' candidate socket');socket.open();
  assert.equal(socket.sent.length,1,'OPEN probe sent first');
  const upTraffic=()=>env.received.filter(value=>value&&value.t==='traffic'&&value.up>0);
  assert.equal(upTraffic().length,0,'initial OPEN probe keeps existing traffic accounting behavior');
  const first=frame(2,1,[9]),second=frame(2,1,[10]);env.send(first);await flush();env.send(second);await flush();
  assert.equal(socket.sent.length,3,carrier+' DATA must not wait for the commit ACK');
  assert.deepEqual(new Uint8Array(socket.sent[1]),new Uint8Array(first));
  assert.deepEqual(new Uint8Array(socket.sent[2]),new Uint8Array(second));
  assert.deepEqual(upTraffic().map(value=>value.up),[first.byteLength,second.byteLength],'successful speculative DATA writes are counted exactly once');
  assert.ok(!env.received.some(value=>value&&value.t==='status'&&value.state==='connected'),'ACK remains the commit fence');
  assert.equal(env.webSockets.length,1,'no extra socket before commit');
  socket.message(new ArrayBuffer(0));await flush();
  assert.equal(socket.sent.length,3,'commit drain must not resend speculative DATA');
  assert.deepEqual(upTraffic().map(value=>value.up),[first.byteLength,second.byteLength],'ACK commit does not count the DATA again');
  assert.ok(env.received.some(value=>value&&value.t==='status'&&value.state==='connected'));
  env.close();await flush();
 }
});
test('candidate pipeline preserves mixed frame order and lane ownership',async page=>{
 for(const carrier of ['websocket','websocket-lanes']){
  const env=await session(page,carrier);env.send(frame(1,1));await flush();const socket=env.webSockets[0];socket.open();
  const mixed=join(frame(1,2),frame(2,2,[2]),frame(2,1,[1]),frame(2,1,[3]));env.send(mixed);await flush();
  assert.equal(env.webSockets.length,1,'other lanes do not open a socket before ACK');
  if(carrier==='websocket'){
   assert.deepEqual(new Uint8Array(socket.sent[1]),new Uint8Array(join(frame(1,2),frame(2,2,[2]),frame(2,1,[1]),frame(2,1,[3]))));
  }else{
   assert.deepEqual(new Uint8Array(socket.sent[1]),new Uint8Array(join(frame(2,1,[1]),frame(2,1,[3]))));
  }
  socket.message(new ArrayBuffer(0));await flush();
  if(carrier==='websocket'){
   assert.equal(socket.sent.length,2,'ACK drain does not duplicate any precommit frame');
   const sent=[];for(const body of socket.sent)for(let offset=0;offset<body.byteLength;){const view=new DataView(body,offset);sent.push([new Uint8Array(body)[offset],new Uint8Array(body)[offset+3]]);offset+=8+view.getUint32(4)}
   assert.deepEqual(sent,[[1,1],[1,2],[2,2],[2,1],[2,1]],'multiplexed frame order is stable and DATA is sent once');
  }else{
  assert.equal(env.webSockets.length,2,'non-candidate lane opens only after ACK');
   const other=env.webSockets[1];other.open();
   await flush();
   assert.deepEqual(new Uint8Array(other.sent[0]),new Uint8Array(join(frame(1,2),frame(2,2,[2]))));
  }
  env.close();await flush();
 }
});
test('precommit native DATA batches are sent once in bounded selections',async page=>{
 for(const carrier of ['websocket','websocket-lanes']){
  const env=await session(page,carrier);env.send(frame(1,1));await flush();const socket=env.webSockets[0];socket.open();
  const frames=Array.from({length:1000},(_,index)=>frame(2,1,[index&255]));const batch=join(...frames),started=process.hrtime.bigint();
  env.send(batch);await flush();const elapsedMs=Number(process.hrtime.bigint()-started)/1e6;
  assert.equal(socket.sent.length,2,carrier+' combines an eligible native batch into one pre-ACK WebSocket send');
  assert.equal(socket.sent[1].byteLength,batch.byteLength);
  assert.ok(elapsedMs<500,carrier+' processes a legal 1000-frame batch without a long synchronous stall: '+elapsedMs.toFixed(1)+'ms');
  socket.message(new ArrayBuffer(0));await flush();assert.equal(socket.sent.length,2,'ACK does not resend the batch');env.close();await flush();
 }
});
test('pre-ACK continuation advances valid aggregate queues beyond one frame batch',async page=>{
 const env=await session(page,'websocket');env.send(frame(1,1));await flush();const socket=env.webSockets[0];
 const makeBatch=offset=>join(...Array.from({length:3000},(_,index)=>frame(2,1,[(offset+index)&255])));
 env.send(makeBatch(0));await flush();env.send(makeBatch(3000));await flush();socket.open();await flush();await env.tick(10);
 let dataFrames=0;for(const body of socket.sent){const bytes=new Uint8Array(body);for(let offset=0;offset<bytes.byteLength;){const view=new DataView(body,offset);if(bytes[offset]===2)dataFrames++;offset+=8+view.getUint32(4)}}
 assert.equal(dataFrames,6000,'all retained DATA reaches the candidate socket in bounded FIFO batches');
 assert.ok(socket.sent.length<=4,'frame and byte bounds cap each continuation send');
 socket.message(new ArrayBuffer(0));await flush();assert.equal(socket.sent.length<=4,true,'commit consumes sent spans without replay');env.close();await flush();
});
test('invalid and lost candidate ACKs and send failures stay fail-closed on replacement 409',async page=>{
 for(const failure of ['invalid-ack','lost-ack','send-throws','initial-send-throws']){
  const env=await session(page,'websocket');env.send(frame(1,1));await flush();const socket=env.webSockets[0];
  if(failure==='initial-send-throws')socket.throwOnSend=1;socket.open();
  if(failure!=='initial-send-throws'){const data=frame(2,1,[6]);if(failure==='send-throws')socket.throwOnSend=2;env.send(data);await flush()}
  assert.equal(socket.sent.length,failure==='initial-send-throws'?0:failure==='send-throws'?1:2);
  assert.equal(env.received.filter(value=>value&&value.t==='traffic'&&value.up>0).length,failure==='send-throws'||failure==='initial-send-throws'?0:1,'failed speculative send is not counted; successful sends count once');
  if(failure==='invalid-ack')socket.message(frame(2,1,[1]));else if(failure==='lost-ack')await env.tick(3000);else if(failure!=='initial-send-throws')socket.close();
  await flush();const replacement=env.pending('/api/v1/session')[0];assert.ok(replacement,'replacement attempt requested');
  env.answer(replacement,409,null,{'X-Carrier-Mode':'websocket','X-Carrier-Attempt':'2','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'committed'});await flush();
  assert.equal(env.webSockets.length,1,'committed predecessor data is never replayed into a new socket');
  assert.equal(socket.sent.length,failure==='initial-send-throws'?0:failure==='send-throws'?1:2);assert.ok(env.received.some(value=>value&&value.t==='close'));
  assert.ok(!env.received.some(value=>value&&value.t==='status'&&value.state==='connected'));
 }
});
test('legacy WebSocket commits its OPEN probe without negotiated ACK behavior',async()=>{
 const env=environment(renderedPage({}, {NEGOTIATION_ENABLED:'false'}));env.send(frame(16,0,[1]));await flush();
 const request=env.pending('/api/v1/session')[0];env.answer(request,200,frame(17),{'X-Session-Token':'B'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'websocket','X-Telemt-Up-Window':'4'});await flush();
 env.send(frame(1,1));await flush();const socket=env.webSockets[0];socket.open();assert.equal(socket.sent.length,1);
 assert.ok(env.received.some(value=>value&&value.t==='status'&&value.state==='connected'));
 env.send(frame(2,1,[3]));await flush();assert.equal(socket.sent.length,2,'legacy WSS keeps normal direct DATA writes');
 env.close();await flush();
});
test('stale candidate callbacks and precommit close cannot commit or leak reservations',async page=>{
 const env=await session(page,'websocket-lanes');env.send(frame(1,1));await flush();const socket=env.webSockets[0],staleMessage=socket.message.bind(socket);socket.open();
 env.send(frame(2,1,[5]));await flush();const staleOpen=socket.onopen;socket.close();await flush();
 const replacement=env.pending('/api/v1/session')[0];assert.ok(replacement);env.answer(replacement,200,frame(17),{'X-Session-Token':'C'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'websocket-lanes','X-Carrier-Attempt':'2','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional','X-Telemt-Up-Window':'4'});await flush();
 const successor=env.webSockets[1];assert.ok(successor);successor.open();await flush();staleOpen();staleMessage(new ArrayBuffer(0));await flush();
 assert.ok(!env.received.some(value=>value&&value.t==='status'&&value.state==='connected'));
 successor.message(new ArrayBuffer(0));await flush();assert.ok(env.received.some(value=>value&&value.t==='status'&&value.state==='connected'));
 env.send({t:'close'});await flush();assert.equal(env.requests.filter(request=>request.options.method==='DELETE').length,1);env.close();await flush();
});
test('precommit WebSocket capacity includes buffered bytes and releases on close',async page=>{
 const env=await session(page,'websocket');env.send(frame(1,1));await flush();const socket=env.webSockets[0];socket.open();
 socket.bufferedAmount=33554432-25;const data=frame(2,1,[4]);env.send(data);await flush();
 assert.equal(socket.sent.length,1,'send-time capacity check prevents an unbounded speculative copy');
  assert.equal(env.received.filter(value=>value&&value.t==='traffic'&&value.up>0).length,0,'deferred DATA is not counted before a successful send');
 socket.bufferedAmount=0;await env.tick(10);assert.equal(socket.sent.length,2,'bounded retry resumes when buffered bytes drain');
  assert.deepEqual(env.received.filter(value=>value&&value.t==='traffic'&&value.up>0).map(value=>value.up),[data.byteLength],'buffer-drain retry accounts DATA once');
 assert.deepEqual(new Uint8Array(socket.sent[1]),new Uint8Array(data));socket.message(new ArrayBuffer(0));await flush();
 socket.bufferedAmount=33554432;env.send(frame(2,1,[5]));await flush();
 assert.equal(socket.sent.length,2,'queue reservation rejects data at the global buffer limit');
 assert.ok(env.received.some(value=>value&&value.t==='close'));
 const laneEnv=await session(page,'websocket-lanes');laneEnv.send(frame(1,1));await flush();const laneSocket=laneEnv.webSockets[0];laneSocket.open();
 laneSocket.bufferedAmount=8388608-20;const laneData=frame(2,1,[6]);laneEnv.send(laneData);await flush();
 assert.equal(laneSocket.sent.length,1,'per-lane send limit includes the WebSocket buffered amount');
 laneSocket.bufferedAmount=0;await laneEnv.tick(10);assert.equal(laneSocket.sent.length,2,'per-lane retry resumes after drain');
 laneSocket.message(new ArrayBuffer(0));await flush();laneEnv.close();await flush();
});
test('precommit retained queue exhaustion fails promptly instead of retrying forever',async()=>{
 for(const carrier of ['websocket','websocket-lanes']){
  const page=renderedPage({}, {QUEUE_LIMIT:128,BATCH_LIMIT:128}),env=await session(page,carrier);env.send(frame(1,1));await flush();
  env.send(frame(2,1,new Array(112).fill(1)));await flush();const socket=env.webSockets[0];socket.open();await flush();
  assert.equal(socket.sent.length,0,carrier+' does not exceed queue capacity to send the retained OPEN');
  assert.ok(env.received.some(value=>value&&value.t==='close'),'permanent precommit capacity shortage fails promptly');
  await env.tick(1000);assert.equal(socket.sent.length,0,'no futile retry remains scheduled');
 }
 const page=renderedPage({}, {QUEUE_ITEMS:2}),env=await session(page,'websocket-lanes');env.send(frame(1,1));await flush();
 env.send(join(frame(2,1,[1]),frame(2,1,[2])));await flush();env.webSockets[0].open();await flush();
 assert.ok(env.received.some(value=>value&&value.t==='close'),'lane frame-item limit includes precommit retained DATA');
 assert.equal(env.webSockets[0].sent.length,0);
});
test('when only speculative copy headroom is exhausted OPEN still commits and drains once',async()=>{
 const page=renderedPage({}, {QUEUE_LIMIT:128,BATCH_LIMIT:128}),env=await session(page,'websocket');env.send(frame(1,1));await flush();
 const data=frame(2,1,new Array(64).fill(3));env.send(data);await flush();const socket=env.webSockets[0];socket.open();await flush();
 assert.equal(socket.sent.length,1,'OPEN-only progress avoids copying retained DATA over the queue cap');
 assert.ok(!env.received.some(value=>value&&value.t==='close'));
 socket.message(new ArrayBuffer(0));await flush();assert.equal(socket.sent.length,2,'ACK releases the probe reservation and regular carrier drain sends DATA');
 assert.deepEqual(new Uint8Array(socket.sent[1]),new Uint8Array(data));env.close();await flush();
});
test('candidate capacity preflight avoids copying a blocked DATA tail',async()=>{
 const env=await session(renderedPage({}, {QUEUE_LIMIT:128,BATCH_LIMIT:128}),'websocket');
 env.send(frame(1,1));await flush();const socket=env.webSockets[0];socket.open();await flush();
 const allocated=[],NativeUint8Array=env.context.Uint8Array,batch=join(...Array.from({length:8},(_,index)=>frame(2,1,[index])));
 env.context.Uint8Array=new Proxy(NativeUint8Array,{construct(target,args,newTarget){if(typeof args[0]==='number')allocated.push(args[0]);return Reflect.construct(target,args,newTarget)}});
 env.send(batch);await flush();
 assert.equal(socket.sent.length,1,'insufficient headroom defers the candidate copy');
 assert.equal(allocated.includes(batch.byteLength),false,'copy preflight runs before allocating the 72-byte candidate tail');
 socket.bufferedAmount=0;socket.message(new ArrayBuffer(0));await flush();
 assert.equal(socket.sent.length,2,'ACK sends the retained native tail through the committed path');
 assert.equal(allocated.filter(size=>size===batch.byteLength).length,1,'the 72-byte joined batch is copied once after commit');
 env.close();await flush();
});
test('negotiated conveyor sends DATA before the OPEN acknowledgement',async page=>{
 for(const android of [false,true])for(const carrier of ['https','https-lanes']){
  const env=await session(page,carrier,4,android);env.send(frame(1,1));await flush();env.send(frame(2,1,[9]));await flush();
  assert.equal(env.pending('/api/v1/up').length,2,carrier+' startup must not wait for ACK1');env.close();await flush();
 }
});
test('unsupported server and disabled conveyor remain serialized',async page=>{
 for(const window of [null,1]){
  const env=await session(page,'https',window);env.send(frame(1,1));await flush();env.send(frame(2,1,[9]));await flush();
  assert.equal(env.pending('/api/v1/up').length,1);env.close();await flush();
 }
});
test('lost ACK1 cannot slide the window after ACK2 through ACK4',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();
 for(let i=0;i<6;i++){env.send(frame(2,1,[i]));await flush()}
 const up=env.pending('/api/v1/up');assert.equal(up.length,4);
 for(const request of up.slice(1)){ack(env,request);await flush()}
 assert.equal(env.requests.filter(r=>r.url.endsWith('/api/v1/up')).length,4);
 ack(env,up[0]);await flush();
 const next=env.pending('/api/v1/up')[0];assert.equal(next.options.headers['X-Up-Seq'],'5');assert.equal(next.options.headers['X-Telemt-Up-Confirmed'],'4');
 env.close();await flush();
});
test('early downlink cannot deliver native data before a verified commit',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();
 const down=env.pending('/api/v1/down')[0];assert.ok(down,'down starts before ACK');const data=frame(2,1,[4]);
 const stream=streaming(env,down,'1',data.byteLength);stream.enqueue(new Uint8Array(data));await flush();assert.equal(binary(env).length,0);
 ack(env,env.pending('/api/v1/up')[0]);await flush();assert.equal(binary(env).length,1);
 assert.equal(env.requests.filter(r=>r.url.endsWith('/api/v1/down')).length,1,'cursor cannot advance before EOF');
 stream.close();await flush();assert.equal(env.pending('/api/v1/down')[0].options.headers['X-Down-Cursor'],'1');env.close();await flush();
});
test('DATA and WINDOW prefixes are delivered once across a mid-body network failure',async page=>{
 for(const carrier of ['https','https-lanes']){
  const env=await session(page,carrier,4);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
  const first=frame(2,1,[1,2]),credit=frame(4,1,[0,0,0,2]),last=frame(3,1),body=join(first,credit,last);
  const stream=streaming(env,env.pending('/api/v1/down')[0],'1',body.byteLength);
  stream.enqueue(new Uint8Array(join(first,credit)));await flush();assert.equal(binary(env).length,2);
  stream.error(new Error('connection lost'));await flush();
  const replay=env.pending('/api/v1/down')[0];assert.ok(replay);assert.equal(replay.options.headers['X-Down-Cursor'],'0');
  env.answer(replay,200,body,{'X-Down-Cursor':'1','Content-Length':String(body.byteLength)});await flush();
  assert.deepEqual(binary(env).map(data=>new Uint8Array(data)[0]),[2,4,3]);
  assert.equal(env.pending('/api/v1/down')[0].options.headers['X-Down-Cursor'],'1');
  assert.equal(env.requests.filter(r=>r.url.endsWith('/api/v1/down')).length,3,'successful replay is consumed without another old-cursor request');env.close();await flush();
 }
});
test('changed replay prefix fails closed without duplicate native frames',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 const data=frame(2,1,[7]),tail=frame(2,1,[8]),body=join(data,tail),stream=streaming(env,env.pending('/api/v1/down')[0],'1',body.byteLength);
 stream.enqueue(new Uint8Array(data));await flush();stream.error(new Error('lost'));await flush();
 const changed=join(frame(2,1,[9]),tail);env.answer(env.pending('/api/v1/down')[0],200,changed,{'X-Down-Cursor':'1','Content-Length':String(changed.byteLength)});await flush();
 assert.equal(binary(env).length,1);assert.ok(env.received.some(value=>value&&value.t==='close'));env.close();await flush();
});
test('partial frame boundaries never escape to native and cancellation owns every lease',async page=>{
 const env=await session(page,'https-lanes',4,true);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 const data=frame(2,1,[1,2,3]),stream=streaming(env,env.pending('/api/v1/down')[0],'1',data.byteLength);
 stream.enqueue(new Uint8Array(data,0,5));await flush();assert.equal(binary(env).length,0);
 stream.enqueue(new Uint8Array(data,5));await flush();assert.equal(binary(env).length,1);
 env.close();await flush();assert.equal(binary(env).length,1);
});
test('post-commit lane batching keeps OPEN and DATA from one native message together',async page=>{
 const env=await session(page,'https-lanes',1);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 const body=join(frame(1,2),frame(2,2,[7]));env.send(body);await flush();
 assert.equal(env.pending('/api/v1/up')[0].options.body.byteLength,body.byteLength);env.close();await flush();
});

test('page-owned HTTP method and identity survive frozen retries',async page=>{
 const expected=/const carrierMethod='(POST|PUT)'/.exec(page)[1],env=await session(page,'https',4);
 assert.equal(env.requests.find(r=>r.url.endsWith('/api/v1/session')).options.method,'POST');
 env.send(frame(1,1));await flush();const first=env.pending('/api/v1/up')[0];ack(env,first);await flush();
 env.send(frame(2,1,[7]));await flush();const original=env.pending('/api/v1/up')[0];
 original.answered=true;original.reject(new Error('lost'));await flush();const replay=env.pending('/api/v1/up')[0];
 assert.equal(replay.options.body,original.options.body);assert.deepEqual(replay.options.headers,original.options.headers);
 assert.equal(replay.options.method,expected);ack(env,replay);await flush();
 for(const request of env.requests.filter(r=>/\/api\/v1\/(up|down)$/.test(r.url)))assert.equal(request.options.method,expected);
 env.close();await flush();assert.equal(env.requests.find(r=>r.options.method==='DELETE').options.method,'DELETE');
});

test('RTT scales time but adds no OPEN ACK barrier or coalescing timer',async page=>{
 for(const rtt of [40,100,400]){
  const env=await session(page,'https',4);env.send(frame(1,1));await flush();await env.tick(1);
  env.send(frame(2,1,[5]));await flush();assert.equal(env.pending('/api/v1/up').length,2);
  await env.tick(rtt-1);for(const request of env.pending('/api/v1/up'))ack(env,request);await flush();
  assert.equal(env.received.filter(value=>value instanceof ArrayBuffer&&new Uint8Array(value)[0]===17).length,1);
  assert.ok(env.received.filter(value=>value&&value.t==='status').every(value=>Object.keys(value).sort().join(',')==='state,t'));
  env.close();await flush();
 }
});

test('simultaneous failed lane polls each consume their own exact replay',async page=>{
 const env=await session(page,'https-lanes',4);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 env.send(frame(1,2));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 const streams=[];
 for(const request of env.pending('/api/v1/down')){
  const id=Number(request.options.headers['X-Lane-ID']),data=frame(2,id,[id]),body=join(data,frame(4,id,[0,0,0,1]));
  const response=streaming(env,request,'1',body.byteLength);response.enqueue(new Uint8Array(data));streams.push({id,response,body});
 }
 await flush();assert.equal(binary(env).length,2);for(const item of streams)item.response.error(new Error('lost'));await flush();
 for(let round=0;round<3;round++){
  for(const request of env.pending('/api/v1/down').filter(r=>r.options.headers['X-Down-Cursor']==='0')){
   const body=streams.find(item=>String(item.id)===request.options.headers['X-Lane-ID']).body;
   env.answer(request,200,body,{'X-Down-Cursor':'1','Content-Length':String(body.byteLength)});
  }await flush();
 }
 assert.equal(binary(env).length,4);assert.equal(env.pending('/api/v1/down').length,2);
 assert.ok(env.pending('/api/v1/down').every(r=>r.options.headers['X-Down-Cursor']==='1'));env.close();await flush();
});

test('incremental decoder rejects changed cursor, invalid WINDOW and cross-lane frames',async page=>{
 for(const invalid of ['cursor','credit','lane']){
  const env=await session(page,'https-lanes',4);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
  const body=invalid==='credit'?frame(4,1,[0,0,0,0]):frame(2,invalid==='lane'?2:1,[1]);
  env.answer(env.pending('/api/v1/down')[0],200,body,{'X-Down-Cursor':invalid==='cursor'?'2':'1','Content-Length':String(body.byteLength)});await flush();
  assert.equal(binary(env).length,0);assert.ok(env.received.some(value=>value&&value.t==='close'));env.close();await flush();
 }
});

test('a replay without Content-Length cannot truncate an already known batch',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 const prefix=frame(2,1,[1]),tail=frame(2,1,[2]),body=join(prefix,tail),response=streaming(env,env.pending('/api/v1/down')[0],'1',body.byteLength);
 response.enqueue(new Uint8Array(prefix));await flush();response.error(new Error('lost'));await flush();
 env.answer(env.pending('/api/v1/down')[0],200,prefix,{'X-Down-Cursor':'1'});await flush();
 assert.equal(binary(env).length,1);assert.ok(env.received.some(value=>value&&value.t==='close'));
 assert.ok(!env.requests.some(r=>r.url.endsWith('/api/v1/down')&&r.options.headers['X-Down-Cursor']==='1'));env.close();await flush();
});

test('a pipelined startup flight adopts the recovery budget once another ACK commits',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();env.send(frame(2,1,[7]));await flush();
 const [head,tail]=env.pending('/api/v1/up');ack(env,head);await flush();tail.answered=true;tail.reject(new Error('lost'));await flush();
 const replay=env.pending('/api/v1/up')[0];assert.ok(replay,'post-commit recovery replays immediately instead of staying in the startup backoff');
 assert.equal(replay.options.body,tail.options.body);ack(env,replay);await flush();env.close();await flush();
});

test('candidate rollback restores every unacknowledged OPEN and DATA without a second WELCOME',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();env.send(frame(2,1,[7]));await flush();
 const retired=env.requests.filter(r=>/\/api\/v1\/(up|down)$/.test(r.url));await env.tick(3001);
 const next=env.pending('/api/v1/session')[0];assert.ok(next,'candidate fallback creates a new session');
 env.answer(next,200,frame(17),{'X-Session-Token':'C'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'https-lanes','X-Carrier-Attempt':'2','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional','X-Telemt-Up-Window':'4'});await flush();
 const first=env.requests.find(r=>r.url.endsWith('/api/v1/up')&&r.options.headers.Authorization==='Bearer '+'C'.repeat(43));
 assert.ok(first);assert.deepEqual(new Uint8Array(first.options.body),new Uint8Array(join(frame(1,1),frame(2,1,[7]))));
 assert.ok(retired.every(r=>r.options.signal.aborted));assert.equal(env.received.filter(value=>value instanceof ArrayBuffer&&new Uint8Array(value)[0]===17).length,1);
 ack(env,first);await flush();env.close();await flush();
});

test('downlink prefix reservations are bounded, cancellable and released on retirement',async page=>{
 const env=environment(page),budget=env.context.TelemtBridgeDownlink.budget(()=>16),first=await budget.acquire(16);
 const controller=new AbortController();let acquired=false;
 const parked=budget.acquire(8,controller.signal).then(release=>{acquired=true;release()},()=>{});await flush();assert.equal(acquired,false);
 controller.abort();await parked;first();assert.equal(budget.used(),0);
 const release=await budget.acquire(16);release();release();assert.equal(budget.used(),0);env.close();await flush();
});

test('two interrupted and differently chunked replays never duplicate DATA WINDOW or CLOSE',async page=>{
 const env=await session(page,'https',4);env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
 const data=frame(2,1,[1]),credit=frame(4,1,[0,0,0,1]),close=frame(3,1),body=join(data,credit,close);
 const first=streaming(env,env.pending('/api/v1/down')[0],'1',body.byteLength);
 first.enqueue(new Uint8Array(data));await flush();first.error(new Error('lost once'));await flush();
 const second=streaming(env,env.pending('/api/v1/down')[0],'1',body.byteLength);
 const prefix=new Uint8Array(join(data,credit));second.enqueue(prefix.subarray(0,3));second.enqueue(prefix.subarray(3));await flush();
 assert.deepEqual(binary(env).map(value=>new Uint8Array(value)[0]),[2,4]);second.error(new Error('lost twice'));await flush();await env.tick(1000);
 const last=streaming(env,env.pending('/api/v1/down')[0],'1',body.byteLength);
 for(const byte of new Uint8Array(body))last.enqueue(new Uint8Array([byte]));last.close();
 for(let i=0;i<20&&(!env.pending('/api/v1/down').length);i++)await flush();
 assert.deepEqual(binary(env).map(value=>new Uint8Array(value)[0]),[2,4,3]);assert.equal(env.pending('/api/v1/down')[0].options.headers['X-Down-Cursor'],'1');
 env.close();await flush();
});

test('multiple precommit lanes survive fallback without losing stream ordering',async page=>{
 const env=await session(page,'https-lanes',4);env.send(join(frame(1,1),frame(1,2)));await flush();
 env.send(join(frame(2,2,[2]),frame(2,1,[1])));await flush();await env.tick(3001);
 const next=env.pending('/api/v1/session')[0];env.answer(next,200,frame(17),{'X-Session-Token':'C'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'https','X-Carrier-Attempt':'2','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional','X-Telemt-Up-Window':'4'});await flush();
 const requests=env.requests.filter(r=>r.url.endsWith('/api/v1/up')&&r.options.headers.Authorization==='Bearer '+'C'.repeat(43));
 const frames=[];for(const request of requests){const bytes=new Uint8Array(request.options.body);for(let offset=0;offset<bytes.length;){const view=new DataView(bytes.buffer,offset);frames.push([bytes[offset],bytes[offset+3]]);offset+=8+view.getUint32(4);}}
 for(const id of [1,2])assert.deepEqual(frames.filter(value=>value[1]===id),[[1,id],[2,id]]);
 assert.equal(frames.length,4);env.close();await flush();
});

test('receiver retirement releases shared prefix capacity without exposing a partial frame',async page=>{
 const env=environment(page),module=env.context.TelemtBridgeDownlink,budget=module.budget(()=>18),received=[];
 function receiver(id){
  let cursor='0',stream;const controller=new AbortController(),response={status:200,headers:new Headers({'X-Down-Cursor':'1','Content-Length':'18'}),body:new ReadableStream({start(value){stream=value}})};
  const owner=module.create({failure:(reason,message)=>Object.assign(new Error(message),{telemtReason:reason}),alive:()=>true,cursor:()=>cursor,lane:id,limit:()=>18,budget,cancel(){},ready:()=>Promise.resolve(),deliver:data=>received.push(new Uint8Array(data)),advance:value=>{cursor=value},finished(){}});
  const result=owner.read(response,controller.signal).catch(()=>{});return {owner,result,stream,controller,cursor:()=>cursor};
 }
 const a=receiver(1);a.stream.enqueue(new Uint8Array(frame(2,1,[1])));await flush();
 const b=receiver(2);b.stream.enqueue(new Uint8Array(join(frame(2,2,[2]),frame(2,2,[3]))));b.stream.close();await flush();
 assert.equal(budget.used(),18);assert.equal(received.length,1);assert.equal(b.cursor(),'0');
 a.owner.close();a.controller.abort();a.stream.error(new Error('retired'));await a.result;await b.result;
 assert.equal(received.length,3);assert.equal(b.cursor(),'1');assert.equal(budget.used(),0);
 b.owner.close();env.close();await flush();
});

test('native close cancels every HTTP request and pagehide cannot repeat cleanup',async page=>{
 for(const android of [false,true])for(const carrier of ['https','https-lanes']){
  const env=await session(page,carrier,4,android);env.send(frame(1,1));await flush();env.send(frame(2,1,[7]));await flush();
  const up=env.pending('/api/v1/up'),down=env.pending('/api/v1/down'),requests=up.concat(down);
  assert.equal(up.length,2);assert.equal(down.length,1);assert.ok(requests.every(request=>!request.options.signal.aborted));
  env.send({t:'close'});await flush();
  assert.ok(requests.every(request=>request.options.signal.aborted));
  assert.equal(env.requests.filter(request=>request.options.method==='DELETE').length,1);
  const count=env.requests.length;env.close();await env.tick(120000);
  assert.equal(env.requests.filter(request=>request.options.method==='DELETE').length,1);
  assert.equal(env.requests.length,count);
 }
});

// WebSocket events are explicit so failed upgrades and stale callbacks are deterministic.
async function laneSession(page){
 const env=environment(page),sockets=[];
 env.context.WebSocket=class {
  static OPEN=1;static CLOSING=2;
  constructor(url,protocol){this.url=url;this.protocol=protocol;this.readyState=0;this.bufferedAmount=0;this.sent=[];sockets.push(this)}
  open(){this.readyState=1;this.onopen?.()}
  send(data){assert.equal(this.readyState,1);this.sent.push(structuredClone(data))}
  receive(data){this.onmessage?.({data})}
  close(){if(this.readyState>=2)return;this.readyState=3;Promise.resolve().then(()=>this.onclose?.())}
 };
 const headers=token=>({'X-Session-Token':token,'X-Down-Cursor':'0','X-Carrier-Mode':'websocket-lanes','X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional'});
 env.send(frame(16,0,[1]));await flush();env.answer(env.pending('/api/v1/session')[0],200,frame(17),headers('B'.repeat(43)));await flush();
 env.send(frame(1,1));await flush();assert.equal(sockets.length,1);
 sockets[0].open();await flush();assert.equal(sockets[0].sent.length,1);sockets[0].receive(new ArrayBuffer(0));await flush();
 assert.ok(env.received.some(value=>value?.t==='status'&&value.state==='connected'));
 return {env,sockets,headers,recoveries:()=>env.requests.filter(request=>request.options.headers?.Accept==='application/vnd.telemt.web-recovery+json')};
}

async function committedMultiplexSession(page){
 const env=environment(page),sockets=[];
 env.context.crypto={getRandomValues(value){for(let index=0;index<value.length;index++)value[index]=(index+1)&255;return value}};
 env.context.WebSocket=class {
  static OPEN=1;static CLOSING=2;
  constructor(url,protocol){this.url=url;this.protocol=protocol;this.readyState=0;this.bufferedAmount=0;this.sent=[];sockets.push(this)}
  open(){this.readyState=1;this.onopen?.()}
  send(data){assert.equal(this.readyState,1);this.sent.push(structuredClone(data))}
  receive(data){this.onmessage?.({data})}
  close(){if(this.readyState>=2)return;this.readyState=3;Promise.resolve().then(()=>this.onclose?.())}
 };
 env.send(frame(16,0,[1]));await flush();
 const request=env.pending('/api/v1/session')[0];assert.ok(request);
 env.answer(request,200,frame(17),{'X-Session-Token':'B'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'websocket','X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional'});await flush();
 env.send(frame(1,7));await flush();const socket=sockets[0];assert.ok(socket);socket.open();await flush();
 socket.receive(new ArrayBuffer(0));await flush();return {env,socket,sockets};
}

test('long scheduling gap proves the committed multiplex socket before requesting recovery',async page=>{
 const {env,socket}=await committedMultiplexSession(page);
 env.suspend(120001);env.send(frame(2,7,[1,2,3]));await flush();
 const controls=socket.sent.flatMap(value=>{const bytes=new Uint8Array(value),view=new DataView(value),result=[];for(let offset=0;offset<bytes.length;){const size=view.getUint32(offset+4);result.push({type:bytes[offset],id:(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3],payload:bytes.slice(offset+8,offset+8+size)});offset+=8+size}return result});
 assert.ok(controls.some(value=>value.type===5&&value.id===0&&value.payload.length===16),'recovery first sends a fresh 16-byte nonce probe');
 assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json').length,0,'policy fetch waits for proof failure/deadline');
 const probe=controls.find(value=>value.type===5&&value.id===0&&value.payload.length===16);socket.receive(frame(6,0,Array.from(probe.payload)));await flush();
 assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json').length,0,'valid proof preserves the current carrier');
 const resent=socket.sent.at(-1),bytes=new Uint8Array(resent);assert.equal(bytes[0],2);assert.equal(bytes[3],7,'held native DATA drains once to the proven old socket');
 env.close();await flush();
});

test('pagehide cancels resume proof before any recovery policy request',async page=>{
 const {env,socket}=await committedMultiplexSession(renderedPage({}, {BRIDGE_RECOVERY_SECS:1}));env.suspend(120001);env.send(frame(2,7,[4]));await flush();
 assert.ok(socket.sent.some(value=>new Uint8Array(value)[0]===5));env.close();await flush();
 const closeCount=env.received.filter(value=>value?.t==='close').length,statusCount=env.received.filter(value=>value?.t==='status').length,sentCount=socket.sent.length;
 env.send(frame(2,7,[5]));await env.tick(1001);await flush();
 assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json').length,0);
 assert.equal(env.received.filter(value=>value?.t==='close').length,closeCount,'deadline adds no close beyond navigation cleanup');
 assert.equal(env.received.filter(value=>value?.t==='status').length,statusCount,'deadline adds no status beyond navigation cleanup');
 assert.equal(socket.sent.length,sentCount,'pagehide prevents held native DATA from reaching the old socket');
});

test('wrong and mixed resume PONG cannot reach native framing',async page=>{
 for(const mixed of [false,true]){
  const {env,socket}=await committedMultiplexSession(page);env.suspend(120001);env.send(frame(2,7,[5]));await flush();
  const probe=socket.sent.map(value=>new Uint8Array(value)).find(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(probe);
  const nonce=Array.from(probe.slice(8));nonce[0]^=0xff;
  socket.receive(mixed?join(frame(6,0,nonce),frame(2,7,[9])):frame(6,0,nonce));await flush();
  assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json'&&!value.answered).length,1);
  assert.equal(env.received.some(value=>value instanceof ArrayBuffer&&([6,2].includes(new Uint8Array(value)[0]))),false,'invalid proof and coalesced DATA stay internal');
  env.close();await flush();
 }
});

test('recovery deadline is terminal when resume PONG never arrives',async page=>{
 const {env,socket}=await committedMultiplexSession(renderedPage({}, {BRIDGE_RECOVERY_SECS:1}));env.suspend(120001);env.send(frame(2,7,[6]));await flush();
 const probe=socket.sent.map(value=>new Uint8Array(value)).find(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(probe);const before=socket.sent.length;
 await env.tick(1001);
 env.send(frame(2,7,[94]));await flush();
 assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json').length,0,'deadline abort cannot start recovery policy fetch');
 assert.equal(socket.sent.length,before,'expired proof cannot drain held native DATA');
 assert.ok(env.received.some(value=>value?.t==='close'),'expired recovery closes the bridge');assert.equal(socket.readyState,3);
});

test('recovery deadline wins when a valid PONG resolves before delayed promise continuation',async page=>{
 const {env,socket}=await committedMultiplexSession(renderedPage({}, {BRIDGE_RECOVERY_SECS:1}));env.suspend(120001);env.send(frame(2,7,[91]));await flush();
 const probe=socket.sent.map(value=>new Uint8Array(value)).find(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(probe);const before=socket.sent.length;
 socket.receive(frame(6,0,Array.from(probe.slice(8))));env.suspend(1001);await flush();
 env.send(frame(2,7,[92]));await flush();
 assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json').length,0,'late continuation cannot fetch policy after successful but expired proof');
 assert.equal(socket.sent.length,before,'late continuation cannot drain held native DATA');
 assert.ok(env.received.some(value=>value?.t==='close'),'expired owner reaches terminal cleanup');assert.equal(socket.readyState,3);
});

test('expired resume proof cannot preserve after its shared one-second deadline',async page=>{
 const {env,socket}=await committedMultiplexSession(page);env.suspend(120001);env.send(frame(2,7,[6]));await flush();
 const probe=socket.sent.map(value=>new Uint8Array(value)).find(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(probe);const before=socket.sent.length;
 env.suspend(1001);socket.receive(frame(6,0,Array.from(probe.slice(8))));await flush();
 assert.equal(env.requests.filter(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json'&&!value.answered).length,1);
 assert.equal(socket.sent.length,before,'expired proof cannot drain held native DATA');
 env.close();await flush();
});

test('replacement checks the recovery deadline before WebSocket send, ACK and HTTPS candidate start',async page=>{
 const policy={v:1,bootstrap:'C'.repeat(43),limits:{carrier_batch_bytes:2097152,pending_bytes_per_session:33554432,pending_items_per_session:16384,max_streams_per_session:1024},timeouts:{long_poll_secs:25,bridge_request_secs:10,bridge_retry_secs:90,bridge_recovery_secs:15,websocket_open_secs:15,reconnect_grace_secs:120},negotiation:{enabled:true,candidate_count:4,deadlines_secs:[3,5,8,12],carrier_probe_coalesce_ms:0}};
 async function replacement(selected='websocket'){
  const {env,socket,sockets}=await committedMultiplexSession(renderedPage({}, {BRIDGE_RECOVERY_SECS:2}));
  const initialMessages=env.received.length;
  env.suspend(120001);env.send(frame(2,7,[91]));await flush();
  const probe=socket.sent.map(value=>new Uint8Array(value)).find(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(probe);
  const nonce=Array.from(probe.slice(8));nonce[0]^=0xff;socket.receive(frame(6,0,nonce));await flush();
  const recovery=env.requests.find(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json'&&!value.answered);assert.ok(recovery);
  env.send(join(frame(1,9),frame(2,9,[93])));await flush();
  env.answer(recovery,200,new TextEncoder().encode(JSON.stringify(policy)),{'Content-Type':'application/vnd.telemt.web-recovery+json'});await flush();
  const create=env.pending('/api/v1/session')[0];assert.ok(create);
  return {env,create,sockets,initialMessages,answer(){env.answer(create,200,frame(17),{'X-Session-Token':'D'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':selected,'X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional','X-Telemt-Up-Window':'4'})}};
 }
 const lateOpen=await replacement();lateOpen.answer();await flush();const notOpened=lateOpen.sockets.at(-1);assert.ok(notOpened);lateOpen.env.suspend(2001);notOpened.open();await flush();
 assert.equal(notOpened.sent.length,0,'expired replacement must not send a candidate probe');assert.ok(lateOpen.env.received.some(value=>value?.t==='close'));
 const lateAck=await replacement();lateAck.answer();await flush();const noAck=lateAck.sockets.at(-1);assert.ok(noAck);noAck.open();await flush();assert.equal(noAck.sent.length,1);lateAck.env.suspend(2001);noAck.receive(new ArrayBuffer(0));await flush();
 assert.equal(lateAck.env.received.slice(lateAck.initialMessages).some(value=>value?.t==='status'&&value.state==='connected'),false,'expired replacement ACK must not publish a connected carrier');assert.ok(lateAck.env.received.some(value=>value?.t==='close'));
 const lateHttp=await replacement('https');lateHttp.env.suspend(2001);lateHttp.answer();await flush();
 assert.equal(lateHttp.env.requests.filter(value=>value.url?.endsWith('/api/v1/up')).length,0,'late HTTP WELCOME must not start a replacement candidate request');assert.ok(lateHttp.env.received.some(value=>value?.t==='close'));
 const timely=await replacement();timely.answer();await flush();const committed=timely.sockets.at(-1);assert.ok(committed);committed.open();await flush();committed.receive(new ArrayBuffer(0));timely.env.suspend(2001);await flush();
 assert.ok(timely.env.received.slice(timely.initialMessages).some(value=>value?.t==='status'&&value.state==='connected'),'on-time replacement ACK publishes success');assert.equal(timely.env.received.some(value=>value?.t==='close'),false,'a published timely commit is not retroactively revoked');
 for(const value of [lateOpen,lateAck,lateHttp,timely]){value.env.close();await flush()}
});

test('a multi-socket resume proof waits for every captured nonce response',async page=>{
 const env=environment(page),module=env.context.TelemtBridgeResumeProbe,sent=[];
 env.context.crypto={getRandomValues(value){for(let index=0;index<value.length;index++)value[index]=(index+1)&255;return value}};
 const sockets=[{send(value){sent.push([0,value])}},{send(value){sent.push([1,value])}}],entries=sockets.map((socket,index)=>({socket,epoch:9,index}));
 let settled=false;const owner=module.create({current:()=>true,ready:()=>true,wait:async()=>{}});const proof=owner.probe(entries).then(()=>{settled=true});await flush();
 assert.equal(sent.length,2);for(const [,value] of sent)assert.equal(new Uint8Array(value).byteLength,24);
 const nonce=index=>Array.from(new Uint8Array(sent[index][1]).slice(8));
 assert.equal(owner.receive(sockets[1],frame(6,0,nonce(1)),9),true);await flush();assert.equal(settled,false);
 assert.equal(owner.receive(sockets[0],frame(6,0,nonce(0)),9),true);await proof;assert.equal(settled,true);
});

test('recovery handoff preserves only complete fresh unexposed OPEN histories',page=>{
 const buffers=environment(page).context.TelemtBridgeBuffers.create({limits:()=>({batchBytes:1024,queueBytes:4096,queueItems:16,laneBytes:1024,laneItems:8}),buffered:()=>0,pending:()=>[],laneMode:()=>false,maxStreams:()=>8,failure:(reason,message)=>Object.assign(new Error(message),{telemtReason:reason})});
 const fresh=join(frame(1,8),frame(2,8,[1,2]));buffers.acceptNativeFrames(fresh,true);
 const handoff=buffers.recoveryHandoff([fresh],{batchBytes:1024,queueBytes:4096,queueItems:16,maxStreams:8,laneBytes:1024,laneItems:8});
 assert.deepEqual(Array.from(handoff.ids),[8]);assert.deepEqual(Array.from(new Uint8Array(handoff.batches[0])),Array.from(new Uint8Array(fresh)));
 const exposed=join(frame(1,7),frame(2,7,[3]));buffers.acceptNativeFrames(exposed,false);
 const stale=buffers.recoveryHandoff([exposed],{batchBytes:1024,queueBytes:4096,queueItems:16,maxStreams:8,laneBytes:1024,laneItems:8});
 assert.deepEqual(Array.from(stale.ids),[]);assert.deepEqual(Array.from(stale.batches),[],'an OPEN previously exposed to the old carrier is never replayed');
});

test('fresh native OPEN and DATA survive recovery policy handoff',async page=>{
 const {env,socket,sockets}=await committedMultiplexSession(page);env.suspend(120001);env.send(frame(2,7,[1]));await flush();
 const probe=new Uint8Array(socket.sent.at(-1)),bad=Array.from(probe.slice(8));bad[0]^=0xff;socket.receive(frame(6,0,bad));await flush();
 const recovery=env.requests.find(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json'&&!value.answered);assert.ok(recovery);
 env.send(join(frame(1,8),frame(2,8,[2,3])));await flush();
 const policy={v:1,bootstrap:'C'.repeat(43),limits:{carrier_batch_bytes:2097152,pending_bytes_per_session:33554432,pending_items_per_session:16384,max_streams_per_session:1024},timeouts:{long_poll_secs:25,bridge_request_secs:10,bridge_retry_secs:90,bridge_recovery_secs:15,websocket_open_secs:15,reconnect_grace_secs:120},negotiation:{enabled:true,candidate_count:4,deadlines_secs:[3,5,8,12],carrier_probe_coalesce_ms:0}};
 env.answer(recovery,200,new TextEncoder().encode(JSON.stringify(policy)),{'Content-Type':'application/vnd.telemt.web-recovery+json'});await flush();
 const replacement=env.pending('/api/v1/session')[0];assert.ok(replacement);env.answer(replacement,200,frame(17),{'X-Session-Token':'D'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'websocket','X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional'});await flush();
 assert.equal(sockets.length,2);sockets[1].open();await flush();
 const sent=[];for(const body of sockets[1].sent){const bytes=new Uint8Array(body),view=new DataView(body);for(let offset=0;offset<bytes.length;){const size=view.getUint32(offset+4);sent.push({type:bytes[offset],id:(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3]});offset+=8+size}}
 assert.ok(sent.some(value=>value.type===1&&value.id===8));assert.ok(sent.some(value=>value.type===2&&value.id===8));
 assert.equal(env.received.filter(value=>value instanceof ArrayBuffer&&new Uint8Array(value)[0]===17).length,1,'replacement WELCOME is not transferred twice');
 env.close();await flush();
});

test('a stream drained after successful resume is not handed off after later recovery',async page=>{
 const policy={v:1,bootstrap:'C'.repeat(43),limits:{carrier_batch_bytes:2097152,pending_bytes_per_session:33554432,pending_items_per_session:16384,max_streams_per_session:1024},timeouts:{long_poll_secs:25,bridge_request_secs:10,bridge_retry_secs:90,bridge_recovery_secs:15,websocket_open_secs:15,reconnect_grace_secs:120},negotiation:{enabled:true,candidate_count:4,deadlines_secs:[3,5,8,12],carrier_probe_coalesce_ms:0}};
 for(const duplicate of [frame(1,9),join(frame(1,9),frame(2,9,[12]))]){
  const {env,socket,sockets}=await committedMultiplexSession(page);
  env.suspend(120001);env.send(frame(2,7,[1]));await flush();
  const firstProbe=socket.sent.map(value=>new Uint8Array(value)).find(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(firstProbe);
  env.send(join(frame(1,9),frame(2,9,[11])));await flush();
  socket.receive(frame(6,0,Array.from(firstProbe.slice(8))));await flush();
  const firstDrain=socket.sent.slice(2).flatMap(body=>{const bytes=new Uint8Array(body),view=new DataView(body),frames=[];for(let offset=0;offset<bytes.length;){const size=view.getUint32(offset+4);frames.push({type:bytes[offset],id:(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3]});offset+=8+size}return frames});
  assert.ok(firstDrain.some(value=>value.type===1&&value.id===9),'fresh stream OPEN is exposed on the proven old socket');
  assert.ok(firstDrain.some(value=>value.type===2&&value.id===9),'fresh stream DATA is exposed on the proven old socket');

  env.suspend(120001);env.send(frame(2,7,[2]));await flush();
  const secondProbe=socket.sent.map(value=>new Uint8Array(value)).findLast(value=>value[0]===5&&value[3]===0&&value.byteLength===24);assert.ok(secondProbe);
  const wrongNonce=Array.from(secondProbe.slice(8));wrongNonce[0]^=0xff;socket.receive(frame(6,0,wrongNonce));await flush();
  const recovery=env.requests.find(value=>value.options.headers?.Accept==='application/vnd.telemt.web-recovery+json'&&!value.answered);assert.ok(recovery);
  env.send(duplicate);await flush();
  env.answer(recovery,200,new TextEncoder().encode(JSON.stringify(policy)),{'Content-Type':'application/vnd.telemt.web-recovery+json'});await flush();
  const replacement=env.pending('/api/v1/session')[0];assert.ok(replacement);
  env.answer(replacement,200,frame(17),{'X-Session-Token':'D'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'websocket','X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional'});await flush();
  sockets.at(-1).open();await flush();
  const replay=[];for(const body of sockets.at(-1).sent){const bytes=new Uint8Array(body),view=new DataView(body);for(let offset=0;offset<bytes.length;){const size=view.getUint32(offset+4);replay.push({type:bytes[offset],id:(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3]});offset+=8+size}}
  assert.equal(replay.some(value=>value.id===9&&(value.type===1||value.type===2)),false,'a later malformed duplicate cannot replay exposed stream 9');
  env.close();await flush();
 }
});

test('failed WELCOME delivery closes the bridge without a second transfer',async page=>{
 const env=environment(page);const post=env.port.postMessage;let failures=0;
 env.port.postMessage=function(value,transfer){if(value instanceof ArrayBuffer&&new Uint8Array(value)[0]===17){failures++;throw new Error('simulated native transfer failure')}return post.call(this,value,transfer)};
 env.send(frame(16,0,[1]));await flush();env.answer(env.pending('/api/v1/session')[0],200,frame(17),{'X-Session-Token':'B'.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':'https','X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional'});await flush();
 assert.equal(failures,1);assert.ok(env.received.some(value=>value?.t==='status'&&value.state==='failed'));assert.equal(env.requests.filter(value=>value.options.method==='DELETE').length,1);
 const requests=env.requests.length,received=env.received.length;let parsedFrames=0;const DataViewType=env.context.DataView;
 env.context.DataView=new Proxy(DataViewType,{construct(target,args){parsedFrames++;return Reflect.construct(target,args)}});
 env.send(frame(1,7));env.send(frame(2,7,[1]));await flush();
 assert.equal(parsedFrames,0,'closed native input is ignored before WEB frame parsing');assert.equal(env.requests.length,requests,'closed native input starts no network work');assert.equal(env.received.length,received,'closed native input publishes no status or transfer');
 env.close();await flush();assert.equal(failures,1,'WELCOME delivery is guarded against a second transfer');
});

test('native HELLO callbacks delivered after close are ignored for browser and Android ports',async page=>{
 for(const android of [false,true]){
  const env=environment(page,android);
  const lateInput=android?env.context.TelegramWebProxy.onmessage:env.port.onmessage;
  env.close();await flush();const requests=env.requests.length,received=env.received.length;
  lateInput({data:frame(16,0,[1])});await flush();
  assert.equal(env.requests.length,requests,'closed late HELLO creates no session request');
  assert.equal(env.received.length,received,'closed late HELLO publishes no status or transfer');
 }
});

test('websocket lanes replace an expired session after idle and upgrade rejection',async page=>{
 const {env,sockets,headers,recoveries}=await laneSession(page);
 await env.tick(600000);assert.equal(recoveries().length,0,'healthy idle alone must not start recovery');
 sockets[0].close();await flush();assert.equal(recoveries().length,0,'established lane loss is isolated');
 env.send(frame(1,2));await flush();const stale=sockets[1];assert.ok(stale.protocol.includes('B'.repeat(43)));
 stale.close();await flush();assert.equal(recoveries().length,1,'failed upgrade must replace the expired session');
 const recovery=recoveries()[0];assert.equal(recovery.options.headers.Authorization,'Bearer '+'B'.repeat(43));
 const policy={v:1,bootstrap:'C'.repeat(43),limits:{carrier_batch_bytes:2097152,pending_bytes_per_session:33554432,pending_items_per_session:16384,max_streams_per_session:1024},timeouts:{long_poll_secs:25,bridge_request_secs:10,bridge_retry_secs:90,bridge_recovery_secs:15,websocket_open_secs:15,reconnect_grace_secs:120},negotiation:{enabled:true,candidate_count:4,deadlines_secs:[3,5,8,12],carrier_probe_coalesce_ms:0}};
 env.answer(recovery,200,new TextEncoder().encode(JSON.stringify(policy)),{'Content-Type':'application/vnd.telemt.web-recovery+json'});await flush();
 const replacement=env.pending('/api/v1/session')[0];assert.ok(replacement);assert.equal(replacement.options.headers.Authorization,'Bearer '+'C'.repeat(43));
 env.answer(replacement,200,frame(17),headers('D'.repeat(43)));await flush();
 env.send(frame(1,3));await flush();const fresh=sockets[2];assert.ok(fresh.protocol.includes('D'.repeat(43)));
 fresh.open();await flush();fresh.receive(new ArrayBuffer(0));await flush();
 // A callback queued by the retired socket must not disturb its replacement.
 stale.onclose();stale.onopen();await flush();assert.equal(fresh.readyState,1);assert.equal(recoveries().length,1);
 const upload=frame(2,3,[7]);env.send(upload);await flush();assert.deepEqual(new Uint8Array(fresh.sent.at(-1)),new Uint8Array(upload));
 const download=frame(2,3,[9]);fresh.receive(download);await flush();assert.deepEqual(new Uint8Array(binary(env).at(-1)),new Uint8Array(frame(2,3,[9])));
 assert.equal(env.received.filter(value=>value instanceof ArrayBuffer&&new Uint8Array(value)[0]===17).length,1,'WELCOME is not replayed to native');
 assert.ok(env.received.filter(value=>value?.t==='status').every(value=>Object.keys(value).sort().join(',')==='state,t'));
 assert.ok(!env.received.some(value=>value?.t==='close'));env.close();await flush();
});

test('concurrent websocket lane open timeouts share one recovery',async page=>{
 const {env,sockets,recoveries}=await laneSession(page);
 env.send(join(frame(1,2),frame(1,3)));await flush();assert.equal(sockets.length,3);
 await env.tick(15000);assert.equal(recoveries().length,1,'one recovery owns both rejected lanes');
 sockets[1].onclose();sockets[2].onclose();await flush();assert.equal(recoveries().length,1);
 env.close();await flush();assert.ok(recoveries()[0].options.signal.aborted);
});

test('upgraded websocket lane closure preserves sibling traffic',async page=>{
 const {env,sockets,recoveries}=await laneSession(page);
 env.send(join(frame(1,2),frame(1,3)));await flush();
 for(const socket of sockets.slice(1)){socket.open();await flush();socket.receive(frame(2,Number(socket.protocol.split('.').at(-1)),[1]));await flush()}
 sockets[1].close();await flush();assert.equal(recoveries().length,0);assert.equal(sockets[2].readyState,1);
 const upload=frame(2,3,[5]);env.send(upload);await flush();assert.deepEqual(new Uint8Array(sockets[2].sent.at(-1)),new Uint8Array(upload));
 const closes=binary(env).filter(value=>new Uint8Array(value)[0]===3).map(value=>new Uint8Array(value)[3]);
 assert.deepEqual(closes,[2]);env.close();await flush();
});

const shortRecoveryPolicy={
 v:1,bootstrap:'C'.repeat(43),
 limits:{carrier_batch_bytes:2097152,pending_bytes_per_session:33554432,pending_items_per_session:16384,max_streams_per_session:1024},
 timeouts:{long_poll_secs:25,bridge_request_secs:10,bridge_retry_secs:90,bridge_recovery_secs:2,websocket_open_secs:15,reconnect_grace_secs:120},
 negotiation:{enabled:true,candidate_count:4,deadlines_secs:[3,5,8,12],carrier_probe_coalesce_ms:0}
};
function sessionHeaders(token,carrier){return {'X-Session-Token':token.repeat(43),'X-Down-Cursor':'0','X-Carrier-Mode':carrier,'X-Carrier-Attempt':'1','X-Carrier-Candidate-Count':'4','X-Carrier-Deadline':'12','X-Carrier-State':'provisional','X-Telemt-Up-Window':'4'}}
async function replacementRecovery(page,endpoint,carrier){
 const shortPage=renderedPage({}, {BRIDGE_RECOVERY_SECS:2});
 const {env,socket}=await committedMultiplexSession(shortPage);
 env.suspend(120001);env.send(frame(2,7,[91]));await flush();env.send(join(frame(1,9),frame(2,9,[93])));await flush();
 socket.receive(frame(6,0,Array(16).fill(0xee)));await flush();await env.tick(1001);await flush();
 const recovery=env.requests.find(request=>request.options.headers?.Accept==='application/vnd.telemt.web-recovery+json'&&!request.answered);assert.ok(recovery,'policy recovery starts after failed WebSocket proof');
 env.answer(recovery,200,new TextEncoder().encode(JSON.stringify(shortRecoveryPolicy)),{'Content-Type':'application/vnd.telemt.web-recovery+json'});await flush();
 if(endpoint==='up'){
  const replacement=env.pending('/api/v1/session')[0];assert.ok(replacement,'replacement session starts');
  env.answer(replacement,200,frame(17),sessionHeaders('D',carrier));await flush();
 }
 const path='/api/v1/'+endpoint,pending=env.pending(path)[0];assert.ok(pending,'replacement '+endpoint+' request starts');
 return {env,path,pending};
}
test('recovery owner deadline fences replacement session and HTTPS lane retries',async page=>{
 for(const [endpoint,carrier] of [['session','websocket'],['up','https'],['up','https-lanes']]){
  const {env,path,pending}=await replacementRecovery(page,endpoint,carrier);
  env.answer(pending,503,null,{});await flush();
  const before=env.requests.filter(request=>request.url.endsWith(path)).length;
  env.suspend(2001);await env.resume();await flush();
  assert.equal(env.requests.filter(request=>request.url.endsWith(path)).length,before,endpoint+' retry does not cross the expired recovery owner');
  assert.ok(env.received.some(value=>value?.t==='close'),'expired replacement recovery closes the bridge');env.close();await flush();
 }
});
test('late committed HTTPS and HTTPS-lanes replay has no post-deadline effects',async page=>{
 for(const carrier of ['https','https-lanes'])for(const direction of ['up','down']){
  const shortPage=renderedPage({}, {BRIDGE_RECOVERY_SECS:2}),env=await session(shortPage,carrier,1);
  env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
  if(direction==='up'){env.send(frame(2,1,[91]));await flush();env.send(frame(2,1,[92]));await flush()}
  const path='/api/v1/'+direction,original=env.pending(path)[0];assert.ok(original);original.answered=true;original.reject(new Error('connection lost'));await flush();
  const replay=env.pending(path)[0];assert.ok(replay,'committed carrier replays its exact pending request');
  const beforeUp=env.requests.filter(request=>request.url.endsWith('/api/v1/up')).length,beforeNative=binary(env).length;
  env.suspend(2001);
  if(direction==='up')ack(env,replay);
  else{const data=frame(2,1,[94]);env.answer(replay,200,data,{'X-Down-Cursor':'1','Content-Length':String(data.byteLength)})}
  await flush();
  assert.equal(env.requests.filter(request=>request.url.endsWith('/api/v1/up')).length,beforeUp,'late replay cannot pump another uplink');
  assert.equal(binary(env).length,beforeNative,'late replay cannot deliver native frames');
  assert.ok(env.received.some(value=>value?.t==='close'),'expired committed replay closes the bridge');env.close();await flush();
 }
});
test('timely committed replay remains usable after its recovery deadline',async page=>{
 for(const carrier of ['https','https-lanes']){
  const shortPage=renderedPage({}, {BRIDGE_RECOVERY_SECS:2}),env=await session(shortPage,carrier,1);
  env.send(frame(1,1));await flush();ack(env,env.pending('/api/v1/up')[0]);await flush();
  env.send(frame(2,1,[91]));await flush();const original=env.pending('/api/v1/up')[0];original.answered=true;original.reject(new Error('connection lost'));await flush();
  const replay=env.pending('/api/v1/up')[0];assert.ok(replay);ack(env,replay);await flush();
  env.suspend(2001);env.send(frame(2,1,[92]));await flush();
  assert.ok(env.pending('/api/v1/up').some(request=>new Uint8Array(request.options.body).includes(92)),carrier+' accepts ordinary DATA after timely ACK ownership');
  assert.ok(!env.received.some(value=>value?.t==='close'));env.close();await flush();
 }
});

if(require.main===module||process.argv.includes('--stdin')){
 (async()=>{if(!tests.length)throw new Error('bridge behavior suite registered no tests');const page=renderedPage();let failed=0;for(const {name,run} of tests){let timer;try{await Promise.race([run(page),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('test made no bounded progress')),5000)})]);console.log('ok - '+name)}catch(error){failed++;console.error('not ok - '+name+'\n'+error.stack)}finally{clearTimeout(timer)}}if(failed)process.exitCode=1;else console.log('telemt-bridge-behavior-complete tests='+tests.length)})();
}else module.exports={renderedPage,environment,frame,join,flush,session,ack,binary};
