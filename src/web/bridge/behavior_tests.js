'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');

let stdinRenderedPage;
function applyRenderedOverrides(page,overrides){
 const declarations={
  NEGOTIATION_ENABLED:[/(\blet negotiationEnabled=)(true|false)(,candidateCount=)/,2],
  BATCH_LIMIT:[/(\blet batchLimit=)(\d+)(,queueLimit=)/,2],
  QUEUE_LIMIT:[/(\bqueueLimit=)(\d+)(,queueItemLimit=)/,2],
  QUEUE_ITEMS:[/(\bqueueItemLimit=)(\d+)(,maxStreams=)/,2]
 };
 for(const [key,value] of Object.entries(overrides)){
  const declaration=declarations[key];if(!declaration)continue;
  const [pattern,valueGroup]=declaration,match=pattern.exec(page);
  if(!match)throw new Error('cannot override rendered '+key+' declaration');
  const replacement=match.slice(1);replacement[valueGroup-1]=String(value);
  page=page.slice(0,match.index)+replacement.join('')+page.slice(match.index+match[0].length);
 }
 return page;
}
function renderedPage(sources={},overrides={}){
 if(process.argv.includes('--stdin')){
  stdinRenderedPage??=fs.readFileSync(0,'utf8');
  return applyRenderedOverrides(stdinRenderedPage,overrides);
 }
 const read=(name)=>sources[name]===undefined?fs.readFileSync(path.join(__dirname,name),'utf8'):sources[name];
 let page=read('document.html');
 const modules={RESPONSE:'response',REQUEST:'request',BUFFER:'buffers',RECOVERY:'recovery',CONVEYOR:'conveyor',DOWNLINK:'downlink'};
 page=page.replace('__DIAGNOSTIC_RUNTIME__','');
 for(const [key,file] of Object.entries(modules))if(page.includes('__'+key+'_RUNTIME__'))page=page.replace('__'+key+'_RUNTIME__',()=>read(file+'.js'));
 page=page.replace('__RUNTIME__',()=>read('runtime.js'));
 const values={BOOTSTRAP:'A'.repeat(43),HOST:'proxy.example.com',BASE_PREFIX:'',CARRIER_METHOD:'POST',NEGOTIATION_ENABLED:'true',CANDIDATE_COUNT:4,CARRIER_DEADLINES:'3,5,8,12',LONG_POLL_SECS:25,BRIDGE_REQUEST_SECS:10,BRIDGE_RETRY_SECS:90,BRIDGE_RECOVERY_SECS:15,WEBSOCKET_OPEN_SECS:15,RECONNECT_GRACE_SECS:120,CARRIER_PROBE_COALESCE_MS:0,BATCH_LIMIT:2097152,QUEUE_LIMIT:33554432,QUEUE_ITEMS:16384,MAX_STREAMS:1024,STATUS_FUNCTION:"state=>{if(port&&!closed)port.postMessage({t:'status',state})}",HELLO_TIMEOUT_CALLBACK:"()=>fail('timeout')",PAGEHIDE_CALLBACK:'()=>close(true)',...overrides};
 return page.replace(/__([A-Z_]+)__/g,(all,key)=>key.startsWith('DIAGNOSTIC_')?'':String(values[key]??''));
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
   open(){if(this.readyState!==0)return;this.readyState=1;if(this.onopen)this.onopen()}
   send(data){if(this.readyState!==1)throw new Error('websocket is not open');if(this.throwOnSend===this.sent.length+1)throw new Error('synthetic send failure');this.sent.push(data.slice(0));this.bufferedAmount+=data.byteLength}
   message(data){if(this.onmessage)this.onmessage({data:data.slice(0)})}
   close(){if(this.readyState===3)return;this.readyState=3;if(this.onclose)this.onclose()}
  }
 };
 if(android)context.TelegramWebProxy={onmessage:null,postMessage(value){received.push(typeof value==='string'?JSON.parse(value):structuredClone(value))}};
 vm.createContext(context);
 for(const match of page.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g))vm.runInContext(match[1],context);
 if(!android)events.get('message')({source:context.parent,origin:'http://127.0.0.1:12345',data:{t:'tproxy-init',v:1},ports:[port]});
 const send=data=>android?context.TelegramWebProxy.onmessage({data}):port.onmessage({data});
 const pending=suffix=>requests.filter(r=>r.url.endsWith(suffix)&&!r.answered);
 const answer=(request,status,body=null,headers={})=>{request.answered=true;request.resolve({status,headers:new Headers(headers),body:body===null?null:new ReadableStream({start(c){c.enqueue(new Uint8Array(body));c.close()}})})};
 return {context,send,pending,answer,received,requests,webSockets,now:()=>now,schedule:(fn,delay)=>context.setTimeout(fn,delay),async tick(ms){const until=now+ms;for(;;){const entry=[...timers].filter(([,t])=>t.at<=until).sort((a,b)=>a[1].at-b[1].at)[0];if(!entry)break;now=entry[1].at;timers.delete(entry[0]);entry[1].fn();await flush()}now=until;await flush()},close(){events.get('pagehide')();}};
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

module.exports={renderedPage,frame,join,flush,environment,session};
if(!process.argv.includes('--benchmark-module'))(async()=>{const page=renderedPage();let failed=0;for(const {name,run} of tests){let timer;try{await Promise.race([run(page),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('test made no bounded progress')),5000)})]);console.log('ok - '+name)}catch(error){failed++;console.error('not ok - '+name+'\n'+error.stack)}finally{clearTimeout(timer)}}if(failed)process.exitCode=1})();
