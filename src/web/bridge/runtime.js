(()=>{'use strict';
let bootstrap="__BOOTSTRAP__";
const relayOrigin='https://__HOST__',relayBase=relayOrigin+'__BASE_PREFIX__',carrierCapabilities='https,https-lanes,websocket,websocket-lanes';
__DIAGNOSTIC_BINDING__;
__DIAGNOSTIC_RUNTIME_STARTED__;
const responseBody=globalThis.TelemtBridgeResponse;if(!responseBody)throw new Error('missing response runtime');
const requestSupport=globalThis.TelemtBridgeRequest;if(!requestSupport)throw new Error('missing request runtime');
const bufferSupport=globalThis.TelemtBridgeBuffers;if(!bufferSupport)throw new Error('missing buffer runtime');
const recoverySupport=globalThis.TelemtBridgeRecovery;if(!recoverySupport)throw new Error('missing recovery runtime');
const resumeProbeSupport=globalThis.TelemtBridgeResumeProbe;if(!resumeProbeSupport)throw new Error('missing resume probe runtime');
// Keep the method page-owned so recovery and config rollback cannot change frozen retries.
const carrierMethod='__CARRIER_METHOD__';
let negotiationEnabled=__NEGOTIATION_ENABLED__,candidateCount=__CANDIDATE_COUNT__,candidateDeadlines=[__CARRIER_DEADLINES__];
let longPollMs=__LONG_POLL_SECS__*1000,bridgeRequestMs=__BRIDGE_REQUEST_SECS__*1000,bridgeRetryMs=__BRIDGE_RETRY_SECS__*1000;
let bridgeRecoveryMs=__BRIDGE_RECOVERY_SECS__*1000,websocketOpenMs=__WEBSOCKET_OPEN_SECS__*1000,reconnectGraceMs=__RECONNECT_GRACE_SECS__*1000;
let probeCoalesceMs=__CARRIER_PROBE_COALESCE_MS__;
let negotiatedCandidateCount=candidateCount,negotiatedFinalDeadline=candidateDeadlines[3],negotiatedFrozen=false;
let batchLimit=__BATCH_LIMIT__,queueLimit=__QUEUE_LIMIT__,queueItemLimit=__QUEUE_ITEMS__,maxStreams=__MAX_STREAMS__;
let laneQueueLimit=Math.min(queueLimit,8388608),laneItemLimit=Math.min(queueItemLimit,1024);const closedLaneLimit=4096;
const fragment=location.hash,androidNonce=/^#android=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1]||'',recoveryPath=location.pathname+location.search;
history.replaceState(null,'',location.pathname);
let initialized=false,closed=false,port=null,sessionToken='',cleanupToken='',createStarted=false,socket=null,socketReady=false,carrier='';
let upSequence=1,downCursor='0',upRunning=false,upLease=null,httpCarrier=null,upWindow=1;
let helloFrame=null,helloTimer=null,welcomeSent=false,carrierAttempt=1,carrierFailure='',carrierCommitted=false,terminalFailure='';
let negotiationStartedAt=0,carrierTimer=null,probeTimer=null,attemptController=null,attemptEpoch=1,candidateRunning=false,switching=false,currentAttempt=null;
let recoveryController=null,recoveryCommit=null,recoveryReplaced=false,lastSchedulerWall=Date.now(),lastSchedulerMonotonic=performance.now(),schedulerGapPending=0,schedulerTimer=null;
const pending=[],upPending=[],recoveryPending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
const canonicalFailures=['timeout','network','upgrade','http','protocol'];
const failure=(reason,message)=>Object.assign(new Error(message||reason),{telemtReason:reason});
const failureReason=(error,fallback)=>error&&canonicalFailures.includes(error.telemtReason)?error.telemtReason:fallback;
const status=__STATUS_FUNCTION__;
const socketURL=()=>relayBase.replace(/^https:/,'wss:')+'/api/v1/ws';
const requestClient=requestSupport.create({
 jitter:Object.freeze(__RETRY_JITTER__),
 base:()=>relayBase,closed:()=>closed,retryMs:()=>bridgeRetryMs,longPollMs:()=>longPollMs,requestMs:()=>bridgeRequestMs,
 batchLimit:()=>batchLimit,read:(response,limit,exact,signal)=>responseBody.read(response,limit,exact,signal),cancel:responseBody.cancel,
 failure,reason:failureReason,retrying:()=>status('reconnecting')
});
const options=requestClient.options,pause=requestClient.pause,request=requestClient.send;
const resumeProbe=resumeProbeSupport.create({
 current:entries=>{
  if(closed||!carrierCommitted||recoveryReplaced||!entries.length)return false;
  if(carrier==='websocket')return entries.length===1&&!entries[0].lane&&entries[0].epoch===attemptEpoch&&socket===entries[0].socket&&socketReady&&socket.readyState===WebSocket.OPEN;
  if(carrier!=='websocket-lanes'||entries.length!==lanes.size)return false;
  return entries.every(entry=>entry.lane&&entry.epoch===attemptEpoch&&lanes.get(entry.lane.id)===entry.lane&&entry.lane.socket===entry.socket&&entry.lane.ready&&!entry.lane.remoteClosed&&entry.socket.readyState===WebSocket.OPEN);
 },
 ready:entry=>entry.socket.bufferedAmount===0&&(entry.lane?(!entry.lane.running&&!entry.lane.pending.length&&!entry.lane.upLease):(!upRunning&&!upPending.length&&!upLease)),
 wait:(milliseconds,signal)=>pause(milliseconds,signal)
});
const buffers=bufferSupport.create({
 limits:()=>({batchBytes:batchLimit,queueBytes:queueLimit,queueItems:queueItemLimit,laneBytes:laneQueueLimit,laneItems:laneItemLimit}),
 buffered:()=>{let total=socket?socket.bufferedAmount:0;for(const value of lanes.values())if(value.socket)total+=value.socket.bufferedAmount;return total},
 pending:()=>pending,laneMode:()=>carrier==='https-lanes'||carrier==='websocket-lanes',maxStreams:()=>maxStreams,failure
});
const {reserve,release,releasePending,frameBound,splitFrames,acceptNativeFrames,observeServerFrames,findProbe,copyProbe,consumeProbe,canSendCandidate,takeBatch,closeFrame,retireStream,retireAllStreams,clearStreams}=buffers;
function detachLease(lease){if(lease.lane){if(lease.lane.upLease===lease)lease.lane.upLease=null}else if(upLease===lease)upLease=null}
function settleBatch(lease){if(!buffers.settleBatch(lease))return false;detachLease(lease);return true}
function cancelBatch(lease){if(!lease||lease.settled)return;buffers.cancelBatch(lease);detachLease(lease)}
const attemptHeaders=(attempt,failure)=>Object.assign({'X-Telemt-Up-Window':'4'},negotiationEnabled?Object.assign({'X-Carrier-Capabilities':carrierCapabilities,'X-Carrier-Attempt':String(attempt)},failure?{'X-Carrier-Failure':failure}:{}):{});
function finishOldRecovery(){
 buffers.clearRecoveryFresh();recoveryReplaced=false;resetScheduler();status('connected');
 while(recoveryPending.length&&!closed){const data=recoveryPending.shift();release(data.byteLength,1,null);queueCarrier(data)}
}
function rejectRecoveryCommit(error){
 const commit=recoveryCommit;if(!commit)return;recoveryCommit=null;commit.accepted=false;
 commit.signal.removeEventListener('abort',commit.abort);commit.reject(error);
}
function resolveRecoveryCommit(){
 const commit=recoveryCommit;if(!commit)return;recoveryCommit=null;commit.accepted=true;recoveryReplaced=false;
 commit.signal.removeEventListener('abort',commit.abort);if(commit.accept)commit.accept();commit.resolve();
}
function recoveryCommitActive(owner){
 if(!owner)return true;if(owner.accepted)return !closed;
 if(closed||recoveryCommit!==owner)return false;
 if(owner.signal.aborted||owner.remaining()<=0){rejectRecoveryCommit(failure('timeout','recovery deadline'));return false}
 return true;
}
function retireCarrier(policy){
 const handoff=buffers.recoveryHandoff(recoveryPending,{batchBytes:policy.limits.carrier_batch_bytes,queueBytes:policy.limits.pending_bytes_per_session,queueItems:policy.limits.pending_items_per_session,maxStreams:policy.limits.max_streams_per_session,laneBytes:Math.min(policy.limits.pending_bytes_per_session,8388608),laneItems:Math.min(policy.limits.pending_items_per_session,1024)});
 stopHttp(false);upWindow=1;
 recoveryReplaced=true;attemptEpoch++;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;clearProbeTimer();
 if(attemptController)attemptController.abort();attemptController=null;
 if(socket){const previous=socket;socket=null;previous.close()}socketReady=false;cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket)lane.socket.close();
 }
 lanes.clear();closedLanes.clear();closedLaneOrder.length=0;releasePending(pending,null);releasePending(recoveryPending,null);
 const retired=retireAllStreams(handoff.ok?handoff.ids:[]);for(const id of retired)if(port){const frame=closeFrame(id);port.postMessage(frame,[frame])}
 if(!handoff.ok){fail('capacity');return false}
 bootstrap=policy.bootstrap;__DIAGNOSTIC_BOOTSTRAP_REPLACED__;batchLimit=policy.limits.carrier_batch_bytes;queueLimit=policy.limits.pending_bytes_per_session;
 queueItemLimit=policy.limits.pending_items_per_session;maxStreams=policy.limits.max_streams_per_session;
 laneQueueLimit=Math.min(queueLimit,8388608);laneItemLimit=Math.min(queueItemLimit,1024);
 longPollMs=policy.timeouts.long_poll_secs*1000;bridgeRequestMs=policy.timeouts.bridge_request_secs*1000;
 bridgeRetryMs=policy.timeouts.bridge_retry_secs*1000;bridgeRecoveryMs=policy.timeouts.bridge_recovery_secs*1000;
 websocketOpenMs=policy.timeouts.websocket_open_secs*1000;reconnectGraceMs=policy.timeouts.reconnect_grace_secs*1000;
 armScheduler();
 negotiationEnabled=policy.negotiation.enabled;candidateCount=policy.negotiation.candidate_count;
 candidateDeadlines=policy.negotiation.deadlines_secs;probeCoalesceMs=policy.negotiation.carrier_probe_coalesce_ms;
 negotiatedCandidateCount=candidateCount;negotiatedFinalDeadline=candidateDeadlines[3];negotiatedFrozen=false;
 sessionToken='';cleanupToken='';carrier='';carrierAttempt=1;carrierFailure='';carrierCommitted=false;
 candidateRunning=false;switching=false;currentAttempt=null;upSequence=1;downCursor='0';upRunning=false;
 buffers.clearRecoveryFresh();buffers.resetRecoveryOwnershipUncertain();
 const reserved=[];for(const data of handoff.batches){if(!reserve(data,null)){releasePending(reserved,null);fail('capacity');return false}reserved.push(data)}
 for(const data of reserved)pending.push(data);
 return true;
}
function replaceCarrier(policy,signal,remaining,epoch,accept){
 if(closed||!helloFrame||!port)throw failure('protocol','missing recovery owner');
 if(signal.aborted||remaining()<=0)throw failure('timeout','recovery deadline');
 if(!retireCarrier(policy))throw failure('capacity');negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch);
 return new Promise((resolve,reject)=>{
  const owner={resolve,reject,signal,remaining,accepted:false,accept,abort:null};
  owner.abort=()=>rejectRecoveryCommit(failure('timeout','recovery deadline'));
  recoveryCommit=owner;signal.addEventListener('abort',owner.abort,{once:true});
  if(!recoveryCommitActive(owner))return;createSession(attemptEpoch,owner);
 });
}
function recoverTransport(error,replay){
 if(closed)return Promise.resolve(false);
 const reason=failureReason(error,'network');
 if(reason==='protocol'){fail(reason);return Promise.resolve(false)}
 return recoveryController.recover(reason,replay);
}
function schedulerGap(){
 const wall=Date.now(),monotonic=performance.now();
 const gap=Math.max(0,wall-lastSchedulerWall,monotonic-lastSchedulerMonotonic);
 lastSchedulerWall=wall;lastSchedulerMonotonic=monotonic;return gap;
}
function resetScheduler(){schedulerGapPending=0;schedulerGap()}
function captureResumeSockets(){
 if(carrier==='websocket'&&socket&&socketReady)return [{socket,epoch:attemptEpoch,lane:null}];
 if(carrier!=='websocket-lanes'||!lanes.size)return null;
 const entries=[...lanes.values()].map(lane=>({socket:lane.socket,epoch:attemptEpoch,lane}));
 return entries.every(entry=>entry.socket&&entry.lane.ready&&!entry.lane.remoteClosed)?entries:null;
}
function probeCommittedCarrier(signal){
 const entries=captureResumeSockets();if(!entries)return Promise.reject(new Error('no captured WebSocket owner'));
 return resumeProbe.probe(entries,signal);
}
function armScheduler(){
 if(schedulerTimer)clearTimeout(schedulerTimer);schedulerTimer=closed?null:setTimeout(sampleScheduler,Math.max(250,Math.min(30000,Math.floor(reconnectGraceMs/4))));
}
function sampleScheduler(){
 schedulerTimer=null;const gap=schedulerGap();if(carrierCommitted&&!recoveryController.active())schedulerGapPending=Math.max(schedulerGapPending,gap);armScheduler();
}
function observeResumeTrigger(){
 const gap=Math.max(schedulerGapPending,schedulerGap());schedulerGapPending=0;if(!carrierCommitted||closed)return;
 if(gap>=2*longPollMs)status('reconnecting');
 if(gap>=reconnectGraceMs&&!recoveryController.active())recoveryController.recover('timeout',carrier==='websocket'||carrier==='websocket-lanes'?probeCommittedCarrier:null);
}
function fail(reason){
 if(closed)return;reason=reason||'protocol';if(canonicalFailures.includes(reason))terminalFailure=reason;
 rejectRecoveryCommit(failure(reason));
 status('failed');if(port)port.postMessage({t:'close'});close(true);
}
function failWelcomeDelivery(){
 if(closed)return;terminalFailure='network';rejectRecoveryCommit(failure('network','WELCOME delivery failed'));
 try{status('failed')}catch(error){}
 try{if(port)port.postMessage({t:'close'})}catch(error){}
 close(true);
}
function deliverWelcome(welcome){
 if(welcomeSent)return 0;
 // Transfer may throw after ownership has moved, so the WELCOME guard stays set.
 welcomeSent=true;
 try{port.postMessage(welcome,[welcome])}catch(error){failWelcomeDelivery();return -1}
 return 1;
}
function knownCarrier(value){return value==='https'||value==='https-lanes'||value==='websocket'||value==='websocket-lanes'}
function sessionEcho(response,expectedAttempt,states,exactAttempt){
 const selected=response.headers.get('X-Carrier-Mode')||'',echo=response.headers.get('X-Carrier-Attempt')||'',windowHeader=response.headers.get('X-Telemt-Up-Window');
 if(windowHeader!==null&&!/^[1-4]$/.test(windowHeader))throw new Error('invalid conveyor window');const upWindow=windowHeader===null?1:Number(windowHeader);
 if(!knownCarrier(selected))throw new Error('invalid carrier mode');
 if(!negotiationEnabled){if(echo!=='')throw new Error('unexpected carrier attempt');return {selected,state:'',upWindow}}
 const count=response.headers.get('X-Carrier-Candidate-Count')||'',deadline=response.headers.get('X-Carrier-Deadline')||'',state=response.headers.get('X-Carrier-State')||'';
 if(!/^[1-4]$/.test(count)||!/^[1-9]\d*$/.test(deadline)||!states.includes(state))throw new Error('invalid carrier state');
 const echoedAttempt=Number(echo),parsedCount=Number(count),parsedDeadline=Number(deadline);
 if(!Number.isInteger(echoedAttempt)||echoedAttempt<1||(exactAttempt?echoedAttempt!==expectedAttempt:echoedAttempt>expectedAttempt))throw new Error('invalid carrier attempt');
 if(parsedCount>candidateCount||parsedDeadline>candidateDeadlines[3])throw new Error('invalid carrier bounds');
 if(!negotiatedFrozen){negotiatedCandidateCount=parsedCount;negotiatedFinalDeadline=parsedDeadline;negotiatedFrozen=true}
 else if(parsedCount!==negotiatedCandidateCount||parsedDeadline!==negotiatedFinalDeadline)throw new Error('changed carrier bounds');
 if(echoedAttempt>negotiatedCandidateCount)throw new Error('carrier attempt exceeds candidates');
 return {selected,state,upWindow};
}
function armCarrierDeadline(epoch){
 if(!negotiationStartedAt||epoch!==attemptEpoch)return;
 if(carrierTimer)clearTimeout(carrierTimer);
 const deadline=carrierAttempt>=negotiatedCandidateCount?negotiatedFinalDeadline:candidateDeadlines[carrierAttempt-1];
 const remaining=negotiationStartedAt+deadline*1000-Date.now();
 carrierTimer=setTimeout(()=>advanceCarrier('timeout',epoch),Math.max(0,remaining));
}
function clearProbeTimer(){if(probeTimer){clearTimeout(probeTimer.timer);probeTimer=null}}
function clearCandidateRetry(next){const state=next&&next.telemt;if(state&&state.retryTimer){clearTimeout(state.retryTimer);state.retryTimer=null}}
function retryCandidateSocket(next){const state=next&&next.telemt;if(!state||state.retryTimer||closed||carrierCommitted||state.epoch!==attemptEpoch)return;state.retryTimer=setTimeout(()=>{state.retryTimer=null;sendCandidateSocket(next)},10)}
function resetCandidate(){
 stopHttp(true);upWindow=1;
 clearProbeTimer();
 if(socket){const previous=socket;socket=null;clearCandidateRetry(previous);previous.close()}socketReady=false;
 cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket){clearCandidateRetry(lane.socket);lane.socket.close()}
 }
 lanes.clear();closedLanes.clear();closedLaneOrder.length=0;upSequence=1;downCursor='0';upRunning=false;
 sessionToken='';carrier='';candidateRunning=false;currentAttempt=null;
}
function advanceConfirmed(reason,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 const recoveryOwner=currentAttempt&&currentAttempt.recoveryOwner||null;if(!recoveryCommitActive(recoveryOwner))return;
 resetCandidate();
 if(carrierAttempt>=negotiatedCandidateCount||Date.now()>=negotiationStartedAt+negotiatedFinalDeadline*1000){switching=false;fail(reason);return}
 carrierAttempt++;carrierFailure=reason;attemptEpoch++;const nextEpoch=attemptEpoch;switching=false;
 status('reconnecting');armCarrierDeadline(nextEpoch);createSession(nextEpoch,recoveryOwner);
}
function advanceCarrier(reason,epoch){
 if(closed||carrierCommitted||epoch!==attemptEpoch||switching)return;
 if(!negotiationEnabled){fail(reason);return}
 switching=true;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;clearProbeTimer();
 const snapshot=currentAttempt;if(attemptController)attemptController.abort();attemptController=null;
 if(!snapshot||snapshot.epoch!==epoch){switching=false;fail('protocol');return}
 if(snapshot.selected){advanceConfirmed(reason,epoch);return}
 resolveAttempt(reason,epoch,snapshot);
}
async function resolveAttempt(reason,epoch,snapshot){
 if(!recoveryCommitActive(snapshot.recoveryOwner))return;
 const controller=new AbortController();attemptController=controller;
 const remaining=negotiationStartedAt+negotiatedFinalDeadline*1000-Date.now();
 if(remaining<=0){switching=false;fail('timeout');return}
 const timer=setTimeout(()=>controller.abort(),remaining);
 try{
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(snapshot.attempt,snapshot.failure),controller.signal);
  const response=await request('/api/v1/session',frozen,snapshot.recoveryOwner?()=>snapshot.recoveryOwner.remaining():undefined);
  if(closed||epoch!==attemptEpoch||!recoveryCommitActive(snapshot.recoveryOwner))return
  if(response.status===409){sessionEcho(response,snapshot.attempt,['committed','healthy'],false);switching=false;fail('protocol');return}
  if(response.status!==200){switching=false;fail('http');return}
  const echo=sessionEcho(response,snapshot.attempt,['provisional','committed','healthy'],true);
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'||(snapshot.selected&&echo.selected!==snapshot.selected))throw new Error('changed carrier replay');
  const welcome=response.body;if(closed||epoch!==attemptEpoch||!recoveryCommitActive(snapshot.recoveryOwner))return;
  cleanupToken=token;
  const welcomeDelivery=deliverWelcome(welcome);if(welcomeDelivery<0)return;if(welcomeDelivery)status('connecting');
  if(echo.state!=='provisional'){switching=false;fail('protocol');return}
  advanceConfirmed(reason,epoch);
 }catch(error){if(!closed&&epoch===attemptEpoch){switching=false;fail(failureReason(error,'protocol'))}}
 finally{clearTimeout(timer);if(attemptController===controller)attemptController=null}
}
function startCandidate(probe,epoch,recoveryOwner){
 if(!probe||closed||carrierCommitted||!sessionToken||candidateRunning||epoch!==attemptEpoch)return;
 clearProbeTimer();candidateRunning=true;
 if(carrier==='https')probeHttp(probe,null,epoch,recoveryOwner);
 else if(carrier==='https-lanes')probeHttp(probe,probe.id,epoch,recoveryOwner);
 else if(carrier==='websocket')openCandidateSocket(probe,null,epoch,recoveryOwner);
 else if(carrier==='websocket-lanes')openCandidateSocket(probe,probe.id,epoch,recoveryOwner);
 else advanceCarrier('protocol',epoch);
}
function maybeStartCandidate(){
 if(closed||carrierCommitted||!sessionToken)return;const recoveryOwner=currentAttempt&&currentAttempt.recoveryOwner||null;if(!recoveryCommitActive(recoveryOwner))return;if(candidateRunning){try{if(carrier==='https'||carrier==='https-lanes')flushHttpPending();else if(carrier==='websocket')sendCandidateSocket(socket);else if(carrier==='websocket-lanes')for(const lane of lanes.values())if(lane.socket&&lane.socket.telemt&&lane.socket.telemt.epoch===attemptEpoch){sendCandidateSocket(lane.socket);break}}catch(error){fail(failureReason(error,'protocol'))}return}const epoch=attemptEpoch;
 let probe;try{probe=findProbe(true)}catch(error){fail('protocol');return}if(!probe)return;
 if(!probeCoalesceMs||probe.hasData){startCandidate(probe,epoch,recoveryOwner);return}
 if(probeTimer)return;const owner={epoch,timer:null};
 owner.timer=setTimeout(()=>{if(probeTimer!==owner||closed||owner.epoch!==attemptEpoch)return;probeTimer=null;let current;try{current=findProbe(false)}catch(error){fail('protocol');return}startCandidate(current,owner.epoch,recoveryOwner)},probeCoalesceMs);
 probeTimer=owner;
}
async function createSession(epoch,recoveryOwner=null){
 if(!recoveryCommitActive(recoveryOwner))return;
 const controller=new AbortController(),attempt=carrierAttempt,failure=carrierFailure;
 const snapshot={epoch,attempt,failure,hello:helloFrame,selected:'',recoveryOwner};currentAttempt=snapshot;attemptController=controller;
 try{
  status('connecting');
  const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(attempt,failure),controller.signal);
  const response=await request('/api/v1/session',frozen,recoveryOwner?()=>recoveryOwner.remaining():undefined);
  if(closed||epoch!==attemptEpoch||!recoveryCommitActive(recoveryOwner))return
  if(response.status===409){sessionEcho(response,attempt,['committed','healthy'],false);fail('protocol');return}
  if(response.status!==200){advanceCarrier('http',epoch);return}
  const echo=sessionEcho(response,attempt,['provisional'],true),selected=echo.selected;snapshot.selected=selected;
  const token=response.headers.get('X-Session-Token')||'',cursor=response.headers.get('X-Down-Cursor')||'';
  if(!token||cursor!=='0'){advanceCarrier('protocol',epoch);return}
  const welcome=response.body;if(closed||epoch!==attemptEpoch||!recoveryCommitActive(recoveryOwner))return;
  carrier=selected;sessionToken=token;cleanupToken=token;downCursor=cursor;upWindow=echo.upWindow;
  const welcomeDelivery=deliverWelcome(welcome);if(welcomeDelivery<0)return;if(welcomeDelivery)status('connecting');
  if(carrier==='websocket')openCandidateSocket(null,null,epoch,recoveryOwner);
  maybeStartCandidate();
 }catch(error){if(closed||epoch!==attemptEpoch)return;advanceCarrier(failureReason(error,'network'),epoch)}
}
function stopHttp(restore){
 if(!httpCarrier)return;const saved=httpCarrier.close(restore);httpCarrier=null;
 for(const data of saved){if(!reserve(data,null)){fail('capacity');return}pending.push(data)}
}
function flushHttpPending(){
 while(httpCarrier&&pending.length&&!closed){const data=pending.shift();release(data.byteLength,1,null);httpCarrier.enqueue(data,true)}
 if(httpCarrier&&!closed)httpCarrier.flush();
}
function probeHttp(probe,laneID,epoch,recoveryOwner){
 if(!recoveryCommitActive(recoveryOwner))return;
 const token=sessionToken;
 httpCarrier=globalThis.TelemtBridgeConveyor.create({
  token,window:upWindow,method:carrierMethod,lanes:carrier==='https-lanes',buffers,options,request,
  remaining:()=>recoveryOwner&&!recoveryOwner.accepted?recoveryOwner.remaining():Infinity,
  queueLimit:()=>queueLimit,batchLimit:()=>batchLimit,committed:()=>carrierCommitted,failure,cancel:responseBody.cancel,
  alive:lane=>!closed&&epoch===attemptEpoch&&token===sessionToken&&recoveryCommitActive(recoveryOwner)&&(!lane||lanes.get(lane.id)===lane),
  commit:()=>commitCarrier(null,epoch,recoveryOwner),recover:recoverTransport,connected:()=>{if(recoveryCommitActive(recoveryOwner))status('connected')},
  traffic:(up,down)=>port.postMessage({t:'traffic',up,down}),
  deliver:data=>{if(!recoveryCommitActive(recoveryOwner))return;observeServerFrames(data);port.postMessage({t:'traffic',up:0,down:data.byteLength});port.postMessage(data,[data])},
  lane:(id,type)=>{
   if(!recoveryCommitActive(recoveryOwner))return null;
   let lane=lanes.get(id);if(!lane&&(type===2||type===3||type===4))return null;
   if(!lane&&closedLanes.has(id))throw failure('protocol','closed lane reused');
   if(!lane&&id!==0&&type!==1)throw failure('protocol','lane did not begin with OPEN');
   return lane||ensureLane(id);
  },
  finish:finishLane,failed:error=>{if(closed||epoch!==attemptEpoch||!recoveryCommitActive(recoveryOwner))return;if(carrierCommitted)fail(failureReason(error,'network'));else advanceCarrier(failureReason(error,'network'),epoch)}
 });
 try{flushHttpPending()}catch(error){fail(failureReason(error,'protocol'))}
}
function commitCarrier(probe,epoch,recoveryOwner){
 if(closed||carrierCommitted||epoch!==attemptEpoch)return;
 if(!recoveryCommitActive(recoveryOwner))return;
 if(switching){fail('protocol');return}
 clearProbeTimer();try{if(probe)consumeProbe(probe)}catch(error){fail('protocol');return}
 carrierCommitted=true;candidateRunning=false;if(carrierTimer)clearTimeout(carrierTimer);carrierTimer=null;
 resetScheduler();
 attemptController=null;currentAttempt=null;
 status('connected');
 while(pending.length&&!closed){const data=pending.shift();release(data.byteLength,1,null);queueCarrier(data)}
 resolveRecoveryCommit();
}
function queueCarrier(data){
 if(closed)return;
 try{
  if(carrier==='https'||carrier==='https-lanes')httpCarrier.enqueue(data);
  else if(carrier==='websocket')queueSocket(data);
  else for(const value of splitFrames(data)){if(closed)break;queueLane(value)}
 }catch(error){fail('protocol')}
}
function sendCandidateSocket(next){
 const state=next&&next.telemt;if(!state||state.epoch!==attemptEpoch||next.readyState!==WebSocket.OPEN||!state.probe)return;
 if(!recoveryCommitActive(state.recoveryOwner))return;
 if(state.lane?state.lane.socket!==next:socket!==next)return;
 clearCandidateRetry(next);
 if(state.sent){
  if(!negotiationEnabled||carrierCommitted)return;
  try{
   const fresh=findProbe(false,state.sentSpans,state.probe.id,2,true);if(!fresh)return;
   const allowed=canSendCandidate(state.lane?state.probe.id:null,next.bufferedAmount,fresh.size);
   if(allowed==='capacity'){fail('capacity');return}if(allowed==='reserved')return;if(allowed!==true){retryCandidateSocket(next);return}
   const data=copyProbe(fresh);next.send(data);port.postMessage({t:'traffic',up:data.byteLength,down:0});state.probe.spans.push(...fresh.spans);state.sentSpans.push(...fresh.spans);if(fresh.more)retryCandidateSocket(next);
  }catch(error){advanceCarrier('upgrade',state.epoch)}
  return;
 }
 let probe=state.probe;
 try{
  const fresh=findProbe(true);if(fresh&&fresh.id===probe.id)probe=fresh;
  let allowed=canSendCandidate(state.lane?probe.id:null,next.bufferedAmount,probe.size);
  if(allowed!==true){probe=findProbe(false);if(!probe)return;allowed=canSendCandidate(state.lane?probe.id:null,next.bufferedAmount,probe.size)}
  if(allowed==='capacity'||allowed==='reserved'){fail('capacity');return}if(allowed!==true){retryCandidateSocket(next);return}
  next.send(copyProbe(probe))
 }catch(error){advanceCarrier('upgrade',state.epoch);return}
 state.probe=probe;state.sent=true;state.sentSpans=probe.spans.slice();if(!negotiationEnabled){if(state.openTimer)clearTimeout(state.openTimer);state.openTimer=null;commitCarrier(probe,state.epoch,state.recoveryOwner)}else sendCandidateSocket(next)
}
function openCandidateSocket(probe,laneID,epoch,recoveryOwner){
 if(!recoveryCommitActive(recoveryOwner))return;
 let lane=laneID===null?null:ensureLane(laneID),next=lane?lane.socket:socket;
 if(next){if(!next.telemt||next.telemt.epoch!==epoch){advanceCarrier('protocol',epoch);return}if(probe)next.telemt.probe=probe;sendCandidateSocket(next);return}
 const token=sessionToken,protocol=laneID===null?(negotiationEnabled?'tproxy-auto-v1.':'tproxy-v1.')+token:(negotiationEnabled?'tproxy-auto-lane-v1.':'tproxy-lane-v1.')+token+'.'+String(laneID);
 next=new WebSocket(socketURL(),protocol);next.binaryType='arraybuffer';next.telemt={epoch,lane,probe,opened:false,sent:false,sentSpans:[],openTimer:null,retryTimer:null,recoveryOwner};
 next.telemt.openTimer=setTimeout(()=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch)return;
  next.close();advanceCarrier('timeout',state.epoch);
 },websocketOpenMs);
 if(lane)lane.socket=next;else socket=next;
 next.onopen=()=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch||!recoveryCommitActive(state.recoveryOwner)){next.close();return}state.opened=true;
  if(state.lane){state.lane.ready=true}else socketReady=true;sendCandidateSocket(next);
 };
 next.onmessage=event=>{
  const state=next.telemt;if(closed||state.epoch!==attemptEpoch||!(event.data instanceof ArrayBuffer)||!recoveryCommitActive(state.recoveryOwner))return;
  clearCandidateRetry(next);
  if(carrierCommitted&&resumeProbe.receive(next,event.data,state.epoch))return;
  if(state.openTimer)clearTimeout(state.openTimer);state.openTimer=null;
  if(!carrierCommitted){if(!state.sent||event.data.byteLength!==0){advanceCarrier('protocol',state.epoch);return}commitCarrier(state.probe,state.epoch,state.recoveryOwner);return}
  try{
   if(state.lane){const values=splitFrames(event.data);for(const value of values)if(value.id!==state.lane.id)throw new Error('cross-lane frame');if(values.some(value=>value.type===3))state.lane.remoteClosed=true}
   else{const bound=frameBound(event.data,4096,batchLimit);if(bound.bytes!==event.data.byteLength)throw new Error('invalid frame batch')}
  }catch(error){if(state.lane)finishLane(state.lane,true);else fail('protocol');return}
  observeServerFrames(event.data);port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 next.onerror=()=>{};
 next.onclose=()=>{
  const state=next.telemt;if(state.openTimer)clearTimeout(state.openTimer);state.openTimer=null;clearCandidateRetry(next);if(state.epoch!==attemptEpoch||closed)return;
  if(!carrierCommitted){advanceCarrier(state.opened?'network':'upgrade',state.epoch);return}
  if(state.lane){state.lane.ready=false;state.lane.socket=null;finishLane(state.lane,true)}else{socketReady=false;recoveryController.recover('network',null)}
 };
}
function queueSocket(data){if(!reserve(data,null)){fail('capacity');return}upPending.push(data);runSocketUp()}
async function waitSocket(next,size,limit,signal){
 while(!closed&&next.readyState===WebSocket.OPEN&&next.bufferedAmount>limit-size)await pause(10,signal);
 if(closed||(signal&&signal.aborted)||next.readyState!==WebSocket.OPEN)throw new Error('websocket closed');
}
async function runSocketUp(){
 if(upRunning||!socketReady)return;upRunning=true;const ownerEpoch=attemptEpoch;let lease=null;
 try{
  while(!closed&&socketReady&&upPending.length){
   lease=takeBatch(upPending,null);upLease=lease;lease.controller=new AbortController();
   await waitSocket(socket,lease.total,queueLimit,lease.controller.signal);socket.send(lease.body);
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lease=null;
  }
 }catch(error){if(!closed&&!(lease&&lease.cancelled))recoverTransport(error,null)}
 finally{if(ownerEpoch===attemptEpoch){upRunning=false;if(!closed&&socketReady&&upPending.length)runSocketUp()}}
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id,sequence:1,cursor:'0',pending:[],bytes:0,items:0,running:false,upLease:null,polling:false,controller:null,socket:null,ready:false,remoteClosed:false};lanes.set(id,lane)}
 return lane;
}
function rememberLaneClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length===closedLaneLimit)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function finishLane(lane,notifyClient){
 if(lanes.get(lane.id)!==lane)return;if(httpCarrier)httpCarrier.finish(lane);
 if(lane.controller)lane.controller.abort();lane.controller=null;cancelBatch(lane.upLease);
 if(lane.socket&&lane.socket.readyState<WebSocket.CLOSING)lane.socket.close();
 releasePending(lane.pending,lane);lanes.delete(lane.id);rememberLaneClosed(lane.id);
 if(notifyClient&&!lane.remoteClosed&&port){retireStream(lane.id);const frame=closeFrame(lane.id);port.postMessage(frame,[frame])}
}
function queueLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(!reserve(value.data,lane)){fail('capacity');return}
 lane.pending.push(value.data);
 openLaneSocket(lane);runLaneSocketUp(lane);
}
function openLaneSocket(lane){
 if(lane.socket||closed)return;lane.socket=new WebSocket(socketURL(),'tproxy-lane-v1.'+sessionToken+'.'+String(lane.id));lane.socket.binaryType='arraybuffer';
 const opened=lane.socket;let upgraded=false,settled=false,openTimer=null;const finishSocket=reason=>{if(settled)return;settled=true;if(openTimer)clearTimeout(openTimer);openTimer=null;if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened)return;lane.ready=false;if(!upgraded){lane.socket=null;opened.close();recoveryController.recover(reason,null);return}finishLane(lane,true)};
 openTimer=setTimeout(()=>finishSocket('timeout'),websocketOpenMs);
 lane.socket.onopen=()=>{if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened){opened.close();return}upgraded=true;lane.ready=true;status('connected');runLaneSocketUp(lane)};
 lane.socket.onmessage=event=>{
  if(openTimer)clearTimeout(openTimer);openTimer=null;
  if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened||!(event.data instanceof ArrayBuffer)){finishLane(lane,true);return}
  if(carrierCommitted&&resumeProbe.receive(opened,event.data,attemptEpoch))return;
  let values;try{values=splitFrames(event.data);for(const value of values)if(value.id!==lane.id)throw new Error('cross-lane frame')}catch(error){finishLane(lane,true);return}
  if(values.some(value=>value.type===3))lane.remoteClosed=true;
  observeServerFrames(event.data);port.postMessage({t:'traffic',up:0,down:event.data.byteLength});port.postMessage(event.data,[event.data]);status('connected');
 };
 lane.socket.onerror=()=>{};lane.socket.onclose=()=>finishSocket(upgraded?'network':'upgrade');
}
async function runLaneSocketUp(lane){
 if(lane.running||!lane.ready)return;lane.running=true;let lease=null;
 try{
  while(!closed&&lane.ready&&lanes.get(lane.id)===lane&&lane.pending.length){
   lease=takeBatch(lane.pending,lane);lane.upLease=lease;lease.controller=new AbortController();
   await waitSocket(lane.socket,lease.total,laneQueueLimit,lease.controller.signal);lane.socket.send(lease.body);
   if(!settleBatch(lease))return;port.postMessage({t:'traffic',up:lease.total,down:0});lease=null;
  }
 }catch(error){if(!closed&&lanes.get(lane.id)===lane&&!(lease&&lease.cancelled))finishLane(lane,true)}
 finally{lane.running=false;if(!closed&&lanes.get(lane.id)===lane&&lane.ready&&lane.pending.length)runLaneSocketUp(lane)}
}
function deleteSession(){
 const token=cleanupToken||sessionToken,headers=canonicalFailures.includes(terminalFailure)?{'X-Carrier-Failure':terminalFailure}:null;
 if(token)fetch(relayBase+'/api/v1/session',options('DELETE',token,null,headers,undefined,true)).catch(()=>{});
}
function close(notifyServer){
 if(closed)return;closed=true;stopHttp(false);if(recoveryController)recoveryController.cancel();rejectRecoveryCommit(failure('network','bridge closed'));if(helloTimer)clearTimeout(helloTimer);helloTimer=null;if(carrierTimer)clearTimeout(carrierTimer);clearProbeTimer();if(schedulerTimer)clearTimeout(schedulerTimer);schedulerTimer=null;if(attemptController)attemptController.abort();
 if(socket){clearCandidateRetry(socket);socket.close()}cancelBatch(upLease);releasePending(upPending,null);
 for(const lane of lanes.values()){
  if(lane.controller)lane.controller.abort();cancelBatch(lane.upLease);releasePending(lane.pending,lane);if(lane.socket){clearCandidateRetry(lane.socket);lane.socket.close()}
 }
 if(notifyServer)deleteSession();releasePending(pending,null);releasePending(recoveryPending,null);lanes.clear();clearStreams();if(port)port.close();
 buffers.assertEmpty();
}
function activatePort(nextPort){
 initialized=true;port=nextPort;__DIAGNOSTIC_BOUNDARY_ACTIVATED__;
 port.onmessage=message=>{
  if(closed)return;
  observeResumeTrigger();
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){__DIAGNOSTIC_HELLO_RECEIVED__;createStarted=true;if(helloTimer)clearTimeout(helloTimer);helloTimer=null;helloFrame=message.data;if(negotiationEnabled){negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch)}createSession(attemptEpoch)}
   else{
    const holdRecovery=recoveryController.active()&&!recoveryReplaced;
    let data;try{data=acceptNativeFrames(message.data,holdRecovery)}catch(error){fail(error&&error.telemtReason==='capacity'?'capacity':'protocol');return}if(!data)return;
    if(holdRecovery){if(!reserve(data,null)){fail('capacity');return}recoveryPending.push(data)}
    else if(!carrierCommitted){if(!reserve(data,null)){fail('capacity');return}pending.push(data);maybeStartCandidate()}
    else queueCarrier(data);
   }
  }else if(message.data&&message.data.t==='close'){__DIAGNOSTIC_CLIENT_CLOSE__;status('failed');close(true)}
 };
 port.start();status('connecting');helloTimer=setTimeout(__HELLO_TIMEOUT_CALLBACK__,bridgeRequestMs);
}
recoveryController=recoverySupport.create({
 budgetMs:()=>bridgeRecoveryMs,requestMs:()=>bridgeRequestMs,url:()=>relayOrigin+recoveryPath,token:()=>cleanupToken||sessionToken,
 read:(response,limit,exact,signal)=>responseBody.read(response,limit,exact,signal),cancel:responseBody.cancel,status:()=>status('reconnecting'),
 restored:finishOldRecovery,replace:replaceCarrier,replaceable:error=>failureReason(error,'network')!=='protocol',
 reason:(error,fallback)=>failureReason(error,fallback),terminal:reason=>fail(recoveryController.remaining()<=0?'timeout':reason)
});
armScheduler();
addEventListener('message',event=>{
 if(event.source!==parent)return;if(initialized){if(event.ports&&event.ports.length===1)event.ports[0].close();return}
 if(event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin)}catch(error){return}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
},{once:false});
function activateAndroid(androidBridge){
 const androidPort={onmessage:null,start(){},close(){androidBridge.onmessage=null},postMessage(value){
  if(value instanceof ArrayBuffer){
   let frames;try{frames=splitFrames(value)}catch(error){fail('protocol');return}
   for(const frame of frames)androidBridge.postMessage(frame.data);
  }else androidBridge.postMessage(JSON.stringify(value));
 }};
 androidBridge.onmessage=event=>{let data=event.data;if(typeof data==='string'){try{data=JSON.parse(data)}catch(error){return}}if(androidPort.onmessage)androidPort.onmessage({data})};
 activatePort(androidPort);androidBridge.postMessage(JSON.stringify({t:'tproxy-android-init',v:1,nonce:androidNonce}));
}
function discoverAndroid(){
 if(!androidNonce)return;const wall=Date.now()+bridgeRequestMs,monotonic=performance.now()+bridgeRequestMs;
 const probe=()=>{
  if(initialized||closed)return;const androidBridge=globalThis.TelegramWebProxy;
  if(androidBridge&&typeof androidBridge.postMessage==='function'){activateAndroid(androidBridge);return}
  const remaining=Math.min(wall-Date.now(),monotonic-performance.now());if(remaining>0)setTimeout(probe,Math.min(100,remaining));
 };probe();
}
discoverAndroid();
addEventListener('online',observeResumeTrigger);
if(globalThis.document&&typeof globalThis.document.addEventListener==='function')globalThis.document.addEventListener('visibilitychange',()=>{if(globalThis.document.visibilityState==='visible')observeResumeTrigger()});
addEventListener('pagehide',__PAGEHIDE_CALLBACK__,{once:true});
})();
