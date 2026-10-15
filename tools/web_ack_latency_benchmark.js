'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

process.argv.push('--benchmark-module');
const {renderedPage,frame,join,flush,session} = require('../src/web/bridge/behavior_tests.js');

// Bridge sources match this published base, so reviewers can run the benchmark without the local parent commit.
const baseline = '9d5b896bb695c55e2905b82f276da84e45a0a2ec';
const bridgeFiles = ['document.html','response.js','request.js','buffers.js','recovery.js','conveyor.js','downlink.js','runtime.js'];
const bridgeDirectory = path.resolve(__dirname,'..','src','web','bridge');
const baselineSources = Object.fromEntries(bridgeFiles.map(file=>[
 file,
 execFileSync('git',['show',baseline+':src/web/bridge/'+file],{cwd:path.resolve(__dirname,'..'),encoding:'utf8'})
]));
const currentSources = Object.fromEntries(bridgeFiles.map(file=>[file,fs.readFileSync(path.join(bridgeDirectory,file),'utf8')]));
const digest = value=>crypto.createHash('sha256').update(value).digest('hex');
const sourceHashes = sources=>Object.fromEntries(bridgeFiles.map(file=>[file,digest(sources[file])]));

function frameTypes(body){
 const bytes=new Uint8Array(body),result=[];
 for(let offset=0;offset<bytes.byteLength;){const view=new DataView(body,offset);result.push({type:bytes[offset],id:(bytes[offset+1]<<16)|(bytes[offset+2]<<8)|bytes[offset+3]});offset+=8+view.getUint32(4)}
 return result;
}

async function measure(page,carrier,rttMs,scenario,android){
 const env=await session(page,carrier,1,android);
 const oneWay=rttMs/2,open=frame(1,1),data=frame(2,1,[9]);
 const dataReadyAt=scenario==='combined'?env.now():null;
 env.send(scenario==='combined'?join(open,data):open);await flush();
 const socket=env.webSockets[0];assert.ok(socket,carrier+' candidate WebSocket');
 let probeSentAt=null,ackAt=null,dataSentAt=null,dataArrivalAt=null,probeSeen=false;
 const send=socket.send.bind(socket);
 socket.send=body=>{
  const copied=body.slice(0),sentAt=env.now(),types=frameTypes(copied);send(body);
  if(probeSentAt===null)probeSentAt=sentAt;
  if(types.some(value=>value.type===2)&&dataSentAt===null)dataSentAt=sentAt;
  env.schedule(()=>{
   socket.bufferedAmount=Math.max(0,socket.bufferedAmount-copied.byteLength);
   if(types.some(value=>value.type===2)&&dataArrivalAt===null)dataArrivalAt=env.now();
   if(!probeSeen){probeSeen=true;env.schedule(()=>{ackAt=env.now();socket.message(new ArrayBuffer(0))},oneWay)}
  },oneWay);
 };
 env.schedule(()=>socket.open(),oneWay);
 await env.tick(oneWay);
 let readyAt=dataReadyAt;
 if(scenario==='delayed'){
  readyAt=env.now()+1;env.schedule(()=>env.send(data),1);await env.tick(1);
 }else if(scenario==='warm'){
  await env.tick(rttMs);
  readyAt=env.now();env.send(data);await flush();
 }
 await env.tick(rttMs*2+20);
 assert.notEqual(dataSentAt,null,carrier+' '+scenario+' DATA was sent');
 assert.notEqual(dataArrivalAt,null,carrier+' '+scenario+' DATA reached the synthetic server');
 const result={carrier,android,rttMs,scenario,dataReadyAtMs:readyAt,probeSentAtMs:probeSentAt,dataSentAtMs:dataSentAt,commitAckAtMs:ackAt,dataServerArrivalAtMs:dataArrivalAt,dataReadyToServerArrivalMs:dataArrivalAt-readyAt};
 env.close();await flush();return result;
}

async function measureBatch(page,carrier,android){
 const env=await session(page,carrier,1,android);env.send(frame(1,1));await flush();const socket=env.webSockets[0];socket.open();
 const batch=join(...Array.from({length:1000},(_,index)=>frame(2,1,[index&255]))),started=process.hrtime.bigint();
 env.send(batch);await flush();const synchronousMs=Number(process.hrtime.bigint()-started)/1e6;
 const sentTypes=socket.sent.flatMap(frameTypes),dataFrames=sentTypes.filter(value=>value.type===2).length;
 const result={carrier,android,scenario:'large-native-batch',frameCount:1000,preAckDataFramesSent:dataFrames,preAckWebSocketMessages:socket.sent.length-1,synchronousQueueProcessingMs:synchronousMs};
 env.close();await flush();return result;
}

async function main(){
 const results=[];
 for(const android of [false,true])for(const rttMs of [20,100,250])for(const carrier of ['websocket','websocket-lanes'])for(const scenario of ['delayed','combined','warm']){
  results.push({source:'baseline',...await measure(renderedPage(baselineSources),carrier,rttMs,scenario,android)});
  results.push({source:'updated',...await measure(renderedPage(currentSources),carrier,rttMs,scenario,android)});
 }
 for(const android of [false,true])for(const carrier of ['websocket','websocket-lanes']){
  results.push({source:'baseline',...await measureBatch(renderedPage(baselineSources),carrier,android)});
  results.push({source:'updated',...await measureBatch(renderedPage(currentSources),carrier,android)});
 }
 const summary=[];
 for(const android of [false,true])for(const rttMs of [20,100,250])for(const carrier of ['websocket','websocket-lanes'])for(const scenario of ['delayed','combined','warm']){
  const old=results.find(value=>value.source==='baseline'&&value.android===android&&value.rttMs===rttMs&&value.carrier===carrier&&value.scenario===scenario);
  const current=results.find(value=>value.source==='updated'&&value.android===android&&value.rttMs===rttMs&&value.carrier===carrier&&value.scenario===scenario);
  summary.push({android,rttMs,carrier,scenario,baselineDataReadyToServerArrivalMs:old.dataReadyToServerArrivalMs,updatedDataReadyToServerArrivalMs:current.dataReadyToServerArrivalMs,improvementMs:old.dataReadyToServerArrivalMs-current.dataReadyToServerArrivalMs});
 }
 const artifact={method:'synthetic browser VM and FIFO WebSocket network; MessagePort and Android bridge message APIs; one-way delay is RTT/2; empty ACK returns after the probe round trip; no ME or Android runtime',baselineCommit:baseline,sourceHashes:{baseline:sourceHashes(baselineSources),updated:sourceHashes(currentSources)},measurements:results,summary};
 const outputs=[path.resolve(__dirname,'..','..','web-ack-20261015','benchmark.json'),path.resolve(__dirname,'..','.ecc','benchmarks','web-ack-20261015.json')];
 for(const output of outputs){fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(artifact,null,2)+'\n')}
 const batches=results.filter(value=>value.scenario==='large-native-batch');
 console.log(JSON.stringify({outputs,summary,batches},null,2));
}

main().catch(error=>{console.error(error.stack||error);process.exitCode=1});
