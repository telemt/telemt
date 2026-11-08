'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'request.js'),'utf8');
const flush=async()=>{for(let i=0;i<20;i++)await Promise.resolve()};
function harness(policy,unit=0.5,cryptoMode='ok',budget=90000){
 let now=0,next=1,calls=0,draws=0;const timers=new Map();
 const context={Uint32Array,AbortController,Date:class extends Date{static now(){return now}},
  Math:Object.assign(Object.create(Math),{random:()=>unit}),
  setTimeout:(fn,ms)=>{const id=next++;timers.set(id,{fn,ms});return id},clearTimeout:id=>timers.delete(id),
  fetch:async()=>{calls++;return {status:503,headers:new Headers({'Retry-After':'1','X-Telemt-Retry-After-Ms':'250'})}}
 };
 if(cryptoMode!=='absent')context.crypto={getRandomValues(word){draws++;if(cryptoMode==='throw')throw Error('unavailable');word[0]=Math.floor(unit*4294967296);return word}};
 vm.createContext(context);vm.runInContext(source,context);
 const settings={jitter:policy,base:()=>'',closed:()=>false,retryMs:()=>budget,longPollMs:()=>0,requestMs:()=>10000,
  batchLimit:()=>8,cancel(){},retrying(){},failure:(_,message)=>new Error(message),reason:()=>'',read:async()=>new ArrayBuffer(0)};
 const client=context.TelemtBridgeRequest.create(settings);
 return {context,timers,client,get calls(){return calls},get draws(){return draws},
  async sample(status=503,headers={'Retry-After':'1','X-Telemt-Retry-After-Ms':'250'}){
   context.fetch=async()=>{calls++;if(status===0)throw Error('network');return {status,headers:new Headers(headers)}};
   const controller=new AbortController();const promise=client.send('/api/v1/up',{signal:controller.signal},null).catch(()=>{});
   await flush();const timer=[...timers.values()][0];assert.ok(timer);const delay=timer.ms;
   controller.abort();await promise;assert.equal(timers.size,0);return delay;
  },async expire(){const item=[...timers.entries()][0];assert.ok(item);timers.delete(item[0]);now+=item[1].ms;item[1].fn();await flush()}
 };
}
module.exports=async()=>{
 const config={enabled:true,min:0,max:250,peak:125,triangular:false};
 for(const mode of ['ok','absent','throw']){
  const h=harness(config,0.5,mode);assert.equal(await h.sample(),375);
 }
 for(const triangular of [false,true]){
  for(const peak of [0,25,100]){
   let sum=0;
   for(let i=0;i<256;i++){
    const h=harness({...config,min:0,max:100,peak,triangular},(i+0.5)/256);
    const value=await h.sample()-250;assert.ok(value>=0&&value<=100);sum+=value;
   }
   assert.ok(Math.abs(sum/256-(triangular?(100+peak)/3:50))<1);
  }
 }
 for(const u of [0,0.25,0.5,0.75,1-1/4294967296]){
  const h=harness({...config,min:0,max:100,peak:50,triangular:true},u);
  const expected=[0,35,50,65,100][[0,0.25,0.5,0.75,1-1/4294967296].indexOf(u)];
  assert.equal(await h.sample()-250,expected);
 }
 const frozen={...config,min:100,max:100};const h=harness(frozen);frozen.min=0;frozen.max=0;
 assert.equal(await h.sample(),350);assert.equal(h.draws,0);
 for(const status of [0,408,429,502,503,504])assert.equal(await h.sample(status,{}),350);
 assert.equal(await h.sample(429,{'Retry-After':'2'}),2100);
 assert.equal(await h.sample(503,{'Retry-After':'40'}),40100);
 assert.equal(await h.sample(503,{'Retry-After':new Date(40000).toUTCString()}),40100);
 assert.equal(await h.sample(503,{'Retry-After':'bad'}),350);
 // Budget exhaustion must not turn a long minimum into an early retry.
 const bounded=harness(config,0.5,'ok',1000);
 bounded.context.fetch=async()=>({status:503,headers:new Headers({'Retry-After':'99999999999999999999999999999999999999999'})});
 const pending=bounded.client.send('/api/v1/up',{},null).then(()=>assert.fail('unexpected success'),()=>{});
 await flush();await bounded.expire();await pending;assert.equal(bounded.timers.size,0);
 // A new draw is made per retry while the exponential base and attempt cap remain.
 const retries=harness(config,0.5);let attempts=0;
 retries.context.fetch=async()=>{attempts++;throw Error('network')};
 const failed=retries.client.send('/api/v1/up',{},null).catch(()=>{});await flush();
 for(const delay of [375,625,1125,2125,2125,2125,2125,2125]){
  assert.equal([...retries.timers.values()][0].ms,delay);await retries.expire();
 }
 await failed;assert.equal(attempts,9);assert.equal(retries.draws,8);assert.equal(retries.timers.size,0);
 // Successful responses do not draw entropy or wait for jitter.
 const success=harness(config);success.context.fetch=async()=>({status:204,headers:new Headers()});
 await success.client.send('/api/v1/up',{},null);assert.equal(success.draws,0);assert.equal(success.timers.size,0);
};
