(()=>{'use strict';
function create(settings){
 // Snapshot policy per page, including during session recovery.
 const jitter=Object.freeze(Object.assign({},settings.jitter||{enabled:false}));
 const randomWord=jitter.enabled?new Uint32Array(1):null;
 function randomUnit(){
  try{if(globalThis.crypto&&typeof globalThis.crypto.getRandomValues==='function'){
   globalThis.crypto.getRandomValues(randomWord);return randomWord[0]/4294967296;
  }}catch(error){}
  return Math.random();
 }
 function jitterMs(){
  const a=jitter.min,b=jitter.max;if(a===b)return a;
  const u=randomUnit();
  if(!jitter.triangular)return a+Math.floor(u*(b-a+1));
  const c=jitter.peak,span=b-a;
  return Math.round(u<(c-a)/span?a+Math.sqrt(u*span*(c-a)):b-Math.sqrt((1-u)*span*(b-c)));
 }
 const pause=(milliseconds,signal)=>new Promise((resolve,reject)=>{
  if(signal&&signal.aborted){reject(new Error('request aborted'));return}
  const timer=setTimeout(done,milliseconds);function done(){if(signal)signal.removeEventListener('abort',abort);resolve()}
  function abort(){clearTimeout(timer);signal.removeEventListener('abort',abort);reject(new Error('request aborted'))}
  if(signal)signal.addEventListener('abort',abort,{once:true});
 });
 const options=(method,token,body,headers,signal,keepalive)=>({
  method,body,signal,keepalive:!!keepalive,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',
  headers:Object.assign(token?{Authorization:'Bearer '+token}:{},body?{'Content-Type':'application/octet-stream'}:{},headers||{})
 });
 function retryAfterMs(response){
  const header=response.headers.get('Retry-After');
  // Only the exact Telemt overload hint overrides its legacy whole-second fallback.
  if(response.status===503&&header==='1'&&response.headers.get('X-Telemt-Retry-After-Ms')==='250')return 250;
  if(!header)return 0;
  // Enabled policies must never shorten a valid server minimum to the legacy 30 s cap.
  if(jitter.enabled&&/^\d+$/.test(header))return Number(header)*1000;
  const seconds=Number(header);
  if(Number.isFinite(seconds)&&seconds>=0)return jitter.enabled?seconds*1000:Math.min(seconds*1000,30000);
  const when=Date.parse(header);
  if(Number.isFinite(when)){const delta=when-Date.now();return delta>0?(jitter.enabled?delta:Math.min(delta,30000)):0;}
  return 0;
 }
 function retryableStatus(status){return status===408||status===429||status===502||status===503||status===504}
 function responsePolicy(path,status){
  if(path==='/api/v1/session'&&status===200)return {limit:8,exact:true,reason:'protocol'};
  if(path==='/api/v1/down'&&status===200)return {limit:settings.batchLimit(),exact:false,reason:'protocol'};
  if(status===204&&(path==='/api/v1/up'||path==='/api/v1/down'))return {limit:0,exact:true,reason:'protocol'};
  return {limit:0,exact:true,reason:'http'};
 }
 async function send(path,frozenOptions,remainingBudget,maxAttempts,receiver){
  let delay=250,attempt=0,lastReason='network';maxAttempts=maxAttempts||9;
  const attempts=()=>typeof maxAttempts==='function'?maxAttempts():maxAttempts;
  const initialBudget=remainingBudget?Math.min(settings.retryMs(),remainingBudget()):settings.retryMs();
  const deadline=Date.now()+Math.max(0,initialBudget),external=frozenOptions.signal;
  const attemptLimit=path==='/api/v1/down'?settings.longPollMs()+settings.requestMs():settings.requestMs();
  while(attempt<attempts()){
   if(settings.closed()||(external&&external.aborted))throw new Error('request aborted');
   const remaining=Math.min(deadline-Date.now(),remainingBudget?remainingBudget():Infinity);if(remaining<=0)break;attempt++;
   const controller=new AbortController(),abort=()=>controller.abort();let timedOut=false;
   if(external)external.addEventListener('abort',abort,{once:true});
   const requestOptions=Object.assign({},frozenOptions,{signal:controller.signal});
   const timer=setTimeout(()=>{timedOut=true;controller.abort()},Math.max(1,Math.min(attemptLimit,remaining)));
   let response=null,wait=0;
   try{
    const fetched=await fetch(settings.base()+path,requestOptions);
    if(retryableStatus(fetched.status)){
     lastReason='http';wait=retryAfterMs(fetched);settings.cancel(fetched);
    }else{
     const policy=responsePolicy(path,fetched.status);let body;
     try{body=receiver&&(fetched.status===200||fetched.status===204)?await receiver(fetched,controller.signal):await settings.read(fetched,policy.limit,policy.exact,controller.signal);}
     catch(error){
      controller.abort();
      if(external&&external.aborted)throw error;
      if(timedOut)throw settings.failure('timeout','response deadline exceeded');
      throw settings.failure(settings.reason(error,policy.reason),error&&error.message);
     }
     response={status:fetched.status,headers:fetched.headers,body};return response;
    }
   }catch(error){
    controller.abort();
    if(settings.closed()||(external&&external.aborted))throw error;
    if(timedOut)lastReason='timeout';
    if(settings.reason(error,'')==='protocol')throw error;
   }finally{clearTimeout(timer);if(external)external.removeEventListener('abort',abort)}
   const after=Math.min(deadline-Date.now(),remainingBudget?remainingBudget():Infinity);if(attempt>=attempts()||after<=0)break;
   settings.retrying();
   const backoff=jitter.enabled?(wait||delay)+jitterMs():wait||delay+Math.floor(Math.random()*Math.max(1,delay/4));
   await pause(Math.min(backoff,after),external);delay=Math.min(delay*2,2000);
  }
  throw settings.failure(lastReason,'carrier retry limit reached');
 }
 return Object.freeze({options,pause,send});
}
globalThis.TelemtBridgeRequest=Object.freeze({create});
})();
