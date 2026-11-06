// Spark AI — secure provider router (Groq / Gemini / OpenRouter) with automatic fallback.
// Keys live ONLY in Vercel env vars: GROQ_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY. They are never sent to the browser.
// Every chat request must carry a valid Firebase ID token (Authorization: Bearer <token>); it is verified here (RS256 vs Google certs).
// Optional env: AI_LIMIT_PER_MIN (default 8), AI_LIMIT_PER_DAY (default 150), AI_MODELS_GROQ / AI_MODELS_GEMINI / AI_MODELS_OPENROUTER (comma lists),
//               FIREBASE_PROJECT_ID (default crimson-notes-8c4d7), plus the existing Upstash/KV vars (used for per-user rate limiting).
const crypto=require('crypto');
let db=null;try{db=require('./_db')}catch(e){}
const PROJECT=process.env.FIREBASE_PROJECT_ID||'crimson-notes-8c4d7';
const list=(k,d)=>(process.env[k]||d).split(',').map(s=>s.trim()).filter(Boolean);
// Free-tier model lists. Free quotas change over time — override with the AI_MODELS_* env vars if a model disappears.
const MODELS={
  groq:list('AI_MODELS_GROQ','llama-3.3-70b-versatile,llama-3.1-8b-instant'),
  gemini:list('AI_MODELS_GEMINI','gemini-2.5-flash,gemini-2.5-flash-lite,gemini-2.0-flash'),
  openrouter:list('AI_MODELS_OPENROUTER','meta-llama/llama-3.3-70b-instruct:free,google/gemma-3-27b-it:free,deepseek/deepseek-chat-v3-0324:free')
};
const KEY={groq:()=>process.env.GROQ_API_KEY,gemini:()=>process.env.GEMINI_API_KEY,openrouter:()=>process.env.OPENROUTER_API_KEY};
const ORDER=['groq','gemini','openrouter'];
const LIM={min:+process.env.AI_LIMIT_PER_MIN||8,day:+process.env.AI_LIMIT_PER_DAY||150};
const MAX_CHARS=70000,MAX_MSGS=40,MAX_OUT=2048;

/* ---------- Firebase ID-token verification (no dependencies) ---------- */
let certs=null,certsExp=0;
async function getCerts(){
  if(certs&&Date.now()<certsExp)return certs;
  const r=await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
  if(!r.ok)throw new Error('certs');
  const m=/max-age=(\d+)/.exec(r.headers.get('cache-control')||'');
  certs=await r.json();certsExp=Date.now()+(m?+m[1]:3600)*1000;return certs}
async function verify(tok){
  const p=String(tok||'').split('.');if(p.length!==3)throw new Error('auth');
  const h=JSON.parse(Buffer.from(p[0],'base64url').toString()),c=JSON.parse(Buffer.from(p[1],'base64url').toString());
  if(h.alg!=='RS256')throw new Error('auth');
  const pem=(await getCerts())[h.kid];if(!pem)throw new Error('auth');
  const ok=crypto.createVerify('RSA-SHA256').update(p[0]+'.'+p[1]).verify(pem,p[2],'base64url');
  const now=Math.floor(Date.now()/1000);
  if(!ok||c.aud!==PROJECT||c.iss!=='https://securetoken.google.com/'+PROJECT||!c.sub||c.exp<now||c.iat>now+300)throw new Error('auth');
  return c.sub}

/* ---------- per-user rate limit (Upstash if configured, else in-memory) ---------- */
const mem=new Map();
async function hit(uid){
  const m=Math.floor(Date.now()/60000),d=Math.floor(Date.now()/86400000);
  try{
    if(!db)throw 0;
    const a=await db('INCR','ai:m:'+uid+':'+m);if(a===1)await db('EXPIRE','ai:m:'+uid+':'+m,90);
    const b=await db('INCR','ai:d:'+uid+':'+d);if(b===1)await db('EXPIRE','ai:d:'+uid+':'+d,90000);
    if(a>LIM.min)return 'min';if(b>LIM.day)return 'day';return null
  }catch(e){
    const k1=uid+':'+m,k2=uid+':d'+d;mem.set(k1,(mem.get(k1)||0)+1);mem.set(k2,(mem.get(k2)||0)+1);
    if(mem.size>5000)mem.clear();
    if(mem.get(k1)>LIM.min)return 'min';if(mem.get(k2)>LIM.day)return 'day';return null}}

/* ---------- provider adapters ---------- */
class PErr extends Error{constructor(kind,msg,retryAfter){super(msg);this.kind=kind;this.retryAfter=retryAfter}}
// kinds: rate | quota | key | network | model | outage | context | bad
function classify(status,body){
  const s=(typeof body==='string'?body:JSON.stringify(body||'')).toLowerCase();
  if(status===401||status===403||/api key|invalid_api_key|permission_denied|unauthenticated/.test(s))return 'key';
  if(status===429||/rate.?limit|resource_exhausted|quota/.test(s))return /per day|daily|tokens per day|quota/.test(s)&&!/per minute/.test(s)?'quota':'rate';
  if(status===404||/model.*(not found|not supported|does not exist|decommission)|no endpoints found/.test(s))return 'model';
  if(status===413||/context|too long|too large|maximum.*tokens|reduce the length/.test(s))return 'context';
  if(status===400)return 'bad';
  if(status>=500)return 'outage';
  return 'outage'}
async function call(url,init,timeout){
  const ac=new AbortController(),tm=setTimeout(()=>ac.abort(),timeout||25000);
  try{const r=await fetch(url,{...init,signal:ac.signal});const txt=await r.text();let j;try{j=JSON.parse(txt)}catch(e){j=txt}
    if(!r.ok)throw new PErr(classify(r.status,j),'http '+r.status,+(r.headers.get('retry-after')||0)||0);return j}
  catch(e){if(e instanceof PErr)throw e;throw new PErr('network',e&&e.name==='AbortError'?'timeout':'network')}finally{clearTimeout(tm)}}
const oa=(base,extra)=>async(model,msgs,o)=>{
  const k=o.key;const j=await call(base,{method:'POST',headers:{Authorization:'Bearer '+k,'Content-Type':'application/json',...(extra||{})},body:JSON.stringify({model,messages:msgs,temperature:o.temperature,max_tokens:o.maxTokens})});
  const c=j.choices&&j.choices[0];const text=c&&c.message&&c.message.content;
  if(!text)throw new PErr('outage','empty');
  return{text:String(text),usage:j.usage?{in:j.usage.prompt_tokens||0,out:j.usage.completion_tokens||0}:null}};
const ADAPT={
  groq:oa('https://api.groq.com/openai/v1/chat/completions'),
  openrouter:oa('https://openrouter.ai/api/v1/chat/completions',{'X-Title':'Spark Notes'}),
  gemini:async(model,msgs,o)=>{
    const sys=msgs.filter(m=>m.role==='system').map(m=>m.content).join('\n\n');
    const contents=msgs.filter(m=>m.role!=='system').map(m=>({role:m.role==='assistant'?'model':'user',parts:[{text:m.content}]}));
    const body={contents,generationConfig:{temperature:o.temperature,maxOutputTokens:o.maxTokens}};if(sys)body.systemInstruction={parts:[{text:sys}]};
    const j=await call('https://generativelanguage.googleapis.com/v1beta/models/'+encodeURIComponent(model)+':generateContent',{method:'POST',headers:{'x-goog-api-key':o.key,'Content-Type':'application/json'},body:JSON.stringify(body)});
    const c=j.candidates&&j.candidates[0];const text=c&&c.content&&(c.content.parts||[]).map(p=>p.text||'').join('');
    if(!text){if(j.promptFeedback&&j.promptFeedback.blockReason)throw new PErr('bad','blocked');throw new PErr('outage','empty')}
    const u=j.usageMetadata;return{text,usage:u?{in:u.promptTokenCount||0,out:u.candidatesTokenCount||0}:null}}
};

/* ---------- health tracking (per warm instance) ---------- */
const down={}; // "provider" or "provider/model" -> until(ms)
const isDown=k=>(down[k]||0)>Date.now();
const mark=(k,ms)=>{down[k]=Date.now()+ms};

function plan(provider,model,strict){
  const out=[];const configured=ORDER.filter(p=>KEY[p]());
  const first=provider&&provider!=='auto'&&KEY[provider]&&KEY[provider]()?provider:null;
  const order=first?(strict?[first]:[first,...configured.filter(p=>p!==first)]):configured;
  for(const p of order){
    const ms=(first===p&&model&&MODELS[p].includes(model))?[model,...MODELS[p].filter(m=>m!==model)]:MODELS[p];
    for(const m of ms)out.push([p,m])}
  return out}

async function run(b){
  const msgs=b.msgs;const tried=[];const cand=plan(b.provider,b.model,b.strict);
  if(!cand.length)return{err:'none',tried};
  let last=null,attempts=0;
  for(const [p,m] of cand){
    if(isDown(p)||isDown(p+'/'+m)){tried.push({p,m,e:'skipped'});continue}
    if(attempts>=5)break; // never loop forever
    attempts++;
    try{
      const r=await ADAPT[p](m,msgs,{key:KEY[p](),temperature:b.temperature,maxTokens:b.maxTokens});
      return{ok:true,text:r.text,usage:r.usage,provider:p,model:m,tried}
    }catch(e){
      const k=e.kind||'outage';last=k;tried.push({p,m,e:k});
      if(k==='key')mark(p,3600e3);else if(k==='quota')mark(p,3600e3);else if(k==='rate')mark(p+'/'+m,Math.min(120e3,Math.max(15e3,(e.retryAfter||20)*1000)));
      else if(k==='outage'||k==='network')mark(p+'/'+m,30e3);else if(k==='model')mark(p+'/'+m,6*3600e3);
      if(k==='context'||k==='bad')continue; // another provider may accept it
      if(attempts<cand.length)await new Promise(r=>setTimeout(r,Math.min(1500,200*2**attempts))) // small exponential backoff
    }}
  return{err:last||'outage',tried}}

function clean(msgs,sys){
  if(!Array.isArray(msgs)||!msgs.length||msgs.length>MAX_MSGS)return null;
  let n=0;const out=[];
  if(sys){const s=String(sys).slice(0,30000);n+=s.length;out.push({role:'system',content:s})}
  for(const m of msgs){if(!m||typeof m.content!=='string'||!['user','assistant'].includes(m.role))return null;n+=m.content.length;out.push({role:m.role,content:m.content})}
  if(n>MAX_CHARS)return 'big';
  if(out[out.length-1].role!=='user')return null;
  return out}

module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  const status=()=>({providers:ORDER.map(p=>({id:p,configured:!!KEY[p](),models:MODELS[p],cooling:isDown(p)})),limits:LIM});
  if(req.method==='GET')return res.status(200).json(status());
  if(req.method!=='POST')return res.status(405).end();
  try{
    const b=typeof req.body==='string'?JSON.parse(req.body):(req.body||{});
    const tok=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
    let uid;try{uid=await verify(tok)}catch(e){return res.status(401).json({error:'auth'})}
    if(b.action==='status')return res.status(200).json(status());
    if(!ORDER.some(p=>KEY[p]()))return res.status(501).json({error:'not_configured'});
    const msgs=clean(b.messages,b.system);
    if(msgs==='big')return res.status(413).json({error:'context'});
    if(!msgs)return res.status(400).json({error:'bad_request'});
    const lim=await hit(uid);
    if(lim)return res.status(429).json({error:'limit_'+lim});
    const r=await run({msgs,provider:String(b.provider||'auto'),model:String(b.model||''),strict:!!b.strict,
      temperature:Math.min(1.2,Math.max(0,+b.temperature>=0?+b.temperature:.5)),maxTokens:Math.min(MAX_OUT,Math.max(64,+b.maxTokens||1200))});
    if(r.ok)return res.status(200).json({text:r.text,provider:r.provider,model:r.model,usage:r.usage,tried:r.tried});
    const map={key:'all_keys',quota:'all_quota',rate:'all_rate',network:'all_down',outage:'all_down',model:'all_down',context:'context',bad:'bad_request',none:'not_configured'};
    return res.status(503).json({error:map[r.err]||'all_down',tried:r.tried})
  }catch(e){return res.status(500).json({error:'server'})}}; // never leak internals
