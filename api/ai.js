// Spark AI — secure provider router (Groq / Gemini / SambaNova / SiliconFlow / OpenCode / OpenRouter / GitHub Models / NVIDIA / Hugging Face / Ollama) with automatic fallback.
// Keys live ONLY in Vercel env vars: GROQ_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY, SAMBANOVA_API_KEY, SILICONFLOW_API_KEY, OPENCODE_API_KEY, GITHUB_MODELS_TOKEN, NVIDIA_API_KEY, HF_TOKEN, OLLAMA_API_KEY (optional base overrides: SILICONFLOW_BASE, OPENCODE_BASE, OLLAMA_BASE). They are never sent to the browser.
// Every chat request must carry a valid Firebase ID token (Authorization: Bearer <token>); it is verified here (RS256 vs Google certs).
// Optional env: AI_LIMIT_PER_MIN (default 8), AI_LIMIT_PER_DAY (default 150), AI_MODELS_GROQ / AI_MODELS_GEMINI / AI_MODELS_<PROVIDER> (comma lists),
//               FIREBASE_PROJECT_ID (default crimson-notes-8c4d7), plus the existing Upstash/KV vars (used for per-user rate limiting).
const crypto=require('crypto');
let db=null;try{db=require('./_db')}catch(e){}
const PROJECT=process.env.FIREBASE_PROJECT_ID||'crimson-notes-8c4d7';
const list=(k,d)=>(process.env[k]||d).split(',').map(s=>s.trim()).filter(Boolean);
// Free-tier model lists. Free quotas change over time — override with the AI_MODELS_* env vars if a model disappears.
const MODELS={
  groq:list('AI_MODELS_GROQ','openai/gpt-oss-120b,llama-3.3-70b-versatile,llama-3.1-8b-instant'),
  gemini:list('AI_MODELS_GEMINI','gemini-3.8-flash,gemini-3.5-flash-lite,gemini-3.6-flash'),
  openrouter:list('AI_MODELS_OPENROUTER','meta-llama/llama-3.3-70b-instruct:free,google/gemma-3-27b-it:free,deepseek/deepseek-chat-v3-0324:free'),
  sambanova:list('AI_MODELS_SAMBANOVA','Meta-Llama-3.3-70B-Instruct,Meta-Llama-3.1-8B-Instruct,DeepSeek-V3.1'),
  siliconflow:list('AI_MODELS_SILICONFLOW','Qwen/Qwen3-8B,THUDM/glm-4-9b-chat,deepseek-ai/DeepSeek-R1-Distill-Qwen-7B'),
  opencode:list('AI_MODELS_OPENCODE','big-pickle,glm-5.3-flash-free,deepseek-v4.1-flash-free'),
  github:list('AI_MODELS_GITHUB','openai/gpt-4.1-mini,openai/gpt-4o-mini,meta/Llama-3.3-70B-Instruct'),
  nvidia:list('AI_MODELS_NVIDIA','meta/llama-3.3-70b-instruct,meta/llama-3.1-70b-instruct,mistralai/mistral-small-24b-instruct'),
  huggingface:list('AI_MODELS_HUGGINGFACE','meta-llama/Llama-3.3-70B-Instruct,Qwen/Qwen2.5-72B-Instruct,openai/gpt-oss-120b'),
  ollama:list('AI_MODELS_OLLAMA','gpt-oss:120b,gpt-oss:20b'),
  anyapi:list('AI_MODELS_ANYAPI','gemma-3n,qwen3-27b')
};
const KEY={groq:()=>process.env.GROQ_API_KEY,gemini:()=>process.env.GEMINI_API_KEY,openrouter:()=>process.env.OPENROUTER_API_KEY,
  sambanova:()=>process.env.SAMBANOVA_API_KEY,siliconflow:()=>process.env.SILICONFLOW_API_KEY,opencode:()=>process.env.OPENCODE_API_KEY,github:()=>process.env.GITHUB_MODELS_TOKEN||process.env.GITHUB_TOKEN,
  nvidia:()=>process.env.NVIDIA_API_KEY,huggingface:()=>process.env.HF_TOKEN||process.env.HUGGINGFACE_API_KEY,ollama:()=>process.env.OLLAMA_API_KEY,anyapi:()=>process.env.ANYAPI_API_KEY};
const ORDER=['groq','gemini','sambanova','siliconflow','opencode','openrouter','github','nvidia','huggingface','ollama','anyapi'];
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
class PErr extends Error{constructor(kind,msg,retryAfter,status,detail){super(msg);this.kind=kind;this.retryAfter=retryAfter;this.status=status;this.detail=detail}}
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
    if(!r.ok){const dm=typeof j==='string'?j:(j&&j.error&&(j.error.message||(typeof j.error==='string'?j.error:'')))||(j&&j.message)||'';throw new PErr(classify(r.status,j),'http '+r.status,+(r.headers.get('retry-after')||0)||0,r.status,String(dm).replace(/\s+/g,' ').slice(0,140))}return j}
  catch(e){if(e instanceof PErr)throw e;throw new PErr('network',e&&e.name==='AbortError'?'timeout':'network')}finally{clearTimeout(tm)}}
const oaMsg=m=>m.images&&m.images.length?{role:m.role,content:[{type:'text',text:m.content},...m.images.map(u=>({type:'image_url',image_url:{url:u}}))]}:{role:m.role,content:m.content};
const oa=(base,extra)=>async(model,msgs,o)=>{
  const k=o.key;const j=await call(typeof base==='function'?base():base,{method:'POST',headers:{Authorization:'Bearer '+k,'Content-Type':'application/json',...(extra||{})},body:JSON.stringify({model,messages:msgs.map(oaMsg),temperature:o.temperature,max_tokens:o.maxTokens})});
  const c=j.choices&&j.choices[0];const text=c&&c.message&&c.message.content;
  if(!text)throw new PErr('outage','empty');
  return{text:String(text),usage:j.usage?{in:j.usage.prompt_tokens||0,out:j.usage.completion_tokens||0}:null}};
const ADAPT={
  groq:oa('https://api.groq.com/openai/v1/chat/completions'),
  openrouter:oa('https://openrouter.ai/api/v1/chat/completions',{'X-Title':'Spark Notes'}),
  sambanova:oa('https://api.sambanova.ai/v1/chat/completions'),
  siliconflow:oa(()=>(process.env.SILICONFLOW_BASE||'https://api.siliconflow.com/v1')+'/chat/completions'),
  opencode:oa(()=>(process.env.OPENCODE_BASE||'https://opencode.ai/inference/openai/v1')+'/chat/completions'),
  github:oa('https://models.github.ai/inference/chat/completions',{Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'}),
  nvidia:oa('https://integrate.api.nvidia.com/v1/chat/completions'),
  huggingface:oa('https://router.huggingface.co/v1/chat/completions'),
  anyapi:oa(()=>(process.env.ANYAPI_BASE||'https://api.anyapi.ai/v1')+'/chat/completions'),
  ollama:oa(()=>(process.env.OLLAMA_BASE||'https://ollama.com/v1')+'/chat/completions'),
  gemini:async(model,msgs,o)=>{
    const sys=msgs.filter(m=>m.role==='system').map(m=>m.content).join('\n\n');
    const contents=msgs.filter(m=>m.role!=='system').map(m=>({role:m.role==='assistant'?'model':'user',parts:[{text:m.content},...(m.images||[]).map(u=>{const x=/^data:(image\/[a-z]+);base64,(.+)$/.exec(u);return{inlineData:{mimeType:x[1],data:x[2]}}})]}));
    const body={contents,generationConfig:{temperature:o.temperature,maxOutputTokens:o.maxTokens}};if(sys)body.systemInstruction={parts:[{text:sys}]};
    const j=await call('https://generativelanguage.googleapis.com/v1beta/models/'+encodeURIComponent(model)+':generateContent',{method:'POST',headers:{'x-goog-api-key':o.key,'Content-Type':'application/json'},body:JSON.stringify(body)});
    const c=j.candidates&&j.candidates[0];const text=c&&c.content&&(c.content.parts||[]).map(p=>p.text||'').join('');
    if(!text){if(j.promptFeedback&&j.promptFeedback.blockReason)throw new PErr('bad','blocked');throw new PErr('outage','empty')}
    const u=j.usageMetadata;return{text,usage:u?{in:u.promptTokenCount||0,out:u.candidatesTokenCount||0}:null}}
};


/* ---------- model discovery: ask each provider which models this key can actually use (free-tier lists change often) ---------- */
const PREF={
  groq:[/gpt-oss-120b/,/llama-3\.3-70b/,/70b/,/qwen/,/gpt-oss-20b/,/llama/,/./],
  gemini:[/^gemini-3\.8-flash$/,/^gemini-3\.6-flash$/,/^gemini-3\.5-flash-lite/,/^gemini-3\.1-flash-lite/,/flash(?!.*lite)/,/lite/,/./],
  openrouter:[/llama.*70b/,/gpt-oss/,/deepseek/,/gemma.*27b/,/qwen/,/./],
  sambanova:[/llama-3\.3-70b/i,/70b/i,/deepseek-v3/i,/llama/i,/./],
  github:[/gpt-4\.1-mini/,/gpt-4o-mini/,/llama-3\.3-70b/i,/gpt-4\.1$/,/gpt-4o$/,/./],
  nvidia:[/llama-3\.3-70b/,/llama-3\.1-70b/,/mistral-small/,/70b/,/./],
  anyapi:[/free/i,/gemma/i,/qwen/i,/flash/i,/./],
  huggingface:[/llama-3\.3-70b/i,/gpt-oss-120b/i,/qwen.*72b/i,/./]};
const SKIP=/whisper|tts|guard|orpheus|embed|playai|safeguard|image|imagen|veo|audio|live|robotics|aqa|vision-preview|moderation/i;
function rank(p,ids){const pr=PREF[p];const sc=id=>{const i=pr.findIndex(r=>r.test(id));return i<0?99:i};return ids.filter(i=>!SKIP.test(i)).sort((x,y)=>sc(x)-sc(y)||(y>x?1:-1))}
const disco={};
async function discover(p){
  if(process.env['AI_MODELS_'+p.toUpperCase()])return MODELS[p]; // explicit override wins
  const c=disco[p];if(c&&Date.now()<c.exp)return c.ids;
  let ids=null;
  try{
    if(p==='groq'){const j=await call('https://api.groq.com/openai/v1/models',{headers:{Authorization:'Bearer '+KEY.groq()}},6000);ids=(j.data||[]).map(m=>m.id)}
    else if(p==='gemini'){const j=await call('https://generativelanguage.googleapis.com/v1beta/models?pageSize=200',{headers:{'x-goog-api-key':KEY.gemini()}},6000);ids=(j.models||[]).filter(m=>(m.supportedGenerationMethods||[]).includes('generateContent')).map(m=>String(m.name).replace(/^models\//,''))}
    else if(p==='sambanova'||p==='nvidia'||p==='anyapi'){const u={anyapi:(process.env.ANYAPI_BASE||'https://api.anyapi.ai/v1')+'/models',sambanova:'https://api.sambanova.ai/v1/models',nvidia:'https://integrate.api.nvidia.com/v1/models'}[p];const j=await call(u,{headers:{Authorization:'Bearer '+KEY[p]()}},6000);ids=(j.data||[]).map(m=>m.id);if(p==='nvidia')ids=ids.filter(i=>/instruct|chat|nemotron/i.test(i)&&!/vision|embed|reward|guard|safety|code|math|parse/i.test(i))}
    else if(p==='github'){const j=await call('https://models.github.ai/catalog/models',{headers:{Authorization:'Bearer '+KEY.github(),Accept:'application/vnd.github+json'}},6000);ids=(Array.isArray(j)?j:[]).filter(m=>(m.supported_output_modalities||['text']).includes('text')&&!/embed/i.test(m.id)&&!/o1|o3|o4|deepseek-r1|grok-3/i.test(m.id.split('/').pop())).map(m=>m.id)}
    else if(p==='openrouter'){const j=await call('https://openrouter.ai/api/v1/models',{},6000);ids=(j.data||[]).map(m=>m.id).filter(i=>/:free$/.test(i))}
  }catch(e){ids=null}
  let out=ids&&ids.length?rank(p,ids).slice(0,3):null;
  // always keep configured defaults as a last resort if discovery returned something unusable
  if(!out||!out.length)out=MODELS[p];
  disco[p]={ids:out,all:ids||[],exp:Date.now()+(ids?30*60e3:2*60e3)};return out}
/* models that can read images */
const VIS={groq:/llama-4|scout|maverick|vision|llava/i,gemini:/gemini|gemma-3/i,sambanova:/llama-4|maverick|vision|e5-/i,siliconflow:/vl|vision/i,opencode:/vl|vision/i,github:/gpt-4o|gpt-4\.1|llama-3\.2.*vision|llama-4|phi-4-multimodal/i,nvidia:/vision|vl|llama-3\.2.*(11|90)b|llama-4|pixtral/i,huggingface:/vl|vision|llama-4/i,ollama:/vl|vision|gemma3|kimi/i,anyapi:/vl|vision|gemma|gpt-4o/i,openrouter:/vl|vision|gemma-3|gemma3|llama-4|pixtral|gemini|mistral-small-3/i};
async function visionModels(p){await discover(p);const c=disco[p]||{};const all=(c.all&&c.all.length?c.all:MODELS[p]).filter(i=>VIS[p].test(i)&&!/embed|tts|whisper|guard|image-gen|imagen/i.test(i));return all.sort((x,y)=>(y>x?1:-1)).slice(0,3)}

/* ---------- health tracking (per warm instance) ---------- */
const down={}; // "provider" or "provider/model" -> until(ms)
const isDown=k=>(down[k]||0)>Date.now();
const mark=(k,ms)=>{down[k]=Date.now()+ms};

async function plan(provider,model,strict,vision){
  const out=[];const configured=ORDER.filter(p=>KEY[p]());const M={};await Promise.all(configured.map(async p=>{M[p]=vision?await visionModels(p):await discover(p)}));
  const first=provider&&provider!=='auto'&&KEY[provider]&&KEY[provider]()?provider:null;
  const order=first?(strict?[first]:[first,...configured.filter(p=>p!==first)]):configured;
  for(const p of order){
    const ms=(first===p&&model&&M[p].includes(model))?[model,...M[p].filter(m=>m!==model)]:M[p];
    for(const m of (ms||[]))out.push([p,m])}
  return out}

async function run(b){
  const msgs=b.msgs;const tried=[];const cand=await plan(b.provider,b.model,b.strict,!!b.vision);
  if(!cand.length)return{err:b.vision?'novision':'none',tried};
  let last=null,attempts=0;
  for(const [p,m] of cand){
    if(isDown(p)||isDown(p+'/'+m)){tried.push({p,m,e:'skipped'});continue}
    if(attempts>=8)break; // never loop forever
    attempts++;
    try{
      const r=await ADAPT[p](m,msgs,{key:KEY[p](),temperature:b.temperature,maxTokens:b.maxTokens});
      return{ok:true,text:r.text,usage:r.usage,provider:p,model:m,tried}
    }catch(e){
      const k=e.kind||'outage';last=k;tried.push({p,m,e:k,s:e.status||0,d:e.detail||e.message||''});
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
  for(const m of msgs){if(!m||typeof m.content!=='string'||!['user','assistant'].includes(m.role))return null;n+=m.content.length;const o={role:m.role,content:m.content};
    if(Array.isArray(m.images)&&m.images.length){if(m!==msgs[msgs.length-1]||m.images.length>2)return null;for(const u of m.images)if(typeof u!=='string'||u.length>900000||!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(u))return null;o.images=m.images}
    out.push(o)}
  if(n>MAX_CHARS)return 'big';
  if(out[out.length-1].role!=='user')return null;
  return out}

module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  const status=async()=>({providers:await Promise.all(ORDER.map(async p=>({id:p,configured:!!KEY[p](),models:KEY[p]()?await discover(p):MODELS[p],cooling:isDown(p)}))),limits:LIM});
  if(req.method==='GET')return res.status(200).json(await status());
  if(req.method!=='POST')return res.status(405).end();
  try{
    const b=typeof req.body==='string'?JSON.parse(req.body):(req.body||{});
    const tok=(req.headers.authorization||'').replace(/^Bearer\s+/i,'');
    let uid;try{uid=await verify(tok)}catch(e){return res.status(401).json({error:'auth'})}
    if(b.action==='status')return res.status(200).json(await status());
    if(b.action==='stt'){ // voice → text (Groq Whisper)
      if(!KEY.groq())return res.status(501).json({error:'not_configured'});
      const buf=Buffer.from(String(b.audio||''),'base64');if(buf.length<1500)return res.status(400).json({error:'empty'});if(buf.length>3300000)return res.status(413).json({error:'big'});
      const lim=await hit(uid);if(lim)return res.status(429).json({error:'limit_'+lim});
      const mime=/^audio\/[\w.+-]+/.test(String(b.mime||''))?String(b.mime).split(';')[0]:'audio/webm';const ext=mime.includes('mp4')?'m4a':mime.includes('ogg')?'ogg':'webm';
      let last='';
      for(const model of ['whisper-large-v3','whisper-large-v3-turbo']){
        try{
          const fd=new FormData();fd.append('file',new Blob([buf],{type:mime}),'a.'+ext);fd.append('model',model);fd.append('temperature','0');fd.append('response_format',b.verbose?'verbose_json':'json');if(b.verbose)fd.append('timestamp_granularities[]','segment');
          if(/^(ar|en|fr|es|de)$/.test(String(b.lang||'')))fd.append('language',String(b.lang));if(b.prompt)fd.append('prompt',String(b.prompt).slice(0,200));
          const r=await fetch('https://api.groq.com/openai/v1/audio/transcriptions',{method:'POST',headers:{Authorization:'Bearer '+KEY.groq()},body:fd});
          const j=await r.json().catch(()=>({}));
          if(r.ok)return res.status(200).json({text:String(j.text||'').trim(),model,segs:b.verbose&&Array.isArray(j.segments)?j.segments.map(x=>({s:+x.start||0,e:+x.end||0,t:String(x.text||'').trim()})).filter(x=>x.t):undefined});
          last=r.status===429?'rate':'fail';if(r.status===401||r.status===403)last='key'
        }catch(e){last='network'}
      }
      return res.status(503).json({error:'stt_'+last})}
    if(!ORDER.some(p=>KEY[p]()))return res.status(501).json({error:'not_configured'});
    const msgs=clean(b.messages,b.system);
    if(msgs==='big')return res.status(413).json({error:'context'});
    if(!msgs)return res.status(400).json({error:'bad_request'});
    const lim=await hit(uid);
    if(lim)return res.status(429).json({error:'limit_'+lim});
    const r=await run({msgs,vision:msgs.some(m=>m.images),provider:String(b.provider||'auto'),model:String(b.model||''),strict:!!b.strict,
      temperature:Math.min(1.2,Math.max(0,+b.temperature>=0?+b.temperature:.5)),maxTokens:Math.min(MAX_OUT,Math.max(64,+b.maxTokens||1200))});
    if(r.ok)return res.status(200).json({text:r.text,provider:r.provider,model:r.model,usage:r.usage,tried:r.tried});
    const map={key:'all_keys',quota:'all_quota',rate:'all_rate',network:'all_down',outage:'all_down',model:'all_down',context:'context',bad:'bad_request',none:'not_configured',novision:'no_vision'};
    return res.status(503).json({error:map[r.err]||'all_down',tried:r.tried})
  }catch(e){return res.status(500).json({error:'server'})}}; // never leak internals
