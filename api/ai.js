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
