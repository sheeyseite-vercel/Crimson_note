const U=process.env.UPSTASH_REDIS_REST_URL||process.env.KV_REST_API_URL;
const T=process.env.UPSTASH_REDIS_REST_TOKEN||process.env.KV_REST_API_TOKEN;
module.exports=async function r(...cmd){
  if(!U||!T)throw new Error('database env vars missing');
  const res=await fetch(U,{method:'POST',headers:{Authorization:'Bearer '+T,'Content-Type':'application/json'},body:JSON.stringify(cmd.map(String))});
  const j=await res.json();if(j.error)throw new Error(j.error);return j.result};
