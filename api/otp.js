// Password-reset OTP: sends a 6-digit code by email (Gmail SMTP) and sets the new password via Firebase (Identity Toolkit REST).
// Env vars: GMAIL_USER, GMAIL_APP_PASSWORD, FIREBASE_SERVICE_ACCOUNT (full JSON), + the existing Upstash/KV vars.
const r=require('./_db');const crypto=require('crypto');
const SA=()=>{try{return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT||'')}catch(e){return null}};
const b64=o=>Buffer.from(typeof o==='string'?o:JSON.stringify(o)).toString('base64url');
async function token(sa){
  const now=Math.floor(Date.now()/1000);
  const un=b64({alg:'RS256',typ:'JWT'})+'.'+b64({iss:sa.client_email,scope:'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/cloud-platform',aud:'https://oauth2.googleapis.com/token',iat:now,exp:now+3000});
  const sig=crypto.createSign('RSA-SHA256').update(un).sign(sa.private_key,'base64url');
  const res=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'grant_type='+encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')+'&assertion='+un+'.'+sig});
  const j=await res.json();if(!j.access_token)throw new Error('token');return j.access_token}
async function itk(sa,tk,path,body){
  const res=await fetch('https://identitytoolkit.googleapis.com/v1/projects/'+sa.project_id+'/'+path,{method:'POST',headers:{Authorization:'Bearer '+tk,'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j=await res.json();if(!res.ok)throw new Error((j.error&&j.error.message)||'itk');return j}
const hash=(e,c)=>crypto.createHmac('sha256',(process.env.OTP_SECRET||(SA()||{}).private_key_id||'spark')).update(e+':'+c).digest('hex');
async function mail(to,code,lang){
  const nm=require('nodemailer');
  const t=nm.createTransport({service:'gmail',auth:{user:process.env.GMAIL_USER,pass:process.env.GMAIL_APP_PASSWORD}});
  const ar=lang!=='en';
  const html=`<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;border:1px solid #eee;border-radius:16px;text-align:center;direction:${ar?'rtl':'ltr'}"><h2 style="margin:0 0 8px;color:#2a1500">Spark</h2><p style="color:#555">${ar?'رمز استعادة كلمة المرور':'Your password reset code'}</p><div style="font-size:34px;font-weight:800;letter-spacing:8px;background:linear-gradient(135deg,#fd7903,#fee800);color:#2a1500;border-radius:14px;padding:14px 0;margin:14px 0;direction:ltr">${code}</div><p style="color:#888;font-size:13px">${ar?'ينتهي الرمز خلال 10 دقائق. إن لم تطلبه فتجاهل هذه الرسالة.':'This code expires in 10 minutes. If you did not request it, ignore this email.'}</p></div>`;
  await t.sendMail({from:'Spark <'+process.env.GMAIL_USER+'>',to,subject:(ar?'رمز استعادة كلمة المرور — ':'Password reset code — ')+code,text:code,html})}
module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  if(req.method==='GET')return res.status(200).json({ok:!!(SA()&&process.env.GMAIL_USER&&process.env.GMAIL_APP_PASSWORD)});
  if(req.method!=='POST')return res.status(405).end();
  try{
    const b=typeof req.body==='string'?JSON.parse(req.body):(req.body||{});
    const email=String(b.email||'').trim().toLowerCase();const act=b.action;
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return res.status(400).json({error:'email'});
    const sa=SA();if(!sa||!process.env.GMAIL_USER||!process.env.GMAIL_APP_PASSWORD)return res.status(501).json({error:'not configured'});
    const key='otp:'+crypto.createHash('sha256').update(email).digest('hex').slice(0,32);
    if(act==='send'){
      if(await r('GET',key+':cd'))return res.status(429).json({error:'wait'});
      await r('SET',key+':cd','1','EX','60');
      const tk=await token(sa);let ok=false;
      try{const j=await itk(sa,tk,'accounts:lookup',{email:[email]});const u=(j.users||[])[0];ok=!!(u&&(u.providerUserInfo||[]).some(p=>p.providerId==='password'))}catch(e){}
      if(ok){const code=String(crypto.randomInt(0,1000000)).padStart(6,'0');
        await r('SET',key,JSON.stringify({h:hash(email,code),n:0}),'EX','600');await mail(email,code,b.lang)}
      return res.status(200).json({ok:true}); // same answer whether or not the account exists
    }
    if(act==='check'||act==='reset'){
      const raw=await r('GET',key);if(!raw)return res.status(400).json({error:'code'});
      const o=JSON.parse(raw);if(o.n>=5){await r('DEL',key);return res.status(429).json({error:'many'})}
      const code=String(b.code||'').replace(/\D/g,'');
      if(hash(email,code)!==o.h){o.n++;await r('SET',key,JSON.stringify(o),'EX','600');return res.status(400).json({error:'code'})}
      if(act==='check')return res.status(200).json({ok:true});
      const pw=String(b.password||'');if(pw.length<6)return res.status(400).json({error:'weak'});
      const tk=await token(sa);const j=await itk(sa,tk,'accounts:lookup',{email:[email]});const u=(j.users||[])[0];if(!u)return res.status(400).json({error:'code'});
      await itk(sa,tk,'accounts:update',{localId:u.localId,password:pw});await r('DEL',key);
      return res.status(200).json({ok:true})}
    return res.status(400).json({error:'action'});
  }catch(e){return res.status(500).json({error:String(e.message||e)})}};
