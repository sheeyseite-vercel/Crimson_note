const r=require('./_db');const crypto=require('crypto');
module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='POST')return res.status(405).end();
  try{
    const b=typeof req.body==='string'?JSON.parse(req.body):req.body;
    const sub=b&&b.sub;if(!sub||!sub.endpoint||!sub.keys)return res.status(400).json({error:'bad subscription'});
    const list=(Array.isArray(b.reminders)?b.reminders:[]).slice(0,200).map(x=>({id:String(x.id).slice(0,40),title:String(x.title||'').slice(0,200),body:String(x.body||'').slice(0,200),rt:+x.rt})).filter(x=>x.rt>0);
    const k='u:'+crypto.createHash('sha256').update(sub.endpoint).digest('hex').slice(0,32);
    await r('SET',k,JSON.stringify({sub,reminders:list,lang:b.lang==='en'?'en':'ar'}));
    await r('SADD','users',k);
    res.status(200).json({ok:true,n:list.length});
  }catch(e){res.status(500).json({error:String(e.message||e)})}};
