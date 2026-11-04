const r=require('./_db');const webpush=require('web-push');
module.exports=async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  const secret=process.env.CRON_SECRET;
  if(!secret||(req.query&&req.query.key)!==secret)return res.status(401).json({error:'unauthorized'});
  try{
    webpush.setVapidDetails(process.env.VAPID_SUBJECT||'mailto:admin@example.com',process.env.VAPID_PUBLIC_KEY,process.env.VAPID_PRIVATE_KEY);
    const keys=await r('SMEMBERS','users')||[];const now=Date.now();let sent=0,removed=0;
    for(const k of keys){
      const raw=await r('GET',k);if(!raw){await r('SREM','users',k);continue}
      const u=JSON.parse(raw);const due=u.reminders.filter(x=>x.rt<=now);if(!due.length)continue;
      let dead=false;
      for(const x of due){
        try{await webpush.sendNotification(u.sub,JSON.stringify({title:x.title,body:x.body,tag:x.id}),{TTL:3600,urgency:'high'});sent++}
        catch(e){if(e.statusCode===404||e.statusCode===410){dead=true;break}}
      }
      if(dead){await r('DEL',k);await r('SREM','users',k);removed++;continue}
      u.reminders=u.reminders.filter(x=>x.rt>now);await r('SET',k,JSON.stringify(u));
    }
    res.status(200).json({ok:true,sent,removed,users:keys.length});
  }catch(e){res.status(500).json({error:String(e.message||e)})}};
