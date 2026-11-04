self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(x){}
  e.waitUntil(self.registration.showNotification(d.title||'Crimson Notes',{body:d.body||'',tag:d.tag||'crimson',renotify:true,vibrate:[200,100,200]}))});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const w of l){if('focus' in w)return w.focus()}return self.clients.openWindow('./#tasks')}))});
