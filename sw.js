const V='spark-v3',CORE=['./','index.html','manifest.json','favicon.svg','icon-192.png','icon-512.png'];
const EXT=['fonts.googleapis.com','fonts.gstatic.com','www.gstatic.com','cdnjs.cloudflare.com'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>Promise.all(CORE.map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{const r=e.request;if(r.method!=='GET')return;const u=new URL(r.url);
 if(u.origin===location.origin&&(u.pathname.startsWith('/api/')||u.pathname.endsWith('version.json')))return;
 if(r.mode==='navigate'){e.respondWith(fetch(r).then(x=>{const c=x.clone();caches.open(V).then(h=>h.put('index.html',c));return x}).catch(()=>caches.match('index.html').then(m=>m||caches.match('./'))));return}
 if(u.origin===location.origin||EXT.includes(u.host)){e.respondWith(caches.open(V).then(h=>h.match(r).then(m=>{const f=fetch(r).then(x=>{if(x&&(x.ok||x.type==='opaque'))h.put(r,x.clone());return x}).catch(()=>m);return m||f})))}});
self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(x){}
 e.waitUntil(self.registration.showNotification(d.title||'Spark',{body:d.body||'',tag:d.tag||'spark',renotify:true,vibrate:[200,100,200,100,300],icon:'icon-192.png',badge:'icon-192.png',timestamp:Date.now(),data:{id:d.tag,url:'./#tasks'},actions:d.tag?[{action:'done',title:'✓'},{action:'snooze',title:'⏰ 10m'}]:[]}))});
self.addEventListener('notificationclick',e=>{e.notification.close();const id=(e.notification.data||{}).id,act=e.action;e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const w of l){if(act)w.postMessage({type:'notif',action:act,id});if(!act&&'focus' in w)return w.focus()}if(act&&l.length)return;return self.clients.openWindow('./#tasks')}))});
