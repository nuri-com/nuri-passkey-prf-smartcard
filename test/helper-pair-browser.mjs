// Fake-only browser acceptance; disposable Chrome profile, never a real card.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('..', import.meta.url));
const scratch=tmpdir();
const browser=process.env.NURI_TEST_BROWSER || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
if(!existsSync(browser)) throw new Error('Set NURI_TEST_BROWSER to an installed Chrome/Chromium executable');
const dir=await mkdtemp(join(scratch,'w22-browser-'));
const freePort=()=>new Promise((resolve,reject)=>{const s=createServer();s.on('error',reject);s.listen(0,'127.0.0.1',()=>{let p=s.address().port;s.close(()=>resolve(p))})});
const port=await freePort(), cdpPort=await freePort();
const token='0123456789abcdef'.repeat(4);
const helper=spawn(process.execPath,[join(root,'scripts/local-card-cosign-server.mjs'),`--port=${port}`,'--backend=simulated'],{cwd:root,env:{...process.env,NURI_COSIGN_TOKEN:token,NURI_CARD_TOKEN_FILE:join(dir,'token')},stdio:['ignore','pipe','pipe']});
let output='';helper.stdout.on('data',d=>output+=d);helper.stderr.on('data',d=>output+=d);
const chrome=spawn(browser,['--headless=new',`--remote-debugging-port=${cdpPort}`,`--user-data-dir=${join(dir,'chrome')}`,'--no-first-run','--no-default-browser-check','--disable-background-networking','about:blank'],{stdio:['ignore','ignore','ignore']});
let ws;
try {
  for(let i=0;i<100;i++){try{await fetch(`http://127.0.0.1:${port}/`);await fetch(`http://127.0.0.1:${cdpPort}/json/version`);break;}catch{await new Promise(r=>setTimeout(r,100));}}
  const code=/Browser pairing code: ([0-9a-f]{16})/.exec(output)?.[1];assert.ok(code,output);
  const target=await(await fetch(`http://127.0.0.1:${cdpPort}/json/new?http://127.0.0.1:${port}/`,{method:'PUT'})).json();
  ws=new WebSocket(target.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let id=0;const pending=new Map(),errors=[];
  ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(m.error):p.resolve(m.result);}else if(m.method==='Runtime.exceptionThrown')errors.push(m.params.exceptionDetails.text);else if(m.method==='Log.entryAdded'&&m.params.entry.source==='security')errors.push(m.params.entry.text);};
  const call=(method,params={})=>new Promise((resolve,reject)=>{const n=++id;pending.set(n,{resolve,reject});ws.send(JSON.stringify({id:n,method,params}));});
  await call('Runtime.enable');await call('Log.enable');
  const evaluate=async(expression)=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;};
  for(let i=0;i<100;i++){if(await evaluate("!!document.querySelector('dialog[open]')"))break;await new Promise(r=>setTimeout(r,50));}
  assert.equal(await evaluate("!!document.querySelector('dialog[open]')"),true,'pairing overlay opens');
  assert.equal(await evaluate('document.cookie'),'','no session before pairing');
  assert.equal(await evaluate("typeof window.NURI_CARD_TOKEN"),'undefined');
  assert.equal(await evaluate(`document.documentElement.innerHTML.includes(${JSON.stringify(token)})`),false);
  await evaluate(`document.querySelector('dialog input').value=${JSON.stringify(code)};document.querySelector('dialog form').requestSubmit();true`);
  for(let i=0;i<100;i++){if(await evaluate("!document.querySelector('dialog')"))break;await new Promise(r=>setTimeout(r,50));}
  assert.equal(await evaluate("!document.querySelector('dialog')"),true,'pairing completed');
  assert.equal(await evaluate('document.cookie'),'','HttpOnly cookie not readable even when paired');
  const cookies=(await call('Network.getAllCookies')).cookies;
  const cookie=cookies.find(c=>c.name==='nuri_cosign_session');assert.ok(cookie);assert.equal(cookie.httpOnly,true);assert.equal(cookie.sameSite,'Strict');assert.equal(cookie.path,'/api/');
  assert.equal(await evaluate("fetch('/api/cosign/info').then(r=>r.status)"),200,'real browser cookie authorizes API');
  await call('Page.reload');
  await new Promise(r=>setTimeout(r,300));
  assert.equal(await evaluate("!!document.querySelector('dialog[open]')"),false,'paired reload does not ask again');
  assert.deepEqual(errors,[],'no runtime/CSP errors');
  console.log(JSON.stringify({browser:'Google Chrome headless, disposable local profile',backend:'simulated only',pairing_overlay:true,paired_api:200,reload_session:true,window_token:'undefined',httpOnly:true,sameSite:'Strict',path:'/api/',csp_runtime_errors:errors}));
} finally {
  ws?.close();
  const stop = (p) => new Promise((resolve) => {
    if (p.exitCode !== null || p.signalCode !== null) { resolve(); return; }
    const timer = setTimeout(() => p.kill('SIGKILL'), 3000);
    p.once('exit', () => { clearTimeout(timer); resolve(); });
    p.kill();
  });
  await Promise.all([stop(helper), stop(chrome)]);
  await rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
