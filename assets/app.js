"use strict";
/* ===========================================================
   Saku — personal finance tracker (static, encrypted on device)
   =========================================================== */
const CONFIG = window.SAKU_CONFIG || { resetEmail:"", web3formsKey:"" };
const VAULT_KEY = "saku.vault.v1";
const SYNC_KEY  = "saku.sync.v1";              // sync config (local, not committed)
const SYNCDEF   = (CONFIG.sync) || {};          // non-secret defaults from config.js (owner/repo/path)
let   PASSWORD  = null;                          // kept in session memory to derive the remote vault key
let   SYNC      = null;                          // {owner,repo,path,branch,token}
const BASE_KEY  = "saku.base.v1";
const SESSION_KEY = "saku.session.v1";           // sessionStorage: survives refresh, gone when the tab/app is closed or 🔒 is pressed              // {sha, wrap}: last vault this device & GitHub agreed on (merge base)
let   syncBusy  = false, syncDirty = false;      // sync queue control
let   authPrompted = false;                      // open the token form at most once per session
let   lastSyncTry = 0, lastSyncOk = 0, lastSyncErr = "";

/* ---------------- crypto (AES-GCM + PBKDF2) ---------------- */
const enc = new TextEncoder(), dec = new TextDecoder();
// no fromCharCode(...bytes): spreading >~120k args throws RangeError, which broke sync once the vault grew past ~120 KB
const b64 = buf => { let s=""; for(const c of new Uint8Array(buf)) s+=String.fromCharCode(c); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveKey(password, salt){
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" },
    base, { name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);   // extractable: the session copy needs exportKey
}
async function encryptObj(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv:b64(iv), ct:b64(ct) };
}
async function decryptObj(key, blob){
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv:unb64(blob.iv) }, key, unb64(blob.ct));
  return JSON.parse(dec.decode(pt));
}

/* ---------------- vault (encrypted localStorage) ---------------- */
let CRYPTOKEY = null, SALT = null;
function readVault(){ try{ return JSON.parse(localStorage.getItem(VAULT_KEY)); }catch(e){ return null; } }
async function writeVault(){
  const blob = await encryptObj(CRYPTOKEY, S);
  const wrap = { v:1, salt:b64(SALT), iter:200000, updatedAt:Date.now(), blob };
  localStorage.setItem(VAULT_KEY, JSON.stringify(wrap));
  saveSession();
  return wrap;
}
// The derived key (never the password) is kept for this tab so a refresh doesn't lock you out
async function saveSession(){
  try{ sessionStorage.setItem(SESSION_KEY, JSON.stringify({salt:b64(SALT), k:b64(await crypto.subtle.exportKey("raw",CRYPTOKEY))})); }catch(e){}
}
async function restoreSession(){
  try{
    const s=JSON.parse(sessionStorage.getItem(SESSION_KEY)), v=readVault();
    if(!s||!v||s.salt!==v.salt) return false;
    const key=await crypto.subtle.importKey("raw", unb64(s.k), "AES-GCM", true, ["encrypt","decrypt"]);
    S=await decryptObj(key, v.blob); normalizeState(); SALT=unb64(v.salt); CRYPTOKEY=key;
    return true;
  }catch(e){ return false; }
}
async function createVault(password){
  SALT = crypto.getRandomValues(new Uint8Array(16));
  CRYPTOKEY = await deriveKey(password, SALT);
  PASSWORD = password;
  S = seed();
  await writeVault();
}
async function unlockVault(password){
  const v = readVault();
  SALT = unb64(v.salt);
  const key = await deriveKey(password, SALT);
  S = await decryptObj(key, v.blob);   // throws if the password is wrong
  normalizeState();
  CRYPTOKEY = key;
  PASSWORD = password;
}
async function changePassword(newPass){
  SALT = crypto.getRandomValues(new Uint8Array(16));
  CRYPTOKEY = await deriveKey(newPass, SALT);
  PASSWORD = newPass;
  await writeVault();
  cloudSync();
}

/* ============================================================
   CLOUD SYNC via GitHub Contents API
   ------------------------------------------------------------
   Stores the vault file (already AES-256 encrypted) in a
   PRIVATE GitHub repo. The token is never committed; it is
   pasted per-device & kept in localStorage. Only ciphertext
   is ever sent to GitHub — unreadable without the password.
   ============================================================ */
function loadSync(){
  try{ const s=JSON.parse(localStorage.getItem(SYNC_KEY)); if(s&&s.token){ SYNC=s; return s; } }catch(e){}
  if(SYNCDEF.owner&&SYNCDEF.repo){ SYNC={owner:SYNCDEF.owner,repo:SYNCDEF.repo,path:SYNCDEF.path||"vault.json",branch:SYNCDEF.branch||"main",token:""}; }
  return SYNC;
}
function saveSync(cfg){ SYNC=cfg; localStorage.setItem(SYNC_KEY, JSON.stringify(cfg)); }
function clearSync(){ SYNC=null; localStorage.removeItem(SYNC_KEY); localStorage.removeItem(BASE_KEY); loadSync(); }
function syncReady(){ return !!(SYNC&&SYNC.owner&&SYNC.repo&&SYNC.path&&SYNC.token); }
function readBase(){ try{ return JSON.parse(localStorage.getItem(BASE_KEY)); }catch(e){ return null; } }
// ponytail: base duplicates the vault in localStorage (~5 MB quota) → fine until the vault nears ~2 MB
function setBase(sha, wrap){ localStorage.setItem(BASE_KEY, JSON.stringify({sha, wrap})); }

function ghHeaders(){ return { "Authorization":"Bearer "+SYNC.token, "Accept":"application/vnd.github+json", "X-GitHub-Api-Version":"2022-11-28" }; }
function ghApi(){ return `https://api.github.com/repos/${SYNC.owner}/${SYNC.repo}`; }
function ghUrl(){ return ghApi()+`/contents/${SYNC.path.split("/").map(encodeURIComponent).join("/")}`; }
const utf8b64  = s => b64(enc.encode(s));
const b64utf8  = s => dec.decode(unb64(s.replace(/\n/g,"")));

async function ghGet(){
  // no-store: GitHub sends max-age=60, and a cached reply means stale data + a stale sha
  const r = await fetch(ghUrl()+`?ref=${encodeURIComponent(SYNC.branch||"main")}`, {headers:ghHeaders(), cache:"no-store"});
  if(r.status===404) return {wrap:null,sha:null};
  if(r.status===401||r.status===403) throw new Error("AUTH");
  if(!r.ok) throw new Error("HTTP "+r.status);
  const j = await r.json();
  if(j.encoding==="none"){                      // file >1 MB: Contents API leaves content empty, the blob API doesn't (≤100 MB)
    const b = await fetch(ghApi()+"/git/blobs/"+j.sha, {headers:ghHeaders()});
    if(!b.ok) throw new Error("HTTP "+b.status);
    j.content = (await b.json()).content;
  }
  return { wrap: JSON.parse(b64utf8(j.content)), sha:j.sha };
}
// Returns the new sha, or null if GitHub's copy moved since `sha` (caller re-pulls & merges)
async function ghPut(wrap, sha){
  const body = { message:"saku sync "+new Date().toISOString(),
                 content: utf8b64(JSON.stringify(wrap)), branch: SYNC.branch||"main" };
  if(sha) body.sha=sha;
  const r = await fetch(ghUrl(), {method:"PUT", headers:{...ghHeaders(),"Content-Type":"application/json"}, body:JSON.stringify(body)});
  if(r.status===409||r.status===422) return null;
  if(r.status===401||r.status===403) throw new Error("AUTH");
  if(!r.ok) throw new Error("HTTP "+r.status);
  return (await r.json()).content.sha;
}
async function openWrap(w){                     // decrypt a vault wrap with the session password
  if(w.salt!==b64(SALT)&&PASSWORD==null) throw new Error("NEEDPASS");   // restored session has the key, not the password
  const key = w.salt===b64(SALT) ? CRYPTOKEY : await deriveKey(PASSWORD, unb64(w.salt));
  return { data: await decryptObj(key, w.blob), key };   // throws OperationError if the password differs
}

/* 3-way merge against the last synced state: per item (lists, by id) or per
   key (objects), keep this device's version if it changed since the last
   sync, otherwise take GitHub's. Both changed → this device wins. Adds,
   edits and deletes from both devices survive. */
function mergeState(b, l, r){
  const pick=(b,l,r)=>JSON.stringify(l)!==JSON.stringify(b) ? l : r;
  const isObj=x=>x&&typeof x==="object"&&!Array.isArray(x);
  const out={};
  for(const k of new Set([...Object.keys(r),...Object.keys(l)])){
    const bv=b?.[k], lv=l[k], rv=r[k];
    let v;
    if(Array.isArray(lv)&&Array.isArray(rv)){          // accounts / txns / recurring: per item, by id
      const m=xs=>new Map((xs||[]).map(x=>[x.id,x])), B=m(bv), L=m(lv), R=m(rv);
      v=[...new Set([...R.keys(),...L.keys()])].map(id=>pick(B.get(id),L.get(id),R.get(id))).filter(Boolean);
    } else if(isObj(lv)&&isObj(rv)) v=mergeState(bv, lv, rv);   // budgets: per category
    else v=pick(bv, lv, rv);
    if(v!==undefined) out[k]=v;
  }
  return out;
}

// Pull → merge → push. Safe to call anytime; calls while busy are queued.
async function cloudSync(){
  if(!syncReady()||!CRYPTOKEY) return;
  if(!navigator.onLine){ setSyncDot("err"); return; }    // the "online" listener retries
  if(syncBusy){ syncDirty=true; return; }
  syncBusy=true; lastSyncTry=Date.now(); setSyncDot("sync");
  try{
    for(let tries=0;;tries++){
      const {wrap, sha} = await ghGet();
      const base = readBase();
      let local = readVault();
      if(wrap && sha!==base?.sha){                        // GitHub changed since our last sync
        const R = await openWrap(wrap);
        // no base yet (first sync on this device) → the older copy is the base = last-write-wins
        const B = base ? (await openWrap(base.wrap)).data : ((wrap.updatedAt||0)>(local.updatedAt||0) ? S : R.data);
        const M = mergeState(B, S, R.data);
        if(JSON.stringify(M)===JSON.stringify(R.data)){   // nothing local to add → adopt GitHub's copy as-is
          const changed = JSON.stringify(S)!==JSON.stringify(R.data);
          S=R.data; normalizeState(); SALT=unb64(wrap.salt); CRYPTOKEY=R.key;
          localStorage.setItem(VAULT_KEY, JSON.stringify(wrap)); setBase(sha, wrap); saveSession();
          if(changed){ render(); toast("Latest data pulled from GitHub"); }
          break;
        }
        S=M; normalizeState(); SALT=unb64(wrap.salt); CRYPTOKEY=R.key;   // converge every device on GitHub's salt
        local=await writeVault(); render();
      } else if(base && local.updatedAt===base.wrap.updatedAt) break;   // nothing new on either side
      const newSha = await ghPut(local, sha);
      if(newSha){ setBase(newSha, local); break; }
      if(tries>=2) throw new Error("CONFLICT");
    }
    lastSyncOk=Date.now(); lastSyncErr=""; setSyncDot("ok");
  }catch(e){
    setSyncDot("err"); lastSyncErr=e.message==="AUTH"?"token expired or rejected":e.message==="NEEDPASS"?"lock & unlock once to finish":e.name==="OperationError"?"different password on GitHub":"network/GitHub error";
    if(e.message==="AUTH"){
      toast("GitHub token expired or rejected — paste a new one",true);
      if(!authPrompted&&!el("scrim").classList.contains("show")){ authPrompted=true; openSync(); }
    }
    else if(e.message==="NEEDPASS") toast("Lock & unlock once to finish syncing",true);
    else if(e.name==="OperationError") toast("GitHub data uses a different password",true);
    else toast("Sync failed — will retry automatically",true);
  }finally{
    syncBusy=false; if(syncDirty){ syncDirty=false; cloudSync(); }
  }
}
function setSyncDot(state){
  const d=el("syncDot"); if(!d) return;
  d.className="sync-dot "+(state||"");
  d.title={sync:"Syncing…",ok:"Synced to GitHub",err:"Sync failed"}[state]||"";
}
// Tab/app comes back: catch up on date rollover, due recurring items and other devices' changes
function resume(throttle){ if(!S) return; processRecurring(); render(); if(!throttle||Date.now()-lastSyncTry>10000) cloudSync(); }
document.addEventListener("visibilitychange",()=>{ if(!document.hidden) resume(); });
addEventListener("focus",()=>resume(true));   // desktop fires focus on every window switch → throttle
addEventListener("online", cloudSync);
function syncStatus(){
  if(!syncReady()) return toast("Cloud Sync is off — set it up in Settings");
  const t=lastSyncOk?new Date(lastSyncOk).toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"}):"";
  toast(syncBusy?"Syncing…":lastSyncErr?"Sync failed: "+lastSyncErr+" — retrying":"Synced with GitHub "+t, !!lastSyncErr&&!syncBusy);
  cloudSync();
}
loadSync();


/* ---------------- constants ---------------- */
const KATEGORI=["Food & Drinks","Transportation","Shopping","Bills & Utilities","Health","Entertainment","Education","Savings & Investment","Installment / Loan","Donation & Gifts","Admin / Fees","Other"];
const JENIS_MASUK=["Salary","Bonus","Business Income","Investment Returns","Incoming Transfer","Cashback","Other"];
const JENIS_TRANSFER=["Credit Card Payment","Investment","Investment Withdrawal","Account Transfer"];
const TIPE=["Bank Account","Investment","Credit Card","Paylater"];
const SWATCHES=["#1B3A4B","#0A5DAE","#00529C","#003D79","#5B3FD6","#00A19A","#1BA876","#1E7E34","#B7791F","#EE4D2D","#7A1F2B","#C0392B"];
const isAsset=t=>t==="Bank Account"||t==="Investment";
const isDebt =t=>t==="Credit Card"||t==="Paylater";

/* ---------------- seed (template with no personal balances) ---------------- */
function seed(){
  const A=[
    ["BCA Account","Bank Account",0,"#0A5DAE","BCA"],
    ["Mandiri Account","Bank Account",0,"#003D79","MDR"],
    ["Cash Wallet","Bank Account",0,"#1E7E34","TUN"],
    ["Krom Account","Bank Account",0,"#5B3FD6","KRM"],
    ["Seabank Account","Bank Account",0,"#00A19A","SEA"],
    ["Bibit Mutual Fund","Investment",0,"#1BA876","BBT"],
    ["Stocks / RDN","Investment",0,"#B7791F","SHM"],
    ["BCA Credit Card","Credit Card",9000000,"#0A5DAE","BCA"],
    ["BRI Credit Card","Credit Card",25000000,"#00529C","BRI"],
    ["CIMB Credit Card","Credit Card",3000000,"#7A1F2B","CMB"],
    ["Shopee Paylater","Paylater",25500000,"#EE4D2D","SPL"],
  ];
  return {
    accounts: A.map((a,i)=>({ id:"a"+(i+1), name:a[0], type:a[1], base:a[2], color:a[3], mono:a[4] })),
    txns: [], adjust: 0, budgets: {}, recurring: []
  };
}
/* One-time migration: older vaults stored account types / category / income /
   transfer labels in Indonesian. The app now stores and compares English
   values (see TIPE/KATEGORI/JENIS_* above), so old data must be translated
   in place or accounts silently stop matching isAsset()/isDebt(). */
const MIGRATE_TIPE={"Rekening":"Bank Account","Investasi":"Investment","Kartu Kredit":"Credit Card"};
const MIGRATE_KATEGORI={"Makanan & Minuman":"Food & Drinks","Transportasi":"Transportation","Belanja":"Shopping","Tagihan & Utilitas":"Bills & Utilities","Kesehatan":"Health","Hiburan":"Entertainment","Pendidikan":"Education","Tabungan & Investasi":"Savings & Investment","Cicilan / Pinjaman":"Installment / Loan","Donasi & Hadiah":"Donation & Gifts","Admin / Biaya":"Admin / Fees","Lainnya":"Other"};
const MIGRATE_JENIS_MASUK={"Gaji":"Salary","Bonus / THR":"Bonus","Pendapatan Usaha":"Business Income","Hasil Investasi":"Investment Returns","Transfer Masuk":"Incoming Transfer","Lainnya":"Other"};
const MIGRATE_JENIS_TRANSFER={"Pembayaran Kartu Kredit":"Credit Card Payment","Investasi":"Investment","Pencairan Investasi":"Investment Withdrawal","Transfer Antar Rekening":"Account Transfer"};
function migrateLegacyData(){
  S.accounts.forEach(a=>{ if(MIGRATE_TIPE[a.type]) a.type=MIGRATE_TIPE[a.type]; });
  S.txns.forEach(t=>{
    if(t.kind==="expense"&&MIGRATE_KATEGORI[t.cat]) t.cat=MIGRATE_KATEGORI[t.cat];
    else if(t.kind==="income"&&MIGRATE_JENIS_MASUK[t.jenis]) t.jenis=MIGRATE_JENIS_MASUK[t.jenis];
    else if(t.kind==="transfer"&&MIGRATE_JENIS_TRANSFER[t.jenis]) t.jenis=MIGRATE_JENIS_TRANSFER[t.jenis];
  });
  (S.recurring||[]).forEach(r=>{
    if(r.kind==="expense"&&MIGRATE_KATEGORI[r.cat]) r.cat=MIGRATE_KATEGORI[r.cat];
    else if(r.kind==="income"&&MIGRATE_JENIS_MASUK[r.jenis]) r.jenis=MIGRATE_JENIS_MASUK[r.jenis];
  });
  if(S.budgets) Object.keys(S.budgets).forEach(k=>{ if(MIGRATE_KATEGORI[k]){ S.budgets[MIGRATE_KATEGORI[k]]=S.budgets[k]; delete S.budgets[k]; } });
}
function normalizeState(){ S.budgets=S.budgets||{}; S.recurring=S.recurring||[]; migrateLegacyData(); }
function uid(){ return "t"+Math.random().toString(36).slice(2,9)+Date.now().toString(36).slice(-3); }

/* ---------------- state ---------------- */
let S=null, filter="all", txSearch="", txFrom="", txTo="";
let recapPeriod="30", recapFrom="", recapTo="", recapDate="";
async function persist(){ await writeVault(); render(); cloudSync(); }

/* ---------------- WIB (GMT+7) date helpers ----------------
   "Today" must always mean the calendar day in Jakarta time, not
   whatever the device's local timezone or UTC happens to be —
   otherwise the date rolls over at the wrong wall-clock hour. */
const WIB_MS=7*60*60*1000;
const wibNow=()=>new Date(Date.now()+WIB_MS);
const ymd=d=>`${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
const wibToday=()=>ymd(wibNow());

/* ---------------- compute ---------------- */
function calc(cutoff){
  const m={}; S.accounts.forEach(a=>m[a.id]={in:0,out:0});
  (cutoff?S.txns.filter(t=>t.date<=cutoff):S.txns).forEach(t=>{
    if(t.kind==="expense"){ if(m[t.acc]) m[t.acc].out+=t.amt; }
    else if(t.kind==="income"){ if(m[t.acc]) m[t.acc].in+=t.amt; }
    else if(t.kind==="transfer"){ if(m[t.from]) m[t.from].out+=t.amt; if(m[t.to]) m[t.to].in+=t.amt; }
  });
  S.accounts.forEach(a=>{ const x=m[a.id];
    if(isAsset(a.type)){ x.balance=a.base+x.in-x.out; x.debt=0; }
    else { x.debt=Math.max(0,x.out-x.in); x.balance=a.base-x.out+x.in; }
  });
  let cash=0,invest=0,debt=0,limit=0;
  S.accounts.forEach(a=>{ const x=m[a.id];
    if(a.type==="Bank Account")cash+=x.balance;
    else if(a.type==="Investment")invest+=x.balance;
    else { debt+=x.debt; limit+=x.balance; }
  });
  const assets=cash+invest, net=assets-debt+(S.adjust||0);
  return {m,cash,invest,debt,limit,assets,net};
}
const accById=id=>S.accounts.find(a=>a.id===id);
const fmt=n=>new Intl.NumberFormat("id-ID",{style:"currency",currency:"IDR",maximumFractionDigits:0}).format(Math.round(n||0));
const fmtShort=n=>{const v=Math.abs(n); if(v>=1e9)return (n/1e9).toFixed(1).replace(".0","")+"B"; if(v>=1e6)return (n/1e6).toFixed(1).replace(".0","")+"M"; if(v>=1e3)return Math.round(n/1e3)+"K"; return Math.round(n);};
const fmtNum=n=>Number(n).toLocaleString("id-ID");
// newest date first; within a day, the most recently added first (sort is stable)
const byDateDesc=txns=>[...txns].reverse().sort((a,b)=>a.date<b.date?1:a.date>b.date?-1:0);
const fmtDate=d=>new Date(d+"T00:00:00").toLocaleDateString("en-US",{day:"numeric",month:"short"});

/* ---------------- render ---------------- */
function render(){
  el("todayLabel").textContent=new Date().toLocaleDateString("en-US",{weekday:"long",day:"numeric",month:"long",year:"numeric",timeZone:"Asia/Jakarta"});
  const c=calc();
  el("netWorth").textContent=fmt(c.net);
  el("heroMeta").innerHTML=`Total assets <b>${fmt(c.assets)}</b> &nbsp;·&nbsp; Debt <b>${fmt(c.debt)}</b>`;
  const total=Math.max(c.assets,1);
  const segs=[["Cash & Bank",c.cash,"var(--teal)"],["Investment",c.invest,"var(--gold)"]];
  el("compTrack").innerHTML=segs.map(s=>`<i class="comp-seg" style="width:${Math.max(0,s[1]/total*100)}%;background:${s[2]}"></i>`).join("");
  el("compLegend").innerHTML=segs.map(s=>`<span class="lg"><span class="dot" style="background:${s[2]}"></span>${s[0]} <b>${fmt(s[1])}</b></span>`).join("")
     +`<span class="lg"><span class="dot" style="background:var(--red)"></span>Debt <b>${fmt(c.debt)}</b></span>`;

  const nets=[]; const now=wibNow();
  for(let i=5;i>=0;i--){
    const d=new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth()-i+1,0));
    nets.push(i===0?c.net:calc(ymd(d)).net);
  }
  const lo=Math.min(...nets), hi=Math.max(...nets), span=Math.max(1,hi-lo);
  const pts=nets.map((v,i)=>`${i/(nets.length-1)*300},${52-(v-lo)/span*48}`).join(" ");
  el("trendChart").innerHTML=`<polyline points="${pts}" fill="none" stroke="#7ee0a8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>`;

  const kpis=[
    ["Total Assets",c.assets,"var(--green)",icoTrendUp],
    ["Investment",c.invest,"var(--gold)",icoChart,S.accounts.filter(a=>a.type==="Investment").length+" accounts"],
    ["Card Debt",c.debt,"var(--red)",icoCard],
    ["Limit Remaining",c.limit,"var(--teal)",icoShield],
  ];
  el("kpis").innerHTML=kpis.map(k=>`<div class="kpi"><div class="k-top"><span class="k-ico" style="background:${tint(k[2])};color:${k[2]}">${k[3]}</span>${k[0]}</div><div class="k-val num" style="color:${k[2]}">${fmt(k[1])}</div>${k[4]?`<div class="k-sub">${k[4]}</div>`:""}</div>`).join("");

  el("accCount").textContent=S.accounts.length;
  el("accGrid").innerHTML=S.accounts.map(a=>{
    const x=c.m[a.id]; let foot="", bar="";
    if(isDebt(a.type)){
      const pct=Math.min(100,x.debt/Math.max(a.base,1)*100);
      foot=`Limit ${fmtShort(a.base)} · remaining <b style="color:var(--teal)">${fmt(x.balance)}</b>`;
      const col=pct>80?"var(--red)":pct>50?"var(--gold)":"var(--teal)";
      bar=`<div class="usebar"><i style="width:${pct}%;background:${col}"></i></div>`;
    } else foot=`Starting balance ${fmtShort(a.base)}`;
    const balColor=isDebt(a.type)?(x.debt>0?"var(--red)":"var(--ink)"):(x.balance<0?"var(--red)":"var(--ink)");
    const big=isDebt(a.type)?(x.debt>0?"−"+fmt(x.debt).replace("Rp","Rp "):fmt(0)):fmt(x.balance);
    return `<div class="acc">
      <div class="acc-actions">
        <button class="mini-btn" data-editacc="${a.id}" title="Edit">${icoEdit}</button>
        <button class="mini-btn danger" data-delacc="${a.id}" title="Delete">${icoTrash}</button></div>
      <div class="acc-top"><div class="logo" style="background:${a.color}">${esc(a.mono)}</div>
        <div><div class="acc-name">${esc(a.name)}</div><div class="acc-type">${a.type}</div></div></div>
      <div class="acc-bal num" style="color:${balColor}">${big}</div>
      <div class="acc-foot">${foot}</div>${bar}</div>`;
  }).join("")+`<button class="add-acc" id="addAccBtn">${icoPlus}<span>Add Account</span></button>`;

  renderMonthly();

  const counts={all:S.txns.length,expense:0,income:0,transfer:0};
  S.txns.forEach(t=>counts[t.kind]++);
  const Fr=[["all","All"],["expense","Expenses"],["income","Income"],["transfer","Transfer & Investment"]];
  el("txFilters").innerHTML=Fr.map(f=>`<button class="chip ${filter===f[0]?"active":""}" data-filter="${f[0]}">${f[1]}<span style="opacity:.6">${counts[f[0]]}</span></button>`).join("");

  el("txCount").textContent=S.txns.length;
  let list=byDateDesc(S.txns);
  if(filter!=="all") list=list.filter(t=>t.kind===filter);
  if(txSearch){
    const q=txSearch.toLowerCase().replace(/^[\d.]+$/,m=>m.replace(/\./g,""));   // "15.000" also finds 15000
    const hay=t=>[t.desc,t.cat,t.jenis,accById(t.acc)?.name,accById(t.from)?.name,accById(t.to)?.name,t.amt].join(" ").toLowerCase();
    list=list.filter(t=>hay(t).includes(q));
  }
  if(txFrom) list=list.filter(t=>t.date>=txFrom);
  if(txTo) list=list.filter(t=>t.date<=txTo);
  el("txList").innerHTML=list.length?list.map(txRow).join(""):emptyState();
  const filtered=filter!=="all"||txSearch||txFrom||txTo;
  el("txSum").classList.toggle("hidden",!filtered);
  if(filtered){
    const sum=k=>list.filter(t=>t.kind===k).reduce((s,t)=>s+t.amt,0);
    el("txSum").innerHTML=`${list.length} shown · Out <b style="color:var(--red)">${fmt(sum("expense"))}</b> · In <b style="color:var(--green)">${fmt(sum("income"))}</b>`;
  }

  renderRecap();
}
/* ---------------- monthly report ---------------- */
let repMonth=null;   // "YYYY-MM" shown in the report; null = current month
const monthLabel=(k,month="long")=>new Date(k+"-01T00:00:00").toLocaleDateString("en-US",month==="long"?{month,year:"numeric"}:{month});
const shiftMonth=(k,n)=>{ const [y,m]=k.split("-").map(Number); return new Date(Date.UTC(y,m-1+n,1)).toISOString().slice(0,7); };
const niceStep=x=>{ const p=10**Math.floor(Math.log10(x)), f=x/p; return (f<=1?1:f<=2?2:f<=5?5:10)*p; };
const signed=n=>(n>=0?"":"−")+fmt(Math.abs(n)).replace("Rp","Rp ");
function renderMonthly(){
  const cur=wibToday().slice(0,7), k=repMonth&&repMonth<cur?repMonth:cur, prevK=shiftMonth(k,-1);
  const byMonth={};
  S.txns.forEach(t=>{ if(t.kind==="transfer") return; const x=byMonth[t.date.slice(0,7)]??={in:0,out:0}; if(t.kind==="income") x.in+=t.amt; else x.out+=t.amt; });
  const m=byMonth[k]||{in:0,out:0}, p=byMonth[prevK]||{in:0,out:0};
  el("repMonth").textContent=monthLabel(k); el("mNext").disabled=k>=cur;
  el("flowIn").textContent=fmt(m.in); el("flowOut").textContent=fmt(m.out);
  el("flowNet").textContent=signed(m.in-m.out); el("flowNet").style.color=m.in>=m.out?"var(--green)":"var(--red)";
  if(p.out){   // spending vs previous month: up is bad
    const pct=Math.round((m.out-p.out)/p.out*100);
    el("flowDelta").innerHTML=`<span style="color:${pct>0?"var(--red)":"var(--green)"}">${pct>0?"▲":pct<0?"▼":"="} ${Math.abs(pct)}%</span> vs ${monthLabel(prevK,"short")}`;
  } else el("flowDelta").textContent="";

  const catTotals={};
  S.txns.forEach(t=>{ if(t.kind==="expense"&&t.date.slice(0,7)===k) catTotals[t.cat]=(catTotals[t.cat]||0)+t.amt; });
  const cats=Object.entries(catTotals).sort((a,b)=>b[1]-a[1]);
  const maxCat=Math.max(1,...cats.map(c=>c[1]));
  el("catList").innerHTML=cats.length?cats.map(([n,v])=>{
    const b=S.budgets[n], over=b&&v>b;
    return `<div class="cat-row"><span class="c-name">${esc(n)}</span><span class="c-bar"><i style="width:${Math.min(100,v/maxCat*100)}%${over?";background:var(--red)":""}"></i></span><span class="c-val num">${fmt(v)}${b?`<span class="c-budget">/ ${fmt(b)}</span>`:""}</span></div>`;
  }).join(""):`<div class="muted-note">No expenses in ${monthLabel(k)}.</div>`;
  const top=S.txns.filter(t=>t.kind==="expense"&&t.date.slice(0,7)===k).sort((a,b)=>b.amt-a.amt).slice(0,3);
  el("topExp").innerHTML=top.length?`<h3 style="margin:18px 0 6px">Biggest expenses</h3><div class="mini-list">${top.map(txRow).join("")}</div>`:"";
  renderChart(byMonth,k,cur);
}
function renderChart(byMonth,sel,cur){
  const data=[...Array(12)].map((_,i)=>{ const k=shiftMonth(cur,i-11); return {k,...(byMonth[k]||{in:0,out:0})}; });
  const max=Math.max(...data.flatMap(d=>[d.in,d.out]));
  el("mTable").innerHTML=`<table class="mt"><tr><th>Month</th><th>In</th><th>Out</th><th>Net</th></tr>${[...data].reverse().map(d=>`<tr><td>${monthLabel(d.k,"short")} ${d.k.slice(0,4)}</td><td class="num">${fmt(d.in)}</td><td class="num">${fmt(d.out)}</td><td class="num">${signed(d.in-d.out)}</td></tr>`).join("")}</table>`;
  if(!max){ el("mChart").innerHTML=`<div class="muted-note">No income or expenses in the last 12 months.</div>`; return; }
  const W=Math.max(260,el("mChart").clientWidth||400), H=170, pl=36, pb=20, pt=8;
  const step=niceStep(max/3), top=Math.ceil(max/step)*step, y=v=>pt+(H-pt-pb)*(1-v/top);
  const gw=(W-pl)/12, bw=Math.min(14,Math.max(3,(gw-8)/2)), narrow=gw<30;
  // column: 4px rounded data end, square at the baseline
  const col=(x,v,cls)=>{ if(v<=0) return ""; const yt=y(v), h=y(0)-yt, r=Math.min(4,h,bw/2);
    return `<path class="${cls}" d="M${x},${y(0)}V${yt+r}Q${x},${yt} ${x+r},${yt}H${x+bw-r}Q${x+bw},${yt} ${x+bw},${yt+r}V${y(0)}Z"/>`; };
  let svg=`<svg width="${W}" height="${H}" role="img" aria-label="Income and expenses per month, last 12 months">`;
  data.forEach((d,i)=>{ if(d.k===sel) svg+=`<rect class="selband" x="${pl+gw*i+1}" y="0" width="${gw-2}" height="${H-pb+2}" rx="6"/>`; });
  for(let v=0;v<=top;v+=step) svg+=`<line class="grid" x1="${pl}" x2="${W}" y1="${y(v)}" y2="${y(v)}"/><text class="ax" x="${pl-6}" y="${y(v)+3.5}" text-anchor="end">${v?fmtShort(v):0}</text>`;
  data.forEach((d,i)=>{
    const cx=pl+gw*i+gw/2;
    svg+=col(cx-bw-1,d.in,"bar-in")+col(cx+1,d.out,"bar-out");   // 2px surface gap between the pair
    svg+=`<text class="ax${d.k===sel?" sel":""}" x="${cx}" y="${H-5}" text-anchor="middle">${monthLabel(d.k,narrow?"narrow":"short")}</text>`;
    svg+=`<rect class="hit" data-month="${d.k}" x="${pl+gw*i}" y="0" width="${gw}" height="${H}" tabindex="0" aria-label="${monthLabel(d.k)}: in ${fmt(d.in)}, out ${fmt(d.out)}"/>`;
  });
  el("mChart").innerHTML=svg+`</svg><div class="tip hidden" id="mTip"></div>`;
  el("mChart").dataset.months=JSON.stringify(data);
}
function chartTip(hit){
  const tip=el("mTip"); if(!tip) return;
  if(!hit){ tip.classList.add("hidden"); return; }
  const d=JSON.parse(el("mChart").dataset.months).find(x=>x.k===hit.dataset.month);
  tip.innerHTML=`<div class="tip-h">${monthLabel(d.k)}</div><div class="tip-r"><i class="key-in"></i><b>${fmt(d.in)}</b> In</div><div class="tip-r"><i class="key-out"></i><b>${fmt(d.out)}</b> Out</div><div class="tip-r"><i></i><b>${signed(d.in-d.out)}</b> Net</div>`;
  tip.classList.remove("hidden");
  const box=el("mChart").getBoundingClientRect(), r=hit.getBoundingClientRect();
  tip.style.left=Math.min(box.width-tip.offsetWidth, Math.max(0, r.left-box.left+r.width/2-tip.offsetWidth/2))+"px";
}
function recapRange(){
  const today=wibNow(), todayStr=ymd(today);
  if(recapPeriod==="7"||recapPeriod==="30"){
    const from=new Date(today); from.setUTCDate(from.getUTCDate()-(recapPeriod==="7"?6:29));
    return [ymd(from), todayStr];
  }
  if(recapPeriod==="month") return [todayStr.slice(0,7)+"-01", todayStr];
  if(recapPeriod==="lastmonth"){
    const from=ymd(new Date(Date.UTC(today.getUTCFullYear(),today.getUTCMonth()-1,1)));
    const to=ymd(new Date(Date.UTC(today.getUTCFullYear(),today.getUTCMonth(),0)));
    return [from,to];
  }
  if(recapPeriod==="date"){ const d=recapDate||todayStr; return [d,d]; }
  return [recapFrom||todayStr, recapTo||todayStr];
}
function renderRecap(){
  const RC=[["7","7 Days"],["30","30 Days"],["month","This Month"],["lastmonth","Last Month"],["date","Specific Date"],["custom","Custom Range"]];
  el("recapFilters").innerHTML=RC.map(f=>`<button class="chip ${recapPeriod===f[0]?"active":""}" data-recapf="${f[0]}">${f[1]}</button>`).join("");
  el("recapDateWrap").classList.toggle("hidden",recapPeriod!=="date");
  el("recapCustomWrap").classList.toggle("hidden",recapPeriod!=="custom");

  const [from,to]=recapRange();
  const days={};
  S.txns.forEach(t=>{
    if(t.date<from||t.date>to) return;
    if(t.kind!=="expense"&&t.kind!=="income") return;
    const d=days[t.date]||(days[t.date]={in:0,out:0});
    if(t.kind==="expense") d.out+=t.amt; else d.in+=t.amt;
  });
  const dates=Object.keys(days).sort((a,b)=>a<b?1:-1);
  let inSum=0,outSum=0; dates.forEach(d=>{inSum+=days[d].in; outSum+=days[d].out;});
  el("recapIn").textContent=fmt(inSum); el("recapOut").textContent=fmt(outSum);
  const net=inSum-outSum;
  el("recapNet").textContent=(net>=0?"":"−")+fmt(Math.abs(net)).replace("Rp","Rp ");
  el("recapNet").style.color=net>=0?"var(--green)":"var(--red)";

  if(recapPeriod==="date"){
    const list=byDateDesc(S.txns).filter(t=>t.date===from&&(t.kind==="expense"||t.kind==="income"));
    el("recapCount").textContent=list.length;
    el("recapList").innerHTML=list.length?list.map(txRow).join(""):`<div style="color:var(--muted);font-size:13px;padding:10px 0">No transactions on this date.</div>`;
    return;
  }
  el("recapCount").textContent=dates.length;
  el("recapList").innerHTML=dates.length?dates.map(d=>{
    const x=days[d];
    return `<div class="cat-row recap-row"><span class="c-name">${fmtDate(d)}</span><span style="flex:1"></span>
      <span class="c-val num" style="color:var(--green)">+${fmt(x.in)}</span>
      <span class="c-val num" style="color:var(--red)">−${fmt(x.out)}</span></div>`;
  }).join("")
    :`<div style="color:var(--muted);font-size:13px;padding:10px 0">No transactions in this period.</div>`;
}
function txRow(t){
  let ico,amtTxt,amtCol,meta;
  if(t.kind==="expense"){ const a=accById(t.acc); ico=icoArrowUp; amtTxt="−"+fmt(t.amt).replace("Rp","Rp "); amtCol="var(--red)"; meta=`<span class="pill">${t.cat}</span> ${a?logoMini(a):"?"}`; }
  else if(t.kind==="income"){ const a=accById(t.acc); ico=icoArrowDown; amtTxt="+"+fmt(t.amt).replace("Rp","Rp "); amtCol="var(--green)"; meta=`<span class="pill">${t.jenis}</span> ${a?logoMini(a):"?"}`; }
  else { const f=accById(t.from),to=accById(t.to); ico=icoSwap; amtTxt=fmt(t.amt); amtCol="var(--gold)"; meta=`<span class="pill">${t.jenis}</span> ${f?logoMini(f):"?"} <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2.5" style="vertical-align:-1px"><path d="M5 12h14M13 6l6 6-6 6"/></svg> ${to?logoMini(to):"?"}`; }
  return `<div class="tx" data-edit="${t.id}">
    <div class="tx-ico" style="background:${tint(amtCol)};color:${amtCol}">${ico}</div>
    <div class="tx-main"><div class="tx-desc">${esc(t.desc||"(no description)")}</div><div class="tx-meta">${meta}</div></div>
    <div class="tx-amt num" style="color:${amtCol}">${amtTxt}</div>
    <div class="tx-date num">${fmtDate(t.date)}</div>
    <button class="tx-del" data-del="${t.id}" title="Delete">${icoTrash}</button></div>`;
}
const logoMini=a=>`<span style="display:inline-flex;align-items:center;gap:4px"><span style="width:13px;height:13px;border-radius:4px;background:${a.color};display:inline-block;vertical-align:-2px"></span>${esc(a.name)}</span>`;
const emptyState=()=>`<div class="empty">${icoReceipt}<p>No transactions here yet.<br>Tap <b>Add Transaction</b> to get started.</p></div>`;

/* ---------------- modal: transaction ---------------- */
let txTab="expense";
function openTx(editId){
  const editing=editId?S.txns.find(t=>t.id===editId):null;
  if(editing) txTab=editing.kind;
  const optAcc=(sel,types)=>S.accounts.filter(a=>!types||types.includes(a.type)).map(a=>`<option value="${a.id}" ${sel===a.id?"selected":""}>${esc(a.name)}</option>`).join("");
  const optList=(arr,sel)=>arr.map(o=>`<option ${o===sel?"selected":""}>${o}</option>`).join("");
  const today=wibToday();
  function body(){
    const d=editing||lastUsed()[txTab]||{};
    const date=`<div class="field"><label>Date</label><input type="date" id="f_date" value="${d.date||today}"></div>`;
    const desc=`<div class="field"><label>Description</label><input id="f_desc" placeholder="e.g. Lunch" value="${editing?esc(d.desc||''):''}"></div>`;
    const amt =`<div class="field amt"><label>Amount (Rp)</label><input id="f_amt" inputmode="numeric" data-money placeholder="0" value="${editing?fmtNum(d.amt):''}"></div>`;
    const extras=editing?"":`<div class="row2"><div class="field"><label>Admin/Fees (Rp, optional)</label><input id="f_admin" inputmode="numeric" data-money placeholder="0"></div><div class="field"><label>Cashback (Rp, optional)</label><input id="f_cashback" inputmode="numeric" data-money placeholder="0"></div></div><div class="field"><label>Cashback goes to</label><select id="f_cashback_acc">${optAcc(null,["Bank Account","Investment"])}</select></div>`;
    if(txTab==="expense") return date+desc+`<div class="field"><label>Category</label><select id="f_cat">${optList(KATEGORI,d.cat)}</select></div>`+`<div class="field"><label>Account</label><select id="f_acc">${optAcc(d.acc)}</select></div>`+amt+`<div class="hint">Bank Account/Investment → balance decreases. Credit Card/Paylater → limit decreases & debt increases.</div>`+extras;
    if(txTab==="income") return date+desc+`<div class="field"><label>Type</label><select id="f_jenis">${optList(JENIS_MASUK,d.jenis)}</select></div>`+`<div class="field"><label>Goes to</label><select id="f_acc">${optAcc(d.acc,["Bank Account","Investment"])}</select></div>`+amt+`<div class="hint">For money coming in from outside (salary, transfer, investment returns).</div>`+extras;
    return date+desc+`<div class="field"><label>Type</label><select id="f_jenis">${optList(JENIS_TRANSFER,d.jenis)}</select></div>`+`<div class="row2"><div class="field"><label>From</label><select id="f_from">${optAcc(d.from)}</select></div><div class="field"><label>To</label><select id="f_to">${optAcc(d.to)}</select></div></div>`+amt+`<div class="hint" id="trHint">Money moves between accounts — net worth is unchanged.</div>`+extras;
  }
  sheet(`<div class="sheet-head"><h3>${editing?"Edit Transaction":"Add Transaction"}</h3>${closeBtn()}</div>
    <div class="sheet-body">
      ${editing?"":`<div class="tabs">${[["expense","Expense"],["income","Income"],["transfer","Transfer"]].map(t=>`<button class="tab ${txTab===t[0]?"active":""}" data-tab="${t[0]}">${t[1]}</button>`).join("")}</div>`}
      <div id="txFormBody">${body()}</div>
      <div class="save-row"><button class="btn btn-primary" id="saveTx" style="flex:1;justify-content:center">${editing?"Save Changes":"Save"}</button></div>
      ${editing?`<button class="del-link" id="delTx">${icoTrash} Delete transaction</button>`:""}
    </div>`);
  if(!editing) qa("[data-tab]").forEach(b=>b.onclick=()=>{
    txTab=b.dataset.tab; qa("[data-tab]").forEach(x=>x.classList.toggle("active",x.dataset.tab===txTab));
    const keep=["f_date","f_desc","f_amt","f_admin","f_cashback"].map(id=>[id,el(id)?.value]);   // switching tab keeps what you typed
    el("txFormBody").innerHTML=body(); bindTrHint();
    keep.forEach(([id,v])=>{ if(el(id)&&v) el(id).value=v; });
  });
  bindTrHint();
  el("saveTx").onclick=()=>{
    const amt=numIn("f_amt");
    if(!amt||amt<=0){ toast("Fill in the amount first",true); return; }
    const base={date:el("f_date").value,desc:el("f_desc").value.trim(),amt};
    let obj;
    if(txTab==="expense") obj={kind:"expense",...base,cat:el("f_cat").value,acc:el("f_acc").value};
    else if(txTab==="income") obj={kind:"income",...base,jenis:el("f_jenis").value,acc:el("f_acc").value};
    else { const from=el("f_from").value,to=el("f_to").value; if(from===to){toast("'From' and 'To' accounts can't be the same",true);return;} obj={kind:"transfer",...base,jenis:el("f_jenis").value,from,to}; }
    if(editing){ obj.id=editing.id; const i=S.txns.findIndex(t=>t.id===editing.id); if(i>=0) S.txns[i]=obj; else S.txns.push(obj); }   // S may have been replaced by a sync while the form was open
    else {
      saveLastUsed(txTab,{acc:obj.acc,cat:obj.cat,jenis:obj.jenis,from:obj.from,to:obj.to});
      obj.id=uid(); S.txns.push(obj);
      const mainAcc=txTab==="transfer"?el("f_from").value:el("f_acc").value;
      const admin=numIn("f_admin");
      if(admin>0) S.txns.push({id:uid(),kind:"expense",date:base.date,desc:(base.desc||"Admin/Fees")+" (admin)",amt:admin,cat:"Admin / Fees",acc:mainAcc});
      const cashback=numIn("f_cashback");
      if(cashback>0) S.txns.push({id:uid(),kind:"income",date:base.date,desc:(base.desc||"Cashback")+" (cashback)",amt:cashback,jenis:"Cashback",acc:el("f_cashback_acc").value});
    }
    persist(); close(); toast(editing?"Transaction updated":"Transaction saved");
  };
  if(editing) el("delTx").onclick=()=>{ close(); deleteTxns([editing.id],"Transaction deleted"); };
}
function bindTrHint(){
  const h=el("trHint"); if(!h) return;
  const f=el("f_from"),t=el("f_to");
  const upd=()=>{ if(f.value===t.value){h.className="hint warn"; h.textContent="⚠ 'From' and 'To' accounts are the same — pick different ones.";} else {h.className="hint"; h.textContent="Money moves between accounts — net worth is unchanged.";} };
  f.onchange=upd; t.onchange=upd; upd();
}

/* ---------------- modal: account ---------------- */
function openAcc(editId){
  const editing=editId?accById(editId):null;
  const d=editing||{type:"Bank Account",color:SWATCHES[0],base:0,mono:""};
  sheet(`<div class="sheet-head"><h3>${editing?"Edit Account":"Add Account"}</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="field"><label>Name</label><input id="a_name" placeholder="e.g. BCA Account" value="${editing?esc(d.name):''}"></div>
      <div class="field"><label>Type</label><select id="a_type">${TIPE.map(t=>`<option ${d.type===t?"selected":""}>${t}</option>`).join("")}</select></div>
      <div class="field"><label id="a_baselab">Starting Balance / Limit (Rp)</label><input id="a_base" inputmode="numeric" data-money placeholder="0" value="${d.base?fmtNum(d.base):""}"></div>
      <div class="field"><label>Logo initials</label><input id="a_mono" maxlength="4" placeholder="auto" value="${editing?esc(d.mono):''}" style="text-transform:uppercase"></div>
      <div class="field"><label>Color</label><div class="swatches" id="a_sw">${SWATCHES.map(c=>`<span class="sw ${c===d.color?"sel":""}" data-c="${c}" style="background:${c}"></span>`).join("")}</div></div>
      <div class="save-row"><button class="btn btn-primary" id="saveAcc" style="flex:1;justify-content:center">${editing?"Save":"Add"}</button></div>
      ${editing?`<button class="del-link" id="delAcc">${icoTrash} Delete account</button>`:""}
    </div>`);
  let color=d.color;
  const lab=()=>{ el("a_baselab").textContent=isDebt(el("a_type").value)?"Limit (Rp)":"Starting Balance (Rp)"; };
  el("a_type").onchange=lab; lab();
  qa("#a_sw .sw").forEach(s=>s.onclick=()=>{qa("#a_sw .sw").forEach(x=>x.classList.remove("sel"));s.classList.add("sel");color=s.dataset.c;});
  el("saveAcc").onclick=()=>{
    const name=el("a_name").value.trim(); if(!name){toast("Enter an account name",true);return;}
    const type=el("a_type").value, base=numIn("a_base");
    let mono=el("a_mono").value.trim().toUpperCase();
    if(!mono) mono=name.replace(/[^A-Za-z ]/g,"").split(/\s+/).map(w=>w[0]||"").join("").slice(0,3).toUpperCase()||name.slice(0,3).toUpperCase();
    const cur=editing&&accById(editing.id);   // look up again: a sync may have replaced S while the form was open
    if(cur) Object.assign(cur,{name,type,base,mono,color});
    else S.accounts.push({id:editing?editing.id:"a"+uid(),name,type,base,mono,color});
    persist(); close(); toast(editing?"Account updated":"Account added");
  };
  if(editing) el("delAcc").onclick=()=>{
    const n=S.txns.filter(t=>t.acc===editing.id||t.from===editing.id||t.to===editing.id).length;
    confirmBox(`Delete "${editing.name}"?`, n?`${n} related transactions will be deleted too.`:"You can undo this for a few seconds.",()=>{
      const id=editing.id, acc=accById(id)||editing, txns=S.txns.filter(t=>t.acc===id||t.from===id||t.to===id);
      S.txns=S.txns.filter(t=>!txns.includes(t)); S.accounts=S.accounts.filter(a=>a.id!==id); persist(); close();
      toast("Account deleted",false,{label:"Undo",fn:()=>{ S.accounts.push(acc); S.txns.push(...txns); persist(); toast("Account restored"); }});
    });
  };
}

/* ---------------- recurring transactions ---------------- */
function nextMonthDate(dateStr){
  const [y,m,d]=dateStr.split("-").map(Number);
  let ny=y, nm=m+1; if(nm>12){nm=1; ny++;}
  const dim=new Date(ny,nm,0).getDate();
  return `${ny}-${String(nm).padStart(2,"0")}-${String(Math.min(d,dim)).padStart(2,"0")}`;
}
function processRecurring(){
  const today=wibToday();
  let changed=false;
  S.recurring.forEach(r=>{
    while(r.nextDate<=today){
      const id="r"+r.id+r.nextDate;   // deterministic: two devices generating the same occurrence merge into one
      if(r.kind==="expense") S.txns.push({id,kind:"expense",date:r.nextDate,desc:r.desc,amt:r.amt,cat:r.cat,acc:r.acc});
      else S.txns.push({id,kind:"income",date:r.nextDate,desc:r.desc,amt:r.amt,jenis:r.jenis,acc:r.acc});
      r.nextDate=nextMonthDate(r.nextDate);
      changed=true;
    }
  });
  if(changed) persist();
}
function openRecurringList(){
  sheet(`<div class="sheet-head"><h3>Recurring Transactions</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint">Automatically recorded every month on the chosen date.</div>
      <div id="recurList">${S.recurring.length?S.recurring.map(r=>`<div class="cat-row"><span class="c-name" style="width:auto;flex:1">${esc(r.desc)} <span style="color:var(--muted)">(day ${r.nextDate.slice(8)})</span></span><span class="c-val num">${fmt(r.amt)}</span><button class="mini-btn danger" data-delrecur="${r.id}" style="margin-left:8px">${icoTrash}</button></div>`).join(""):`<div style="color:var(--muted);font-size:13px;padding:10px 0">No recurring transactions yet.</div>`}</div>
      <div class="save-row"><button class="btn btn-primary" id="addRecur" style="flex:1;justify-content:center">${icoPlus} Add</button></div>
    </div>`);
  qa("[data-delrecur]").forEach(b=>b.onclick=()=>{
    const r=S.recurring.find(x=>x.id===b.dataset.delrecur);
    S.recurring=S.recurring.filter(x=>x!==r); persist(); openRecurringList();
    toast("Recurring transaction removed",false,{label:"Undo",fn:()=>{ S.recurring.push(r); persist(); if(el("recurList")) openRecurringList(); }});
  });
  el("addRecur").onclick=openRecurringForm;
}
let recurKind="expense";
function openRecurringForm(){
  recurKind="expense";
  const optAcc=(types)=>S.accounts.filter(a=>!types||types.includes(a.type)).map(a=>`<option value="${a.id}">${esc(a.name)}</option>`).join("");
  const optList=arr=>arr.map(o=>`<option>${o}</option>`).join("");
  function body(){
    return `<div class="field"><label>Description</label><input id="r_desc" placeholder="e.g. Netflix"></div>`
      +(recurKind==="expense"?`<div class="field"><label>Category</label><select id="r_cat">${optList(KATEGORI)}</select></div>`+`<div class="field"><label>Account</label><select id="r_acc">${optAcc()}</select></div>`
        :`<div class="field"><label>Type</label><select id="r_cat">${optList(JENIS_MASUK)}</select></div>`+`<div class="field"><label>Goes to</label><select id="r_acc">${optAcc(["Bank Account","Investment"])}</select></div>`)
      +`<div class="field"><label>Amount (Rp)</label><input id="r_amt" inputmode="numeric" data-money placeholder="0"></div>`
      +`<div class="field"><label>Day of month</label><input id="r_day" type="number" min="1" max="28" value="1"></div>`;
  }
  sheet(`<div class="sheet-head"><h3>Add Recurring Transaction</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="tabs"><button class="tab active" data-rkind="expense">Expense</button><button class="tab" data-rkind="income">Income</button></div>
      <div id="recurFormBody">${body()}</div>
      <div class="save-row"><button class="btn btn-primary" id="saveRecur" style="flex:1;justify-content:center">Save</button></div>
    </div>`);
  qa("[data-rkind]").forEach(b=>b.onclick=()=>{ recurKind=b.dataset.rkind; qa("[data-rkind]").forEach(x=>x.classList.toggle("active",x.dataset.rkind===recurKind)); el("recurFormBody").innerHTML=body(); });
  el("saveRecur").onclick=()=>{
    const desc=el("r_desc").value.trim(), amt=numIn("r_amt"), day=Math.min(28,Math.max(1,parseInt(el("r_day").value,10)||1));
    if(!desc||amt<=0){ toast("Fill in the description and amount",true); return; }
    const today=wibNow(); const y=today.getUTCFullYear(), m=today.getUTCMonth()+1, dd=today.getUTCDate();
    let nextDate=`${y}-${String(m).padStart(2,"0")}-${String(day).padStart(2,"0")}`;
    if(day<dd) nextDate=nextMonthDate(nextDate);
    const r={id:uid(),kind:recurKind,desc,amt,acc:el("r_acc").value,nextDate};
    if(recurKind==="expense") r.cat=el("r_cat").value; else r.jenis=el("r_cat").value;
    S.recurring.push(r); persist(); openRecurringList(); toast("Recurring transaction added");
  };
}

/* ---------------- modal: category budgets ---------------- */
function openBudgets(){
  sheet(`<div class="sheet-head"><h3>Category Budgets</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint">Set a monthly limit per category (optional). Leave blank for no limit.</div>
      ${KATEGORI.map(c=>`<div class="field"><label>${c}</label><input data-budget="${c}" inputmode="numeric" data-money placeholder="0" value="${S.budgets[c]?fmtNum(S.budgets[c]):""}"></div>`).join("")}
      <div class="save-row"><button class="btn btn-primary" id="saveBudgets" style="flex:1;justify-content:center">Save</button></div>
    </div>`);
  el("saveBudgets").onclick=()=>{
    qa("[data-budget]").forEach(inp=>{
      const v=parseInt((inp.value||"").replace(/\D/g,""),10);
      if(v>0) S.budgets[inp.dataset.budget]=v; else delete S.budgets[inp.dataset.budget];
    });
    persist(); close(); toast("Budgets saved");
  };
}

/* ---------------- modal: settings ---------------- */
function openSettings(){
  sheet(`<div class="sheet-head"><h3>Settings</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="field"><label>Theme</label><div class="tx-controls" style="margin:0">${["system","light","dark"].map(t=>`<button class="chip ${themePref()===t?"active":""}" data-theme-set="${t}">${t[0].toUpperCase()+t.slice(1)}</button>`).join("")}</div></div>
      <div class="field"><label>Manual Balance Adjustment (Rp)</label><input id="s_adj" inputmode="numeric" value="${S.adjust||0}"></div>
      <div class="hint">Corrects net worth. Set to <b>0</b> once all balances are recorded. Can be negative.</div>
      <div class="save-row"><button class="btn btn-primary" id="saveAdj" style="flex:1;justify-content:center">Save Adjustment</button></div>
      <div style="height:18px"></div>
      <div class="save-row">
        <button class="btn btn-ghost" id="expBtn" style="flex:1;justify-content:center">${icoDownload} Download backup</button>
        <button class="btn btn-ghost" id="impBtn" style="flex:1;justify-content:center">${icoUpload} Import backup</button>
      </div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="csvBtn" style="flex:1;justify-content:center">${icoDownload} Download transactions CSV</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="recurBtn" style="flex:1;justify-content:center">${icoReset} Recurring Transactions</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="syncBtn" style="flex:1;justify-content:center">${icoCloud} Cloud Sync (GitHub)</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="pwBtn" style="flex:1;justify-content:center">${icoKey} Change password</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="resetBtn" style="flex:1;justify-content:center;color:var(--red)">${icoReset} Reset to zero (requires email code)</button></div>
      <input type="file" id="impFile" accept="application/json" class="hidden">
    </div>`);
  el("saveAdj").onclick=()=>{ S.adjust=parseInt((el("s_adj").value||"0").replace(/[^\d-]/g,""),10)||0; persist(); close(); toast("Adjustment saved"); };
  qa("[data-theme-set]").forEach(b=>b.onclick=()=>{
    try{ localStorage.setItem("saku.theme", b.dataset.themeSet); }catch(e){}
    applyTheme(); qa("[data-theme-set]").forEach(x=>x.classList.toggle("active",x===b));
  });
  el("expBtn").onclick=exportBackup;
  el("impBtn").onclick=()=>el("impFile").click();
  el("impFile").onchange=importBackup;
  el("csvBtn").onclick=exportCSV;
  el("recurBtn").onclick=openRecurringList;
  el("syncBtn").onclick=openSync;
  el("pwBtn").onclick=openChangePass;
  el("resetBtn").onclick=openReset;
}

/* ---------------- modal: GitHub sync ---------------- */
function openSync(){
  const c = SYNC || {owner:"",repo:"",path:"vault.json",branch:"main",token:""};
  const on = syncReady();
  sheet(`<div class="sheet-head"><h3>Cloud Sync (GitHub)</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint" style="margin-bottom:14px">Save your (already <b>encrypted</b>) data to a <b>private</b> GitHub repo so it can be opened on any device. Only encrypted text is sent — unreadable without your password. ${on?'<b style="color:var(--green)">Status: active.</b>':'<b style="color:var(--red)">Status: not active.</b>'}</div>
      <div class="field"><label>GitHub username / owner</label><input id="y_owner" value="${esc(c.owner||"")}" placeholder="e.g. bbkukuh"></div>
      <div class="field"><label>Repo name (PRIVATE, data only)</label><input id="y_repo" value="${esc(c.repo||"")}" placeholder="e.g. saku-data"></div>
      <div class="field"><label>File name</label><input id="y_path" value="${esc(c.path||"vault.json")}" placeholder="vault.json"></div>
      <div class="field"><label>Branch</label><input id="y_branch" value="${esc(c.branch||"main")}" placeholder="main"></div>
      <div class="field"><label>Fine-grained token (this repo only, Contents: Read &amp; Write)</label><input type="password" id="y_token" value="${esc(c.token||"")}" placeholder="github_pat_..."></div>
      <div class="hint">The token is <b>not</b> committed; it's kept only on this device. Create one at GitHub → Settings → Developer settings → Fine-grained tokens, scope it to the data repo, and grant <b>Contents: Read and write</b>.</div>
      <div class="save-row" style="margin-top:6px">
        <button class="btn btn-primary" id="y_save" style="flex:1;justify-content:center">Save &amp; connect</button>
      </div>
      ${on?`<div class="save-row"><button class="btn btn-ghost" id="y_off" style="flex:1;justify-content:center;color:var(--red)">Disconnect this device</button></div>`:""}
    </div>`);
  const readForm=()=>({
    owner:el("y_owner").value.trim(), repo:el("y_repo").value.trim(),
    path:(el("y_path").value.trim()||"vault.json"), branch:(el("y_branch").value.trim()||"main"),
    token:el("y_token").value.trim()
  });
  el("y_save").onclick=()=>{
    const cfg=readForm();
    if(!cfg.owner||!cfg.repo||!cfg.token){ toast("Owner, repo, and token are required",true); return; }
    // same target (e.g. just a new token) → keep the merge base so unsynced edits merge instead of overwrite
    if(!SYNC||["owner","repo","path","branch"].some(k=>SYNC[k]!==cfg[k])) localStorage.removeItem(BASE_KEY);
    saveSync(cfg); authPrompted=false; close(); cloudSync();
  };
  if(el("y_off")) el("y_off").onclick=()=>{ clearSync(); setSyncDot(""); close(); toast("Sync disconnected from this device"); };
}

function exportBackup(){
  const blob=new Blob([JSON.stringify(S,null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download="saku-backup-"+wibToday()+".json"; a.click();
  toast("Backup downloaded");
}
function exportCSV(){
  const rows=[["Date","Type","Description","Amount","Category/Type","Account/From","To"]];
  [...S.txns].sort((a,b)=>a.date<b.date?-1:1).forEach(t=>{
    if(t.kind==="expense") rows.push([t.date,"Expense",t.desc||"",t.amt,t.cat,accById(t.acc)?.name||"",""]);
    else if(t.kind==="income") rows.push([t.date,"Income",t.desc||"",t.amt,t.jenis,accById(t.acc)?.name||"",""]);
    else rows.push([t.date,"Transfer",t.desc||"",t.amt,t.jenis,accById(t.from)?.name||"",accById(t.to)?.name||""]);
  });
  const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
  const blob=new Blob([csv],{type:"text/csv"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download="saku-transactions-"+wibToday()+".csv"; a.click();
  toast("CSV downloaded");
}
function importBackup(e){
  const file=e.target.files[0]; if(!file) return;
  const r=new FileReader();
  r.onload=()=>{ try{
    const obj=JSON.parse(r.result);
    if(!obj.accounts||!Array.isArray(obj.txns)) throw 0;
    S=obj; normalizeState(); persist(); close(); toast("Backup imported");
  }catch(err){ toast("Invalid backup file",true); } };
  r.readAsText(file);
}

function openChangePass(){
  sheet(`<div class="sheet-head"><h3>Change Password</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="field"><label>New password</label><input type="password" id="p_new" placeholder="At least 6 characters"></div>
      <div class="field"><label>Confirm</label><input type="password" id="p_new2" placeholder="Confirm password"></div>
      <div class="hint">Your data will be re-encrypted with the new password. Don't forget it — without the password, the data can't be unlocked.</div>
      <div class="save-row"><button class="btn btn-primary" id="p_save" style="flex:1;justify-content:center">Save</button></div>
    </div>`);
  el("p_save").onclick=async()=>{
    const a=el("p_new").value,b=el("p_new2").value;
    if(a.length<6){toast("Password must be at least 6 characters",true);return;}
    if(a!==b){toast("Passwords don't match",true);return;}
    await changePassword(a); close(); toast("Password changed");
  };
}

/* ---------------- reset (code via email) ---------------- */
let pendingCode=null;
async function sendResetCode(code){
  if(!CONFIG.web3formsKey) return {ok:false,reason:"nokey"};
  try{
    const res=await fetch("https://api.web3forms.com/submit",{
      method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json"},
      body:JSON.stringify({ access_key:CONFIG.web3formsKey, subject:"Saku Reset Code", from_name:"Saku", email:CONFIG.resetEmail,
        message:`Code to reset your Saku data to zero: ${code}\n\nIgnore this email if you did not request a reset.` })
    });
    const j=await res.json();
    return {ok:!!j.success,reason:j.message||""};
  }catch(e){ return {ok:false,reason:"network"}; }
}
function doResetToZero(){
  S.txns=[]; S.accounts.forEach(a=>a.base=0); S.adjust=0;
  persist(); close(); toast("All data reset to zero");
}
function openReset(){
  if(!CONFIG.web3formsKey){
    sheet(`<div class="sheet-head"><h3>Reset Not Set Up</h3>${closeBtn()}</div>
      <div class="sheet-body">
        <div class="preview">Sending a code to <b>${esc(CONFIG.resetEmail||"your email")}</b> hasn't been configured yet.<br><br>
        Sign up at <b>web3forms.com</b> with that email, copy the <b>access key</b>, then paste it into <b>config.js</b> (see README).<br><br>
        Or, use the backup option below to reset with your password instead.</div>
        <div class="save-row"><button class="btn btn-ghost" id="r_pw" style="flex:1;justify-content:center;color:var(--red)">Reset with password</button></div>
      </div>`);
    el("r_pw").onclick=()=>resetWithPassword();
    return;
  }
  sheet(`<div class="sheet-head"><h3>Reset to Zero</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="preview">For security, a confirmation code will be sent to <b>${esc(CONFIG.resetEmail)}</b>. All transactions & balances will be zeroed out (accounts stay).</div>
      <div class="save-row"><button class="btn btn-primary" id="r_send" style="flex:1;justify-content:center;background:var(--red)">Send code to email</button></div>
    </div>`);
  el("r_send").onclick=async()=>{
    el("r_send").textContent="Sending…"; el("r_send").disabled=true;
    pendingCode=String(Math.floor(100000+Math.random()*900000));
    const r=await sendResetCode(pendingCode);
    if(!r.ok){ toast("Failed to send email: "+(r.reason||"try again"),true); el("r_send").textContent="Send code to email"; el("r_send").disabled=false; return; }
    sheet(`<div class="sheet-head"><h3>Enter Code</h3>${closeBtn()}</div>
      <div class="sheet-body">
        <div class="preview">A 6-digit code was sent to <b>${esc(CONFIG.resetEmail)}</b>. Check your inbox/spam, then enter it below.</div>
        <div class="field"><label>Confirmation code</label><input id="r_code" inputmode="numeric" maxlength="6" placeholder="######" style="text-align:center;letter-spacing:.3em;font-family:'Space Grotesk'"></div>
        <div class="save-row"><button class="btn btn-primary" id="r_confirm" style="flex:1;justify-content:center;background:var(--red)">Reset now</button></div>
      </div>`);
    el("r_confirm").onclick=()=>{ if(el("r_code").value.trim()===pendingCode){ pendingCode=null; doResetToZero(); } else toast("Wrong code",true); };
  };
}
function resetWithPassword(){
  sheet(`<div class="sheet-head"><h3>Confirm Reset</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="preview">Enter your password to zero out all transactions & balances.</div>
      <div class="field"><label>Password</label><input type="password" id="r_pwf" placeholder="Password"></div>
      <div class="save-row"><button class="btn btn-primary" id="r_pwgo" style="flex:1;justify-content:center;background:var(--red)">Reset to zero</button></div>
    </div>`);
  el("r_pwgo").onclick=async()=>{
    try{ const v=readVault(); await decryptObj(await deriveKey(el("r_pwf").value, unb64(v.salt)), v.blob); doResetToZero(); }
    catch(e){ toast("Wrong password",true); }
  };
}

/* ---------------- confirm + modal plumbing ---------------- */
function confirmBox(title,msg,onYes){
  sheet(`<div class="sheet-head"><h3>${esc(title)}</h3></div>
    <div class="sheet-body"><div class="preview" style="margin-bottom:18px">${msg}</div>
    <div class="save-row"><button class="btn btn-ghost" id="cNo" style="flex:1;justify-content:center">Cancel</button>
    <button class="btn btn-primary" id="cYes" style="flex:1;justify-content:center;background:var(--red)">Delete</button></div></div>`);
  el("cNo").onclick=close; el("cYes").onclick=onYes;
}
let sheetDirty=false, downOnScrim=false;
function sheet(html){
  const wasOpen=el("scrim").classList.contains("show");
  el("sheet").innerHTML=html; el("scrim").classList.add("show"); document.body.classList.add("modal-open"); sheetDirty=false;
  qa("[data-close]").forEach(b=>b.onclick=close);
  if(!wasOpen||!history.state?.sheet) history.pushState({sheet:1},"");   // phone Back closes the sheet instead of leaving the app
}
function hideSheet(){ el("scrim").classList.remove("show"); document.body.classList.remove("modal-open"); }
function close(){ hideSheet(); if(history.state?.sheet) history.back(); }
// Backdrop tap / Esc never discard typed input — only × (or Back) does
function softClose(){ if(sheetDirty) toast("Unsaved changes — tap × to discard",true); else close(); }
addEventListener("popstate",()=>{ if(!history.state?.sheet) hideSheet(); });
el("sheet").addEventListener("input",()=>{ sheetDirty=true; });
// a drag that starts inside the sheet (e.g. selecting text) and ends on the backdrop is not a backdrop tap
el("scrim").addEventListener("pointerdown",e=>{ downOnScrim=e.target===el("scrim"); });
const closeBtn=()=>`<button class="icon-btn" data-close style="box-shadow:none;background:var(--bg)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg></button>`;

/* ---------------- toast ---------------- */
let toastT;
function toast(msg,err,action){
  const t=el("toast");
  t.innerHTML=(err?icoWarn:icoCheck)+`<span>${esc(msg)}</span>`+(action?`<button class="toast-act">${esc(action.label)}</button>`:"");
  if(action) t.querySelector(".toast-act").onclick=()=>{ t.classList.remove("show"); action.fn(); };
  t.classList.add("show"); clearTimeout(toastT); toastT=setTimeout(()=>t.classList.remove("show"),action?6000:2400);
}
function deleteTxns(ids,msg){
  const gone=S.txns.filter(t=>ids.includes(t.id));
  S.txns=S.txns.filter(t=>!ids.includes(t.id)); persist();
  toast(msg,false,{label:"Undo",fn:()=>{ S.txns.push(...gone); persist(); toast("Transaction restored"); }});
}

/* ---------------- icons ---------------- */
const icoPlus=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>`;
const icoTrash=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>`;
const icoEdit=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 013 3L7 19l-4 1 1-4z"/></svg>`;
const icoArrowUp=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7M9 7h8v8"/></svg>`;
const icoArrowDown=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 7L7 17M15 17H7V9"/></svg>`;
const icoSwap=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 10h14l-4-4M17 14H3l4 4"/></svg>`;
const icoTrendUp=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8M15 7h6v6"/></svg>`;
const icoChart=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>`;
const icoCard=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2.5"/><path d="M2 10h20"/></svg>`;
const icoShield=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>`;
const icoReceipt=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 3v18l2-1 2 1 2-1 2 1 2-1 2 1V3l-2 1-2-1-2 1-2-1-2 1z"/><path d="M9 8h6M9 12h6"/></svg>`;
const icoCheck=`<svg viewBox="0 0 24 24" fill="none" stroke="#7ee0a8" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>`;
const icoWarn=`<svg viewBox="0 0 24 24" fill="none" stroke="#ffb4a8" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>`;
const icoDownload=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 11l5 5 5-5M5 21h14"/></svg>`;
const icoUpload=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21V9M7 13l5-5 5 5M5 3h14"/></svg>`;
const icoKey=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.5 12.5L20 3M16 7l3 3M14 9l3 3"/></svg>`;
const icoReset=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 109-9 9 9 0 00-7 3.3M3 4v3.3H6.3"/></svg>`;
const icoCloud=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 18a4 4 0 01-.5-7.97A6 6 0 0118 9.5 3.5 3.5 0 0117.5 18z"/><path d="M12 12v6M9.5 15.5L12 18l2.5-2.5"/></svg>`;

/* ---------------- helpers ---------------- */
function el(id){return document.getElementById(id);}
function qa(s){return [...document.querySelectorAll(s)];}
function lastUsed(){ try{ return JSON.parse(localStorage.getItem("saku.last.v1"))||{}; }catch(e){ return {}; } }
function saveLastUsed(tab,v){ try{ localStorage.setItem("saku.last.v1", JSON.stringify({...lastUsed(),[tab]:v})); }catch(e){} }
function numIn(id){return parseInt((el(id).value||"").replace(/\D/g,""),10)||0;}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function tint(v){return `color-mix(in srgb, ${v} 14%, transparent)`;}   // works in light & dark
function themePref(){ try{ return localStorage.getItem("saku.theme")||"system"; }catch(e){ return "system"; } }

/* ---------------- events ---------------- */
document.addEventListener("click",e=>{
  const ed=e.target.closest("[data-del]"); if(ed){ e.stopPropagation(); deleteTxns([ed.dataset.del],"Transaction deleted"); return; }
  const hm=e.target.closest(".hit[data-month]"); if(hm){ repMonth=hm.dataset.month; render(); return; }
  const da=e.target.closest("[data-delacc]"); if(da){e.stopPropagation(); openAcc(da.dataset.delacc); setTimeout(()=>{const b=el("delAcc"); if(b)b.click();},0); return;}
  const ea=e.target.closest("[data-editacc]"); if(ea){e.stopPropagation(); openAcc(ea.dataset.editacc); return;}
  const ee=e.target.closest("[data-edit]"); if(ee){ openTx(ee.dataset.edit); return;}
  const fl=e.target.closest("[data-filter]"); if(fl){ filter=fl.dataset.filter; render(); return;}
  const rf=e.target.closest("[data-recapf]"); if(rf){ recapPeriod=rf.dataset.recapf; render(); return;}
  if(e.target.closest("#addAccBtn")) openAcc();
  if(e.target===el("scrim")&&downOnScrim) softClose();
});
// Money fields: live thousand separators ("15000000" → "15.000.000"), caret stays put
document.addEventListener("input",e=>{
  const i=e.target; if(!i.matches("[data-money]")) return;
  const before=i.value.slice(0,i.selectionStart).replace(/\D/g,"").length;
  const d=i.value.replace(/\D/g,"").replace(/^0+(?=\d)/,"");
  i.value=d?fmtNum(d):"";
  let pos=0; for(let n=0; pos<i.value.length&&n<before; pos++) if(/\d/.test(i.value[pos])) n++;
  i.setSelectionRange(pos,pos);
});

/* ---------------- lock screen ---------------- */
function showLockError(msg){ el("lockErr").textContent=msg||""; }
function setupLockUI(){
  const hasVault=!!readVault();
  el("lockTitle").textContent=hasVault?"Unlock Saku":"Create Password";
  el("lockDesc").textContent=hasVault?"Enter your password to unlock your financial records.":"Create a password to lock & encrypt your data on this device.";
  el("lockPass2").classList.toggle("hidden",hasVault);
  el("lockBtn").textContent=hasVault?"Unlock":"Save & Unlock";
  el("lockNote").textContent=hasVault?"Data is encrypted (AES-256). Without the password, it can't be read.":"Write down your password carefully. If you forget it, the data can't be recovered.";
  el("lockPass").value=""; el("lockPass2").value=""; showLockError("");
  el("lockCloud").classList.toggle("hidden", false);   // always available to connect a device
  setTimeout(()=>el("lockPass").focus(),60);
}

/* Connect a new device: pull the vault from GitHub, then unlock with the password */
function openCloudConnect(){
  const c = SYNC || {owner:SYNCDEF.owner||"",repo:SYNCDEF.repo||"",path:SYNCDEF.path||"vault.json",branch:SYNCDEF.branch||"main",token:""};
  sheet(`<div class="sheet-head"><h3>Connect to GitHub</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint" style="margin-bottom:14px">Pull data from your private GitHub repo, then unlock with the same password used on your other device.</div>
      <div class="field"><label>GitHub username / owner</label><input id="cc_owner" value="${esc(c.owner)}" placeholder="e.g. bbkukuh"></div>
      <div class="field"><label>Repo name (private)</label><input id="cc_repo" value="${esc(c.repo)}" placeholder="saku-data"></div>
      <div class="field"><label>File name</label><input id="cc_path" value="${esc(c.path)}" placeholder="vault.json"></div>
      <div class="field"><label>Branch</label><input id="cc_branch" value="${esc(c.branch)}" placeholder="main"></div>
      <div class="field"><label>Fine-grained token</label><input type="password" id="cc_token" value="${esc(c.token||"")}" placeholder="github_pat_..."></div>
      <div class="field"><label>Saku password</label><input type="password" id="cc_pass" placeholder="The same password"></div>
      <div class="save-row"><button class="btn btn-primary" id="cc_go" style="flex:1;justify-content:center">Pull &amp; Unlock</button></div>
    </div>`);
  el("cc_go").onclick=async()=>{
    const cfg={owner:el("cc_owner").value.trim(),repo:el("cc_repo").value.trim(),
      path:(el("cc_path").value.trim()||"vault.json"),branch:(el("cc_branch").value.trim()||"main"),
      token:el("cc_token").value.trim()};
    const pass=el("cc_pass").value;
    if(!cfg.owner||!cfg.repo||!cfg.token){ toast("Owner, repo, and token are required",true); return; }
    if(!pass){ toast("Enter the password",true); return; }
    saveSync(cfg); PASSWORD=pass;
    try{
      const {wrap,sha}=await ghGet();
      if(!wrap){ toast("Repo is empty — no data on GitHub yet",true); return; }
      const salt=unb64(wrap.salt), key=await deriveKey(pass,salt);
      S=await decryptObj(key,wrap.blob);          // throws if the password is wrong
      normalizeState();
      SALT=salt; CRYPTOKEY=key;
      localStorage.setItem(VAULT_KEY, JSON.stringify(wrap)); setBase(sha, wrap);
      close(); enterApp(); setSyncDot("ok"); toast("Connected — data pulled from GitHub");
    }catch(e){
      PASSWORD=null;
      if(e.message==="AUTH") toast("Token/permission rejected by GitHub",true);
      else if(e.name==="OperationError"||/decrypt/i.test(e.message)) toast("Wrong password for this data",true);
      else toast("Failed to connect — check owner/repo/branch",true);
    }
  };
}
async function tryUnlock(){
  const hasVault=!!readVault(); const pass=el("lockPass").value;
  showLockError("");
  if(!hasVault){
    if(pass.length<6){ showLockError("Password must be at least 6 characters."); return; }
    if(pass!==el("lockPass2").value){ showLockError("Passwords don't match."); return; }
    await createVault(pass); enterApp();
  } else {
    try{ await unlockVault(pass); enterApp(); }
    catch(e){ showLockError("Wrong password."); el("lockPass").select(); }
  }
}
function enterApp(){
  el("lockScreen").classList.add("hidden");
  el("app").classList.remove("hidden");
  processRecurring();
  render();
  saveSession();
  cloudSync();
}
function lockNow(){ try{ sessionStorage.removeItem(SESSION_KEY); }catch(e){} CRYPTOKEY=null; PASSWORD=null; S=null; el("app").classList.add("hidden"); el("lockScreen").classList.remove("hidden"); setupLockUI(); }

el("lockBtn").onclick=tryUnlock;
el("lockPass").addEventListener("keydown",e=>{if(e.key==="Enter"){ if(readVault()) tryUnlock(); else el("lockPass2").focus(); }});
el("lockPass2").addEventListener("keydown",e=>{if(e.key==="Enter")tryUnlock();});
el("btnLock").onclick=lockNow;
el("lockCloud").onclick=openCloudConnect;
el("btnAdd").onclick=()=>{txTab="expense";openTx();};
el("fab").onclick=()=>{txTab="expense";openTx();};
el("btnSettings").onclick=openSettings;
el("btnBudget").onclick=openBudgets;
el("txSearch").oninput=()=>{txSearch=el("txSearch").value.trim(); render();};
el("txFrom").onchange=()=>{txFrom=el("txFrom").value; render();};
el("txTo").onchange=()=>{txTo=el("txTo").value; render();};
el("recapDate").onchange=()=>{recapDate=el("recapDate").value; render();};
el("recapFrom").onchange=()=>{recapFrom=el("recapFrom").value; render();};
el("recapTo").onchange=()=>{recapTo=el("recapTo").value; render();};
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&el("scrim").classList.contains("show"))softClose();});
el("syncStatus").onclick=syncStatus;
el("mPrev").onclick=()=>{ repMonth=shiftMonth(repMonth||wibToday().slice(0,7),-1); render(); };
el("mNext").onclick=()=>{ repMonth=shiftMonth(repMonth||wibToday().slice(0,7),1); render(); };
el("mChart").addEventListener("pointermove",e=>chartTip(e.target.closest(".hit")));
el("mChart").addEventListener("pointerleave",()=>chartTip(null));
el("mChart").addEventListener("focusin",e=>chartTip(e.target.closest(".hit")));
el("mChart").addEventListener("focusout",()=>chartTip(null));
el("mChart").addEventListener("keydown",e=>{ const h=e.target.closest(".hit"); if(h&&(e.key==="Enter"||e.key===" ")){ e.preventDefault(); repMonth=h.dataset.month; render(); } });
let resizeT; addEventListener("resize",()=>{ clearTimeout(resizeT); resizeT=setTimeout(()=>{ if(S) renderMonthly(); },150); });

/* ---------------- boot ---------------- */
if(!(window.crypto&&crypto.subtle)){
  document.getElementById("lockDesc").textContent="This browser doesn't support encryption. Open via https (GitHub Pages) or localhost.";
}
setupLockUI();
restoreSession().then(ok=>{ if(ok) enterApp(); });
