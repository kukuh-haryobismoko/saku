"use strict";
/* ===========================================================
   Saku — catatan keuangan (statis, terenkripsi di perangkat)
   =========================================================== */
const CONFIG = window.SAKU_CONFIG || { resetEmail:"", web3formsKey:"" };
const VAULT_KEY = "saku.vault.v1";
const SYNC_KEY  = "saku.sync.v1";              // konfigurasi sinkronisasi (lokal, tidak di-commit)
const SYNCDEF   = (CONFIG.sync) || {};          // default non-rahasia dari config.js (owner/repo/path)
let   PASSWORD  = null;                          // disimpan di memori sesi utk derive key vault remote
let   SYNC      = null;                          // {owner,repo,path,branch,token}
let   REMOTE_SHA= null;                          // sha file terakhir di GitHub (utk update aman)
let   syncBusy  = false, syncDirty = false;      // pengatur antrian push

/* ---------------- crypto (AES-GCM + PBKDF2) ---------------- */
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveKey(password, salt){
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" },
    base, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
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
  return wrap;
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
  S = await decryptObj(key, v.blob);   // throws if wrong password
  normalizeState();
  CRYPTOKEY = key;
  PASSWORD = password;
}
async function changePassword(newPass){
  SALT = crypto.getRandomValues(new Uint8Array(16));
  CRYPTOKEY = await deriveKey(newPass, SALT);
  PASSWORD = newPass;
  await writeVault();
  cloudPush();
}

/* ============================================================
   SINKRONISASI CLOUD via GitHub Contents API
   ------------------------------------------------------------
   Menyimpan file vault (SUDAH terenkripsi AES-256) ke repo
   GitHub PRIVAT. Token tidak pernah di-commit; ditempel
   per-perangkat & disimpan di localStorage. Yang terkirim ke
   GitHub hanya ciphertext — tanpa kata sandi, tak terbaca.
   ============================================================ */
function loadSync(){
  try{ const s=JSON.parse(localStorage.getItem(SYNC_KEY)); if(s&&s.token){ SYNC=s; return s; } }catch(e){}
  if(SYNCDEF.owner&&SYNCDEF.repo){ SYNC={owner:SYNCDEF.owner,repo:SYNCDEF.repo,path:SYNCDEF.path||"vault.json",branch:SYNCDEF.branch||"main",token:""}; }
  return SYNC;
}
function saveSync(cfg){ SYNC=cfg; localStorage.setItem(SYNC_KEY, JSON.stringify(cfg)); }
function clearSync(){ SYNC=null; REMOTE_SHA=null; localStorage.removeItem(SYNC_KEY); loadSync(); }
function syncReady(){ return !!(SYNC&&SYNC.owner&&SYNC.repo&&SYNC.path&&SYNC.token); }

function ghHeaders(){ return { "Authorization":"Bearer "+SYNC.token, "Accept":"application/vnd.github+json", "X-GitHub-Api-Version":"2022-11-28" }; }
function ghUrl(){ return `https://api.github.com/repos/${SYNC.owner}/${SYNC.repo}/contents/${SYNC.path.split("/").map(encodeURIComponent).join("/")}`; }
const utf8b64  = s => b64(enc.encode(s));
const b64utf8  = s => dec.decode(unb64(s.replace(/\n/g,"")));

async function ghGet(){
  const r = await fetch(ghUrl()+`?ref=${encodeURIComponent(SYNC.branch||"main")}`, {headers:ghHeaders()});
  if(r.status===404){ REMOTE_SHA=null; return {wrap:null,sha:null}; }
  if(r.status===401||r.status===403) throw new Error("AUTH");
  if(!r.ok) throw new Error("HTTP "+r.status);
  const j = await r.json(); REMOTE_SHA=j.sha;
  return { wrap: JSON.parse(b64utf8(j.content)), sha:j.sha };
}
async function ghPut(wrap){
  const body = { message:"saku sync "+new Date().toISOString(),
                 content: utf8b64(JSON.stringify(wrap)), branch: SYNC.branch||"main" };
  if(REMOTE_SHA) body.sha=REMOTE_SHA;
  let r = await fetch(ghUrl(), {method:"PUT", headers:{...ghHeaders(),"Content-Type":"application/json"}, body:JSON.stringify(body)});
  if(r.status===409||r.status===422){           // sha basi → ambil sha terbaru lalu coba lagi
    await ghGet(); body.sha=REMOTE_SHA;
    r = await fetch(ghUrl(), {method:"PUT", headers:{...ghHeaders(),"Content-Type":"application/json"}, body:JSON.stringify(body)});
  }
  if(r.status===401||r.status===403) throw new Error("AUTH");
  if(!r.ok) throw new Error("HTTP "+r.status);
  const j = await r.json(); REMOTE_SHA = j.content && j.content.sha;
}

// Unggah vault lokal ke GitHub (antri bila sedang sibuk)
function cloudPush(){
  if(!syncReady()) return;
  if(syncBusy){ syncDirty=true; return; }
  syncBusy=true; setSyncDot("sync");
  const wrap = readVault();
  ghPut(wrap)
    .then(()=>{ setSyncDot("ok"); })
    .catch(e=>{ setSyncDot("err"); if(e.message==="AUTH") toast("Token GitHub ditolak — perbarui di Pengaturan",true); else toast("Gagal sinkron ke GitHub",true); })
    .finally(()=>{ syncBusy=false; if(syncDirty){ syncDirty=false; cloudPush(); } });
}

// Tarik vault dari GitHub. adopt=true → pakai bila remote lebih baru (untuk perangkat lain).
async function cloudPull(adopt){
  if(!syncReady()) return {status:"off"};
  const {wrap} = await ghGet();
  if(!wrap) return {status:"empty"};
  const local = readVault();
  const remoteNewer = !local || (wrap.updatedAt||0) > (local.updatedAt||0);
  if(adopt && remoteNewer){
    if(PASSWORD==null) throw new Error("LOCKED");
    const salt = unb64(wrap.salt);
    const key  = await deriveKey(PASSWORD, salt);
    const data = await decryptObj(key, wrap.blob);   // throws bila kata sandi beda
    S=data; normalizeState(); SALT=salt; CRYPTOKEY=key;
    localStorage.setItem(VAULT_KEY, JSON.stringify(wrap));
    return {status:"pulled"};
  }
  return {status: remoteNewer?"remote-newer":"up-to-date"};
}

// Auto-pull saat masuk app
async function cloudAutoPull(){
  if(!syncReady()) return;
  setSyncDot("sync");
  try{
    const r = await cloudPull(true);
    setSyncDot("ok");
    if(r.status==="pulled"){ render(); toast("Data terbaru ditarik dari GitHub"); }
    else if(r.status==="empty"){ cloudPush(); }   // repo masih kosong → unggah lokal
  }catch(e){
    setSyncDot("err");
    if(e.message==="AUTH") toast("Token GitHub ditolak — perbarui di Pengaturan",true);
    else if(e.message!=="LOCKED") toast("Gagal menarik dari GitHub",true);
  }
}
function setSyncDot(state){
  const d=el("syncDot"); if(!d) return;
  d.className="sync-dot "+(state||"");
  d.title={sync:"Menyinkron…",ok:"Tersinkron ke GitHub",err:"Sinkron gagal"}[state]||"";
}
loadSync();


/* ---------------- constants ---------------- */
const KATEGORI=["Makanan & Minuman","Transportasi","Belanja","Tagihan & Utilitas","Kesehatan","Hiburan","Pendidikan","Tabungan & Investasi","Cicilan / Pinjaman","Donasi & Hadiah","Admin / Biaya","Lainnya"];
const JENIS_MASUK=["Gaji","Bonus / THR","Pendapatan Usaha","Hasil Investasi","Transfer Masuk","Cashback","Lainnya"];
const JENIS_TRANSFER=["Pembayaran Kartu Kredit","Investasi","Pencairan Investasi","Transfer Antar Rekening"];
const TIPE=["Rekening","Investasi","Kartu Kredit","Paylater"];
const SWATCHES=["#1B3A4B","#0A5DAE","#00529C","#003D79","#5B3FD6","#00A19A","#1BA876","#1E7E34","#B7791F","#EE4D2D","#7A1F2B","#C0392B"];
const isAsset=t=>t==="Rekening"||t==="Investasi";
const isDebt =t=>t==="Kartu Kredit"||t==="Paylater";

/* ---------------- seed (template tanpa saldo pribadi) ---------------- */
function seed(){
  const A=[
    ["Rekening BCA","Rekening",0,"#0A5DAE","BCA"],
    ["Rekening Mandiri","Rekening",0,"#003D79","MDR"],
    ["Dompet Tunai","Rekening",0,"#1E7E34","TUN"],
    ["Rekening Krom","Rekening",0,"#5B3FD6","KRM"],
    ["Rekening Seabank","Rekening",0,"#00A19A","SEA"],
    ["Reksa Dana Bibit","Investasi",0,"#1BA876","BBT"],
    ["Saham / RDN","Investasi",0,"#B7791F","SHM"],
    ["Kartu Kredit BCA","Kartu Kredit",9000000,"#0A5DAE","BCA"],
    ["Kartu Kredit BRI","Kartu Kredit",25000000,"#00529C","BRI"],
    ["Kartu Kredit CIMB","Kartu Kredit",3000000,"#7A1F2B","CMB"],
    ["Shopee Paylater","Paylater",25500000,"#EE4D2D","SPL"],
  ];
  return {
    accounts: A.map((a,i)=>({ id:"a"+(i+1), name:a[0], type:a[1], base:a[2], color:a[3], mono:a[4] })),
    txns: [], adjust: 0, budgets: {}, recurring: []
  };
}
function normalizeState(){ S.budgets=S.budgets||{}; S.recurring=S.recurring||[]; }
function uid(){ return "t"+Math.random().toString(36).slice(2,9)+Date.now().toString(36).slice(-3); }

/* ---------------- state ---------------- */
let S=null, filter="all", txSearch="", txFrom="", txTo="";
async function persist(){ await writeVault(); render(); cloudPush(); }

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
    if(a.type==="Rekening")cash+=x.balance;
    else if(a.type==="Investasi")invest+=x.balance;
    else { debt+=x.debt; limit+=x.balance; }
  });
  const assets=cash+invest, net=assets-debt+(S.adjust||0);
  return {m,cash,invest,debt,limit,assets,net};
}
const accById=id=>S.accounts.find(a=>a.id===id);
const fmt=n=>new Intl.NumberFormat("id-ID",{style:"currency",currency:"IDR",maximumFractionDigits:0}).format(Math.round(n||0));
const fmtShort=n=>{const v=Math.abs(n); if(v>=1e9)return (n/1e9).toFixed(1).replace(".0","")+" M"; if(v>=1e6)return (n/1e6).toFixed(1).replace(".0","")+" jt"; if(v>=1e3)return Math.round(n/1e3)+" rb"; return Math.round(n);};
const fmtDate=d=>new Date(d+"T00:00:00").toLocaleDateString("id-ID",{day:"numeric",month:"short"});

/* ---------------- render ---------------- */
function render(){
  const c=calc();
  el("netWorth").textContent=fmt(c.net);
  el("heroMeta").innerHTML=`Total aset <b>${fmt(c.assets)}</b> &nbsp;·&nbsp; Utang <b>${fmt(c.debt)}</b>`;
  const total=Math.max(c.assets,1);
  const segs=[["Tunai & Rekening",c.cash,"var(--teal)"],["Investasi",c.invest,"var(--gold)"]];
  el("compTrack").innerHTML=segs.map(s=>`<i class="comp-seg" style="width:${Math.max(0,s[1]/total*100)}%;background:${s[2]}"></i>`).join("");
  el("compLegend").innerHTML=segs.map(s=>`<span class="lg"><span class="dot" style="background:${s[2]}"></span>${s[0]} <b>${fmt(s[1])}</b></span>`).join("")
     +`<span class="lg"><span class="dot" style="background:var(--red)"></span>Utang <b>${fmt(c.debt)}</b></span>`;

  const nets=[]; const now=new Date();
  for(let i=5;i>=0;i--){
    const d=new Date(now.getFullYear(),now.getMonth()-i+1,0);
    nets.push(i===0?c.net:calc(d.toISOString().slice(0,10)).net);
  }
  const lo=Math.min(...nets), hi=Math.max(...nets), span=Math.max(1,hi-lo);
  const pts=nets.map((v,i)=>`${i/(nets.length-1)*300},${52-(v-lo)/span*48}`).join(" ");
  el("trendChart").innerHTML=`<polyline points="${pts}" fill="none" stroke="#7ee0a8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>`;

  const kpis=[
    ["Total Aset",c.assets,"var(--green)",icoTrendUp],
    ["Investasi",c.invest,"var(--gold)",icoChart,S.accounts.filter(a=>a.type==="Investasi").length+" akun"],
    ["Utang Kartu",c.debt,"var(--red)",icoCard],
    ["Sisa Limit",c.limit,"var(--teal)",icoShield],
  ];
  el("kpis").innerHTML=kpis.map(k=>`<div class="kpi"><div class="k-top"><span class="k-ico" style="background:${tint(k[2])};color:${k[2]}">${k[3]}</span>${k[0]}</div><div class="k-val" style="color:${k[2]}">${fmt(k[1])}</div>${k[4]?`<div class="k-sub">${k[4]}</div>`:""}</div>`).join("");

  el("accCount").textContent=S.accounts.length;
  el("accGrid").innerHTML=S.accounts.map(a=>{
    const x=c.m[a.id]; let foot="", bar="";
    if(isDebt(a.type)){
      const pct=Math.min(100,x.debt/Math.max(a.base,1)*100);
      foot=`Limit ${fmtShort(a.base)} · sisa <b style="color:var(--teal)">${fmt(x.balance)}</b>`;
      const col=pct>80?"var(--red)":pct>50?"var(--gold)":"var(--teal)";
      bar=`<div class="usebar"><i style="width:${pct}%;background:${col}"></i></div>`;
    } else foot=`Saldo awal ${fmtShort(a.base)}`;
    const balColor=isDebt(a.type)?(x.debt>0?"var(--red)":"var(--ink)"):(x.balance<0?"var(--red)":"var(--ink)");
    const big=isDebt(a.type)?(x.debt>0?"−"+fmt(x.debt).replace("Rp","Rp "):fmt(0)):fmt(x.balance);
    return `<div class="acc">
      <div class="acc-actions">
        <button class="mini-btn" data-editacc="${a.id}" title="Ubah">${icoEdit}</button>
        <button class="mini-btn danger" data-delacc="${a.id}" title="Hapus">${icoTrash}</button></div>
      <div class="acc-top"><div class="logo" style="background:${a.color}">${esc(a.mono)}</div>
        <div><div class="acc-name">${esc(a.name)}</div><div class="acc-type">${a.type}</div></div></div>
      <div class="acc-bal num" style="color:${balColor}">${big}</div>
      <div class="acc-foot">${foot}</div>${bar}</div>`;
  }).join("")+`<button class="add-acc" id="addAccBtn">${icoPlus}<span>Tambah Sumber Dana</span></button>`;

  const monthKey=new Date().toISOString().slice(0,7);
  const mt=S.txns.filter(t=>t.date.slice(0,7)===monthKey);
  const catTotals={}; let outSum=0,inSum=0;
  mt.forEach(t=>{ if(t.kind==="expense"){catTotals[t.cat]=(catTotals[t.cat]||0)+t.amt; outSum+=t.amt;} if(t.kind==="income") inSum+=t.amt; });
  const cats=Object.entries(catTotals).sort((a,b)=>b[1]-a[1]);
  const maxCat=Math.max(1,...cats.map(c=>c[1]));
  el("catSub").textContent=new Date(monthKey+"-01T00:00:00").toLocaleDateString("id-ID",{month:"long",year:"numeric"});
  el("catList").innerHTML=cats.length?cats.map(([n,v])=>{
    const b=S.budgets[n];
    const pct=Math.min(100,v/maxCat*100);
    const barCol=b&&v>b?"var(--red)":undefined;
    return `<div class="cat-row"><span class="c-name">${n}</span><span class="c-bar"><i style="width:${pct}%${barCol?";background:"+barCol:""}"></i></span><span class="c-val num">${fmt(v)}${b?`<span class="c-budget">/ ${fmt(b)}</span>`:""}</span></div>`;
  }).join("")
    :`<div style="color:var(--muted);font-size:13px;padding:10px 0">Belum ada pengeluaran bulan ini.</div>`;
  el("flowIn").textContent=fmt(inSum); el("flowOut").textContent=fmt(outSum);
  const net=inSum-outSum; el("flowNet").textContent=(net>=0?"":"−")+fmt(Math.abs(net)).replace("Rp","Rp ");
  el("flowNet").style.color=net>=0?"var(--green)":"var(--red)";

  const counts={all:S.txns.length,expense:0,income:0,transfer:0};
  S.txns.forEach(t=>counts[t.kind]++);
  const Fr=[["all","Semua"],["expense","Pengeluaran"],["income","Pemasukan"],["transfer","Transfer & Investasi"]];
  el("txFilters").innerHTML=Fr.map(f=>`<button class="chip ${filter===f[0]?"active":""}" data-filter="${f[0]}">${f[1]}<span style="opacity:.6">${counts[f[0]]}</span></button>`).join("");

  el("txCount").textContent=S.txns.length;
  let list=[...S.txns].sort((a,b)=>a.date<b.date?1:a.date>b.date?-1:0);
  if(filter!=="all") list=list.filter(t=>t.kind===filter);
  if(txSearch) list=list.filter(t=>(t.desc||"").toLowerCase().includes(txSearch.toLowerCase()));
  if(txFrom) list=list.filter(t=>t.date>=txFrom);
  if(txTo) list=list.filter(t=>t.date<=txTo);
  el("txList").innerHTML=list.length?list.map(txRow).join(""):emptyState();
}
function txRow(t){
  let ico,amtTxt,amtCol,meta;
  if(t.kind==="expense"){ const a=accById(t.acc); ico=icoArrowUp; amtTxt="−"+fmt(t.amt).replace("Rp","Rp "); amtCol="var(--red)"; meta=`<span class="pill">${t.cat}</span> ${a?logoMini(a):"?"}`; }
  else if(t.kind==="income"){ const a=accById(t.acc); ico=icoArrowDown; amtTxt="+"+fmt(t.amt).replace("Rp","Rp "); amtCol="var(--green)"; meta=`<span class="pill">${t.jenis}</span> ${a?logoMini(a):"?"}`; }
  else { const f=accById(t.from),to=accById(t.to); ico=icoSwap; amtTxt=fmt(t.amt); amtCol="var(--gold)"; meta=`<span class="pill">${t.jenis}</span> ${f?logoMini(f):"?"} <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2.5" style="vertical-align:-1px"><path d="M5 12h14M13 6l6 6-6 6"/></svg> ${to?logoMini(to):"?"}`; }
  return `<div class="tx" data-edit="${t.id}">
    <div class="tx-ico" style="background:${tint(amtCol)};color:${amtCol}">${ico}</div>
    <div class="tx-main"><div class="tx-desc">${esc(t.desc||"(tanpa deskripsi)")}</div><div class="tx-meta">${meta}</div></div>
    <div class="tx-amt num" style="color:${amtCol}">${amtTxt}</div>
    <div class="tx-date num">${fmtDate(t.date)}</div>
    <button class="tx-del" data-del="${t.id}" title="Hapus">${icoTrash}</button></div>`;
}
const logoMini=a=>`<span style="display:inline-flex;align-items:center;gap:4px"><span style="width:13px;height:13px;border-radius:4px;background:${a.color};display:inline-block;vertical-align:-2px"></span>${esc(a.name)}</span>`;
const emptyState=()=>`<div class="empty">${icoReceipt}<p>Belum ada transaksi di sini.<br>Ketuk <b>Catat Transaksi</b> untuk mulai.</p></div>`;

/* ---------------- modal: transaction ---------------- */
let txTab="expense";
function openTx(editId){
  const editing=editId?S.txns.find(t=>t.id===editId):null;
  if(editing) txTab=editing.kind;
  const optAcc=(sel,types)=>S.accounts.filter(a=>!types||types.includes(a.type)).map(a=>`<option value="${a.id}" ${sel===a.id?"selected":""}>${esc(a.name)}</option>`).join("");
  const optList=(arr,sel)=>arr.map(o=>`<option ${o===sel?"selected":""}>${o}</option>`).join("");
  const today=new Date().toISOString().slice(0,10), d=editing||{};
  function body(){
    const date=`<div class="field"><label>Tanggal</label><input type="date" id="f_date" value="${d.date||today}"></div>`;
    const desc=`<div class="field"><label>Deskripsi</label><input id="f_desc" placeholder="mis. Makan siang" value="${editing?esc(d.desc||''):''}"></div>`;
    const amt =`<div class="field amt"><label>Jumlah (Rp)</label><input id="f_amt" inputmode="numeric" placeholder="0" value="${editing?d.amt:''}"></div>`;
    const extras=editing?"":`<div class="row2"><div class="field"><label>Admin/Biaya (Rp, opsional)</label><input id="f_admin" inputmode="numeric" placeholder="0"></div><div class="field"><label>Cashback (Rp, opsional)</label><input id="f_cashback" inputmode="numeric" placeholder="0"></div></div><div class="field"><label>Cashback masuk ke</label><select id="f_cashback_acc">${optAcc(null,["Rekening","Investasi"])}</select></div>`;
    if(txTab==="expense") return date+desc+`<div class="field"><label>Kategori</label><select id="f_cat">${optList(KATEGORI,d.cat)}</select></div>`+`<div class="field"><label>Sumber Dana</label><select id="f_acc">${optAcc(d.acc)}</select></div>`+amt+`<div class="hint">Rekening/Investasi → saldo berkurang. Kartu/Paylater → limit berkurang & utang bertambah.</div>`+extras;
    if(txTab==="income") return date+desc+`<div class="field"><label>Jenis</label><select id="f_jenis">${optList(JENIS_MASUK,d.jenis)}</select></div>`+`<div class="field"><label>Masuk ke</label><select id="f_acc">${optAcc(d.acc,["Rekening","Investasi"])}</select></div>`+amt+`<div class="hint">Untuk uang masuk dari luar (gaji, transfer, hasil investasi).</div>`+extras;
    return date+desc+`<div class="field"><label>Jenis</label><select id="f_jenis">${optList(JENIS_TRANSFER,d.jenis)}</select></div>`+`<div class="row2"><div class="field"><label>Dari</label><select id="f_from">${optAcc(d.from)}</select></div><div class="field"><label>Ke</label><select id="f_to">${optAcc(d.to)}</select></div></div>`+amt+`<div class="hint" id="trHint">Uang pindah antar akun — kekayaan bersih tidak berubah.</div>`+extras;
  }
  sheet(`<div class="sheet-head"><h3>${editing?"Ubah Transaksi":"Catat Transaksi"}</h3>${closeBtn()}</div>
    <div class="sheet-body">
      ${editing?"":`<div class="tabs">${[["expense","Pengeluaran"],["income","Pemasukan"],["transfer","Transfer"]].map(t=>`<button class="tab ${txTab===t[0]?"active":""}" data-tab="${t[0]}">${t[1]}</button>`).join("")}</div>`}
      <div id="txFormBody">${body()}</div>
      <div class="save-row"><button class="btn btn-primary" id="saveTx" style="flex:1;justify-content:center">${editing?"Simpan Perubahan":"Simpan"}</button></div>
      ${editing?`<button class="del-link" id="delTx">${icoTrash} Hapus transaksi</button>`:""}
    </div>`);
  if(!editing) qa("[data-tab]").forEach(b=>b.onclick=()=>{txTab=b.dataset.tab; qa("[data-tab]").forEach(x=>x.classList.toggle("active",x.dataset.tab===txTab)); el("txFormBody").innerHTML=body(); bindTrHint();});
  bindTrHint();
  el("saveTx").onclick=()=>{
    const amt=numIn("f_amt");
    if(!amt||amt<=0){ toast("Isi jumlah dulu ya",true); return; }
    const base={date:el("f_date").value,desc:el("f_desc").value.trim(),amt};
    let obj;
    if(txTab==="expense") obj={kind:"expense",...base,cat:el("f_cat").value,acc:el("f_acc").value};
    else if(txTab==="income") obj={kind:"income",...base,jenis:el("f_jenis").value,acc:el("f_acc").value};
    else { const from=el("f_from").value,to=el("f_to").value; if(from===to){toast("Akun 'Dari' dan 'Ke' tidak boleh sama",true);return;} obj={kind:"transfer",...base,jenis:el("f_jenis").value,from,to}; }
    if(editing){ obj.id=editing.id; S.txns[S.txns.findIndex(t=>t.id===editing.id)]=obj; }
    else {
      obj.id=uid(); S.txns.push(obj);
      const mainAcc=txTab==="transfer"?el("f_from").value:el("f_acc").value;
      const admin=numIn("f_admin");
      if(admin>0) S.txns.push({id:uid(),kind:"expense",date:base.date,desc:(base.desc||"Admin/Biaya")+" (admin)",amt:admin,cat:"Admin / Biaya",acc:mainAcc});
      const cashback=numIn("f_cashback");
      if(cashback>0) S.txns.push({id:uid(),kind:"income",date:base.date,desc:(base.desc||"Cashback")+" (cashback)",amt:cashback,jenis:"Cashback",acc:el("f_cashback_acc").value});
    }
    persist(); close(); toast(editing?"Transaksi diperbarui":"Transaksi dicatat");
  };
  if(editing) el("delTx").onclick=()=>{ S.txns=S.txns.filter(t=>t.id!==editing.id); persist(); close(); toast("Transaksi dihapus"); };
}
function bindTrHint(){
  const h=el("trHint"); if(!h) return;
  const f=el("f_from"),t=el("f_to");
  const upd=()=>{ if(f.value===t.value){h.className="hint warn"; h.textContent="⚠ Akun 'Dari' dan 'Ke' sama — pilih yang berbeda.";} else {h.className="hint"; h.textContent="Uang pindah antar akun — kekayaan bersih tidak berubah.";} };
  f.onchange=upd; t.onchange=upd; upd();
}

/* ---------------- modal: account ---------------- */
function openAcc(editId){
  const editing=editId?accById(editId):null;
  const d=editing||{type:"Rekening",color:SWATCHES[0],base:0,mono:""};
  sheet(`<div class="sheet-head"><h3>${editing?"Ubah Sumber Dana":"Tambah Sumber Dana"}</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="field"><label>Nama</label><input id="a_name" placeholder="mis. Rekening BCA" value="${editing?esc(d.name):''}"></div>
      <div class="field"><label>Tipe</label><select id="a_type">${TIPE.map(t=>`<option ${d.type===t?"selected":""}>${t}</option>`).join("")}</select></div>
      <div class="field"><label id="a_baselab">Saldo Awal / Limit (Rp)</label><input id="a_base" inputmode="numeric" placeholder="0" value="${d.base||""}"></div>
      <div class="field"><label>Inisial logo</label><input id="a_mono" maxlength="4" placeholder="otomatis" value="${editing?esc(d.mono):''}" style="text-transform:uppercase"></div>
      <div class="field"><label>Warna</label><div class="swatches" id="a_sw">${SWATCHES.map(c=>`<span class="sw ${c===d.color?"sel":""}" data-c="${c}" style="background:${c}"></span>`).join("")}</div></div>
      <div class="save-row"><button class="btn btn-primary" id="saveAcc" style="flex:1;justify-content:center">${editing?"Simpan":"Tambah"}</button></div>
      ${editing?`<button class="del-link" id="delAcc">${icoTrash} Hapus sumber dana</button>`:""}
    </div>`);
  let color=d.color;
  const lab=()=>{ el("a_baselab").textContent=isDebt(el("a_type").value)?"Limit (Rp)":"Saldo Awal (Rp)"; };
  el("a_type").onchange=lab; lab();
  qa("#a_sw .sw").forEach(s=>s.onclick=()=>{qa("#a_sw .sw").forEach(x=>x.classList.remove("sel"));s.classList.add("sel");color=s.dataset.c;});
  el("saveAcc").onclick=()=>{
    const name=el("a_name").value.trim(); if(!name){toast("Isi nama akun",true);return;}
    const type=el("a_type").value, base=numIn("a_base");
    let mono=el("a_mono").value.trim().toUpperCase();
    if(!mono) mono=name.replace(/[^A-Za-z ]/g,"").split(/\s+/).map(w=>w[0]||"").join("").slice(0,3).toUpperCase()||name.slice(0,3).toUpperCase();
    if(editing) Object.assign(editing,{name,type,base,mono,color});
    else S.accounts.push({id:"a"+uid(),name,type,base,mono,color});
    persist(); close(); toast(editing?"Sumber dana diperbarui":"Sumber dana ditambah");
  };
  if(editing) el("delAcc").onclick=()=>{
    const n=S.txns.filter(t=>t.acc===editing.id||t.from===editing.id||t.to===editing.id).length;
    confirmBox(`Hapus "${editing.name}"?`, n?`Ada ${n} transaksi terkait yang ikut terhapus.`:"Tindakan ini tidak bisa dibatalkan.",()=>{
      S.txns=S.txns.filter(t=>t.acc!==editing.id&&t.from!==editing.id&&t.to!==editing.id);
      S.accounts=S.accounts.filter(a=>a.id!==editing.id); persist(); close(); toast("Sumber dana dihapus");
    });
  };
}

/* ---------------- transaksi berulang ---------------- */
function nextMonthDate(dateStr){
  const [y,m,d]=dateStr.split("-").map(Number);
  let ny=y, nm=m+1; if(nm>12){nm=1; ny++;}
  const dim=new Date(ny,nm,0).getDate();
  return `${ny}-${String(nm).padStart(2,"0")}-${String(Math.min(d,dim)).padStart(2,"0")}`;
}
function processRecurring(){
  const today=new Date().toISOString().slice(0,10);
  let changed=false;
  S.recurring.forEach(r=>{
    while(r.nextDate<=today){
      const id=uid();
      if(r.kind==="expense") S.txns.push({id,kind:"expense",date:r.nextDate,desc:r.desc,amt:r.amt,cat:r.cat,acc:r.acc});
      else S.txns.push({id,kind:"income",date:r.nextDate,desc:r.desc,amt:r.amt,jenis:r.jenis,acc:r.acc});
      r.nextDate=nextMonthDate(r.nextDate);
      changed=true;
    }
  });
  if(changed) persist();
}
function openRecurringList(){
  sheet(`<div class="sheet-head"><h3>Transaksi Berulang</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint">Otomatis dicatat setiap bulan pada tanggal yang ditentukan.</div>
      <div id="recurList">${S.recurring.length?S.recurring.map(r=>`<div class="cat-row"><span class="c-name" style="width:auto;flex:1">${esc(r.desc)} <span style="color:var(--muted)">(tgl ${r.nextDate.slice(8)})</span></span><span class="c-val num">${fmt(r.amt)}</span><button class="mini-btn danger" data-delrecur="${r.id}" style="margin-left:8px">${icoTrash}</button></div>`).join(""):`<div style="color:var(--muted);font-size:13px;padding:10px 0">Belum ada transaksi berulang.</div>`}</div>
      <div class="save-row"><button class="btn btn-primary" id="addRecur" style="flex:1;justify-content:center">${icoPlus} Tambah</button></div>
    </div>`);
  qa("[data-delrecur]").forEach(b=>b.onclick=()=>{ S.recurring=S.recurring.filter(r=>r.id!==b.dataset.delrecur); persist(); openRecurringList(); });
  el("addRecur").onclick=openRecurringForm;
}
let recurKind="expense";
function openRecurringForm(){
  recurKind="expense";
  const optAcc=(types)=>S.accounts.filter(a=>!types||types.includes(a.type)).map(a=>`<option value="${a.id}">${esc(a.name)}</option>`).join("");
  const optList=arr=>arr.map(o=>`<option>${o}</option>`).join("");
  function body(){
    return `<div class="field"><label>Deskripsi</label><input id="r_desc" placeholder="mis. Netflix"></div>`
      +(recurKind==="expense"?`<div class="field"><label>Kategori</label><select id="r_cat">${optList(KATEGORI)}</select></div>`+`<div class="field"><label>Sumber Dana</label><select id="r_acc">${optAcc()}</select></div>`
        :`<div class="field"><label>Jenis</label><select id="r_cat">${optList(JENIS_MASUK)}</select></div>`+`<div class="field"><label>Masuk ke</label><select id="r_acc">${optAcc(["Rekening","Investasi"])}</select></div>`)
      +`<div class="field"><label>Jumlah (Rp)</label><input id="r_amt" inputmode="numeric" placeholder="0"></div>`
      +`<div class="field"><label>Tanggal tiap bulan</label><input id="r_day" type="number" min="1" max="28" value="1"></div>`;
  }
  sheet(`<div class="sheet-head"><h3>Tambah Transaksi Berulang</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="tabs"><button class="tab active" data-rkind="expense">Pengeluaran</button><button class="tab" data-rkind="income">Pemasukan</button></div>
      <div id="recurFormBody">${body()}</div>
      <div class="save-row"><button class="btn btn-primary" id="saveRecur" style="flex:1;justify-content:center">Simpan</button></div>
    </div>`);
  qa("[data-rkind]").forEach(b=>b.onclick=()=>{ recurKind=b.dataset.rkind; qa("[data-rkind]").forEach(x=>x.classList.toggle("active",x.dataset.rkind===recurKind)); el("recurFormBody").innerHTML=body(); });
  el("saveRecur").onclick=()=>{
    const desc=el("r_desc").value.trim(), amt=numIn("r_amt"), day=Math.min(28,Math.max(1,parseInt(el("r_day").value,10)||1));
    if(!desc||amt<=0){ toast("Isi deskripsi dan jumlah",true); return; }
    const today=new Date(); const y=today.getFullYear(), m=today.getMonth()+1, dd=today.getDate();
    let nextDate=`${y}-${String(m).padStart(2,"0")}-${String(day).padStart(2,"0")}`;
    if(day<dd) nextDate=nextMonthDate(nextDate);
    const r={id:uid(),kind:recurKind,desc,amt,acc:el("r_acc").value,nextDate};
    if(recurKind==="expense") r.cat=el("r_cat").value; else r.jenis=el("r_cat").value;
    S.recurring.push(r); persist(); openRecurringList(); toast("Transaksi berulang ditambah");
  };
}

/* ---------------- modal: anggaran kategori ---------------- */
function openBudgets(){
  sheet(`<div class="sheet-head"><h3>Anggaran per Kategori</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint">Set batas bulanan per kategori (opsional). Kosongkan untuk tanpa batas.</div>
      ${KATEGORI.map(c=>`<div class="field"><label>${c}</label><input data-budget="${c}" inputmode="numeric" placeholder="0" value="${S.budgets[c]||""}"></div>`).join("")}
      <div class="save-row"><button class="btn btn-primary" id="saveBudgets" style="flex:1;justify-content:center">Simpan</button></div>
    </div>`);
  el("saveBudgets").onclick=()=>{
    qa("[data-budget]").forEach(inp=>{
      const v=parseInt((inp.value||"").replace(/\D/g,""),10);
      if(v>0) S.budgets[inp.dataset.budget]=v; else delete S.budgets[inp.dataset.budget];
    });
    persist(); close(); toast("Anggaran disimpan");
  };
}

/* ---------------- modal: settings ---------------- */
function openSettings(){
  sheet(`<div class="sheet-head"><h3>Pengaturan</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="field"><label>Penyesuaian Manual Saldo (Rp)</label><input id="s_adj" inputmode="numeric" value="${S.adjust||0}"></div>
      <div class="hint">Koreksi kekayaan bersih. Set ke <b>0</b> bila semua saldo sudah tercatat. Boleh negatif.</div>
      <div class="save-row"><button class="btn btn-primary" id="saveAdj" style="flex:1;justify-content:center">Simpan Penyesuaian</button></div>
      <div style="height:18px"></div>
      <div class="save-row">
        <button class="btn btn-ghost" id="expBtn" style="flex:1;justify-content:center">${icoDownload} Unduh cadangan</button>
        <button class="btn btn-ghost" id="impBtn" style="flex:1;justify-content:center">${icoUpload} Impor cadangan</button>
      </div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="csvBtn" style="flex:1;justify-content:center">${icoDownload} Unduh CSV transaksi</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="recurBtn" style="flex:1;justify-content:center">${icoReset} Transaksi Berulang</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="syncBtn" style="flex:1;justify-content:center">${icoCloud} Sinkronisasi Cloud (GitHub)</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="pwBtn" style="flex:1;justify-content:center">${icoKey} Ganti kata sandi</button></div>
      <div style="height:10px"></div>
      <div class="save-row"><button class="btn btn-ghost" id="resetBtn" style="flex:1;justify-content:center;color:var(--red)">${icoReset} Reset ke nol (perlu kode email)</button></div>
      <input type="file" id="impFile" accept="application/json" class="hidden">
    </div>`);
  el("saveAdj").onclick=()=>{ S.adjust=parseInt((el("s_adj").value||"0").replace(/[^\d-]/g,""),10)||0; persist(); close(); toast("Penyesuaian disimpan"); };
  el("expBtn").onclick=exportBackup;
  el("impBtn").onclick=()=>el("impFile").click();
  el("impFile").onchange=importBackup;
  el("csvBtn").onclick=exportCSV;
  el("recurBtn").onclick=openRecurringList;
  el("syncBtn").onclick=openSync;
  el("pwBtn").onclick=openChangePass;
  el("resetBtn").onclick=openReset;
}

/* ---------------- modal: sinkronisasi GitHub ---------------- */
function openSync(){
  const c = SYNC || {owner:"",repo:"",path:"vault.json",branch:"main",token:""};
  const on = syncReady();
  sheet(`<div class="sheet-head"><h3>Sinkronisasi Cloud (GitHub)</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint" style="margin-bottom:14px">Simpan data (yang sudah <b>terenkripsi</b>) ke repo GitHub <b>privat</b> agar bisa dibuka di perangkat mana pun. Yang terkirim hanya teks terenkripsi — tanpa kata sandi Anda, tak terbaca. ${on?'<b style="color:var(--green)">Status: aktif.</b>':'<b style="color:var(--red)">Status: belum aktif.</b>'}</div>
      <div class="field"><label>Username / owner GitHub</label><input id="y_owner" value="${esc(c.owner||"")}" placeholder="mis. bbkukuh"></div>
      <div class="field"><label>Nama repo (PRIVAT, khusus data)</label><input id="y_repo" value="${esc(c.repo||"")}" placeholder="mis. saku-data"></div>
      <div class="field"><label>Nama file</label><input id="y_path" value="${esc(c.path||"vault.json")}" placeholder="vault.json"></div>
      <div class="field"><label>Branch</label><input id="y_branch" value="${esc(c.branch||"main")}" placeholder="main"></div>
      <div class="field"><label>Fine-grained token (hanya repo ini, Contents: Read &amp; Write)</label><input type="password" id="y_token" value="${esc(c.token||"")}" placeholder="github_pat_..."></div>
      <div class="hint">Token <b>tidak</b> ikut di-commit; tersimpan hanya di perangkat ini. Buat di GitHub → Settings → Developer settings → Fine-grained tokens, batasi ke repo data, beri izin <b>Contents: Read and write</b>.</div>
      <div class="save-row" style="margin-top:6px">
        <button class="btn btn-primary" id="y_save" style="flex:1;justify-content:center">Simpan &amp; Uji</button>
      </div>
      <div class="save-row">
        <button class="btn btn-ghost" id="y_pull" style="flex:1;justify-content:center">${icoDownload} Tarik sekarang</button>
        <button class="btn btn-ghost" id="y_push" style="flex:1;justify-content:center">${icoUpload} Unggah sekarang</button>
      </div>
      ${on?`<div class="save-row"><button class="btn btn-ghost" id="y_off" style="flex:1;justify-content:center;color:var(--red)">Putuskan dari perangkat ini</button></div>`:""}
    </div>`);
  const readForm=()=>({
    owner:el("y_owner").value.trim(), repo:el("y_repo").value.trim(),
    path:(el("y_path").value.trim()||"vault.json"), branch:(el("y_branch").value.trim()||"main"),
    token:el("y_token").value.trim()
  });
  el("y_save").onclick=async()=>{
    const cfg=readForm();
    if(!cfg.owner||!cfg.repo||!cfg.token){ toast("Owner, repo, dan token wajib diisi",true); return; }
    saveSync(cfg); REMOTE_SHA=null;
    try{
      const {wrap}=await ghGet();                 // uji koneksi
      if(!wrap){ cloudPush(); toast("Tersambung. Data lokal diunggah."); }
      else { const r=await cloudPull(true); if(r.status!=="pulled") cloudPush(); toast(r.status==="pulled"?"Tersambung. Data ditarik dari GitHub.":"Tersambung & sinkron."); render(); }
      setSyncDot("ok"); close();
    }catch(e){
      setSyncDot("err");
      toast(e.message==="AUTH"?"Token/izin ditolak GitHub":(e.message==="LOCKED"?"Buka kunci dulu":"Gagal menyambung — cek owner/repo/branch"),true);
    }
  };
  el("y_pull").onclick=async()=>{
    saveSync(readForm()); REMOTE_SHA=null;
    try{ const r=await cloudPull(true); render(); toast(r.status==="pulled"?"Data ditarik":r.status==="empty"?"Repo masih kosong":"Sudah versi terbaru"); setSyncDot("ok"); }
    catch(e){ setSyncDot("err"); toast(e.message==="AUTH"?"Token ditolak":"Gagal menarik",true); }
  };
  el("y_push").onclick=async()=>{
    saveSync(readForm()); REMOTE_SHA=null;
    try{ await ghGet().catch(()=>{}); await ghPut(readVault()); toast("Data diunggah ke GitHub"); setSyncDot("ok"); }
    catch(e){ setSyncDot("err"); toast(e.message==="AUTH"?"Token ditolak":"Gagal mengunggah",true); }
  };
  if(el("y_off")) el("y_off").onclick=()=>{ clearSync(); setSyncDot(""); close(); toast("Sinkronisasi diputus dari perangkat ini"); };
}

function exportBackup(){
  const blob=new Blob([JSON.stringify(S,null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download="saku-cadangan-"+new Date().toISOString().slice(0,10)+".json"; a.click();
  toast("Cadangan diunduh");
}
function exportCSV(){
  const rows=[["Tanggal","Jenis","Deskripsi","Jumlah","Kategori/Jenis","Akun/Dari","Ke"]];
  [...S.txns].sort((a,b)=>a.date<b.date?-1:1).forEach(t=>{
    if(t.kind==="expense") rows.push([t.date,"Pengeluaran",t.desc||"",t.amt,t.cat,accById(t.acc)?.name||"",""]);
    else if(t.kind==="income") rows.push([t.date,"Pemasukan",t.desc||"",t.amt,t.jenis,accById(t.acc)?.name||"",""]);
    else rows.push([t.date,"Transfer",t.desc||"",t.amt,t.jenis,accById(t.from)?.name||"",accById(t.to)?.name||""]);
  });
  const csv=rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(",")).join("\n");
  const blob=new Blob([csv],{type:"text/csv"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download="saku-transaksi-"+new Date().toISOString().slice(0,10)+".csv"; a.click();
  toast("CSV diunduh");
}
function importBackup(e){
  const file=e.target.files[0]; if(!file) return;
  const r=new FileReader();
  r.onload=()=>{ try{
    const obj=JSON.parse(r.result);
    if(!obj.accounts||!Array.isArray(obj.txns)) throw 0;
    S=obj; normalizeState(); persist(); close(); toast("Cadangan diimpor");
  }catch(err){ toast("File cadangan tidak valid",true); } };
  r.readAsText(file);
}

function openChangePass(){
  sheet(`<div class="sheet-head"><h3>Ganti Kata Sandi</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="field"><label>Kata sandi baru</label><input type="password" id="p_new" placeholder="Minimal 6 karakter"></div>
      <div class="field"><label>Ulangi</label><input type="password" id="p_new2" placeholder="Ulangi kata sandi"></div>
      <div class="hint">Data akan dienkripsi ulang dengan kata sandi baru. Jangan sampai lupa — tanpa sandi, data tidak bisa dibuka.</div>
      <div class="save-row"><button class="btn btn-primary" id="p_save" style="flex:1;justify-content:center">Simpan</button></div>
    </div>`);
  el("p_save").onclick=async()=>{
    const a=el("p_new").value,b=el("p_new2").value;
    if(a.length<6){toast("Sandi minimal 6 karakter",true);return;}
    if(a!==b){toast("Kedua sandi tidak sama",true);return;}
    await changePassword(a); close(); toast("Kata sandi diganti");
  };
}

/* ---------------- reset (kode via email) ---------------- */
let pendingCode=null;
async function sendResetCode(code){
  if(!CONFIG.web3formsKey) return {ok:false,reason:"nokey"};
  try{
    const res=await fetch("https://api.web3forms.com/submit",{
      method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json"},
      body:JSON.stringify({ access_key:CONFIG.web3formsKey, subject:"Kode Reset Saku", from_name:"Saku", email:CONFIG.resetEmail,
        message:`Kode untuk mereset data Saku Anda ke nol: ${code}\n\nAbaikan email ini bila Anda tidak meminta reset.` })
    });
    const j=await res.json();
    return {ok:!!j.success,reason:j.message||""};
  }catch(e){ return {ok:false,reason:"network"}; }
}
function doResetToZero(){
  S.txns=[]; S.accounts.forEach(a=>a.base=0); S.adjust=0;
  persist(); close(); toast("Semua data direset ke nol");
}
function openReset(){
  if(!CONFIG.web3formsKey){
    sheet(`<div class="sheet-head"><h3>Reset Belum Aktif</h3>${closeBtn()}</div>
      <div class="sheet-body">
        <div class="preview">Pengiriman kode ke <b>${esc(CONFIG.resetEmail||"email Anda")}</b> belum diatur.<br><br>
        Buka <b>web3forms.com</b>, daftarkan email itu, salin <b>access key</b>, lalu tempel ke file <b>config.js</b> (lihat README).<br><br>
        Atau, gunakan opsi cadangan di bawah untuk reset dengan kata sandi.</div>
        <div class="save-row"><button class="btn btn-ghost" id="r_pw" style="flex:1;justify-content:center;color:var(--red)">Reset dengan kata sandi</button></div>
      </div>`);
    el("r_pw").onclick=()=>resetWithPassword();
    return;
  }
  sheet(`<div class="sheet-head"><h3>Reset ke Nol</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="preview">Untuk keamanan, kode konfirmasi akan dikirim ke <b>${esc(CONFIG.resetEmail)}</b>. Semua transaksi & saldo akan dinolkan (akun tetap ada).</div>
      <div class="save-row"><button class="btn btn-primary" id="r_send" style="flex:1;justify-content:center;background:var(--red)">Kirim kode ke email</button></div>
    </div>`);
  el("r_send").onclick=async()=>{
    el("r_send").textContent="Mengirim…"; el("r_send").disabled=true;
    pendingCode=String(Math.floor(100000+Math.random()*900000));
    const r=await sendResetCode(pendingCode);
    if(!r.ok){ toast("Gagal kirim email: "+(r.reason||"coba lagi"),true); el("r_send").textContent="Kirim kode ke email"; el("r_send").disabled=false; return; }
    sheet(`<div class="sheet-head"><h3>Masukkan Kode</h3>${closeBtn()}</div>
      <div class="sheet-body">
        <div class="preview">Kode 6 digit dikirim ke <b>${esc(CONFIG.resetEmail)}</b>. Cek inbox/spam, lalu masukkan di bawah.</div>
        <div class="field"><label>Kode konfirmasi</label><input id="r_code" inputmode="numeric" maxlength="6" placeholder="######" style="text-align:center;letter-spacing:.3em;font-family:'Space Grotesk'"></div>
        <div class="save-row"><button class="btn btn-primary" id="r_confirm" style="flex:1;justify-content:center;background:var(--red)">Reset sekarang</button></div>
      </div>`);
    el("r_confirm").onclick=()=>{ if(el("r_code").value.trim()===pendingCode){ pendingCode=null; doResetToZero(); } else toast("Kode salah",true); };
  };
}
function resetWithPassword(){
  sheet(`<div class="sheet-head"><h3>Konfirmasi Reset</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="preview">Masukkan kata sandi Anda untuk menolkan semua transaksi & saldo.</div>
      <div class="field"><label>Kata sandi</label><input type="password" id="r_pwf" placeholder="Kata sandi"></div>
      <div class="save-row"><button class="btn btn-primary" id="r_pwgo" style="flex:1;justify-content:center;background:var(--red)">Reset ke nol</button></div>
    </div>`);
  el("r_pwgo").onclick=async()=>{
    try{ const v=readVault(); await decryptObj(await deriveKey(el("r_pwf").value, unb64(v.salt)), v.blob); doResetToZero(); }
    catch(e){ toast("Kata sandi salah",true); }
  };
}

/* ---------------- confirm + modal plumbing ---------------- */
function confirmBox(title,msg,onYes){
  sheet(`<div class="sheet-head"><h3>${esc(title)}</h3></div>
    <div class="sheet-body"><div class="preview" style="margin-bottom:18px">${msg}</div>
    <div class="save-row"><button class="btn btn-ghost" id="cNo" style="flex:1;justify-content:center">Batal</button>
    <button class="btn btn-primary" id="cYes" style="flex:1;justify-content:center;background:var(--red)">Hapus</button></div></div>`);
  el("cNo").onclick=close; el("cYes").onclick=onYes;
}
function sheet(html){ el("sheet").innerHTML=html; el("scrim").classList.add("show"); document.body.style.overflow="hidden"; qa("[data-close]").forEach(b=>b.onclick=close); }
function close(){ el("scrim").classList.remove("show"); document.body.style.overflow=""; }
const closeBtn=()=>`<button class="icon-btn" data-close style="box-shadow:none;background:var(--bg)"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg></button>`;

/* ---------------- toast ---------------- */
let toastT;
function toast(msg,err){ const t=el("toast"); t.innerHTML=(err?icoWarn:icoCheck)+`<span>${esc(msg)}</span>`; t.classList.add("show"); clearTimeout(toastT); toastT=setTimeout(()=>t.classList.remove("show"),2400); }

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
function numIn(id){return parseInt((el(id).value||"").replace(/\D/g,""),10)||0;}
function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function tint(v){const map={"var(--green)":"#e3f1e7","var(--red)":"#fbe6e3","var(--gold)":"#f6ecd8","var(--teal)":"#e0efef"};return map[v]||"#eef3f4";}

/* ---------------- events ---------------- */
document.addEventListener("click",e=>{
  const ed=e.target.closest("[data-del]"); if(ed){e.stopPropagation(); const t=S.txns.find(x=>x.id===ed.dataset.del); confirmBox("Hapus transaksi?",esc(t&&t.desc||"")+" — "+fmt(t&&t.amt||0),()=>{S.txns=S.txns.filter(x=>x.id!==ed.dataset.del);persist();close();toast("Transaksi dihapus");}); return;}
  const da=e.target.closest("[data-delacc]"); if(da){e.stopPropagation(); openAcc(da.dataset.delacc); setTimeout(()=>{const b=el("delAcc"); if(b)b.click();},0); return;}
  const ea=e.target.closest("[data-editacc]"); if(ea){e.stopPropagation(); openAcc(ea.dataset.editacc); return;}
  const ee=e.target.closest("[data-edit]"); if(ee){ openTx(ee.dataset.edit); return;}
  const fl=e.target.closest("[data-filter]"); if(fl){ filter=fl.dataset.filter; render(); return;}
  if(e.target.closest("#addAccBtn")) openAcc();
  if(e.target===el("scrim")) close();
});

/* ---------------- lock screen ---------------- */
function showLockError(msg){ el("lockErr").textContent=msg||""; }
function setupLockUI(){
  const hasVault=!!readVault();
  el("lockTitle").textContent=hasVault?"Buka Saku":"Buat Kata Sandi";
  el("lockDesc").textContent=hasVault?"Masukkan kata sandi untuk membuka catatan keuangan Anda.":"Buat kata sandi untuk mengunci & mengenkripsi data Anda di perangkat ini.";
  el("lockPass2").classList.toggle("hidden",hasVault);
  el("lockBtn").textContent=hasVault?"Buka":"Simpan & Buka";
  el("lockNote").textContent=hasVault?"Data dienkripsi (AES-256). Tanpa sandi, data tidak terbaca.":"Catat sandi Anda baik-baik. Jika lupa, data tidak bisa dipulihkan.";
  el("lockPass").value=""; el("lockPass2").value=""; showLockError("");
  el("lockCloud").classList.toggle("hidden", false);   // selalu tersedia utk sambung perangkat
  setTimeout(()=>el("lockPass").focus(),60);
}

/* Sambungkan perangkat baru: tarik vault dari GitHub lalu buka dgn kata sandi */
function openCloudConnect(){
  const c = SYNC || {owner:SYNCDEF.owner||"",repo:SYNCDEF.repo||"",path:SYNCDEF.path||"vault.json",branch:SYNCDEF.branch||"main",token:""};
  sheet(`<div class="sheet-head"><h3>Sambungkan ke GitHub</h3>${closeBtn()}</div>
    <div class="sheet-body">
      <div class="hint" style="margin-bottom:14px">Tarik data dari repo GitHub privat Anda, lalu buka dengan kata sandi yang sama seperti di perangkat lain.</div>
      <div class="field"><label>Username / owner GitHub</label><input id="cc_owner" value="${esc(c.owner)}" placeholder="mis. bbkukuh"></div>
      <div class="field"><label>Nama repo (privat)</label><input id="cc_repo" value="${esc(c.repo)}" placeholder="saku-data"></div>
      <div class="field"><label>Nama file</label><input id="cc_path" value="${esc(c.path)}" placeholder="vault.json"></div>
      <div class="field"><label>Branch</label><input id="cc_branch" value="${esc(c.branch)}" placeholder="main"></div>
      <div class="field"><label>Fine-grained token</label><input type="password" id="cc_token" value="${esc(c.token||"")}" placeholder="github_pat_..."></div>
      <div class="field"><label>Kata sandi Saku</label><input type="password" id="cc_pass" placeholder="Kata sandi yang sama"></div>
      <div class="save-row"><button class="btn btn-primary" id="cc_go" style="flex:1;justify-content:center">Tarik &amp; Buka</button></div>
    </div>`);
  el("cc_go").onclick=async()=>{
    const cfg={owner:el("cc_owner").value.trim(),repo:el("cc_repo").value.trim(),
      path:(el("cc_path").value.trim()||"vault.json"),branch:(el("cc_branch").value.trim()||"main"),
      token:el("cc_token").value.trim()};
    const pass=el("cc_pass").value;
    if(!cfg.owner||!cfg.repo||!cfg.token){ toast("Owner, repo, dan token wajib diisi",true); return; }
    if(!pass){ toast("Isi kata sandi",true); return; }
    saveSync(cfg); REMOTE_SHA=null; PASSWORD=pass;
    try{
      const {wrap}=await ghGet();
      if(!wrap){ toast("Repo kosong — belum ada data di GitHub",true); return; }
      const salt=unb64(wrap.salt), key=await deriveKey(pass,salt);
      S=await decryptObj(key,wrap.blob);          // throws bila kata sandi salah
      normalizeState();
      SALT=salt; CRYPTOKEY=key;
      localStorage.setItem(VAULT_KEY, JSON.stringify(wrap));
      close(); enterApp(); setSyncDot("ok"); toast("Tersambung — data ditarik dari GitHub");
    }catch(e){
      PASSWORD=null;
      if(e.message==="AUTH") toast("Token/izin ditolak GitHub",true);
      else if(e.name==="OperationError"||/decrypt/i.test(e.message)) toast("Kata sandi salah untuk data ini",true);
      else toast("Gagal menyambung — cek owner/repo/branch",true);
    }
  };
}
async function tryUnlock(){
  const hasVault=!!readVault(); const pass=el("lockPass").value;
  showLockError("");
  if(!hasVault){
    if(pass.length<6){ showLockError("Sandi minimal 6 karakter."); return; }
    if(pass!==el("lockPass2").value){ showLockError("Kedua sandi tidak sama."); return; }
    await createVault(pass); enterApp();
  } else {
    try{ await unlockVault(pass); enterApp(); }
    catch(e){ showLockError("Kata sandi salah."); el("lockPass").select(); }
  }
}
function enterApp(){
  el("lockScreen").classList.add("hidden");
  el("app").classList.remove("hidden");
  el("todayLabel").textContent=new Date().toLocaleDateString("id-ID",{weekday:"long",day:"numeric",month:"long",year:"numeric"});
  processRecurring();
  render();
  cloudAutoPull();
}
function lockNow(){ CRYPTOKEY=null; PASSWORD=null; S=null; el("app").classList.add("hidden"); el("lockScreen").classList.remove("hidden"); setupLockUI(); }

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
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&el("scrim").classList.contains("show"))close();});

/* ---------------- boot ---------------- */
if(!(window.crypto&&crypto.subtle)){
  document.getElementById("lockDesc").textContent="Browser ini tidak mendukung enkripsi. Buka lewat https (GitHub Pages) atau localhost.";
}
setupLockUI();
