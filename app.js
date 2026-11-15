/* かけがえ: かける専用の しゃしん ほぞんアプリ
   - ぜんぶ ブラウザの中で あんごうか(AES-GCM)してから Firebase に おくる。あいことばは どこにも ほぞんしない
   - おなじ しゃしんは ひとつだけ: 中身から HMAC の ID を つくり、同じ ID は ぜったいに 2つ できない */
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getFirestore, doc, getDoc, setDoc, collection, getDocs, deleteDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { getStorage, ref, uploadBytes, getBytes, deleteObject } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

const app = initializeApp({
  apiKey: "AIzaSyDMFs-m2sIJzXa2sKtG7DVhKNNBcU4Ahr8", authDomain: "batarungotai.firebaseapp.com", projectId: "batarungotai",
  storageBucket: "batarungotai.firebasestorage.app", messagingSenderId: "397468782727", appId: "1:397468782727:web:59ab0d085871b187cbe822"
});
const db = getFirestore(app), st = getStorage(app);
const C_META = 'kakegae_meta', C_ITEM = 'kakegae_items', C_ALB = 'kakegae_albums', ST_DIR = 'kakegae/';
const $ = s => document.querySelector(s), enc = new TextEncoder(), dec = new TextDecoder();

/* ---------- あんごう ---------- */
const b64 = u8 => { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = u8 => [...u8].map(x => x.toString(16).padStart(2, '0')).join('');
let KEY = null, HKEY = null;
async function derive(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' }, base, 512));
  KEY = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  HKEY = await crypto.subtle.importKey('raw', bits.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}
async function seal(u8) { const iv = crypto.getRandomValues(new Uint8Array(12)), ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, KEY, u8)); const o = new Uint8Array(12 + ct.length); o.set(iv); o.set(ct, 12); return o; }
async function open(u8) { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.subarray(0, 12) }, KEY, u8.subarray(12))); }
const sealJson = async o => b64(await seal(enc.encode(JSON.stringify(o))));
const openJson = async s => JSON.parse(dec.decode(await open(unb64(s))));

/* ---------- ロック画面 ---------- */
let first = false, salt = null;
async function lockInit() {
  const m = await getDoc(doc(db, C_META, 'main'));
  if (!m.exists()) { first = true; $('#lockSub').textContent = 'はじめて だね。あたらしい あいことばを きめてね\n(わすれたら ひらけなく なるよ)'; $('#lockSub').style.whiteSpace = 'pre-line'; $('#pw2').classList.remove('hide'); $('#lockGo').textContent = 'きめる'; }
  else salt = unb64(m.data().salt), window.__check = m.data().check;
}
async function unlock() {
  const pw = $('#pw').value, msg = $('#lockMsg'); msg.textContent = '';
  if (!pw) return;
  $('#lockGo').disabled = true; msg.textContent = 'ひらいています…';
  try {
    if (first) {
      if (pw.length < 6) { msg.textContent = '6もじ いじょうに してね'; return; }
      if (pw !== $('#pw2').value) { msg.textContent = 'ふたつが ちがうよ'; return; }
      salt = crypto.getRandomValues(new Uint8Array(16)); await derive(pw, salt);
      await setDoc(doc(db, C_META, 'main'), { salt: b64(salt), check: await sealJson({ ok: 'kakegae' }), at: serverTimestamp() });
    } else {
      await derive(pw, salt);
      try { const r = await openJson(window.__check); if (r.ok !== 'kakegae') throw 0; } catch (e) { KEY = HKEY = null; msg.textContent = 'あいことばが ちがうよ'; return; }
    }
    $('#lock').classList.add('hide'); $('#app').classList.remove('hide'); $('#pw').value = $('#pw2').value = '';
    await loadAll(); go('all');
  } catch (e) { msg.textContent = 'うまく いかなかったよ(' + (e.message || e) + ')'; }
  finally { $('#lockGo').disabled = false; }
}
function relock() { KEY = HKEY = null; items = []; albums = []; revokeAll(); location.reload(); }
$('#lockGo').onclick = unlock; $('#pw').onkeydown = $('#pw2').onkeydown = e => { if (e.key === 'Enter') unlock(); };
$('#lockBtn').onclick = relock;
document.addEventListener('visibilitychange', () => { if (document.hidden && KEY) { clearTimeout(lockT); lockT = setTimeout(() => { if (document.hidden) relock(); }, 5 * 60 * 1000); } else clearTimeout(lockT); });
let lockT;

/* ---------- データ ---------- */
let items = [], albums = [];   // items: {id, m:{n,t,s,w,h,d,dur,fav,alb}, thumb:url}
const urls = new Set();
const blobUrl = (u8, type) => { const u = URL.createObjectURL(new Blob([u8], { type })); urls.add(u); return u; };
function revokeAll() { urls.forEach(u => URL.revokeObjectURL(u)); urls.clear(); }
async function loadAll() {
  const [a, b] = await Promise.all([getDocs(collection(db, C_ITEM)), getDocs(collection(db, C_ALB))]);
  const out = [];
  await Promise.all(a.docs.map(async d => {
    try { const x = d.data(); const m = await openJson(x.meta); out.push({ id: d.id, m, thumb: x.thumb ? blobUrl(await open(unb64(x.thumb)), 'image/jpeg') : '' }); } catch (e) { }
  }));
  items = out.sort((p, q) => q.m.d - p.m.d);
  const al = [];
  await Promise.all(b.docs.map(async d => { try { al.push({ id: d.id, ...(await openJson(d.data().meta)) }); } catch (e) { } }));
  albums = al.sort((p, q) => p.at - q.at);
}

/* ---------- 画面 ---------- */
let tab = 'all', curAlb = null, selMode = false, picked = new Set();
const fmtDay = ms => { const d = new Date(ms); return d.getFullYear() + '年' + (d.getMonth() + 1) + '月' + d.getDate() + '日'; };
const fmtDur = s => Math.floor(s / 60) + ':' + String(Math.floor(s % 60)).padStart(2, '0');
function toast(t) { const e = $('#toast'); e.textContent = t; e.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => e.classList.remove('on'), 2200); }
function go(t, alb) {
  tab = t; curAlb = alb || null; selMode = false; picked.clear();
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.t === t));
  render();
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => go(b.dataset.t));
$('#selBtn').onclick = () => { selMode = !selMode; picked.clear(); render(); };
function list() {
  if (tab === 'fav') return items.filter(i => i.m.fav);
  if (tab === 'alb' && curAlb) return items.filter(i => i.m.alb === curAlb);
  return items;
}
function render() {
  const main = $('#main'), sel = selMode && (tab === 'all' || tab === 'fav' || curAlb);
  $('#selBtn').classList.toggle('hide', !(tab === 'all' || tab === 'fav' || curAlb));
  $('#selBtn').textContent = sel ? 'やめる' : 'えらぶ';
  $('#selbar').classList.toggle('hide', !sel); main.style.paddingBottom = sel ? '70px' : '0';
  if (tab === 'up') { $('#ttl').textContent = 'アップロード'; return renderUp(); }
  if (tab === 'alb' && !curAlb) { $('#ttl').textContent = 'アルバム'; return renderAlbums(); }
  const alb = curAlb && albums.find(a => a.id === curAlb);
  $('#ttl').textContent = tab === 'fav' ? 'おきにいり' : alb ? alb.name : 'しゃしん';
  const L = list();
  if (!L.length) { main.innerHTML = '<div class="empty">' + (tab === 'fav' ? 'ハートを つけた しゃしんが ここに あつまるよ' : 'まだ なにも ないよ<br>したの「アップ」から いれてね') + '</div>'; return; }
  let h = '', last = '';
  if (alb) h += '<div style="padding:10px 14px;display:flex;gap:8px"><button class="btn ghost" id="albBack">‹ もどる</button><button class="btn ghost" id="albRen">なまえ</button><button class="btn ghost" id="albDel">アルバムを けす</button></div>';
  h += '<div class="' + (sel ? 'sel' : '') + '">';
  for (const it of L) {
    const day = fmtDay(it.m.d);
    if (day !== last) { if (last) h += '</div>'; h += '<div class="day">' + day + '</div><div class="grid">'; last = day; }
    h += '<div class="cell' + (picked.has(it.id) ? ' picked' : '') + '" data-id="' + it.id + '">' + (it.thumb ? '<img loading="lazy" src="' + it.thumb + '">' : '') + (it.m.t === 'v' ? '<span class="dur">▶ ' + fmtDur(it.m.dur || 0) + '</span>' : '') + (it.m.fav ? '<span class="fav">💗</span>' : '') + '<span class="chk">' + (picked.has(it.id) ? '✓' : '') + '</span></div>';
  }
  h += '</div></div>'; main.innerHTML = h;
  main.querySelectorAll('.cell').forEach(c => c.onclick = () => {
    const id = c.dataset.id;
    if (sel) { picked.has(id) ? picked.delete(id) : picked.add(id); c.classList.toggle('picked'); c.querySelector('.chk').textContent = picked.has(id) ? '✓' : ''; }
    else openViewer(L, id);
  });
  if (alb) { $('#albBack').onclick = () => go('alb'); $('#albRen').onclick = () => renameAlbum(alb); $('#albDel').onclick = () => deleteAlbum(alb); }
}
function renderAlbums() {
  let h = '<div class="albs">';
  for (const a of albums) { const mem = items.filter(i => i.m.alb === a.id), cv = mem[0]; h += '<div class="alb" data-id="' + a.id + '"><div class="cv">' + (cv && cv.thumb ? '<img src="' + cv.thumb + '">' : '📁') + '</div><div class="nm">' + esc(a.name) + '<small>' + mem.length + 'まい</small></div></div>'; }
  h += '<div class="alb" id="albNew"><div class="cv">＋</div><div class="nm">あたらしい<small>アルバムを つくる</small></div></div></div>';
  $('#main').innerHTML = h;
  $('#main').querySelectorAll('.alb[data-id]').forEach(e => e.onclick = () => go('alb', e.dataset.id));
  $('#albNew').onclick = async () => { const n = await ask('アルバムの なまえ', ''); if (n) { await newAlbum(n); render(); } };
}
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/* ---------- ダイアログ ---------- */
function dlg(html) { $('#dbox').innerHTML = html; $('#dlg').classList.remove('hide'); return $('#dbox'); }
function closeDlg() { $('#dlg').classList.add('hide'); $('#dbox').innerHTML = ''; }
$('#dlg').onclick = e => { if (e.target.id === 'dlg') { closeDlg(); if (dlg.resolve) dlg.resolve(null); } };
function ask(title, val) { return new Promise(res => { dlg.resolve = res; const b = dlg('<h3>' + title + '</h3><input id="dIn" value="' + esc(val) + '" maxlength="30"><div class="row"><button class="btn ghost" id="dNo">やめる</button><button class="btn" id="dOk">きめる</button></div>'); const i = b.querySelector('#dIn'); setTimeout(() => i.focus(), 50); b.querySelector('#dNo').onclick = () => { closeDlg(); res(null); }; b.querySelector('#dOk').onclick = () => { closeDlg(); res(i.value.trim() || null); }; }); }
function confirmDlg(title, okLabel, danger) { return new Promise(res => { dlg.resolve = res; const b = dlg('<h3>' + title + '</h3><div class="row"><button class="btn ghost" id="dNo">やめる</button><button class="btn' + (danger ? ' danger' : '') + '" id="dOk">' + okLabel + '</button></div>'); b.querySelector('#dNo').onclick = () => { closeDlg(); res(false); }; b.querySelector('#dOk').onclick = () => { closeDlg(); res(true); }; }); }
function pickAlbum() { return new Promise(res => { dlg.resolve = res; let h = '<h3>どの アルバムに いれる？</h3>'; for (const a of albums) h += '<button class="opt" data-id="' + a.id + '">📁 ' + esc(a.name) + '</button>'; h += '<button class="opt" data-id="__new">＋ あたらしい アルバム</button><button class="opt" data-id="__none">アルバムから はずす</button>'; const b = dlg(h); b.querySelectorAll('.opt').forEach(o => o.onclick = async () => { const id = o.dataset.id; closeDlg(); if (id === '__new') { const n = await ask('アルバムの なまえ', ''); res(n ? (await newAlbum(n)).id : null); } else res(id); }); }); }

/* ---------- アルバム ---------- */
async function newAlbum(name) { const id = hex(crypto.getRandomValues(new Uint8Array(8))), a = { id, name, at: Date.now() }; await setDoc(doc(db, C_ALB, id), { meta: await sealJson({ name, at: a.at }) }); albums.push(a); return a; }
async function renameAlbum(a) { const n = await ask('あたらしい なまえ', a.name); if (!n) return; a.name = n; await setDoc(doc(db, C_ALB, a.id), { meta: await sealJson({ name: n, at: a.at }) }); render(); }
async function deleteAlbum(a) { if (!await confirmDlg('「' + a.name + '」を けす？\n(しゃしんは のこるよ)', 'けす', true)) return; for (const it of items.filter(i => i.m.alb === a.id)) { delete it.m.alb; await saveMeta(it); } await deleteDoc(doc(db, C_ALB, a.id)); albums = albums.filter(x => x.id !== a.id); go('alb'); }

/* ---------- 保存・削除 ---------- */
async function saveMeta(it) {
  const x = (await getDoc(doc(db, C_ITEM, it.id))).data();
  await setDoc(doc(db, C_ITEM, it.id), { ...x, meta: await sealJson(it.m) });
}
async function toggleFav(its) {
  const on = its.some(i => !i.m.fav);
  for (const i of its) { i.m.fav = on ? 1 : 0; if (!on) delete i.m.fav; await saveMeta(i); }
  return on;
}
async function removeItems(its) {
  for (const i of its) { await deleteDoc(doc(db, C_ITEM, i.id)); try { await deleteObject(ref(st, ST_DIR + i.id)); } catch (e) { } }
  const ids = new Set(its.map(i => i.id)); items = items.filter(i => !ids.has(i.id));
}
async function download(its) {
  for (const it of its) {
    try {
      toast('ほぞんの じゅんび…');
      const u8 = await open(new Uint8Array(await getBytes(ref(st, ST_DIR + it.id))));
      const u = URL.createObjectURL(new Blob([u8], { type: it.m.mt || 'application/octet-stream' })), a = document.createElement('a');
      a.href = u; a.download = it.m.n || it.id; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 30000);
    } catch (e) { toast('ほぞんできなかったよ'); }
  }
}
const picks = () => items.filter(i => picked.has(i.id));
$('#sbFav').onclick = async () => { const p = picks(); if (!p.length) return; const on = await toggleFav(p); toast(on ? 'おきにいりに いれたよ' : 'おきにいりから はずしたよ'); selMode = false; picked.clear(); render(); };
$('#sbAlb').onclick = async () => { const p = picks(); if (!p.length) return; const id = await pickAlbum(); if (id == null) return; for (const i of p) { if (id === '__none') delete i.m.alb; else i.m.alb = id; await saveMeta(i); } toast('うごかしたよ'); selMode = false; picked.clear(); render(); };
$('#sbDl').onclick = async () => { const p = picks(); if (!p.length) return; await download(p); };
$('#sbDel').onclick = async () => { const p = picks(); if (!p.length) return; if (!await confirmDlg(p.length + 'まいを けす？\nもとには もどせないよ', 'けす', true)) return; await removeItems(p); toast('けしたよ'); selMode = false; picked.clear(); render(); };

/* ---------- ビューア ---------- */
let vList = [], vIdx = 0, vToken = 0;
async function openViewer(L, id) { vList = L; vIdx = L.findIndex(i => i.id === id); $('#viewer').classList.remove('hide'); showV(); }
async function showV() {
  const it = vList[vIdx]; if (!it) return closeV();
  const tok = ++vToken, vst = $('#vst');
  $('#vTitle').textContent = fmtDay(it.m.d) + '  (' + (vIdx + 1) + '/' + vList.length + ')';
  $('#vFav').textContent = it.m.fav ? '💗' : '♡';
  vst.innerHTML = '<div class="ld">ひらいています…</div>' + (vIdx > 0 ? '<button class="arr l" id="vPrev">‹</button>' : '') + (vIdx < vList.length - 1 ? '<button class="arr r" id="vNext">›</button>' : '');
  const pv = $('#vPrev'), nx = $('#vNext'); if (pv) pv.onclick = () => { vIdx--; showV(); }; if (nx) nx.onclick = () => { vIdx++; showV(); };
  try {
    const u8 = await open(new Uint8Array(await getBytes(ref(st, ST_DIR + it.id)))); if (tok !== vToken) return;
    const u = blobUrl(u8, it.m.mt || (it.m.t === 'v' ? 'video/mp4' : 'image/jpeg')), el = document.createElement(it.m.t === 'v' ? 'video' : 'img');
    el.src = u; if (it.m.t === 'v') { el.controls = true; el.playsInline = true; }
    vst.querySelector('.ld').replaceWith(el);
  } catch (e) { if (tok === vToken) vst.querySelector('.ld').textContent = 'ひらけなかったよ'; }
}
function closeV() { vToken++; $('#viewer').classList.add('hide'); $('#vst').innerHTML = ''; render(); }
$('#vClose').onclick = closeV;
$('#vFav').onclick = async () => { const it = vList[vIdx]; await toggleFav([it]); $('#vFav').textContent = it.m.fav ? '💗' : '♡'; };
$('#vAlb').onclick = async () => { const it = vList[vIdx], id = await pickAlbum(); if (id == null) return; if (id === '__none') delete it.m.alb; else it.m.alb = id; await saveMeta(it); toast('うごかしたよ'); };
$('#vDl').onclick = () => download([vList[vIdx]]);
$('#vDel').onclick = async () => { const it = vList[vIdx]; if (!await confirmDlg('この しゃしんを けす？\nもとには もどせないよ', 'けす', true)) return; await removeItems([it]); vList = vList.filter(i => i.id !== it.id); if (vIdx >= vList.length) vIdx = vList.length - 1; vList.length ? showV() : closeV(); };
$('#vInfo').onclick = () => { const it = vList[vIdx]; dlg('<h3>' + esc(it.m.n || '') + '</h3><div style="color:var(--sub);line-height:1.9;font-size:14px">' + fmtDay(it.m.d) + ' ' + new Date(it.m.d).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }) + '<br>' + (it.m.w ? it.m.w + '×' + it.m.h + '<br>' : '') + (it.m.s / 1048576).toFixed(1) + ' MB</div><div class="row"><button class="btn ghost" id="dNo">とじる</button></div>').querySelector('#dNo').onclick = closeDlg; };
let tx = 0; $('#vst').addEventListener('touchstart', e => tx = e.touches[0].clientX, { passive: true });
$('#vst').addEventListener('touchend', e => { const dx = e.changedTouches[0].clientX - tx; if (Math.abs(dx) > 60) { if (dx < 0 && vIdx < vList.length - 1) { vIdx++; showV(); } else if (dx > 0 && vIdx > 0) { vIdx--; showV(); } } });
document.addEventListener('keydown', e => { if ($('#viewer').classList.contains('hide')) return; if (e.key === 'Escape') closeV(); if (e.key === 'ArrowLeft' && vIdx > 0) { vIdx--; showV(); } if (e.key === 'ArrowRight' && vIdx < vList.length - 1) { vIdx++; showV(); } });

/* ---------- アップロード ---------- */
let jobs = [], running = false;
function renderUp() {
  const main = $('#main');
  main.innerHTML = '<div class="up"><div class="drop">しゃしんや どうがを えらんでね<br>たくさん いっぺんに えらべるよ<br>おなじ しゃしんは じどうで とばすよ<br><button class="btn" id="pick">えらぶ</button></div><div id="jobs"></div></div>';
  $('#pick').onclick = () => $('#file').click(); drawJobs();
}
function drawJobs() {
  const j = $('#jobs'); if (!j) return;
  const lab = { wait: 'まってる', run: 'おくってる', ok: 'できた', dup: 'もう あるよ', err: 'しっぱい' };
  j.innerHTML = jobs.map(x => '<div class="job"><span class="n">' + esc(x.f.name) + '</span><span class="s ' + x.st + '">' + lab[x.st] + (x.err ? ' (' + esc(x.err) + ')' : '') + '</span></div>' + (x.st === 'run' ? '<div class="bar"><i style="width:' + x.p + '%"></i></div>' : '')).join('');
  if (jobs.length) { const ok = jobs.filter(x => x.st === 'ok').length, dup = jobs.filter(x => x.st === 'dup').length; j.insertAdjacentHTML('afterbegin', '<div style="padding:4px 0 10px;font-size:13px;color:var(--sub)">' + jobs.length + 'まい中  できた ' + ok + ' / ダブり ' + dup + '</div>'); }
}
$('#file').onchange = e => { for (const f of e.target.files) jobs.push({ f, st: 'wait', p: 0 }); e.target.value = ''; if (tab !== 'up') go('up'); else drawJobs(); runJobs(); };
async function runJobs() {
  if (running) return; running = true;
  const seen = new Set(items.map(i => i.id));
  const worker = async () => {
    for (; ;) {
      const j = jobs.find(x => x.st === 'wait'); if (!j) return; j.st = 'run'; drawJobs();
      try {
        const buf = new Uint8Array(await j.f.arrayBuffer());
        const id = hex(new Uint8Array(await crypto.subtle.sign('HMAC', HKEY, buf)));
        if (seen.has(id) || (await getDoc(doc(db, C_ITEM, id))).exists()) { j.st = 'dup'; seen.add(id); drawJobs(); continue; }
        seen.add(id); j.p = 20; drawJobs();
        const isV = j.f.type.startsWith('video/'), info = isV ? await videoInfo(j.f) : await imageInfo(j.f, buf);
        const m = { n: j.f.name, t: isV ? 'v' : 'i', mt: j.f.type, s: j.f.size, w: info.w, h: info.h, d: info.d || j.f.lastModified || Date.now(), dur: info.dur };
        if (!m.w) { delete m.w; delete m.h; } if (!m.dur) delete m.dur;
        const sealed = await seal(buf); j.p = 40; drawJobs();
        await uploadBytes(ref(st, ST_DIR + id), sealed); j.p = 90; drawJobs();
        const th = info.thumb ? await seal(info.thumb) : null;
        await setDoc(doc(db, C_ITEM, id), { meta: await sealJson(m), thumb: th ? b64(th) : '', up: serverTimestamp() });
        items.push({ id, m, thumb: info.thumb ? blobUrl(info.thumb, 'image/jpeg') : '' }); items.sort((p, q) => q.m.d - p.m.d);
        j.st = 'ok'; j.p = 100; drawJobs();
      } catch (e) { j.st = 'err'; j.err = e.message || String(e); seen.delete(j.id); drawJobs(); }
    }
  };
  await Promise.all([worker(), worker()]);
  running = false; const ok = jobs.filter(x => x.st === 'ok').length; if (ok) toast(ok + 'まい ほぞんしたよ');
}
/* サムネイル・サイズ・とった日 */
function drawThumb(src, w, h) {
  const k = Math.min(1, 360 / Math.max(w, h)), c = document.createElement('canvas'); c.width = Math.round(w * k); c.height = Math.round(h * k);
  c.getContext('2d').drawImage(src, 0, 0, c.width, c.height);
  return new Promise(r => c.toBlob(async b => r(b ? new Uint8Array(await b.arrayBuffer()) : null), 'image/jpeg', .72));
}
async function imageInfo(f, buf) {
  const d = exifDate(buf), url = URL.createObjectURL(f);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('ひらけない')); i.src = url; });
    return { w: img.naturalWidth, h: img.naturalHeight, d, thumb: await drawThumb(img, img.naturalWidth, img.naturalHeight) };
  } catch (e) { return { d, thumb: null }; } finally { URL.revokeObjectURL(url); }
}
async function videoInfo(f) {
  const url = URL.createObjectURL(f), v = document.createElement('video'); v.muted = true; v.playsInline = true; v.preload = 'metadata'; v.src = url;
  try {
    await new Promise((res, rej) => { v.onloadeddata = res; v.onerror = () => rej(0); setTimeout(rej, 8000); });
    const dur = v.duration || 0; v.currentTime = Math.min(1, dur / 3 || 0);
    await new Promise(r => { v.onseeked = r; setTimeout(r, 2500); });
    return { w: v.videoWidth, h: v.videoHeight, dur, thumb: await drawThumb(v, v.videoWidth, v.videoHeight) };
  } catch (e) { return { thumb: null }; } finally { URL.revokeObjectURL(url); }
}
function exifDate(u8) {   // JPEG の「とった日」(なければ null)
  try {
    if (u8[0] !== 0xFF || u8[1] !== 0xD8) return null;
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength); let p = 2;
    while (p < 65536 && p < u8.length - 4) {
      if (u8[p] !== 0xFF) return null; const mk = u8[p + 1], len = dv.getUint16(p + 2);
      if (mk === 0xE1 && dec.decode(u8.subarray(p + 4, p + 8)) === 'Exif') {
        const t = p + 10, le = dv.getUint16(t) === 0x4949, g16 = o => dv.getUint16(t + o, le), g32 = o => dv.getUint32(t + o, le);
        const find = (off, tag) => { const n = g16(off); for (let i = 0; i < n; i++) { const e = off + 2 + i * 12; if (g16(e) === tag) return g32(e + 8); } return null; };
        const sub = find(g32(4), 0x8769); if (sub == null) return null; const dp = find(sub, 0x9003); if (dp == null) return null;
        const s = dec.decode(u8.subarray(t + dp, t + dp + 19)), m = s.match(/(\d{4}):(\d\d):(\d\d) (\d\d):(\d\d):(\d\d)/);
        return m ? new Date(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]).getTime() : null;
      }
      p += 2 + len;
    }
  } catch (e) { } return null;
}

lockInit().catch(e => { $('#lockMsg').textContent = 'つながらなかったよ'; });
