/* かけがえ: かける専用の写真保存アプリ
   - 写真・動画はブラウザの中で暗号化(AES-GCM)してから Firebase に送る。合言葉はどこにも保存しない
   - 同じ写真は1枚だけ: 中身から HMAC の ID を作り、同じ ID は2つ作れない
   - 速さ: 一覧は端末に(暗号化したまま)覚えておき、2回目からは新しい分だけ取る。アップは4枚同時 */
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getFirestore, doc, getDoc, setDoc, collection, getDocs, query, where, Timestamp, serverTimestamp, deleteDoc } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { getStorage, ref, uploadBytes, uploadBytesResumable, getBytes, deleteObject } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

const app = initializeApp({
  apiKey: "AIzaSyDMFs-m2sIJzXa2sKtG7DVhKNNBcU4Ahr8", authDomain: "batarungotai.firebaseapp.com", projectId: "batarungotai",
  storageBucket: "batarungotai.firebasestorage.app", messagingSenderId: "397468782727", appId: "1:397468782727:web:59ab0d085871b187cbe822"
});
const db = getFirestore(app), st = getStorage(app);
const C_META = 'kakegae_meta', C_ITEM = 'kakegae_items', C_ALB = 'kakegae_albums', ST_DIR = 'kakegae/';
const $ = s => document.querySelector(s), enc = new TextEncoder(), dec = new TextDecoder();

/* ---------- 端末のメモ(IndexedDB。中身は暗号化したまま) ---------- */
let _idb = null;
function idb() {
  return _idb || (_idb = new Promise((res, rej) => {
    try { const q = indexedDB.open('kakegae', 1); q.onupgradeneeded = () => { q.result.createObjectStore('docs', { keyPath: 'id' }); q.result.createObjectStore('kv'); }; q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); } catch (e) { rej(e); }
  }).catch(() => null));
}
async function tx(store, mode, fn) {
  const d = await idb(); if (!d) return null;
  return new Promise(res => { try { const t = d.transaction(store, mode), s = t.objectStore(store), r = fn(s); t.oncomplete = () => res(r && r.result !== undefined ? r.result : null); t.onerror = t.onabort = () => res(null); } catch (e) { res(null); } });
}
const kvGet = k => tx('kv', 'readonly', s => s.get(k)), kvSet = (k, v) => tx('kv', 'readwrite', s => s.put(v, k)), kvDel = k => tx('kv', 'readwrite', s => s.delete(k));
const docAll = () => tx('docs', 'readonly', s => s.getAll()), docPut = r => tx('docs', 'readwrite', s => s.put(r)), docClear = () => tx('docs', 'readwrite', s => s.clear());

/* ---------- 暗号 ---------- */
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
let first = false, salt = null, check = null, fid = null;
async function lockInit() {
  const m = await getDoc(doc(db, C_META, 'main'));
  if (!m.exists()) { first = true; $('#lockSub').textContent = '初めて開きます。新しい合言葉を決めてください\n(忘れると二度と開けません)'; $('#pw2').classList.remove('hide'); $('#lockGo').textContent = '決める'; return; }
  salt = unb64(m.data().salt); check = m.data().check;
  fid = await kvGet('face');
  if (fid && fid.salt === m.data().salt && window.PublicKeyCredential) { $('#faceGo').classList.remove('hide'); unlockFace(true); }
}
async function finishUnlock() {
  $('#lock').classList.add('hide'); $('#app').classList.remove('hide'); $('#pw').value = $('#pw2').value = '';
  $('#main').innerHTML = '<div class="empty">読み込み中…</div>'; await loadAll();
}
async function unlock() {
  const pw = $('#pw').value, msg = $('#lockMsg'); msg.textContent = '';
  if (!pw) return;
  $('#lockGo').disabled = true; msg.textContent = '開いています…';
  try {
    if (first) {
      if (pw.length < 6) { msg.textContent = '6文字以上にしてください'; return; }
      if (pw !== $('#pw2').value) { msg.textContent = '2つが一致しません'; return; }
      salt = crypto.getRandomValues(new Uint8Array(16)); await derive(pw, salt);
      await setDoc(doc(db, C_META, 'main'), { salt: b64(salt), check: await sealJson({ ok: 'kakegae' }), at: serverTimestamp() });
    } else {
      await derive(pw, salt);
      try { const r = await openJson(check); if (r.ok !== 'kakegae') throw 0; } catch (e) { KEY = HKEY = null; msg.textContent = '合言葉が違います'; return; }
    }
    await finishUnlock();
  } catch (e) { msg.textContent = 'うまくいきませんでした(' + (e.message || e) + ')'; }
  finally { $('#lockGo').disabled = false; }
}
async function unlockFace(auto) {
  if (!fid) return; const msg = $('#lockMsg');
  try {
    await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), allowCredentials: [{ id: fid.cred, type: 'public-key', transports: ['internal'] }], userVerification: 'required', timeout: 60000, rpId: location.hostname } });
    KEY = fid.key; HKEY = fid.hkey;
    try { const r = await openJson(check); if (r.ok !== 'kakegae') throw 0; } catch (e) { KEY = HKEY = null; await kvDel('face'); fid = null; $('#faceGo').classList.add('hide'); msg.textContent = '顔認証の登録が古くなりました。合言葉で開いてください'; return; }
    await finishUnlock();
  } catch (e) { if (!auto) msg.textContent = '顔認証で開けませんでした。合言葉でも開けます'; }
}
async function enrollFace() {
  if (!window.PublicKeyCredential) return toast('この端末は顔認証に対応していません');
  try {
    const c = await navigator.credentials.create({ publicKey: { rp: { name: 'かけがえ', id: location.hostname }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'kakeru', displayName: 'かける' }, challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' }, timeout: 60000 } });
    await kvSet('face', { cred: new Uint8Array(c.rawId), key: KEY, hkey: HKEY, salt: b64(salt) });
    fid = await kvGet('face'); toast(fid ? '顔認証で開けるようにしました' : '登録できませんでした');
  } catch (e) { toast('登録をやめました'); }
}
async function relock() { revokeAll(); location.reload(); }
$('#lockGo').onclick = unlock; $('#faceGo').onclick = () => unlockFace(false); $('#pw').onkeydown = $('#pw2').onkeydown = e => { if (e.key === 'Enter') unlock(); };
$('#lockBtn').onclick = relock;
let lockT;
document.addEventListener('visibilitychange', () => { if (document.hidden && KEY) { clearTimeout(lockT); lockT = setTimeout(() => { if (document.hidden && !running) relock(); }, 5 * 60 * 1000); } else clearTimeout(lockT); });   // アップ中は自動ロックしない

/* ---------- データ(端末のメモ + 新しい分だけ取得) ---------- */
let items = [], albums = [];
const itemMap = new Map(), seen = new Set(), urls = new Set(), modMap = new Map();
const blobUrl = (u8, type) => { const u = URL.createObjectURL(new Blob([u8], { type })); urls.add(u); return u; };
function revokeAll() { urls.forEach(u => URL.revokeObjectURL(u)); urls.clear(); }
const thumbOf = it => { if (it._u) return it._u; if (!it.tb) return ''; return it._p || (it._p = open(unb64(it.tb)).then(u8 => { it._u = blobUrl(u8, 'image/jpeg'); return it._u; }).catch(() => '')); };
async function ingest(rec) {
  modMap.set(rec.id, rec.mod);
  if (rec.del) { itemMap.delete(rec.id); seen.delete(rec.id); return; }
  try { const old = itemMap.get(rec.id); const m = await openJson(rec.meta); const it = { id: rec.id, m, tb: rec.thumb || '' }; if (old && old.tb === it.tb) { it._u = old._u; it._p = old._p; } itemMap.set(rec.id, it); seen.add(rec.id); } catch (e) { }
}
const rebuild = () => { items = [...itemMap.values()].sort((p, q) => q.m.d - p.m.d); };
async function loadAll() {
  const sv = await kvGet('salt');
  if (sv !== b64(salt)) { await docClear(); await kvDel('last'); await kvSet('salt', b64(salt)); }
  const cached = (await docAll()) || [];
  await Promise.all(cached.map(ingest)); rebuild();
  const fresh = cached.length === 0;
  const done = sync(); if (fresh) await done;
  go('all'); done.then(() => { if (!document.hidden) { rebuild(); if (!['up'].includes(tab) && $('#viewer').classList.contains('hide')) render(); } }).catch(() => { });
}
async function sync() {
  const last = await kvGet('last');
  const q = last ? query(collection(db, C_ITEM), where('mod', '>', Timestamp.fromMillis(last - 3000))) : collection(db, C_ITEM);
  const [a, b] = await Promise.all([getDocs(q), getDocs(collection(db, C_ALB))]);
  let mx = last || 0; const recs = [];
  for (const d of a.docs) { const x = d.data(), mod = x.mod && x.mod.toMillis ? x.mod.toMillis() : 0; recs.push({ id: d.id, meta: x.meta, thumb: x.thumb || '', del: x.del ? 1 : 0, mod }); mx = Math.max(mx, mod); }
  await Promise.all(recs.map(async r => { await docPut(r.del ? { id: r.id, del: 1, mod: r.mod } : r); await ingest(r); }));
  await kvSet('last', mx); rebuild();
  const al = []; await Promise.all(b.docs.map(async d => { try { al.push({ id: d.id, ...(await openJson(d.data().meta)) }); } catch (e) { } }));
  albums = al.sort((p, q) => p.at - q.at);
}

/* ---------- 画面 ---------- */
let tab = 'all', curAlb = null, selMode = false, picked = new Set();
const fmtDay = ms => { const d = new Date(ms); return d.getFullYear() + '年' + (d.getMonth() + 1) + '月' + d.getDate() + '日'; };
const fmtDur = s => Math.floor(s / 60) + ':' + String(Math.floor(s % 60)).padStart(2, '0');
const fmtSize = n => n >= 1073741824 ? (n / 1073741824).toFixed(2) + ' GB' : (n / 1048576).toFixed(1) + ' MB';
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function toast(t) { const e = $('#toast'); e.textContent = t; e.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => e.classList.remove('on'), 2400); }
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
  const main = $('#main'), canSel = tab === 'all' || tab === 'fav' || curAlb, sel = selMode && canSel;
  $('#selBtn').classList.toggle('hide', !canSel);
  $('#selBtn').textContent = sel ? 'やめる' : '選択';
  $('#selbar').classList.toggle('hide', !sel); main.style.paddingBottom = sel ? '70px' : '0';
  if (tab === 'up') { $('#ttl').textContent = 'アップロード'; return renderUp(); }
  if (tab === 'alb' && !curAlb) { $('#ttl').textContent = 'アルバム'; return renderAlbums(); }
  const alb = curAlb && albums.find(a => a.id === curAlb);
  $('#ttl').textContent = tab === 'fav' ? 'お気に入り' : alb ? alb.name : '写真';
  const L = list();
  if (!L.length) { main.innerHTML = (alb ? albumBar() : '') + '<div class="empty">' + (tab === 'fav' ? 'ハートを付けた写真がここに集まります' : alb ? 'このアルバムは空です' : 'まだ何もありません<br>下の「アップ」から入れてください') + '</div>'; bindAlbBar(alb); return; }
  let h = alb ? albumBar() : '', last = '';
  h += '<div class="' + (sel ? 'sel' : '') + '">';
  for (const it of L) {
    const day = fmtDay(it.m.d);
    if (day !== last) { if (last) h += '</div>'; h += '<div class="day">' + day + '</div><div class="grid">'; last = day; }
    h += '<div class="cell' + (picked.has(it.id) ? ' picked' : '') + '" data-id="' + it.id + '"><img alt="">' + (it.m.t === 'v' ? '<span class="dur">▶ ' + fmtDur(it.m.dur || 0) + '</span>' : '') + (it.m.fav ? '<span class="fav">💗</span>' : '') + '<span class="chk">' + (picked.has(it.id) ? '✓' : '') + '</span></div>';
  }
  h += '</div></div>'; main.innerHTML = h;
  const byId = new Map(L.map(i => [i.id, i]));
  main.querySelectorAll('.cell').forEach(c => {
    const it = byId.get(c.dataset.id), img = c.querySelector('img');
    if (!it.tb) { img.remove(); c.insertAdjacentHTML('afterbegin', '<span class="ph0">' + (it.m.t === 'v' ? '🎬' : '🖼') + '</span>'); }
    if (it._u) img.src = it._u; else { const p = thumbOf(it); if (p) Promise.resolve(p).then(u => { if (u && c.isConnected) img.src = u; }); }
    c.onclick = () => {
      const id = c.dataset.id;
      if (sel) { picked.has(id) ? picked.delete(id) : picked.add(id); c.classList.toggle('picked'); c.querySelector('.chk').textContent = picked.has(id) ? '✓' : ''; }
      else openViewer(L, id);
    };
  });
  bindAlbBar(alb);
}
const albumBar = () => '<div class="albbar"><button class="btn ghost" id="albBack">‹ 戻る</button><button class="btn ghost" id="albRen">名前</button><button class="btn ghost" id="albDel">アルバムを削除</button></div>';
function bindAlbBar(alb) { if (!alb) return; $('#albBack').onclick = () => go('alb'); $('#albRen').onclick = () => renameAlbum(alb); $('#albDel').onclick = () => deleteAlbum(alb); }
function renderAlbums() {
  let h = '<div class="albs">';
  for (const a of albums) { const mem = items.filter(i => i.m.alb === a.id), cv = mem[0]; h += '<div class="alb" data-id="' + a.id + '"><div class="cv">' + (cv && cv.tb ? '<img alt="" data-cv="' + cv.id + '">' : '📁') + '</div><div class="nm">' + esc(a.name) + '<small>' + mem.length + '枚</small></div></div>'; }
  h += '<div class="alb" id="albNew"><div class="cv">＋</div><div class="nm">新規作成<small>アルバムを作る</small></div></div></div>';
  $('#main').innerHTML = h;
  $('#main').querySelectorAll('img[data-cv]').forEach(i => { const it = itemMap.get(i.dataset.cv); Promise.resolve(thumbOf(it)).then(u => { if (u) i.src = u; }); });
  $('#main').querySelectorAll('.alb[data-id]').forEach(e => e.onclick = () => go('alb', e.dataset.id));
  $('#albNew').onclick = async () => { const n = await ask('アルバムの名前', ''); if (n) { await newAlbum(n); render(); } };
}

/* ---------- ダイアログ ---------- */
function dlg(html) { $('#dbox').innerHTML = html; $('#dlg').classList.remove('hide'); return $('#dbox'); }
function closeDlg() { $('#dlg').classList.add('hide'); $('#dbox').innerHTML = ''; }
$('#dlg').onclick = e => { if (e.target.id === 'dlg') { closeDlg(); if (dlg.resolve) dlg.resolve(null); } };
function ask(title, val) { return new Promise(res => { dlg.resolve = res; const b = dlg('<h3>' + title + '</h3><input id="dIn" value="' + esc(val) + '" maxlength="30"><div class="row"><button class="btn ghost" id="dNo">やめる</button><button class="btn" id="dOk">決める</button></div>'); const i = b.querySelector('#dIn'); setTimeout(() => i.focus(), 50); b.querySelector('#dNo').onclick = () => { closeDlg(); res(null); }; b.querySelector('#dOk').onclick = () => { closeDlg(); res(i.value.trim() || null); }; }); }
function confirmDlg(title, okLabel, danger) { return new Promise(res => { dlg.resolve = res; const b = dlg('<h3 style="white-space:pre-line">' + title + '</h3><div class="row"><button class="btn ghost" id="dNo">やめる</button><button class="btn' + (danger ? ' danger' : '') + '" id="dOk">' + okLabel + '</button></div>'); b.querySelector('#dNo').onclick = () => { closeDlg(); res(false); }; b.querySelector('#dOk').onclick = () => { closeDlg(); res(true); }; }); }
function pickAlbum() { return new Promise(res => { dlg.resolve = res; let h = '<h3>どのアルバムに入れますか?</h3>'; for (const a of albums) h += '<button class="opt" data-id="' + a.id + '">📁 ' + esc(a.name) + '</button>'; h += '<button class="opt" data-id="__new">＋ 新しいアルバム</button><button class="opt" data-id="__none">アルバムから外す</button>'; const b = dlg(h); b.querySelectorAll('.opt').forEach(o => o.onclick = async () => { const id = o.dataset.id; closeDlg(); if (id === '__new') { const n = await ask('アルバムの名前', ''); res(n ? (await newAlbum(n)).id : null); } else res(id); }); }); }

/* ---------- 設定(保存容量・顔認証) ---------- */
$('#setBtn').onclick = () => {
  const n = items.length, vids = items.filter(i => i.m.t === 'v').length, size = items.reduce((s, i) => s + (i.m.s || 0), 0);
  const yen = size / 1073741824 * 3.5;
  const b = dlg('<h3>保存容量</h3><div class="stat"><div class="big">' + fmtSize(size) + '</div><div>写真 ' + (n - vids) + '枚 / 動画 ' + vids + '本(計 ' + n + '件)</div><div class="mut">料金の目安: 月 約' + (yen < 1 ? '1円未満' : Math.round(yen) + '円') + '(1GBあたり約3.5円で計算)<br>※正確な使用量は Firebase コンソールの Storage で確認できます</div></div><h3 style="margin-top:18px">ロック</h3>' +
    '<button class="opt" id="fidBtn">' + (fid ? '✓ 顔認証で開く: オン(押すとオフ)' : '顔認証(Face ID)で開けるようにする') + '</button><button class="opt" id="lkBtn">今すぐロックする</button><div class="row"><button class="btn ghost" id="dNo">閉じる</button></div>');
  b.querySelector('#dNo').onclick = closeDlg; b.querySelector('#lkBtn').onclick = relock;
  b.querySelector('#fidBtn').onclick = async () => { closeDlg(); if (fid) { await kvDel('face'); fid = null; toast('顔認証をオフにしました'); } else await enrollFace(); };
};

/* ---------- アルバム ---------- */
async function newAlbum(name) { const id = hex(crypto.getRandomValues(new Uint8Array(8))), a = { id, name, at: Date.now() }; await setDoc(doc(db, C_ALB, id), { meta: await sealJson({ name, at: a.at }) }); albums.push(a); return a; }
async function renameAlbum(a) { const n = await ask('新しい名前', a.name); if (!n) return; a.name = n; await setDoc(doc(db, C_ALB, a.id), { meta: await sealJson({ name: n, at: a.at }) }); render(); }
async function deleteAlbum(a) { if (!await confirmDlg('「' + a.name + '」を削除しますか?\n(写真は残ります)', '削除', true)) return; for (const it of items.filter(i => i.m.alb === a.id)) { delete it.m.alb; await saveMeta(it); } await deleteDoc(doc(db, C_ALB, a.id)); albums = albums.filter(x => x.id !== a.id); go('alb'); }

/* ---------- 保存・削除 ---------- */
async function saveMeta(it) {
  const rec = { meta: await sealJson(it.m), thumb: it.tb || '', mod: serverTimestamp() };
  await setDoc(doc(db, C_ITEM, it.id), rec);
  await docPut({ id: it.id, meta: rec.meta, thumb: rec.thumb, del: 0, mod: Date.now() });
}
async function toggleFav(its) {
  const on = its.some(i => !i.m.fav);
  await Promise.all(its.map(i => { if (on) i.m.fav = 1; else delete i.m.fav; return saveMeta(i); }));
  return on;
}
async function removeItems(its) {
  await Promise.all(its.map(async i => {
    await setDoc(doc(db, C_ITEM, i.id), { del: 1, mod: serverTimestamp() });   // 目印だけ残す(他の端末にも消えたことが伝わる)
    await docPut({ id: i.id, del: 1, mod: Date.now() }); try { await deleteObject(ref(st, ST_DIR + i.id)); } catch (e) { }
    itemMap.delete(i.id); seen.delete(i.id); plain.delete(i.id);
  }));
  rebuild();
}
async function download(its) {
  for (const it of its) {
    try {
      toast('保存の準備中…');
      const u8 = await fetchPlain(it), u = URL.createObjectURL(new Blob([u8], { type: it.m.mt || 'application/octet-stream' })), a = document.createElement('a');
      a.href = u; a.download = it.m.n || it.id; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 30000);
    } catch (e) { toast('保存できませんでした'); }
  }
}
const picks = () => items.filter(i => picked.has(i.id));
$('#sbFav').onclick = async () => { const p = picks(); if (!p.length) return; const on = await toggleFav(p); toast(on ? 'お気に入りに入れました' : 'お気に入りから外しました'); selMode = false; picked.clear(); render(); };
$('#sbAlb').onclick = async () => { const p = picks(); if (!p.length) return; const id = await pickAlbum(); if (id == null) return; await Promise.all(p.map(i => { if (id === '__none') delete i.m.alb; else i.m.alb = id; return saveMeta(i); })); toast('移動しました'); selMode = false; picked.clear(); render(); };
$('#sbDl').onclick = async () => { const p = picks(); if (!p.length) return; await download(p); };
$('#sbDel').onclick = async () => { const p = picks(); if (!p.length) return; if (!await confirmDlg(p.length + '件を削除しますか?\nもとには戻せません', '削除', true)) return; await removeItems(p); toast('削除しました'); selMode = false; picked.clear(); render(); };

/* ---------- ビューア(となりを先読み) ---------- */
const plain = new Map();   // id -> Promise<Uint8Array>(復号済み。最大6件)
function fetchPlain(it) {
  if (plain.has(it.id)) { const p = plain.get(it.id); plain.delete(it.id); plain.set(it.id, p); return p; }
  const p = getBytes(ref(st, ST_DIR + it.id)).then(b => open(new Uint8Array(b)));
  p.catch(() => plain.delete(it.id)); plain.set(it.id, p);
  while (plain.size > 6) plain.delete(plain.keys().next().value);
  return p;
}
let vList = [], vIdx = 0, vToken = 0;
function openViewer(L, id) { vList = L; vIdx = L.findIndex(i => i.id === id); $('#viewer').classList.remove('hide'); showV(); }
async function showV() {
  const it = vList[vIdx]; if (!it) return closeV();
  const tok = ++vToken, vst = $('#vst');
  $('#vTitle').textContent = fmtDay(it.m.d) + '  (' + (vIdx + 1) + '/' + vList.length + ')';
  $('#vFav').textContent = it.m.fav ? '💗' : '♡';
  const th = it._u || '';
  vst.innerHTML = (th ? '<img class="ph" src="' + th + '">' : '<div class="ld">開いています…</div>') + (vIdx > 0 ? '<button class="arr l" id="vPrev">‹</button>' : '') + (vIdx < vList.length - 1 ? '<button class="arr r" id="vNext">›</button>' : '');
  const pv = $('#vPrev'), nx = $('#vNext'); if (pv) pv.onclick = () => { vIdx--; showV(); }; if (nx) nx.onclick = () => { vIdx++; showV(); };
  try {
    const u8 = await fetchPlain(it); if (tok !== vToken) return;
    const u = blobUrl(u8, it.m.mt || (it.m.t === 'v' ? 'video/mp4' : 'image/jpeg')), el = document.createElement(it.m.t === 'v' ? 'video' : 'img');
    el.src = u; if (it.m.t === 'v') { el.controls = true; el.playsInline = true; if (!it.tb || !it.m.dur) backfillVideo(it, u); }
    const old = vst.querySelector('.ph,.ld'); if (old) old.replaceWith(el); else vst.prepend(el);
    [vList[vIdx + 1], vList[vIdx - 1]].forEach(n => { if (n && n.m.t !== 'v') fetchPlain(n).catch(() => { }); });
  } catch (e) { if (tok === vToken) { const l = vst.querySelector('.ld,.ph'); if (l) l.outerHTML = '<div class="ld">開けませんでした</div>'; } }
}
async function backfillVideo(it, u) {   // サムネイルか長さが空の動画は、開いたときに埋める
  const v = document.createElement('video'); v.muted = true; v.playsInline = true; v.preload = 'auto'; v.src = u;
  try {
    const r = await videoFrame(v); let ch = false;
    if (r.dur && !it.m.dur) { it.m.dur = r.dur; ch = true; }
    if (r.w && !it.m.w) { it.m.w = r.w; it.m.h = r.h; ch = true; }
    if (r.thumb && !it.tb) { it.tb = b64(await seal(r.thumb)); it._u = it._p = null; ch = true; }
    if (ch) await saveMeta(it);
  } catch (e) { } finally { v.removeAttribute('src'); v.load(); }
}
function closeV() { vToken++; $('#viewer').classList.add('hide'); $('#vst').innerHTML = ''; render(); }
$('#vClose').onclick = closeV;
$('#vFav').onclick = async () => { const it = vList[vIdx]; await toggleFav([it]); $('#vFav').textContent = it.m.fav ? '💗' : '♡'; };
$('#vAlb').onclick = async () => { const it = vList[vIdx], id = await pickAlbum(); if (id == null) return; if (id === '__none') delete it.m.alb; else it.m.alb = id; await saveMeta(it); toast('移動しました'); };
$('#vDl').onclick = () => download([vList[vIdx]]);
$('#vDel').onclick = async () => { const it = vList[vIdx]; if (!await confirmDlg('この写真を削除しますか?\nもとには戻せません', '削除', true)) return; await removeItems([it]); vList = vList.filter(i => i.id !== it.id); if (vIdx >= vList.length) vIdx = vList.length - 1; vList.length ? showV() : closeV(); };
$('#vInfo').onclick = () => { const it = vList[vIdx]; dlg('<h3>' + esc(it.m.n || '') + '</h3><div style="color:var(--sub);line-height:1.9;font-size:14px">' + fmtDay(it.m.d) + ' ' + new Date(it.m.d).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }) + '<br>' + (it.m.w ? it.m.w + '×' + it.m.h + '<br>' : '') + fmtSize(it.m.s || 0) + '</div><div class="row"><button class="btn ghost" id="dNo">閉じる</button></div>').querySelector('#dNo').onclick = closeDlg; };
let tx0 = 0; $('#vst').addEventListener('touchstart', e => tx0 = e.touches[0].clientX, { passive: true });
$('#vst').addEventListener('touchend', e => { const dx = e.changedTouches[0].clientX - tx0; if (Math.abs(dx) > 60) { if (dx < 0 && vIdx < vList.length - 1) { vIdx++; showV(); } else if (dx > 0 && vIdx > 0) { vIdx--; showV(); } } });
document.addEventListener('keydown', e => { if ($('#viewer').classList.contains('hide')) return; if (e.key === 'Escape') closeV(); if (e.key === 'ArrowLeft' && vIdx > 0) { vIdx--; showV(); } if (e.key === 'ArrowRight' && vIdx < vList.length - 1) { vIdx++; showV(); } });

/* ---------- アップロード(4枚同時) ---------- */
let jobs = [], running = false;
let staged = [], stageSkipped = 0, thumbIO = null;
const monthKey = ms => { const d = new Date(ms || Date.now()); return d.getFullYear() * 100 + d.getMonth() + 1; };
const monthLabel = k => Math.floor(k / 100) + '年' + (k % 100) + '月';
function stage(fs) {   // 選んだ写真から、保存済みを自動で外して、確認画面に並べる
  const known = new Set(items.map(i => i.m.n + '|' + i.m.s)), have = new Set(staged.map(x => x.fp));
  for (const f of fs) { const fp = f.name + '|' + f.size; if (known.has(fp) || have.has(fp)) { stageSkipped++; continue; } have.add(fp); staged.push({ f, fp, ck: true, mo: monthKey(f.lastModified) }); }
  if (tab !== 'up') go('up'); else renderUp();
}
function loadThumb(img, f) {
  if (!f.type.startsWith('image/')) { img.replaceWith(Object.assign(document.createElement('span'), { className: 'ph0', textContent: '🎬' })); return; }
  createImageBitmap(f, { resizeWidth: 200, resizeQuality: 'low' }).then(bm => { const c = document.createElement('canvas'); c.width = bm.width; c.height = bm.height; c.getContext('2d').drawImage(bm, 0, 0); c.toBlob(b => { if (b) img.src = blobUrl(b, 'image/jpeg'); }, 'image/jpeg', .6); }).catch(() => { img.replaceWith(Object.assign(document.createElement('span'), { className: 'ph0', textContent: '🖼' })); });
}
function renderUp() {
  const main = $('#main');
  const pickBox = '<div class="drop' + (staged.length ? ' small' : '') + '">' + (staged.length ? '' : '写真や動画を選んでください<br>まとめて何枚でも選べます<br>保存済みの写真は自動で外れます<br>') + '<button class="btn" id="pick">' + (staged.length ? '追加で選ぶ' : '選ぶ') + '</button></div>';
  if (!staged.length) {
    main.innerHTML = '<div class="up">' + (stageSkipped ? '<div class="note">保存済みの ' + stageSkipped + '件は外しました</div>' : '') + pickBox + '<div id="jobs"></div></div>';
    $('#pick').onclick = () => $('#file').click(); drawJobs(); return;
  }
  const by = {}; for (const x of staged) (by[x.mo] = by[x.mo] || []).push(x);
  const months = Object.keys(by).map(Number).sort((p, q) => q - p);
  let h = '<div class="up rv">' + pickBox + '<div class="note">' + (stageSkipped ? '保存済みの ' + stageSkipped + '件は外しました。' : '') + '外したい写真は、タップしてチェックを外してください</div>';
  for (const mo of months) {
    const L = by[mo], on = L.filter(x => x.ck).length;
    h += '<div class="mh"><span>' + monthLabel(mo) + '  <small>' + on + '/' + L.length + '件</small></span><button class="ib" data-mo="' + mo + '">' + (on === L.length ? 'この月を全部外す' : 'この月を全部チェック') + '</button></div><div class="grid">';
    for (const x of L) h += '<div class="cell' + (x.ck ? ' on' : '') + '" data-i="' + staged.indexOf(x) + '"><img alt=""><span class="chk">' + (x.ck ? '✓' : '') + '</span></div>';
    h += '</div>';
  }
  h += '<div id="jobs"></div><div style="height:90px"></div></div>';
  main.innerHTML = h;
  const n = staged.filter(x => x.ck).length;
  main.insertAdjacentHTML('beforeend', '<div id="goBar"><button class="btn" id="goUp"' + (n ? '' : ' disabled') + '>' + n + '件をアップロード</button><button class="btn ghost" id="goNo">やめる</button></div>');
  $('#pick').onclick = () => $('#file').click();
  $('#goNo').onclick = () => { staged = []; stageSkipped = 0; $('#goBar') && $('#goBar').remove(); renderUp(); };
  $('#goUp').onclick = () => { for (const x of staged) if (x.ck) jobs.push({ f: x.f, st: 'wait', p: 0 }); staged = []; stageSkipped = 0; renderUp(); runJobs(); };
  main.querySelectorAll('[data-mo]').forEach(bt => bt.onclick = () => { const L = by[bt.dataset.mo], all = L.every(x => x.ck); L.forEach(x => x.ck = !all); const y = main.scrollTop; renderUp(); $('#main').scrollTop = y; });
  main.querySelectorAll('.cell').forEach(c => { c.onclick = () => { const x = staged[c.dataset.i]; x.ck = !x.ck; renderUp.keep = main.scrollTop; const y = main.scrollTop; renderUp(); $('#main').scrollTop = y; }; });
  if (thumbIO) thumbIO.disconnect();
  thumbIO = new IntersectionObserver(es => es.forEach(e => { if (e.isIntersecting) { thumbIO.unobserve(e.target); const x = staged[e.target.parentNode.dataset.i]; if (x) loadThumb(e.target, x.f); } }), { root: main, rootMargin: '300px' });
  main.querySelectorAll('.cell img').forEach(i => thumbIO.observe(i));
  drawJobs();
}
let drawT = 0;
function drawJobs() { if (drawT) return; drawT = setTimeout(() => { drawT = 0; drawJobsNow(); }, 150); }   // 何百件でも重くならないよう、まとめて描く
function drawJobsNow() {
  const j = $('#jobs'); if (!j) return;
  const lab = { wait: '待機中', run: '送信中', ok: '完了', dup: '保存済み', err: '失敗' };
  const cnt = { wait: 0, run: 0, ok: 0, dup: 0, err: 0 }; for (const x of jobs) cnt[x.st]++;
  if (!jobs.length) { j.innerHTML = ''; return; }
  const done = cnt.ok + cnt.dup + cnt.err, pct = Math.round(done / jobs.length * 100);
  let h = '<div class="sum"><div class="bar big"><i style="width:' + pct + '%"></i></div><div class="sumt">' + done + ' / ' + jobs.length + '件 処理済み(完了 ' + cnt.ok + (cnt.dup ? ' / 保存済み ' + cnt.dup : '') + (cnt.err ? ' / 失敗 ' + cnt.err : '') + ')</div>' + (cnt.err && !cnt.run && !cnt.wait ? '<button class="btn" id="retry" style="margin:8px 0">失敗した ' + cnt.err + '件をもう一度送る</button>' : '') + (cnt.run + cnt.wait ? '<div class="sumt">アップ中は、この画面を開いたままにしてください</div>' : '') + '</div>';
  const show = jobs.filter(x => x.st === 'run' || x.st === 'err').slice(0, 12);
  h += show.map(x => '<div class="job"><span class="n">' + esc(x.f.name) + '</span><span class="s ' + x.st + '">' + lab[x.st] + '</span></div>' + (x.err ? '<div class="jerr">' + esc(String(x.err).slice(0, 80)) + '</div>' : '') + (x.st === 'run' ? '<div class="bar"><i style="width:' + Math.round(x.p) + '%"></i></div>' : '')).join('');
  j.innerHTML = h;
  const r = $('#retry'); if (r) r.onclick = () => { jobs.forEach(x => { if (x.st === 'err') { x.st = 'wait'; x.err = ''; x.tries = 0; } }); runJobs(); };
}
$('#file').onchange = e => { const fs = [...e.target.files]; e.target.value = ''; stage(fs); };
function putBlob(path, u8, onp) {
  const r = ref(st, path);
  if (u8.length < 16 * 1048576) return uploadBytes(r, u8).then(() => onp(1));
  return new Promise((res, rej) => { const t = uploadBytesResumable(r, u8); t.on('state_changed', s => onp(s.bytesTransferred / s.totalBytes), rej, res); });
}
async function runJobs() {
  if (running) return; running = true;
  let wl = null; try { wl = await navigator.wakeLock.request('screen'); } catch (e) { }   // アップ中は画面を消さない
  const worker = async () => {
    for (; ;) {
      const j = jobs.find(x => x.st === 'wait'); if (!j) return; j.st = 'run'; j.p = 2; drawJobs();
      try {
        const buf = new Uint8Array(await j.f.arrayBuffer());
        const id = j.id = hex(new Uint8Array(await crypto.subtle.sign('HMAC', HKEY, buf)));
        if (seen.has(id)) { j.st = 'dup'; drawJobs(); continue; }
        seen.add(id);
        const isV = j.f.type.startsWith('video/');
        const infoP = isV ? videoInfo(j.f) : imageInfo(j.f, buf);                                   // 重複確認と同時に進める
        const remote = await getDoc(doc(db, C_ITEM, id));
        if (remote.exists() && !remote.data().del) { j.st = 'dup'; drawJobs(); continue; }
        const [info, sealed] = await Promise.all([infoP, seal(buf)]); j.p = 15; drawJobs();
        const m = { n: j.f.name, t: isV ? 'v' : 'i', mt: j.f.type, s: j.f.size, w: info.w, h: info.h, d: info.d || j.f.lastModified || Date.now(), dur: info.dur };
        if (!m.w) { delete m.w; delete m.h; } if (!m.dur) delete m.dur;
        const [th, meta] = await Promise.all([info.thumb ? seal(info.thumb) : null, sealJson(m)]);
        const tb = th ? b64(th) : '';
        await putBlob(ST_DIR + id, sealed, f => { j.p = 15 + 80 * f; });
        j.p = 97; drawJobs();
        await setDoc(doc(db, C_ITEM, id), { meta, thumb: tb, mod: serverTimestamp() });
        await docPut({ id, meta, thumb: tb, del: 0, mod: Date.now() });
        itemMap.set(id, { id, m, tb }); rebuild();
        j.st = 'ok'; j.p = 100; drawJobs();
      } catch (e) {
        if (j.id) seen.delete(j.id);
        if ((j.tries = (j.tries || 0) + 1) < 3) { j.st = 'wait'; await new Promise(r => setTimeout(r, 1500 * j.tries)); }   // 電波が弱いときは自動で2回までやり直す
        else { j.st = 'err'; j.err = e.name === 'NotReadableError' ? 'ファイルを読み込めません(iCloudの写真は、先に端末へダウンロードしてください)' : (e.message || String(e)); }
        drawJobs();
      }
    }
  };
  const t = setInterval(drawJobs, 500);
  await Promise.all([worker(), worker(), worker(), worker()]);
  clearInterval(t); drawJobs(); running = false; try { wl && wl.release(); } catch (e) { }
  const ok = jobs.filter(x => x.st === 'ok').length; if (ok) toast(ok + '件を保存しました');
}
/* サムネイル・サイズ・撮影日 */
function drawThumb(src, w, h) {
  const k = Math.min(1, 280 / Math.max(w, h)), c = document.createElement('canvas'); c.width = Math.max(1, Math.round(w * k)); c.height = Math.max(1, Math.round(h * k));
  c.getContext('2d').drawImage(src, 0, 0, c.width, c.height);
  return new Promise(r => c.toBlob(async b => r(b ? new Uint8Array(await b.arrayBuffer()) : null), 'image/jpeg', .65));
}
async function imageInfo(f, buf) {
  const d = exifDate(buf), url = URL.createObjectURL(f);
  try {
    const img = await new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('timeout')), 20000); const i = new Image(); i.onload = () => { clearTimeout(t); res(i); }; i.onerror = () => { clearTimeout(t); rej(new Error('画像を開けません')); }; i.src = url; });
    return { w: img.naturalWidth, h: img.naturalHeight, d, thumb: await drawThumb(img, img.naturalWidth, img.naturalHeight) };
  } catch (e) { return { d, thumb: null }; } finally { URL.revokeObjectURL(url); }
}
const waitEv = (el, ev, ms) => new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('timeout ' + ev)), ms); el.addEventListener(ev, () => { clearTimeout(t); res(); }, { once: true }); el.addEventListener('error', () => { clearTimeout(t); rej(new Error('video error')); }, { once: true }); });
async function videoFrame(v) {   // 動画の1コマ目あたりを取る。取れなくても長さと大きさは返す
  const out = {};
  try {
    if (!(v.readyState >= 1)) await waitEv(v, 'loadedmetadata', 20000);
    out.dur = isFinite(v.duration) ? v.duration : 0; out.w = v.videoWidth; out.h = v.videoHeight;
    const at = Math.min(1, (out.dur || 0) / 3) || 0.01;
    const sk = waitEv(v, 'seeked', 15000); v.currentTime = at; await sk;
    out.thumb = await drawThumb(v, v.videoWidth, v.videoHeight);
  } catch (e) { }
  return out;
}
async function videoInfo(f) {
  const url = URL.createObjectURL(f), v = document.createElement('video'); v.muted = true; v.playsInline = true; v.preload = 'auto'; v.src = url;
  try { const r = await videoFrame(v); return { w: r.w, h: r.h, dur: r.dur, thumb: r.thumb || null }; } finally { v.removeAttribute('src'); v.load(); URL.revokeObjectURL(url); }
}
function exifDate(u8) {
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

lockInit().catch(e => { $('#lockMsg').textContent = '接続できませんでした'; });
