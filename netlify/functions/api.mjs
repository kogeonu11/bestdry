// 세탁베스트드라이 - Netlify Functions 서버 (저장소: Netlify Blobs)
// 문의 사항 / 매장 소식 / 갤러리 / 관리자 계정을 서버에 저장합니다.
import crypto from 'node:crypto';

let _getStore;
async function store(name) {
  if (!_getStore) _getStore = globalThis.__TEST_GETSTORE__ || (await import('@netlify/blobs')).getStore;
  return _getStore({ name, consistency: 'strong' });
}

// ===== 설정 =====
const INITIAL_PASSWORD = process.env.ADMIN_INITIAL_PASSWORD || 'admin1234'; // 처음 한 번만 쓰이는 임시 비밀번호
const MAX_TOTAL_UPLOAD = 5.2 * 1024 * 1024; // Netlify 함수 요청 한도(약 6MB) 안쪽
const POST_COOLDOWN = 30 * 1000;
const MIN_FILL = 4 * 1000;
const ADMIN_IDLE = 12 * 3600 * 1000;

class HttpError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; } }
const fail = (msg, status = 400) => { throw new HttpError(msg, status); };

// ===== 도우미 =====
const b64u = (b) => Buffer.from(b).toString('base64url');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt$' + salt + '$' + crypto.scryptSync(pw, salt, 64).toString('hex');
}
function checkPw(pw, stored) {
  const [, salt, h] = String(stored).split('$');
  if (!salt || !h) return false;
  const a = Buffer.from(crypto.scryptSync(pw, salt, 64).toString('hex'));
  const b = Buffer.from(h);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

function parseCookies(req) {
  const out = {};
  for (const p of (req.headers.get('cookie') || '').split(/;\s*/)) { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i)] = p.slice(i + 1); }
  return out;
}

async function run(req, context, holder) {
  const url = new URL(req.url);
  const act = url.searchParams.get('a') || '';
  const ctx = { cookies: holder.cookies };
  const secure = url.protocol === 'https:' || (req.headers.get('x-forwarded-proto') === 'https');

  const dbs = await store('db');
  const get = async (k, d) => { const v = await dbs.get(k, { type: 'json' }); return v == null ? d : v; };
  const put = (k, v) => dbs.setJSON(k, v);

  // ----- 설정 (비밀키, 관리자 비밀번호) -----
  let st = await get('settings', null);
  if (!st) {
    st = { secret: crypto.randomBytes(32).toString('hex'), admin_hash: hashPw(INITIAL_PASSWORD), admin_email: '', seq: { posts: 0, news: 0, gallery: 0 } };
    await put('settings', st);
  }
  const saveSettings = () => put('settings', st);
  const sign = (obj) => { const p = b64u(JSON.stringify(obj)); return p + '.' + crypto.createHmac('sha256', st.secret).update(p).digest('base64url'); };
  const unsign = (tok) => {
    if (!tok) return null; const [p, m] = String(tok).split('.'); if (!p || !m) return null;
    const exp = crypto.createHmac('sha256', st.secret).update(p).digest('base64url');
    if (!safeEq(m, exp)) return null;
    try { return JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return null; }
  };
  const setCookie = (name, val, maxAge) => ctx.cookies.push(`${name}=${val}; Path=/; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}${maxAge != null ? '; Max-Age=' + maxAge : ''}`);
  const pwStamp = () => sha(st.admin_hash).slice(0, 12);
  const issueAdmin = () => setCookie('bd_admin', sign({ t: Date.now(), v: pwStamp() }), 43200);
  const cookies = parseCookies(req);
  const sess = unsign(cookies.bd_admin);
  const isAdmin = !!(sess && sess.v === pwStamp() && Date.now() - sess.t < ADMIN_IDLE);
  if (isAdmin) issueAdmin(); // 사용 중에는 로그인 유지 시간 연장
  const needAdmin = () => { if (!isAdmin) fail('관리자 로그인이 필요합니다.', 403); };
  const needPost = () => { if (req.method !== 'POST' || req.headers.get('x-requested-with') !== 'fetch') fail('잘못된 요청입니다.', 400); };

  const ip = sha(req.headers.get('x-nf-client-connection-ip') || context?.ip || 'unknown').slice(0, 24);
  // ----- 요청 횟수 제한 -----
  const rate = async (kind, windowMs) => { const r = await get('rate', {}); return (r[kind + ':' + ip] || []).filter((t) => t > Date.now() - windowMs).length; };
  const rateAdd = async (kind) => {
    const r = await get('rate', {}), now = Date.now(), k = kind + ':' + ip;
    for (const key of Object.keys(r)) { r[key] = r[key].filter((t) => t > now - 1800 * 1000); if (!r[key].length) delete r[key]; }
    (r[k] = r[k] || []).push(now); await put('rate', r);
  };
  const rateClear = async (kind) => { const r = await get('rate', {}); delete r[kind + ':' + ip]; await put('rate', r); };

  const readJson = async () => { const t = await req.text(); if (t.length > 70000) fail('요청이 너무 큽니다.', 413); try { const j = JSON.parse(t || '{}'); return j && typeof j === 'object' ? j : {}; } catch { return {}; } };
  const str = (b, k, max) => (typeof b[k] === 'string' ? b[k].slice(0, max).trim() : '');
  const validEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) && e.length <= 120;
  const nextId = async (kind) => { st.seq[kind] = (st.seq[kind] || 0) + 1; await saveSettings(); return st.seq[kind]; };

  // ===== 라우팅 =====
  switch (act) {

    case 'ping': return { ok: true };

    case 'state': {
      const posts = (await get('posts', [])).map((p) => ({
        id: p.id, notice: !!p.notice, nick: p.nick, title: p.title, text: p.text, ts: p.at,
        reply: p.reply ? { text: p.reply.text, ts: p.reply.at } : null }));
      const news = (await get('news', [])).map((n) => ({ id: n.id, notice: !!n.notice, title: n.title, text: n.text, ts: n.at }));
      const gallery = (await get('gallery', [])).map((g) => ({
        id: g.id, title: g.title, text: g.text, ts: g.at,
        files: g.files.map((f) => ({ kind: f.kind, name: f.name, url: '/.netlify/functions/api?a=file&k=' + f.key })) }));
      return { ok: true, admin: isAdmin, email: isAdmin ? st.admin_email || '' : '', posts, news, gallery };
    }

    // ---------- 보안 문자 ----------
    case 'captcha': {
      const set = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; let code = '';
      for (let i = 0; i < 5; i++) code += set[crypto.randomInt(set.length)];
      setCookie('bd_cap', sign({ c: code, t: Date.now() }), 900);
      const r = (n) => crypto.randomInt(n);
      let svg = '<svg xmlns="http://www.w3.org/2000/svg" width="170" height="56" viewBox="0 0 170 56"><rect width="170" height="56" fill="#D5EBF2"/>';
      for (let i = 0; i < 7; i++) svg += `<path d="M${r(170)} ${r(56)} C${r(170)} ${r(56)} ${r(170)} ${r(56)} ${r(170)} ${r(56)}" stroke="#12323A" stroke-opacity=".45" stroke-width="1.5" fill="none"/>`;
      for (let i = 0; i < 60; i++) svg += `<rect x="${r(170)}" y="${r(56)}" width="2" height="2" fill="#12323A" fill-opacity=".5"/>`;
      for (let i = 0; i < 5; i++) svg += `<text x="0" y="0" transform="translate(${14 + i * 29} ${38 + r(11) - 5}) rotate(${r(51) - 25})" font-family="Arial,Helvetica,sans-serif" font-weight="700" font-size="${28 + r(8)}" fill="#12323A">${code[i]}</text>`;
      return { raw: svg + '</svg>', type: 'image/svg+xml; charset=utf-8' };
    }

    // ---------- 관리자 계정 ----------
    case 'login': {
      needPost();
      if ((await rate('login', 600 * 1000)) >= 5) fail('로그인 시도가 너무 많습니다. 10분 후에 다시 시도해주세요.', 429);
      const b = await readJson(); const pw = String(b.password || '');
      // 비상용: 환경변수 ADMIN_FORCE_PASSWORD 가 설정되어 있으면 그 비밀번호로 로그인하고 비밀번호를 그 값으로 바꿉니다.
      const force = process.env.ADMIN_FORCE_PASSWORD;
      if (force && pw && safeEq(pw, force)) { st.admin_hash = hashPw(pw); await saveSettings(); }
      else if (!pw || !checkPw(pw, st.admin_hash)) { await rateAdd('login'); await new Promise((r) => setTimeout(r, 600)); fail('비밀번호가 맞지 않습니다.', 401); }
      await rateClear('login'); issueAdmin();
      return { ok: true };
    }
    case 'logout': needPost(); setCookie('bd_admin', '', 0); return { ok: true };

    case 'chpw': {
      needPost(); needAdmin();
      if ((await rate('chpw', 600 * 1000)) >= 5) fail('시도가 너무 많습니다. 잠시 후 다시 시도해주세요.', 429);
      const b = await readJson(); const email = str(b, 'email', 120), nw = String(b.new || '');
      if (!checkPw(String(b.cur || ''), st.admin_hash)) { await rateAdd('chpw'); fail('현재 비밀번호가 맞지 않습니다.', 401); }
      if (email && !validEmail(email)) fail('이메일 형식이 올바르지 않습니다.');
      if (nw) { if (nw.length < 8) fail('새 비밀번호는 8자 이상이어야 합니다.'); st.admin_hash = hashPw(nw); }
      st.admin_email = email; await saveSettings(); issueAdmin(); await rateClear('chpw');
      return { ok: true };
    }

    case 'recover_request': {
      needPost();
      if ((await rate('recover', 1800 * 1000)) >= 3) fail('요청이 너무 많습니다. 30분 후에 다시 시도해주세요.', 429);
      await rateAdd('recover');
      const b = await readJson(); const email = str(b, 'email', 120).toLowerCase();
      if (st.admin_email && email && safeEq(email, st.admin_email.toLowerCase())) {
        const code = String(crypto.randomInt(1000000)).padStart(6, '0');
        st.rec = { hash: crypto.createHmac('sha256', st.secret).update(code).digest('hex'), exp: Date.now() + 600000, tries: 0 };
        await saveSettings();
        const key = process.env.RESEND_API_KEY;
        if (!key) console.error('[bestdry] RESEND_API_KEY 가 설정되지 않아 인증 메일을 보내지 못했습니다.');
        else {
          try {
            const r = await fetch('https://api.resend.com/emails', {
              method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
              body: JSON.stringify({ from: process.env.MAIL_FROM || 'onboarding@resend.dev', to: [st.admin_email],
                subject: '[세탁베스트드라이] 관리자 비밀번호 재설정 인증 코드',
                text: `관리자 비밀번호 재설정 인증 코드입니다.\n\n인증 코드: ${code}\n\n10분 안에 입력해주세요. 본인이 요청하지 않았다면 이 메일은 무시하셔도 됩니다.` }) });
            if (!r.ok) console.error('[bestdry] 메일 발송 실패', r.status, await r.text());
          } catch (e) { console.error('[bestdry] 메일 발송 오류', e.message); }
        }
      }
      return { ok: true }; // 등록 여부를 알려주지 않도록 항상 같은 응답
    }

    case 'recover_verify': {
      needPost();
      if ((await rate('recover_v', 1800 * 1000)) >= 10) fail('시도가 너무 많습니다. 30분 후에 다시 시도해주세요.', 429);
      const b = await readJson(); const code = str(b, 'code', 12), nw = String(b.new || '');
      const rec = st.rec;
      if (!rec || Date.now() > rec.exp) fail('인증 코드가 없거나 만료되었습니다. 인증 코드를 다시 받아주세요.');
      if (rec.tries >= 5) { delete st.rec; await saveSettings(); fail('인증 시도 횟수를 넘었습니다. 인증 코드를 다시 받아주세요.'); }
      if (!safeEq(rec.hash, crypto.createHmac('sha256', st.secret).update(code).digest('hex'))) {
        rec.tries++; await saveSettings(); await rateAdd('recover_v'); fail('인증 코드가 맞지 않습니다.');
      }
      if (nw.length < 8) fail('새 비밀번호는 8자 이상이어야 합니다.');
      st.admin_hash = hashPw(nw); delete st.rec; await saveSettings(); await rateClear('login');
      return { ok: true };
    }

    // ---------- 문의 사항 ----------
    case 'post_create': {
      needPost();
      const b = await readJson();
      let nick = str(b, 'nick', 12); const title = str(b, 'title', 40), text = str(b, 'text', 500);
      if (isAdmin && !nick) nick = '관리자';
      if (!nick || !title || !text) fail('닉네임, 제목, 내용을 모두 입력해주세요.');
      if (!isAdmin) {
        if (str(b, 'hp', 200)) return { ok: true, fake: true };
        const cap = unsign(cookies.bd_cap); setCookie('bd_cap', '', 0);
        if (!cap) fail('보안 문자를 새로고침한 뒤 다시 입력해주세요.');
        if (Date.now() - cap.t < MIN_FILL) fail('너무 빠르게 제출되었습니다. 내용을 확인한 뒤 다시 눌러주세요.');
        if (str(b, 'captcha', 10).toUpperCase() !== cap.c) fail('보안 문자가 맞지 않습니다. 새 문자로 다시 입력해주세요.');
        if ((await rate('post', POST_COOLDOWN)) > 0) fail('연속 등록은 제한됩니다. 잠시 후에 다시 시도해주세요.', 429);
        if (/https?:|www\.|\.(com|net|kr|co)\b/i.test(title + ' ' + text)) fail('링크나 사이트 주소는 올릴 수 없습니다.');
      }
      const posts = await get('posts', []); const token = crypto.randomBytes(16).toString('hex'); const id = await nextId('posts');
      posts.unshift({ id, nick, title, text, at: Date.now(), notice: isAdmin && !!b.notice, token: sha(token) });
      await put('posts', posts); if (!isAdmin) await rateAdd('post');
      return { ok: true, id, token };
    }
    case 'post_delete': {
      needPost();
      const b = await readJson(); const id = Number(b.id), token = String(b.token || '');
      const posts = await get('posts', []); const p = posts.find((x) => x.id === id);
      if (!p) fail('이미 삭제되었거나 없는 글입니다.', 404);
      if (!isAdmin && (!token || !safeEq(p.token, sha(token)))) fail('삭제 권한이 없습니다.', 403);
      await put('posts', posts.filter((x) => x.id !== id)); return { ok: true };
    }
    case 'reply_set': {
      needPost(); needAdmin(); const b = await readJson(); const text = str(b, 'text', 500);
      if (!text) fail('답변 내용을 입력해주세요.');
      const posts = await get('posts', []); const p = posts.find((x) => x.id === Number(b.id));
      if (p) { p.reply = { text, at: Date.now() }; await put('posts', posts); } return { ok: true };
    }
    case 'reply_del': {
      needPost(); needAdmin(); const b = await readJson();
      const posts = await get('posts', []); const p = posts.find((x) => x.id === Number(b.id));
      if (p) { delete p.reply; await put('posts', posts); } return { ok: true };
    }
    case 'notice_set': {
      needPost(); needAdmin(); const b = await readJson();
      const posts = await get('posts', []); const p = posts.find((x) => x.id === Number(b.id));
      if (p) { p.notice = !!b.notice; await put('posts', posts); } return { ok: true };
    }

    // ---------- 매장 소식 ----------
    case 'news_create': {
      needPost(); needAdmin(); const b = await readJson(); const title = str(b, 'title', 60), text = str(b, 'text', 2000);
      if (!title || !text) fail('제목과 내용을 모두 입력해주세요.');
      const news = await get('news', []); news.unshift({ id: await nextId('news'), title, text, notice: !!b.notice, at: Date.now() });
      await put('news', news); return { ok: true };
    }
    case 'news_notice_set': {
      needPost(); needAdmin(); const b = await readJson();
      const news = await get('news', []); const n = news.find((x) => x.id === Number(b.id));
      if (n) { n.notice = !!b.notice; await put('news', news); } return { ok: true };
    }
    case 'news_delete': {
      needPost(); needAdmin(); const b = await readJson();
      await put('news', (await get('news', [])).filter((x) => x.id !== Number(b.id))); return { ok: true };
    }

    // ---------- 갤러리 ----------
    case 'gallery_create': {
      needPost(); needAdmin();
      let fd; try { fd = await req.formData(); } catch { fail('올리는 파일이 너무 크거나 형식이 올바르지 않습니다. (한 번에 약 5MB까지)', 413); }
      const title = String(fd.get('title') || '').trim().slice(0, 40), text = String(fd.get('text') || '').trim().slice(0, 500);
      if (!title) fail('제목을 입력해주세요.');
      const files = fd.getAll('files[]').filter((f) => f && typeof f === 'object' && 'arrayBuffer' in f);
      if (!files.length) fail('사진이나 영상을 한 개 이상 선택해주세요.');
      if (files.length > 10) fail('한 번에 최대 10개까지 올릴 수 있습니다.');
      const sniff = (u) => {
        const h = (a, b) => a.every((v, i) => u[b + i] === v);
        if (h([0xff, 0xd8, 0xff], 0)) return ['image/jpeg', 'jpg', 'image'];
        if (h([0x89, 0x50, 0x4e, 0x47], 0)) return ['image/png', 'png', 'image'];
        if (h([0x47, 0x49, 0x46, 0x38], 0)) return ['image/gif', 'gif', 'image'];
        if (h([0x52, 0x49, 0x46, 0x46], 0) && h([0x57, 0x45, 0x42, 0x50], 8)) return ['image/webp', 'webp', 'image'];
        if (h([0x66, 0x74, 0x79, 0x70], 4)) return ['video/mp4', 'mp4', 'video'];
        if (h([0x1a, 0x45, 0xdf, 0xa3], 0)) return ['video/webm', 'webm', 'video'];
        return null;
      };
      let total = 0; const plan = [];
      for (const f of files) {
        const buf = Buffer.from(await f.arrayBuffer()); total += buf.length;
        if (total > MAX_TOTAL_UPLOAD) fail('한 번에 올릴 수 있는 전체 용량(약 5MB)을 넘었습니다. 파일 수를 줄이거나 나눠서 올려주세요.', 413);
        const kind = sniff(buf); const label = String(f.name || 'file');
        if (!kind) fail(`"${label}" 은(는) 올릴 수 없는 형식입니다. (사진: jpg·png·gif·webp, 영상: mp4·webm)`);
        const name = label.replace(/^.*[\\/]/, '').replace(/[^\p{L}\p{N}._ -]/gu, '').slice(0, 100) || 'file';
        plan.push({ buf, mime: kind[0], ext: kind[1], kind: kind[2], name, key: crypto.randomBytes(12).toString('hex') + '.' + kind[1] });
      }
      const fs = await store('files');
      for (const p of plan) await fs.set(p.key, p.buf.buffer.slice(p.buf.byteOffset, p.buf.byteOffset + p.buf.byteLength), { metadata: { type: p.mime, name: p.name } });
      const gal = await get('gallery', []);
      gal.unshift({ id: await nextId('gallery'), title, text, at: Date.now(), files: plan.map((p) => ({ kind: p.kind, name: p.name, key: p.key })) });
      await put('gallery', gal); return { ok: true };
    }
    case 'gallery_delete': {
      needPost(); needAdmin(); const b = await readJson();
      const gal = await get('gallery', []); const g = gal.find((x) => x.id === Number(b.id));
      if (g) { const fs = await store('files'); for (const f of g.files) await fs.delete(f.key); await put('gallery', gal.filter((x) => x.id !== g.id)); }
      return { ok: true };
    }
    case 'file': {
      const k = url.searchParams.get('k') || '';
      if (!/^[a-f0-9]{24}\.(jpg|png|gif|webp|mp4|webm)$/.test(k)) fail('없는 파일입니다.', 404);
      const fs = await store('files'); const r = await fs.getWithMetadata(k, { type: 'arrayBuffer' });
      if (!r) fail('없는 파일입니다.', 404);
      return { raw: r.data, type: r.metadata?.type || 'application/octet-stream', cache: 'public, max-age=31536000, immutable' };
    }

    default: fail('알 수 없는 요청입니다.', 404);
  }
}

export default async (req, context) => {
  let out, status = 200;
  const holder = { cookies: [] };
  try { out = await run(req, context, holder); }
  catch (e) {
    if (e instanceof HttpError) { status = e.status; out = { ok: false, error: e.message }; }
    else { console.error('[bestdry]', e); status = 500; out = { ok: false, error: '서버 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.' }; }
  }
  const h = new Headers({ 'X-Content-Type-Options': 'nosniff' });
  for (const c of holder.cookies) h.append('Set-Cookie', c);
  if (out && out.raw !== undefined) {
    h.set('Content-Type', out.type); h.set('Cache-Control', out.cache || 'no-store');
    return new Response(out.raw, { status, headers: h });
  }
  h.set('Content-Type', 'application/json; charset=utf-8'); h.set('Cache-Control', 'no-store');
  return new Response(JSON.stringify(out), { status, headers: h });
};
