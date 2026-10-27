'use strict';
/**
 * Test platformasi serveri (hech qanday tashqi paketsiz, faqat Node.js 18+).
 *
 * Ishga tushirish:   ADMIN_PASSWORD="kuchli-parol" node server.js
 * Ma'lumotlar:       data.json faylida saqlanadi (server o'chsa ham yo'qolmaydi)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- Sozlamalar ----------
const PORT = Number(process.env.PORT) || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // nginx/hosting orqasida bo'lsa 1 qiling
const MAX_PARTICIPANTS = 30;                  // bitta to'plamga ko'pi bilan nechta odam
const CODE_GRACE_MS = 10 * 60 * 1000;         // savollar tugagach kod yana 10 daqiqa amal qiladi
const ANSWER_GRACE_MS = 1500;                 // tarmoq kechikishi uchun kichik zaxira
const PUBLIC_DIR = path.join(__dirname, 'public');
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // O/0, I/1 kabi adashtiradigan harflarsiz

// ---------- Ma'lumotlar bazasi (JSON fayl) ----------
let db = { secret: '', sets: [] };
try {
  db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
} catch (_) { /* birinchi ishga tushish */ }
if (!db.secret) db.secret = crypto.randomBytes(32).toString('hex');
if (!Array.isArray(db.sets)) db.sets = [];

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; flush(); }, 150);
}
function flush() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE); // yarim yozilgan fayl qolmasligi uchun
}
flush();
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { flush(); } finally { process.exit(0); } });
}

// ---------- Yordamchilar ----------
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (m) => new HttpError(400, m);

function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { reject(new HttpError(413, 'Hajm juda katta')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        resolve(v && typeof v === 'object' ? v : {});
      } catch (_) { reject(bad("So'rov formati noto'g'ri")); }
    });
    req.on('error', reject);
  });
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const x = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (x) return x;
  }
  return req.socket.remoteAddress || 'unknown';
}

// ---------- Admin autentifikatsiyasi ----------
function sign(value) {
  return crypto.createHmac('sha256', db.secret + ADMIN_PASSWORD).update(value).digest('hex');
}
function makeAdminToken() {
  const exp = String(Date.now() + 12 * 3600 * 1000);
  return exp + '.' + sign(exp);
}
function isAdmin(req) {
  const tok = parseCookies(req).admin;
  if (!tok) return false;
  const [exp, sig] = tok.split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const good = Buffer.from(sign(exp));
  const got = Buffer.from(sig);
  return good.length === got.length && crypto.timingSafeEqual(good, got);
}
function requireAdmin(req) {
  if (!isAdmin(req)) throw new HttpError(401, 'Avval admin sifatida kiring');
}

const loginFails = new Map(); // ip -> {count, until}
function checkLoginAllowed(ip) {
  const f = loginFails.get(ip);
  if (f && f.until > Date.now()) {
    throw new HttpError(429, `Juda ko'p urinish. ${Math.ceil((f.until - Date.now()) / 1000)} soniyadan keyin urinib ko'ring`);
  }
}
function registerLoginFail(ip) {
  const f = loginFails.get(ip) || { count: 0, until: 0 };
  f.count += 1;
  if (f.count >= 5) { f.until = Date.now() + 60_000; f.count = 0; }
  loginFails.set(ip, f);
}

// ---------- Mantiq ----------
const newId = () => crypto.randomBytes(5).toString('hex');
const newToken = () => crypto.randomBytes(18).toString('hex');

function newCode() {
  for (;;) {
    let c = '';
    for (let i = 0; i < 6; i++) c += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
    if (!db.sets.some((s) => s.code === c)) return c;
  }
}

/** lobby = hali boshlanmagan, running = davom etmoqda, ended = vaqt tugagan */
function statusOf(s, now) {
  if (!s.startedAt) return 'lobby';
  return now < s.endsAt ? 'running' : 'ended';
}
/** Kod faqat savollar tugagandan keyin 10 daqiqagacha ochiq */
function codeUntil(s) { return s.endsAt ? s.endsAt + CODE_GRACE_MS : null; }
function codeAlive(s, now) { return !s.endsAt || now < s.endsAt + CODE_GRACE_MS; }

function countCorrect(s, p) {
  let n = 0;
  s.questions.forEach((q, i) => { if (p.answers[i] === q.correct) n++; });
  return n;
}
function isFinished(s, p, now) { return !!p.finishedAt || statusOf(s, now) === 'ended'; }

function cleanSetInput(b) {
  const title = String(b.title || '').trim().slice(0, 120);
  if (!title) throw bad("To'plam nomini kiriting");
  const durationMin = Math.round(Number(b.durationMin));
  if (!(durationMin >= 1 && durationMin <= 300)) throw bad("Vaqt 1 dan 300 daqiqagacha bo'lishi kerak");
  if (!Array.isArray(b.questions) || !b.questions.length) throw bad('Kamida bitta savol kerak');
  if (b.questions.length > 200) throw bad("Savollar soni 200 tadan oshmasin");
  const questions = b.questions.map((q, i) => {
    const text = String((q && q.text) || '').trim().slice(0, 500);
    if (!text) throw bad(`${i + 1}-savol matni bo'sh`);
    const options = (Array.isArray(q.options) ? q.options : []).map((o) => String(o || '').trim().slice(0, 300));
    if (options.length < 2 || options.length > 6) throw bad(`${i + 1}-savolda 2 tadan 6 tagacha variant bo'lishi kerak`);
    if (options.some((o) => !o)) throw bad(`${i + 1}-savolda bo'sh variant bor`);
    const correct = Number(q.correct);
    if (!Number.isInteger(correct) || correct < 0 || correct >= options.length) throw bad(`${i + 1}-savolda to'g'ri javob belgilanmagan`);
    return { text, options, correct };
  });
  return { title, durationMin, questions };
}

function getSet(id) {
  const s = db.sets.find((x) => x.id === id);
  if (!s) throw new HttpError(404, "To'plam topilmadi");
  return s;
}

// ---------- Admin ko'rinishlari ----------
function setSummary(s, now) {
  const qn = s.questions.length;
  const fin = s.participants.filter((p) => isFinished(s, p, now));
  const avg = s.participants.length && qn
    ? Math.round(s.participants.reduce((a, p) => a + countCorrect(s, p) / qn, 0) / s.participants.length * 100)
    : null;
  return {
    id: s.id, title: s.title, code: s.code, status: statusOf(s, now),
    questionCount: qn, durationMin: s.durationMin,
    participants: s.participants.length, finished: fin.length, avgPercent: avg,
    startedAt: s.startedAt, endsAt: s.endsAt, codeUntil: codeUntil(s), createdAt: s.createdAt,
  };
}

function adminOverview(now) {
  const sets = db.sets.slice().sort((a, b) => b.createdAt - a.createdAt).map((s) => setSummary(s, now));
  const totalParticipants = sets.reduce((a, s) => a + s.participants, 0);
  const totalFinished = sets.reduce((a, s) => a + s.finished, 0);
  let pctSum = 0, pctN = 0;
  for (const s of db.sets) {
    const qn = s.questions.length;
    for (const p of s.participants) {
      if (isFinished(s, p, now) && qn) { pctSum += countCorrect(s, p) / qn; pctN++; }
    }
  }
  return {
    now,
    totals: {
      sets: sets.length, participants: totalParticipants, finished: totalFinished,
      avgPercent: pctN ? Math.round(pctSum / pctN * 100) : null,
    },
    sets,
  };
}

function adminSetDetail(s, now) {
  const qn = s.questions.length;
  const st = statusOf(s, now);
  const participants = s.participants.map((p) => {
    const finished = isFinished(s, p, now);
    const correct = countCorrect(s, p);
    const endTs = p.finishedAt || (st === 'ended' ? s.endsAt : null);
    const from = s.startedAt ? Math.max(p.joinedAt, s.startedAt) : null;
    return {
      id: p.id, name: p.name, answered: Object.keys(p.answers).length, correct,
      percent: qn ? Math.round(correct / qn * 100) : 0, finished, joinedAt: p.joinedAt,
      timeSec: endTs && from ? Math.max(0, Math.round((Math.min(endTs, s.endsAt) - from) / 1000)) : null,
    };
  });
  const total = s.participants.length;
  const questions = s.questions.map((q, i) => {
    const dist = q.options.map(() => 0);
    let answered = 0;
    for (const p of s.participants) {
      const a = p.answers[i];
      if (a !== undefined) { dist[a]++; answered++; }
    }
    const correctCount = dist[q.correct];
    return {
      text: q.text, options: q.options, correct: q.correct, dist, answered,
      skipped: total - answered, correctCount,
      rate: total ? Math.round(correctCount / total * 100) : null,
    };
  });
  const percents = participants.map((p) => p.percent);
  return {
    ...setSummary(s, now),
    now,
    maxParticipants: MAX_PARTICIPANTS,
    stats: {
      avgPercent: percents.length ? Math.round(percents.reduce((a, b) => a + b, 0) / percents.length) : null,
      best: percents.length ? Math.max(...percents) : null,
      worst: percents.length ? Math.min(...percents) : null,
    },
    participantList: participants,
    questions,
  };
}

// ---------- Qatnashuvchi ko'rinishi ----------
function sessionView(s, p, now) {
  const st = statusOf(s, now);
  const finished = isFinished(s, p, now);
  const v = {
    now, title: s.title, status: st, name: p.name, total: s.questions.length,
    durationMin: s.durationMin, startedAt: s.startedAt, endsAt: s.endsAt,
    codeUntil: codeUntil(s), finished, answers: p.answers,
  };
  if (st === 'running' && !p.finishedAt) {
    // To'g'ri javoblar test davomida HECH QACHON yuborilmaydi
    v.questions = s.questions.map((q) => ({ text: q.text, options: q.options }));
  }
  if (finished) {
    const correct = countCorrect(s, p);
    v.score = correct;
    v.percent = s.questions.length ? Math.round(correct / s.questions.length * 100) : 0;
  }
  if (st === 'ended') {
    // Tahlil faqat hamma uchun vaqt tugagach ochiladi (boshqalarga oldindan oshkor bo'lmasligi uchun)
    v.review = s.questions.map((q, i) => ({
      text: q.text, options: q.options, correct: q.correct,
      mine: p.answers[i] === undefined ? null : p.answers[i],
    }));
  }
  return v;
}

function getCtx(code, token) {
  const c = String(code || '').trim().toUpperCase();
  const s = db.sets.find((x) => x.code === c);
  if (!s) throw new HttpError(404, "Kod noto'g'ri");
  const now = Date.now();
  if (!codeAlive(s, now)) throw new HttpError(410, 'Bu kodning muddati tugagan');
  const p = s.participants.find((x) => x.token === token);
  if (!p) throw new HttpError(401, 'Qatnashuvchi topilmadi. Qaytadan kiring');
  return { s, p, now };
}

// ---------- API ----------
async function api(req, res, url) {
  const m = req.method;
  const p = url.pathname;
  let mt;

  // ----- Admin -----
  if (p === '/api/admin/login' && m === 'POST') {
    const ip = clientIp(req);
    checkLoginAllowed(ip);
    const b = await readBody(req);
    const a = Buffer.from(String(b.password || ''));
    const z = Buffer.from(ADMIN_PASSWORD);
    const ok = a.length === z.length && crypto.timingSafeEqual(a, z);
    if (!ok) { registerLoginFail(ip); throw new HttpError(401, "Parol noto'g'ri"); }
    loginFails.delete(ip);
    const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    return send(res, 200, { ok: true }, {
      'Set-Cookie': `admin=${makeAdminToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${secure}`,
    });
  }
  if (p === '/api/admin/logout' && m === 'POST') {
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }
  if (p === '/api/admin/overview' && m === 'GET') {
    requireAdmin(req);
    return send(res, 200, adminOverview(Date.now()));
  }
  if (p === '/api/admin/sets' && m === 'POST') {
    requireAdmin(req);
    const data = cleanSetInput(await readBody(req));
    const s = {
      id: newId(), code: newCode(), ...data, createdAt: Date.now(),
      startedAt: null, endsAt: null, participants: [],
    };
    db.sets.push(s);
    save();
    return send(res, 201, { id: s.id, code: s.code });
  }
  if ((mt = p.match(/^\/api\/admin\/sets\/([a-f0-9]+)(?:\/(start|end))?$/))) {
    requireAdmin(req);
    const s = getSet(mt[1]);
    const action = mt[2];
    const now = Date.now();
    if (!action && m === 'GET') {
      const d = adminSetDetail(s, now);
      d.editable = statusOf(s, now) === 'lobby';
      if (d.editable) d.rawQuestions = s.questions; // tahrirlash uchun
      return send(res, 200, d);
    }
    if (!action && m === 'PUT') {
      if (statusOf(s, now) !== 'lobby') throw new HttpError(409, "Test boshlangandan keyin o'zgartirib bo'lmaydi");
      Object.assign(s, cleanSetInput(await readBody(req)));
      save();
      return send(res, 200, { ok: true });
    }
    if (!action && m === 'DELETE') {
      db.sets = db.sets.filter((x) => x.id !== s.id);
      save();
      return send(res, 200, { ok: true });
    }
    if (action === 'start' && m === 'POST') {
      if (s.startedAt) throw new HttpError(409, 'Test allaqachon boshlangan');
      s.startedAt = now;
      s.endsAt = now + s.durationMin * 60_000;
      save();
      return send(res, 200, { ok: true });
    }
    if (action === 'end' && m === 'POST') {
      if (statusOf(s, now) !== 'running') throw new HttpError(409, 'Test hozir davom etmayapti');
      s.endsAt = now;
      save();
      return send(res, 200, { ok: true });
    }
    throw new HttpError(405, 'Usul qo\'llab-quvvatlanmaydi');
  }

  // ----- Qatnashuvchi -----
  if (p === '/api/join' && m === 'POST') {
    const b = await readBody(req);
    const code = String(b.code || '').trim().toUpperCase();
    const s = db.sets.find((x) => x.code === code);
    if (!s) throw new HttpError(404, "Kod noto'g'ri");
    const now = Date.now();
    if (!codeAlive(s, now)) throw new HttpError(410, 'Bu kodning muddati tugagan');
    // Qaytib kirish (sahifa yangilansa yoki aloqa uzilsa): token bilan
    if (b.token) {
      const ex = s.participants.find((x) => x.token === String(b.token));
      if (ex) return send(res, 200, { token: ex.token, name: ex.name });
    }
    const name = String(b.name || '').replace(/\s+/g, ' ').trim().slice(0, 40);
    if (name.length < 2) throw bad('Ismingizni kiriting (kamida 2 ta belgi)');
    if (statusOf(s, now) === 'ended') throw new HttpError(403, "Test tugagan, yangi qatnashuvchi qo'shila olmaydi");
    if (s.participants.length >= MAX_PARTICIPANTS) throw new HttpError(403, `Joylar to'lgan (${MAX_PARTICIPANTS}/${MAX_PARTICIPANTS})`);
    if (s.participants.some((x) => x.name.toLowerCase() === name.toLowerCase())) {
      throw new HttpError(409, "Bu ism bilan allaqachon kirilgan. Boshqa ism yozing");
    }
    const part = { id: newId(), token: newToken(), name, joinedAt: now, answers: {}, finishedAt: null };
    s.participants.push(part);
    save();
    return send(res, 201, { token: part.token, name: part.name });
  }
  if (p === '/api/session' && m === 'GET') {
    const { s, p: part, now } = getCtx(url.searchParams.get('code'), url.searchParams.get('token'));
    return send(res, 200, sessionView(s, part, now));
  }
  if (p === '/api/answer' && m === 'POST') {
    const b = await readBody(req);
    const { s, p: part, now } = getCtx(b.code, b.token);
    if (!s.startedAt) throw new HttpError(409, 'Test hali boshlanmagan');
    if (part.finishedAt || now > s.endsAt + ANSWER_GRACE_MS) throw new HttpError(409, 'Vaqt tugagan yoki test yakunlangan');
    const q = Number(b.q), choice = Number(b.choice);
    if (!Number.isInteger(q) || q < 0 || q >= s.questions.length) throw bad("Savol raqami noto'g'ri");
    if (!Number.isInteger(choice) || choice < 0 || choice >= s.questions[q].options.length) throw bad("Variant noto'g'ri");
    if (part.answers[q] !== undefined) throw new HttpError(409, "Bu savolga javob allaqachon belgilangan, o'zgartirib bo'lmaydi");
    part.answers[q] = choice; // bir marta yoziladi va hech qachon o'zgarmaydi
    save();
    return send(res, 200, { ok: true });
  }
  if (p === '/api/finish' && m === 'POST') {
    const b = await readBody(req);
    const { s, p: part, now } = getCtx(b.code, b.token);
    if (statusOf(s, now) === 'running' && !part.finishedAt) { part.finishedAt = now; save(); }
    return send(res, 200, { ok: true });
  }
  if (p === '/api/health') return send(res, 200, { ok: true });

  throw new HttpError(404, 'Topilmadi');
}

// ---------- Statik fayllar ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.png': 'image/png', '.webmanifest': 'application/manifest+json; charset=utf-8',
};
// Bitta fayl rejimi: build-single.js shu qatorni public/ papkasi mazmuni bilan almashtiradi
const EMBED = {"/admin.html":"PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9InV6Ij4KPGhlYWQ+CiAgPG1ldGEgY2hhcnNldD0idXRmLTgiPgogIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgdmlld3BvcnQtZml0PWNvdmVyIj4KICA8bWV0YSBuYW1lPSJ0aGVtZS1jb2xvciIgY29udGVudD0iIzI1NjNlYiI+CiAgPGxpbmsgcmVsPSJpY29uIiB0eXBlPSJpbWFnZS9wbmciIGhyZWY9Ii9pY29uLTE5Mi5wbmciPgogIDx0aXRsZT5BZG1pbiBwYW5lbGk8L3RpdGxlPgogIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iL3N0eWxlLmNzcyI+CjwvaGVhZD4KPGJvZHk+CiAgPGRpdiBpZD0iYXBwIj48L2Rpdj4KICA8c2NyaXB0IHNyYz0iL2NvbW1vbi5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9Ii9hZG1pbi5qcyI+PC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=","/admin.js":"Ly8gQWRtaW4gcGFuZWxpOiB0bydwbGFtIHlhcmF0aXNoLCBrb2RuaSBrbydyaXNoLCB0YXltZXJuaSBib3NocWFyaXNoLCBuYXRpamFsYXIgdmEgZGlhZ25vc3Rpa2EKKGZ1bmN0aW9uICgpIHsKICBjb25zdCBhcHAgPSAkKCcjYXBwJyk7CiAgbGV0IHBvbGwgPSBudWxsOyAgICAgIC8vIGRhdnJpeSB5YW5naWxhc2gKICBsZXQgY2xvY2sgPSBudWxsOyAgICAgLy8gc2VrdW5kaWdhIGJpciBtYXJ0YSB0YXltZXJuaSB5YW5naWxhc2gKICBsZXQgb2Zmc2V0ID0gMDsgICAgICAgLy8gc2VydmVyIHZhcXRpIC0gdGVsZWZvbiB2YXF0aQogIGNvbnN0IExFVFRFUlMgPSAnQUJDREVGJzsKICBjb25zdCBTVEFUVVMgPSB7IGxvYmJ5OiAnS3V0aWxtb3FkYScsIHJ1bm5pbmc6ICdEYXZvbSBldG1vcWRhJywgZW5kZWQ6ICdUdWdhZ2FuJyB9OwoKICBmdW5jdGlvbiBzdG9wKCkgeyBjbGVhckludGVydmFsKHBvbGwpOyBjbGVhckludGVydmFsKGNsb2NrKTsgcG9sbCA9IGNsb2NrID0gbnVsbDsgfQogIGZ1bmN0aW9uIG9uRXJyKGUpIHsgaWYgKGUuc3RhdHVzID09PSA0MDEpIHNob3dMb2dpbigpOyBlbHNlIHRvYXN0KGUubWVzc2FnZSk7IH0KCiAgLy8gPT09PT09PT09PT09PT09PT0gS2lyaXNoID09PT09PT09PT09PT09PT09CiAgZnVuY3Rpb24gc2hvd0xvZ2luKG1zZykgewogICAgc3RvcCgpOwogICAgYXBwLmlubmVySFRNTCA9IGAKICAgICAgPGRpdiBjbGFzcz0id3JhcCBuYXJyb3ciPjxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxoMT5BZG1pbiBraXJpc2hpPC9oMT4KICAgICAgICA8bGFiZWwgZm9yPSJwdyI+UGFyb2w8L2xhYmVsPgogICAgICAgIDxpbnB1dCBpZD0icHciIHR5cGU9InBhc3N3b3JkIiBhdXRvY29tcGxldGU9ImN1cnJlbnQtcGFzc3dvcmQiPgogICAgICAgIDxidXR0b24gaWQ9ImdvIiBjbGFzcz0icHJpbWFyeSI+S2lyaXNoPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImVyciIgaWQ9ImVyciI+JHtlc2MobXNnIHx8ICcnKX08L3A+CiAgICAgIDwvZGl2PjwvZGl2PmA7CiAgICBjb25zdCBzdWJtaXQgPSBhc3luYyAoKSA9PiB7CiAgICAgIHRyeSB7IGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2FkbWluL2xvZ2luJywgeyBwYXNzd29yZDogJCgnI3B3JykudmFsdWUgfSk7IHNob3dPdmVydmlldygpOyB9CiAgICAgIGNhdGNoIChlKSB7ICQoJyNlcnInKS50ZXh0Q29udGVudCA9IGUubWVzc2FnZTsgfQogICAgfTsKICAgICQoJyNnbycpLm9uY2xpY2sgPSBzdWJtaXQ7CiAgICAkKCcjcHcnKS5vbmtleWRvd24gPSAoZSkgPT4geyBpZiAoZS5rZXkgPT09ICdFbnRlcicpIHN1Ym1pdCgpOyB9OwogICAgJCgnI3B3JykuZm9jdXMoKTsKICB9CgogIC8vID09PT09PT09PT09PT09PT09IFVtdW1peSBrbydyaW5pc2ggPT09PT09PT09PT09PT09PT0KICBhc3luYyBmdW5jdGlvbiBzaG93T3ZlcnZpZXcoKSB7CiAgICBzdG9wKCk7CiAgICBjb25zdCBkcmF3ID0gYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBkID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9hZG1pbi9vdmVydmlldycpOwogICAgICBjb25zdCB0ID0gZC50b3RhbHM7CiAgICAgIGFwcC5pbm5lckhUTUwgPSBgCiAgICAgICAgPGRpdiBjbGFzcz0id3JhcCI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJhZG1pbi1oZWFkIj4KICAgICAgICAgICAgPGgxPkJvc2hxYXJ1diBwYW5lbGk8L2gxPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJidG5zIiBzdHlsZT0ibWFyZ2luOjAiPgogICAgICAgICAgICAgIDxidXR0b24gaWQ9Im5ldyIgY2xhc3M9InByaW1hcnkiPisgWWFuZ2kgdG8ncGxhbTwvYnV0dG9uPgogICAgICAgICAgICAgIDxidXR0b24gaWQ9Im91dCI+Q2hpcWlzaDwvYnV0dG9uPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdHMiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48Yj4ke3Quc2V0c308L2I+PHNwYW4+U2F2b2xsYXIgdG8ncGxhbWk8L3NwYW4+PC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InN0YXQiPjxiPiR7dC5wYXJ0aWNpcGFudHN9PC9iPjxzcGFuPkphbWkgcWF0bmFzaHV2Y2hpbGFyPC9zcGFuPjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48Yj4ke3QuZmluaXNoZWR9PC9iPjxzcGFuPlRvcHNoaXJpbGdhbiB0ZXN0bGFyPC9zcGFuPjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48Yj4ke3QuYXZnUGVyY2VudCA9PT0gbnVsbCA/ICfigJQnIDogdC5hdmdQZXJjZW50ICsgJyUnfTwvYj48c3Bhbj5PJ3J0YWNoYSBuYXRpamE8L3NwYW4+PC9kaXY+CiAgICAgICAgICA8L2Rpdj4KICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgICAgICA8aDM+VG8ncGxhbWxhcjwvaDM+CiAgICAgICAgICAgICR7ZC5zZXRzLmxlbmd0aCA/IGAKICAgICAgICAgICAgPGRpdiBjbGFzcz0idGJsLXdyYXAiPjx0YWJsZT4KICAgICAgICAgICAgICA8dGhlYWQ+PHRyPjx0aD5Ob21pPC90aD48dGg+S29kPC90aD48dGg+SG9sYXQ8L3RoPjx0aD5TYXZvbDwvdGg+PHRoPlFhdG5hc2hkaTwvdGg+PHRoPlR1Z2F0ZGk8L3RoPjx0aD5PJ3J0YWNoYTwvdGg+PC90cj48L3RoZWFkPgogICAgICAgICAgICAgIDx0Ym9keT4ke2Quc2V0cy5tYXAoKHMpID0+IGAKICAgICAgICAgICAgICAgIDx0ciBjbGFzcz0iY2xpY2siIGRhdGEtaWQ9IiR7ZXNjKHMuaWQpfSI+CiAgICAgICAgICAgICAgICAgIDx0ZD48Yj4ke2VzYyhzLnRpdGxlKX08L2I+PC90ZD4KICAgICAgICAgICAgICAgICAgPHRkPjxjb2RlPiR7ZXNjKHMuY29kZSl9PC9jb2RlPjwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD48c3BhbiBjbGFzcz0iYmFkZ2UgJHtzLnN0YXR1c30iPiR7U1RBVFVTW3Muc3RhdHVzXX08L3NwYW4+PC90ZD4KICAgICAgICAgICAgICAgICAgPHRkPiR7cy5xdWVzdGlvbkNvdW50fTwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD4ke3MucGFydGljaXBhbnRzfS8zMDwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD4ke3MuZmluaXNoZWR9PC90ZD4KICAgICAgICAgICAgICAgICAgPHRkPiR7cy5hdmdQZXJjZW50ID09PSBudWxsID8gJ+KAlCcgOiBzLmF2Z1BlcmNlbnQgKyAnJSd9PC90ZD4KICAgICAgICAgICAgICAgIDwvdHI+YCkuam9pbignJyl9PC90Ym9keT4KICAgICAgICAgICAgPC90YWJsZT48L2Rpdj5gIDogYDxwIGNsYXNzPSJtdXRlZCI+SG96aXJjaGEgdG8ncGxhbSB5bydxLiDCq1lhbmdpIHRvJ3BsYW3CuyB0dWdtYXNpbmkgYm9zaW5nLjwvcD5gfQogICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+YDsKICAgICAgJCgnI25ldycpLm9uY2xpY2sgPSAoKSA9PiBzaG93RWRpdG9yKG51bGwpOwogICAgICAkKCcjb3V0Jykub25jbGljayA9IGFzeW5jICgpID0+IHsgYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvYWRtaW4vbG9nb3V0Jyk7IHNob3dMb2dpbigpOyB9OwogICAgICAkJCgndHIuY2xpY2snKS5mb3JFYWNoKChyKSA9PiB7IHIub25jbGljayA9ICgpID0+IHNob3dEZXRhaWwoci5kYXRhc2V0LmlkKTsgfSk7CiAgICB9OwogICAgdHJ5IHsgYXdhaXQgZHJhdygpOyB9IGNhdGNoIChlKSB7IHJldHVybiBvbkVycihlKTsgfQogICAgcG9sbCA9IHNldEludGVydmFsKCgpID0+IGRyYXcoKS5jYXRjaChvbkVyciksIDUwMDApOwogIH0KCiAgLy8gPT09PT09PT09PT09PT09PT0gVG8ncGxhbSB0YWZzaWxvdGkgPT09PT09PT09PT09PT09PT0KICBhc3luYyBmdW5jdGlvbiBzaG93RGV0YWlsKGlkKSB7CiAgICBzdG9wKCk7CiAgICBsZXQgZCA9IG51bGw7CgogICAgY29uc3QgZHJhdyA9IGFzeW5jICgpID0+IHsKICAgICAgZCA9IGF3YWl0IGFwaSgnR0VUJywgJy9hcGkvYWRtaW4vc2V0cy8nICsgaWQpOwogICAgICBvZmZzZXQgPSBkLm5vdyAtIERhdGUubm93KCk7CiAgICAgIGNvbnN0IGxpbmsgPSBgJHtsb2NhdGlvbi5vcmlnaW59Lz9rb2Q9JHtkLmNvZGV9YDsKICAgICAgY29uc3QgbGlzdCA9IGQucGFydGljaXBhbnRMaXN0LnNsaWNlKCkuc29ydCgoYSwgYikgPT4gYi5wZXJjZW50IC0gYS5wZXJjZW50IHx8IGEubmFtZS5sb2NhbGVDb21wYXJlKGIubmFtZSkpOwogICAgICBhcHAuaW5uZXJIVE1MID0gYAogICAgICAgIDxkaXYgY2xhc3M9IndyYXAiPgogICAgICAgICAgPGRpdiBjbGFzcz0iYWRtaW4taGVhZCI+CiAgICAgICAgICAgIDxidXR0b24gaWQ9ImJhY2siPuKGkCBPcnFhZ2E8L2J1dHRvbj4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9ImJhZGdlICR7ZC5zdGF0dXN9Ij4ke1NUQVRVU1tkLnN0YXR1c119PC9zcGFuPgogICAgICAgICAgPC9kaXY+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICAgIDxoMT4ke2VzYyhkLnRpdGxlKX08L2gxPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCI+JHtkLnF1ZXN0aW9uQ291bnR9IHRhIHNhdm9sIMK3IHVtdW1peSB2YXF0OiAke2QuZHVyYXRpb25NaW59IGRhcWlxYTwvZGl2PgogICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW46MTRweCAwIj48c3BhbiBjbGFzcz0iY29kZWJveCIgaWQ9ImNvZGVib3giPiR7ZXNjKGQuY29kZSl9PC9zcGFuPjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJsaW5rcm93Ij4KICAgICAgICAgICAgICA8aW5wdXQgaWQ9ImxpbmsiIHJlYWRvbmx5IHZhbHVlPSIke2VzYyhsaW5rKX0iPgogICAgICAgICAgICAgIDxidXR0b24gaWQ9ImNvcHkiPk51c3hhIG9saXNoPC9idXR0b24+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8cCBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJtYXJnaW46MTBweCAwIDAiPgogICAgICAgICAgICAgICR7ZC5zdGF0dXMgPT09ICdsb2JieScgPyAnUWF0bmFzaHV2Y2hpbGFyIGtvZCB5b2tpIGhhdm9sYSBvcnFhbGkga2lyaWIsIGt1dGlzaCB4b25hc2lkYSB0dXJhZGkuIMKrVGVzdG5pIGJvc2hsYXNowrtuaSBib3NnYW5pbmdpemRhIGhhbW1hIHVjaHVuIGJpciB2YXF0ZGEgdGF5bWVyIGlzaGdhIHR1c2hhZGkuJyA6ICcnfQogICAgICAgICAgICAgICR7ZC5jb2RlVW50aWwgPyBgS29kICR7ZXNjKGZtdENsb2NrKGQuY29kZVVudGlsKSl9IGdhY2hhIGFtYWwgcWlsYWRpIChzYXZvbGxhciB0dWdhZ2FjaCArMTAgZGFxaXFhKSwga2V5aW4gYnUga29kIGJpbGFuIHRlc3Qgb2NoaWxtYXlkaS5gIDogJyd9CiAgICAgICAgICAgIDwvcD4KICAgICAgICAgICAgJHtkLnN0YXR1cyAhPT0gJ2xvYmJ5JyA/IGA8cCBzdHlsZT0ibWFyZ2luOjEwcHggMCAwIj5Rb2xnYW4gdmFxdDogPGIgY2xhc3M9InRpbWVyIiBpZD0idGltZXIiPjwvYj48L3A+YCA6ICcnfQogICAgICAgICAgICA8ZGl2IGNsYXNzPSJidG5zIj4KICAgICAgICAgICAgICAke2Quc3RhdHVzID09PSAnbG9iYnknID8gYDxidXR0b24gaWQ9InN0YXJ0IiBjbGFzcz0icHJpbWFyeSBzdWNjZXNzIj7ilrYgVGVzdG5pIGJvc2hsYXNoICgke2QuZHVyYXRpb25NaW59IGRhcS4pPC9idXR0b24+PGJ1dHRvbiBpZD0iZWRpdCI+VGFocmlybGFzaDwvYnV0dG9uPmAgOiAnJ30KICAgICAgICAgICAgICAke2Quc3RhdHVzID09PSAncnVubmluZycgPyBgPGJ1dHRvbiBpZD0iZW5kIiBjbGFzcz0iZGFuZ2VyIj7ilqAgSG96aXIgdHVnYXRpc2g8L2J1dHRvbj5gIDogJyd9CiAgICAgICAgICAgICAgPGJ1dHRvbiBpZD0iZGVsIiBjbGFzcz0iZGFuZ2VyIj5PJ2NoaXJpc2g8L2J1dHRvbj4KICAgICAgICAgICAgICA8YnV0dG9uIGlkPSJjc3YiPkNTViB5dWtsYWIgb2xpc2g8L2J1dHRvbj4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICA8L2Rpdj4KCiAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0cyI+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InN0YXQiPjxiPiR7ZC5wYXJ0aWNpcGFudHN9LyR7ZC5tYXhQYXJ0aWNpcGFudHN9PC9iPjxzcGFuPlFvJ3NoaWxnYW5sYXI8L3NwYW4+PC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9InN0YXQiPjxiPiR7ZC5maW5pc2hlZH08L2I+PHNwYW4+WWFrdW5sYWdhbmxhcjwvc3Bhbj48L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdCI+PGI+JHtkLnN0YXRzLmF2Z1BlcmNlbnQgPT09IG51bGwgPyAn4oCUJyA6IGQuc3RhdHMuYXZnUGVyY2VudCArICclJ308L2I+PHNwYW4+TydydGFjaGEgbmF0aWphPC9zcGFuPjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0Ij48Yj4ke2Quc3RhdHMuYmVzdCA9PT0gbnVsbCA/ICfigJQnIDogZC5zdGF0cy5iZXN0ICsgJyUnfTwvYj48c3Bhbj5FbmcgeXVxb3JpPC9zcGFuPjwvZGl2PgogICAgICAgICAgPC9kaXY+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICAgIDxoMz5RYXRuYXNodXZjaGlsYXI8L2gzPgogICAgICAgICAgICAke2xpc3QubGVuZ3RoID8gYDxkaXYgY2xhc3M9InRibC13cmFwIj48dGFibGU+CiAgICAgICAgICAgICAgPHRoZWFkPjx0cj48dGg+IzwvdGg+PHRoPklzbTwvdGg+PHRoPkphdm9iIGJlcmRpPC90aD48dGg+VG8nZydyaTwvdGg+PHRoPk5hdGlqYTwvdGg+PHRoPlZhcXQ8L3RoPjx0aD5Ib2xhdDwvdGg+PC90cj48L3RoZWFkPgogICAgICAgICAgICAgIDx0Ym9keT4ke2xpc3QubWFwKChwLCBpKSA9PiBgCiAgICAgICAgICAgICAgICA8dHI+CiAgICAgICAgICAgICAgICAgIDx0ZD4ke2kgKyAxfTwvdGQ+PHRkPjxiPiR7ZXNjKHAubmFtZSl9PC9iPjwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD4ke3AuYW5zd2VyZWR9LyR7ZC5xdWVzdGlvbkNvdW50fTwvdGQ+PHRkPiR7cC5jb3JyZWN0fTwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD48Yj4ke3AucGVyY2VudH0lPC9iPjwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD4ke3AudGltZVNlYyA9PT0gbnVsbCA/ICfigJQnIDogZm10VGltZShwLnRpbWVTZWMpfTwvdGQ+CiAgICAgICAgICAgICAgICAgIDx0ZD4ke3AuZmluaXNoZWQgPyAnPHNwYW4gY2xhc3M9Im9rLXRleHQiPlR1Z2F0Z2FuPC9zcGFuPicgOiAnSXNobGF5YXB0aSd9PC90ZD4KICAgICAgICAgICAgICAgIDwvdHI+YCkuam9pbignJyl9PC90Ym9keT4KICAgICAgICAgICAgPC90YWJsZT48L2Rpdj5gIDogYDxwIGNsYXNzPSJtdXRlZCI+SG96aXJjaGEgaGVjaCBraW0gcW8nc2hpbG1hZ2FuLjwvcD5gfQogICAgICAgICAgPC9kaXY+CgogICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICAgIDxoMz5EaWFnbm9zdGlrYSAoc2F2b2xsYXIgYm8neWljaGEpPC9oMz4KICAgICAgICAgICAgPHAgY2xhc3M9Im11dGVkIj5Gb2l6IOKAlCBxYXRuYXNodXZjaGlsYXJuaW5nIG5lY2hhIGZvaXppIHNodSBzYXZvbGdhIHRvJ2cncmkgamF2b2IgYmVyZ2FuaS4gWWFzaGlsIOKAlCB0bydnJ3JpIHZhcmlhbnQuPC9wPgogICAgICAgICAgICAke2QucXVlc3Rpb25zLm1hcCgocSwgaSkgPT4gcXVlc3Rpb25TdGF0KHEsIGksIGQucGFydGljaXBhbnRzKSkuam9pbignJyl9CiAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj5gOwoKICAgICAgJCgnI2JhY2snKS5vbmNsaWNrID0gc2hvd092ZXJ2aWV3OwogICAgICAkKCcjY29weScpLm9uY2xpY2sgPSBhc3luYyAoKSA9PiB7CiAgICAgICAgdHJ5IHsgYXdhaXQgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQobGluayk7IHRvYXN0KCdIYXZvbGEgbnVzeGFsYW5kaScpOyB9CiAgICAgICAgY2F0Y2ggKF8pIHsgJCgnI2xpbmsnKS5zZWxlY3QoKTsgdG9hc3QoJ0hhdm9sYW5pIHFvXCdsZGEgbnVzeGFsYW5nJyk7IH0KICAgICAgfTsKICAgICAgY29uc3QgYWN0ID0gKHNlbCwgZm4pID0+IHsgY29uc3QgYiA9ICQoc2VsKTsgaWYgKGIpIGIub25jbGljayA9IGZuOyB9OwogICAgICBhY3QoJyNzdGFydCcsIGFzeW5jICgpID0+IHsKICAgICAgICBpZiAoIWNvbmZpcm0oYFRlc3QgaG96aXIgYm9zaGxhbmFkaSB2YSAke2QuZHVyYXRpb25NaW59IGRhcWlxYWRhbiBrZXlpbiB0dWdheWRpLiBCb3NobGF5bWl6bWk/YCkpIHJldHVybjsKICAgICAgICB0cnkgeyBhd2FpdCBhcGkoJ1BPU1QnLCBgL2FwaS9hZG1pbi9zZXRzLyR7aWR9L3N0YXJ0YCk7IGF3YWl0IGRyYXcoKTsgfSBjYXRjaCAoZSkgeyBvbkVycihlKTsgfQogICAgICB9KTsKICAgICAgYWN0KCcjZW5kJywgYXN5bmMgKCkgPT4gewogICAgICAgIGlmICghY29uZmlybSgnVGVzdG5pIGhvemlyIHR1Z2F0YW1pem1pPyBIYW1tYSBxYXRuYXNodXZjaGkgdWNodW4geWFrdW5sYW5hZGkuJykpIHJldHVybjsKICAgICAgICB0cnkgeyBhd2FpdCBhcGkoJ1BPU1QnLCBgL2FwaS9hZG1pbi9zZXRzLyR7aWR9L2VuZGApOyBhd2FpdCBkcmF3KCk7IH0gY2F0Y2ggKGUpIHsgb25FcnIoZSk7IH0KICAgICAgfSk7CiAgICAgIGFjdCgnI2RlbCcsIGFzeW5jICgpID0+IHsKICAgICAgICBpZiAoIWNvbmZpcm0oIkJ1IHRvJ3BsYW0gdmEgYmFyY2hhIG5hdGlqYWxhciBidXR1bmxheSBvJ2NoaXJpbGFkaS4gRGF2b20gZXRhbWl6bWk/IikpIHJldHVybjsKICAgICAgICB0cnkgeyBhd2FpdCBhcGkoJ0RFTEVURScsICcvYXBpL2FkbWluL3NldHMvJyArIGlkKTsgc2hvd092ZXJ2aWV3KCk7IH0gY2F0Y2ggKGUpIHsgb25FcnIoZSk7IH0KICAgICAgfSk7CiAgICAgIGFjdCgnI2VkaXQnLCAoKSA9PiBzaG93RWRpdG9yKGlkKSk7CiAgICAgIGFjdCgnI2NzdicsICgpID0+IGRvd25sb2FkQ3N2KGQsIGxpc3QpKTsKICAgICAgdGlja0Nsb2NrKCk7CiAgICB9OwoKICAgIGNvbnN0IHRpY2tDbG9jayA9ICgpID0+IHsKICAgICAgY29uc3QgZWwgPSAkKCcjdGltZXInKTsKICAgICAgaWYgKCFlbCB8fCAhZCB8fCAhZC5lbmRzQXQpIHJldHVybjsKICAgICAgY29uc3QgcmVtID0gKGQuZW5kc0F0IC0gKERhdGUubm93KCkgKyBvZmZzZXQpKSAvIDEwMDA7CiAgICAgIGVsLnRleHRDb250ZW50ID0gZC5zdGF0dXMgPT09ICdlbmRlZCcgfHwgcmVtIDw9IDAgPyAnMDA6MDAnIDogZm10VGltZShyZW0pOwogICAgICBlbC5jbGFzc0xpc3QudG9nZ2xlKCd3YXJuJywgcmVtIDwgNjApOwogICAgfTsKCiAgICB0cnkgeyBhd2FpdCBkcmF3KCk7IH0gY2F0Y2ggKGUpIHsgcmV0dXJuIG9uRXJyKGUpOyB9CiAgICBwb2xsID0gc2V0SW50ZXJ2YWwoKCkgPT4gZHJhdygpLmNhdGNoKG9uRXJyKSwgMzAwMCk7CiAgICBjbG9jayA9IHNldEludGVydmFsKHRpY2tDbG9jaywgNTAwKTsKICB9CgogIGZ1bmN0aW9uIHF1ZXN0aW9uU3RhdChxLCBpLCB0b3RhbCkgewogICAgY29uc3QgcmF0ZSA9IHEucmF0ZTsKICAgIGNvbnN0IGxldmVsID0gcmF0ZSA9PT0gbnVsbCA/ICcnIDogcmF0ZSA+PSA3MCA/ICdlYXN5JyA6IHJhdGUgPj0gNDAgPyAnbWlkJyA6ICdoYXJkJzsKICAgIGNvbnN0IGxhYmVsID0geyBlYXN5OiAnT3NvbicsIG1pZDogIk8ncnRhY2hhIiwgaGFyZDogJ1FpeWluJyB9W2xldmVsXSB8fCAnJzsKICAgIGNvbnN0IGNscyA9IHsgZWFzeTogJ2dvb2QnLCBtaWQ6ICdtaWQnLCBoYXJkOiAnYmFkJyB9W2xldmVsXSB8fCAnJzsKICAgIHJldHVybiBgCiAgICAgIDxkaXYgc3R5bGU9InBhZGRpbmc6MTJweCAwO2JvcmRlci10b3A6MXB4IHNvbGlkIHZhcigtLWxpbmUpIj4KICAgICAgICA8ZGl2IGNsYXNzPSJxaGVhZCI+CiAgICAgICAgICA8Yj4ke2kgKyAxfS4gJHtlc2MocS50ZXh0KX08L2I+CiAgICAgICAgICAke2xldmVsID8gYDxzcGFuIGNsYXNzPSJ0YWcgJHtsZXZlbH0iPiR7bGFiZWx9IMK3ICR7cmF0ZX0lPC9zcGFuPmAgOiAnJ30KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJiYXIgJHtjbHN9IiBzdHlsZT0ibWFyZ2luOjhweCAwIj48aSBzdHlsZT0id2lkdGg6JHtyYXRlIHx8IDB9JSI+PC9pPjwvZGl2PgogICAgICAgICR7cS5vcHRpb25zLm1hcCgobywgaikgPT4gewogICAgICAgICAgY29uc3QgcGN0ID0gdG90YWwgPyBNYXRoLnJvdW5kKHEuZGlzdFtqXSAvIHRvdGFsICogMTAwKSA6IDA7CiAgICAgICAgICByZXR1cm4gYDxkaXYgY2xhc3M9Im9wdHJvdyAke2ogPT09IHEuY29ycmVjdCA/ICdyaWdodCcgOiAnJ30iPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJ0Ij48c3Bhbj4ke0xFVFRFUlNbal19Ljwvc3Bhbj48c3Bhbj4ke2VzYyhvKX0ke2ogPT09IHEuY29ycmVjdCA/ICcg4pyTJyA6ICcnfTwvc3Bhbj48L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0ibXV0ZWQiPiR7cS5kaXN0W2pdfSAoJHtwY3R9JSk8L2Rpdj4KICAgICAgICAgIDwvZGl2PmA7CiAgICAgICAgfSkuam9pbignJyl9CiAgICAgICAgJHtxLnNraXBwZWQgPyBgPGRpdiBjbGFzcz0ibXV0ZWQiPkphdm9iIGJlcm1hZ2FuOiAke3Euc2tpcHBlZH08L2Rpdj5gIDogJyd9CiAgICAgIDwvZGl2PmA7CiAgfQoKICBmdW5jdGlvbiBjc3ZDZWxsKHYpIHsKICAgIGxldCBzID0gU3RyaW5nKHYpOwogICAgaWYgKC9eWz0rXC1AXHRccl0vLnRlc3QocykpIHMgPSAiJyIgKyBzOyAvLyBFeGNlbCBmb3JtdWxhc2kgc2lmYXRpZGEgb2NoaWxpYiBrZXRtYXNsaWdpIHVjaHVuCiAgICByZXR1cm4gJyInICsgcy5yZXBsYWNlKC8iL2csICciIicpICsgJyInOwogIH0KICBmdW5jdGlvbiBkb3dubG9hZENzdihkLCBsaXN0KSB7CiAgICBjb25zdCByb3dzID0gW1sn4oSWJywgJ0lzbScsICdKYXZvYiBiZXJkaScsICJUbydnJ3JpIiwgJ05hdGlqYSAlJywgJ1ZhcXQnLCAnSG9sYXQnXV07CiAgICBsaXN0LmZvckVhY2goKHAsIGkpID0+IHJvd3MucHVzaChbaSArIDEsIHAubmFtZSwgYCR7cC5hbnN3ZXJlZH0vJHtkLnF1ZXN0aW9uQ291bnR9YCwgcC5jb3JyZWN0LCBwLnBlcmNlbnQsCiAgICAgIHAudGltZVNlYyA9PT0gbnVsbCA/ICcnIDogZm10VGltZShwLnRpbWVTZWMpLCBwLmZpbmlzaGVkID8gJ1R1Z2F0Z2FuJyA6ICdJc2hsYXlhcHRpJ10pKTsKICAgIGNvbnN0IGNzdiA9ICfvu78nICsgcm93cy5tYXAoKHIpID0+IHIubWFwKGNzdkNlbGwpLmpvaW4oJywnKSkuam9pbignXHJcbicpOwogICAgY29uc3QgYSA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2EnKTsKICAgIGEuaHJlZiA9IFVSTC5jcmVhdGVPYmplY3RVUkwobmV3IEJsb2IoW2Nzdl0sIHsgdHlwZTogJ3RleHQvY3N2O2NoYXJzZXQ9dXRmLTgnIH0pKTsKICAgIGEuZG93bmxvYWQgPSBgbmF0aWphbGFyLSR7ZC5jb2RlfS5jc3ZgOwogICAgYS5jbGljaygpOwogICAgc2V0VGltZW91dCgoKSA9PiBVUkwucmV2b2tlT2JqZWN0VVJMKGEuaHJlZiksIDEwMDApOwogIH0KCiAgLy8gPT09PT09PT09PT09PT09PT0gVGFocmlybGFnaWNoID09PT09PT09PT09PT09PT09CiAgYXN5bmMgZnVuY3Rpb24gc2hvd0VkaXRvcihpZCkgewogICAgc3RvcCgpOwogICAgbGV0IEUgPSB7IHRpdGxlOiAnJywgZHVyYXRpb25NaW46IDIwLCBxdWVzdGlvbnM6IFtdIH07CiAgICBpZiAoaWQpIHsKICAgICAgdHJ5IHsKICAgICAgICBjb25zdCBkID0gYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9hZG1pbi9zZXRzLycgKyBpZCk7CiAgICAgICAgaWYgKCFkLmVkaXRhYmxlKSB7IHRvYXN0KCJUZXN0IGJvc2hsYW5nYW5kYW4ga2V5aW4gbyd6Z2FydGlyaWIgYm8nbG1heWRpIik7IHJldHVybiBzaG93RGV0YWlsKGlkKTsgfQogICAgICAgIEUgPSB7IHRpdGxlOiBkLnRpdGxlLCBkdXJhdGlvbk1pbjogZC5kdXJhdGlvbk1pbiwgcXVlc3Rpb25zOiBKU09OLnBhcnNlKEpTT04uc3RyaW5naWZ5KGQucmF3UXVlc3Rpb25zKSkgfTsKICAgICAgfSBjYXRjaCAoZSkgeyByZXR1cm4gb25FcnIoZSk7IH0KICAgIH0gZWxzZSB7CiAgICAgIEUucXVlc3Rpb25zLnB1c2goYmxhbmtRKCkpOwogICAgfQoKICAgIGFwcC5pbm5lckhUTUwgPSBgCiAgICAgIDxkaXYgY2xhc3M9IndyYXAiPgogICAgICAgIDxkaXYgY2xhc3M9ImFkbWluLWhlYWQiPjxidXR0b24gaWQ9ImJhY2siPuKGkCBCZWtvciBxaWxpc2g8L2J1dHRvbj48aDE+JHtpZCA/ICJUbydwbGFtbmkgdGFocmlybGFzaCIgOiAiWWFuZ2kgdG8ncGxhbSJ9PC9oMT48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgIDxsYWJlbCBmb3I9ImUtdGl0bGUiPlRvJ3BsYW0gbm9taTwvbGFiZWw+CiAgICAgICAgICA8aW5wdXQgaWQ9ImUtdGl0bGUiIG1heGxlbmd0aD0iMTIwIiB2YWx1ZT0iJHtlc2MoRS50aXRsZSl9IiBwbGFjZWhvbGRlcj0iTWFzYWxhbjogVGFyaXgg4oCUIDEtbmF6b3JhdCI+CiAgICAgICAgICA8bGFiZWwgZm9yPSJlLWR1ciI+VW11bWl5IHZhcXQgKGRhcWlxYSk8L2xhYmVsPgogICAgICAgICAgPGlucHV0IGlkPSJlLWR1ciIgdHlwZT0ibnVtYmVyIiBtaW49IjEiIG1heD0iMzAwIiB2YWx1ZT0iJHtFLmR1cmF0aW9uTWlufSI+CiAgICAgICAgICA8cCBjbGFzcz0ibXV0ZWQiPkJ1IHZhcXQgYnV0dW4gdG8ncGxhbSB1Y2h1bi4gRmFxYXQgc2l6IGJlbGdpbGF5c2l6LCBxYXRuYXNodXZjaGlsYXIgbyd6Z2FydGlyYSBvbG1heWRpLjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgIDxoMz5LbydwIHNhdm9sbmkgYmlyZGFuIHFvJ3NoaXNoIChpeHRpeW9yaXkpPC9oMz4KICAgICAgICAgIDxwIGNsYXNzPSJtdXRlZCI+U2F2b2xsYXJuaSBzaHUga28ncmluaXNoZGEgeW96aW5nIHlva2kgV29yZCBkYW4gdGFzaGxhbmcuIFNhdm9sbGFyIG9yYXNpZGEgYm8nc2ggcWF0b3IsIHRvJ2cncmkgdmFyaWFudCBvbGRpZ2EgPGI+KjwvYj4gcW8neWluZzo8L3A+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJoaW50Ij5PJ3piZWtpc3RvbiBwb3l0YXh0aSBxYXlzaSBzaGFoYXI/CipUb3Noa2VudApTYW1hcnFhbmQKQnV4b3JvCgoyICsgMiBuZWNoYT8KMwoqNAo1PC9kaXY+CiAgICAgICAgICA8dGV4dGFyZWEgaWQ9ImUtYnVsayIgcm93cz0iNiIgc3R5bGU9Im1hcmdpbi10b3A6MTBweCI+PC90ZXh0YXJlYT4KICAgICAgICAgIDxkaXYgY2xhc3M9ImJ0bnMiPjxidXR0b24gaWQ9ImUtcGFyc2UiPlNhdm9sbGFyZ2EgYXlsYW50aXJpc2g8L2J1dHRvbj48L2Rpdj4KICAgICAgICAgIDxwIGNsYXNzPSJlcnIiIGlkPSJlLWJ1bGtlcnIiPjwvcD4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGlkPSJlLXFzIj48L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJidG5zIj48YnV0dG9uIGlkPSJlLWFkZCI+KyBTYXZvbCBxbydzaGlzaDwvYnV0dG9uPjwvZGl2PgogICAgICAgIDxidXR0b24gaWQ9ImUtc2F2ZSIgY2xhc3M9InByaW1hcnkiPlNhcWxhc2g8L2J1dHRvbj4KICAgICAgICA8cCBjbGFzcz0iZXJyIiBpZD0iZS1lcnIiPjwvcD4KICAgICAgPC9kaXY+YDsKCiAgICBjb25zdCBxc0JveCA9ICQoJyNlLXFzJyk7CiAgICBmdW5jdGlvbiBkcmF3UXMoKSB7CiAgICAgIHFzQm94LmlubmVySFRNTCA9IEUucXVlc3Rpb25zLm1hcCgocSwgaSkgPT4gYAogICAgICAgIDxkaXYgY2xhc3M9ImNhcmQgcWVkaXQiIGRhdGEtaT0iJHtpfSI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJxaGVhZCI+PGI+JHtpICsgMX0tc2F2b2w8L2I+PGJ1dHRvbiBjbGFzcz0ic21hbGwgZGFuZ2VyIiBkYXRhLWFjdD0iZGVscSI+TydjaGlyaXNoPC9idXR0b24+PC9kaXY+CiAgICAgICAgICA8dGV4dGFyZWEgZGF0YS1mPSJ0ZXh0IiByb3dzPSIyIiBwbGFjZWhvbGRlcj0iU2F2b2wgbWF0bmkiPiR7ZXNjKHEudGV4dCl9PC90ZXh0YXJlYT4KICAgICAgICAgIDxkaXYgY2xhc3M9Im11dGVkIiBzdHlsZT0ibWFyZ2luLXRvcDo2cHgiPlRvJ2cncmkgdmFyaWFudG5pIGRvaXJhIGJpbGFuIGJlbGdpbGFuZzo8L2Rpdj4KICAgICAgICAgICR7cS5vcHRpb25zLm1hcCgobywgaikgPT4gYAogICAgICAgICAgICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJyYWRpbyIgbmFtZT0iYyR7aX0iIGRhdGEtYWN0PSJjb3JyZWN0IiBkYXRhLW89IiR7an0iICR7cS5jb3JyZWN0ID09PSBqID8gJ2NoZWNrZWQnIDogJyd9PgogICAgICAgICAgICAgIDxiPiR7TEVUVEVSU1tqXX08L2I+CiAgICAgICAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGRhdGEtZj0ib3B0IiBkYXRhLW89IiR7an0iIHZhbHVlPSIke2VzYyhvKX0iIG1heGxlbmd0aD0iMzAwIiBwbGFjZWhvbGRlcj0iVmFyaWFudCAke0xFVFRFUlNbal19Ij4KICAgICAgICAgICAgICAke3Eub3B0aW9ucy5sZW5ndGggPiAyID8gYDxidXR0b24gY2xhc3M9InNtYWxsIiBkYXRhLWFjdD0iZGVsb3B0IiBkYXRhLW89IiR7an0iPsOXPC9idXR0b24+YCA6ICcnfQogICAgICAgICAgICA8L2Rpdj5gKS5qb2luKCcnKX0KICAgICAgICAgICR7cS5vcHRpb25zLmxlbmd0aCA8IDYgPyBgPGJ1dHRvbiBjbGFzcz0ic21hbGwiIGRhdGEtYWN0PSJhZGRvcHQiPisgVmFyaWFudCBxbydzaGlzaDwvYnV0dG9uPmAgOiAnJ30KICAgICAgICA8L2Rpdj5gKS5qb2luKCcnKTsKICAgIH0KICAgIGRyYXdRcygpOwoKICAgIC8vIE1hdG5uaSBvJ3pnYXJ0aXJnYW5kYSBob2xhdG5pIHlhbmdpbGF5bWl6IChxYXl0YSBjaGl6bWFzZGFuLCBrdXJzb3Igc2FrcmFtYXNsaWdpIHVjaHVuKQogICAgcXNCb3guYWRkRXZlbnRMaXN0ZW5lcignaW5wdXQnLCAoZSkgPT4gewogICAgICBjb25zdCBjYXJkID0gZS50YXJnZXQuY2xvc2VzdCgnLnFlZGl0Jyk7IGlmICghY2FyZCkgcmV0dXJuOwogICAgICBjb25zdCBxID0gRS5xdWVzdGlvbnNbTnVtYmVyKGNhcmQuZGF0YXNldC5pKV07CiAgICAgIGlmIChlLnRhcmdldC5kYXRhc2V0LmYgPT09ICd0ZXh0JykgcS50ZXh0ID0gZS50YXJnZXQudmFsdWU7CiAgICAgIGlmIChlLnRhcmdldC5kYXRhc2V0LmYgPT09ICdvcHQnKSBxLm9wdGlvbnNbTnVtYmVyKGUudGFyZ2V0LmRhdGFzZXQubyldID0gZS50YXJnZXQudmFsdWU7CiAgICB9KTsKICAgIHFzQm94LmFkZEV2ZW50TGlzdGVuZXIoJ2NsaWNrJywgKGUpID0+IHsKICAgICAgY29uc3QgYnRuID0gZS50YXJnZXQuY2xvc2VzdCgnW2RhdGEtYWN0XScpOyBpZiAoIWJ0bikgcmV0dXJuOwogICAgICBjb25zdCBjYXJkID0gYnRuLmNsb3Nlc3QoJy5xZWRpdCcpOyBjb25zdCBpID0gTnVtYmVyKGNhcmQuZGF0YXNldC5pKTsgY29uc3QgcSA9IEUucXVlc3Rpb25zW2ldOwogICAgICBjb25zdCBvID0gTnVtYmVyKGJ0bi5kYXRhc2V0Lm8pOwogICAgICBzd2l0Y2ggKGJ0bi5kYXRhc2V0LmFjdCkgewogICAgICAgIGNhc2UgJ2NvcnJlY3QnOiBxLmNvcnJlY3QgPSBvOyByZXR1cm47CiAgICAgICAgY2FzZSAnYWRkb3B0JzogcS5vcHRpb25zLnB1c2goJycpOyBicmVhazsKICAgICAgICBjYXNlICdkZWxvcHQnOgogICAgICAgICAgcS5vcHRpb25zLnNwbGljZShvLCAxKTsKICAgICAgICAgIGlmIChxLmNvcnJlY3QgPT09IG8pIHEuY29ycmVjdCA9IDA7IGVsc2UgaWYgKHEuY29ycmVjdCA+IG8pIHEuY29ycmVjdC0tOwogICAgICAgICAgYnJlYWs7CiAgICAgICAgY2FzZSAnZGVscSc6IEUucXVlc3Rpb25zLnNwbGljZShpLCAxKTsgYnJlYWs7CiAgICAgIH0KICAgICAgZHJhd1FzKCk7CiAgICB9KTsKCiAgICAkKCcjZS1hZGQnKS5vbmNsaWNrID0gKCkgPT4geyBFLnF1ZXN0aW9ucy5wdXNoKGJsYW5rUSgpKTsgZHJhd1FzKCk7IHFzQm94Lmxhc3RFbGVtZW50Q2hpbGQuc2Nyb2xsSW50b1ZpZXcoeyBiZWhhdmlvcjogJ3Ntb290aCcgfSk7IH07CiAgICAkKCcjYmFjaycpLm9uY2xpY2sgPSAoKSA9PiAoaWQgPyBzaG93RGV0YWlsKGlkKSA6IHNob3dPdmVydmlldygpKTsKCiAgICAkKCcjZS1wYXJzZScpLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgIGNvbnN0IHsgcXVlc3Rpb25zLCBlcnJvcnMgfSA9IHBhcnNlQnVsaygkKCcjZS1idWxrJykudmFsdWUpOwogICAgICAvLyBibydzaCBib3NobGFuZydpY2ggc2F2b2xuaSBvbGliIHRhc2hsYXltaXoKICAgICAgRS5xdWVzdGlvbnMgPSBFLnF1ZXN0aW9ucy5maWx0ZXIoKHEpID0+IHEudGV4dC50cmltKCkgfHwgcS5vcHRpb25zLnNvbWUoKG8pID0+IG8udHJpbSgpKSk7CiAgICAgIEUucXVlc3Rpb25zLnB1c2goLi4ucXVlc3Rpb25zKTsKICAgICAgZHJhd1FzKCk7CiAgICAgICQoJyNlLWJ1bGtlcnInKS50ZXh0Q29udGVudCA9IGVycm9ycy5qb2luKCcgJyk7CiAgICAgIGlmIChxdWVzdGlvbnMubGVuZ3RoKSB7ICQoJyNlLWJ1bGsnKS52YWx1ZSA9ICcnOyB0b2FzdChgJHtxdWVzdGlvbnMubGVuZ3RofSB0YSBzYXZvbCBxbydzaGlsZGlgKTsgfQogICAgfTsKCiAgICAkKCcjZS1zYXZlJykub25jbGljayA9IGFzeW5jICgpID0+IHsKICAgICAgY29uc3QgYm9keSA9IHsgdGl0bGU6ICQoJyNlLXRpdGxlJykudmFsdWUsIGR1cmF0aW9uTWluOiBOdW1iZXIoJCgnI2UtZHVyJykudmFsdWUpLCBxdWVzdGlvbnM6IEUucXVlc3Rpb25zIH07CiAgICAgIGNvbnN0IGJ0biA9ICQoJyNlLXNhdmUnKTsgYnRuLmRpc2FibGVkID0gdHJ1ZTsgJCgnI2UtZXJyJykudGV4dENvbnRlbnQgPSAnJzsKICAgICAgdHJ5IHsKICAgICAgICBpZiAoaWQpIHsgYXdhaXQgYXBpKCdQVVQnLCAnL2FwaS9hZG1pbi9zZXRzLycgKyBpZCwgYm9keSk7IHNob3dEZXRhaWwoaWQpOyB9CiAgICAgICAgZWxzZSB7IGNvbnN0IHIgPSBhd2FpdCBhcGkoJ1BPU1QnLCAnL2FwaS9hZG1pbi9zZXRzJywgYm9keSk7IHNob3dEZXRhaWwoci5pZCk7IH0KICAgICAgfSBjYXRjaCAoZSkgewogICAgICAgIGlmIChlLnN0YXR1cyA9PT0gNDAxKSByZXR1cm4gc2hvd0xvZ2luKCk7CiAgICAgICAgJCgnI2UtZXJyJykudGV4dENvbnRlbnQgPSBlLm1lc3NhZ2U7IGJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICB9CiAgICB9OwogIH0KCiAgY29uc3QgYmxhbmtRID0gKCkgPT4gKHsgdGV4dDogJycsIG9wdGlvbnM6IFsnJywgJycsICcnLCAnJ10sIGNvcnJlY3Q6IDAgfSk7CgogIGZ1bmN0aW9uIHBhcnNlQnVsayh0ZXh0KSB7CiAgICBjb25zdCBxdWVzdGlvbnMgPSBbXSwgZXJyb3JzID0gW107CiAgICBjb25zdCBibG9ja3MgPSB0ZXh0LnJlcGxhY2UoL1xyL2csICcnKS5zcGxpdCgvXG5ccypcbi8pLm1hcCgoYikgPT4gYi50cmltKCkpLmZpbHRlcihCb29sZWFuKTsKICAgIGJsb2Nrcy5mb3JFYWNoKChiLCBuKSA9PiB7CiAgICAgIGNvbnN0IGxpbmVzID0gYi5zcGxpdCgnXG4nKS5tYXAoKGwpID0+IGwudHJpbSgpKS5maWx0ZXIoQm9vbGVhbik7CiAgICAgIGNvbnN0IG9wdHMgPSBsaW5lcy5zbGljZSgxKTsKICAgICAgaWYgKG9wdHMubGVuZ3RoIDwgMikgcmV0dXJuIGVycm9ycy5wdXNoKGAke24gKyAxfS1ibG9rOiBrYW1pZGEgMiB0YSB2YXJpYW50IGtlcmFrLmApOwogICAgICBpZiAob3B0cy5sZW5ndGggPiA2KSByZXR1cm4gZXJyb3JzLnB1c2goYCR7biArIDF9LWJsb2s6IHZhcmlhbnRsYXIgNiB0YWRhbiBvc2htYXNpbi5gKTsKICAgICAgY29uc3Qgc3RhcnMgPSBvcHRzLmZpbHRlcigobCkgPT4gbC5zdGFydHNXaXRoKCcqJykpLmxlbmd0aDsKICAgICAgaWYgKHN0YXJzICE9PSAxKSByZXR1cm4gZXJyb3JzLnB1c2goYCR7biArIDF9LWJsb2s6IHRvJ2cncmkgdmFyaWFudCBvbGRpZ2EgYXluYW4gYml0dGEgKiBxbyd5aW5nLmApOwogICAgICBxdWVzdGlvbnMucHVzaCh7CiAgICAgICAgdGV4dDogbGluZXNbMF0sIG9wdGlvbnM6IG9wdHMubWFwKChsKSA9PiBsLnJlcGxhY2UoL15cKlxzKi8sICcnKSksCiAgICAgICAgY29ycmVjdDogb3B0cy5maW5kSW5kZXgoKGwpID0+IGwuc3RhcnRzV2l0aCgnKicpKSwKICAgICAgfSk7CiAgICB9KTsKICAgIHJldHVybiB7IHF1ZXN0aW9ucywgZXJyb3JzIH07CiAgfQoKICAvLyA9PT09PT09PT09PT09PT09PSBCb3NobGFzaCA9PT09PT09PT09PT09PT09PQogIChhc3luYyBmdW5jdGlvbiBpbml0KCkgewogICAgdHJ5IHsgYXdhaXQgYXBpKCdHRVQnLCAnL2FwaS9hZG1pbi9vdmVydmlldycpOyBzaG93T3ZlcnZpZXcoKTsgfSBjYXRjaCAoXykgeyBzaG93TG9naW4oKTsgfQogIH0pKCk7Cn0pKCk7Cg==","/app.js":"Ly8gUWF0bmFzaHV2Y2hpIHRvbW9uaToga29kIGJpbGFuIGtpcmlzaCAtPiBrdXRpc2ggLT4gdGVzdCAtPiBuYXRpamEKKGZ1bmN0aW9uICgpIHsKICBjb25zdCBhcHAgPSAkKCcjYXBwJyk7CiAgbGV0IFMgPSBudWxsOyAgICAgICAgICAvLyBzZXJ2ZXJkYW4ga2VsZ2FuIG94aXJnaSBob2xhdAogIGxldCBjZmcgPSBudWxsOyAgICAgICAgLy8geyBjb2RlLCB0b2tlbiwgbmFtZSB9CiAgbGV0IG9mZnNldCA9IDA7ICAgICAgICAvLyBzZXJ2ZXIgdmFxdGkgYmlsYW4gdGVsZWZvbiB2YXF0aSBvcmFzaWRhZ2kgZmFycQogIGxldCBjdXIgPSAwOyAgICAgICAgICAgLy8gaG96aXJnaSBzYXZvbCBpbmRla3NpCiAgbGV0IHNlbGVjdGVkID0gbnVsbDsgICAvLyB0YW5sYW5nYW4gKGhhbGkgdGFzZGlxbGFubWFnYW4pIHZhcmlhbnQKICBsZXQgYnVzeSA9IGZhbHNlOwogIGxldCBwb2xsVGltZXIgPSBudWxsOwogIGNvbnN0IExFVFRFUlMgPSAnQUJDREVGJzsKCiAgLy8gLS0tLS0tLS0tLSBsb2NhbFN0b3JhZ2UgKHRyeS9jYXRjaDogYmEnemkgYnJhdXplcmxhcmRhIGJsb2tsYW5nYW4gYm8nbGFkaSkgLS0tLS0tLS0tLQogIGNvbnN0IHN0b3JlID0gewogICAgZ2V0KGspIHsgdHJ5IHsgcmV0dXJuIEpTT04ucGFyc2UobG9jYWxTdG9yYWdlLmdldEl0ZW0oaykgfHwgJ251bGwnKTsgfSBjYXRjaCAoXykgeyByZXR1cm4gbnVsbDsgfSB9LAogICAgc2V0KGssIHYpIHsgdHJ5IHsgbG9jYWxTdG9yYWdlLnNldEl0ZW0oaywgSlNPTi5zdHJpbmdpZnkodikpOyB9IGNhdGNoIChfKSB7fSB9LAogICAgZGVsKGspIHsgdHJ5IHsgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oayk7IH0gY2F0Y2ggKF8pIHt9IH0sCiAgfTsKCiAgY29uc3QgZW5jID0gZW5jb2RlVVJJQ29tcG9uZW50OwoKICAvLyAtLS0tLS0tLS0tIEtpcmlzaCBla3JhbmkgLS0tLS0tLS0tLQogIGZ1bmN0aW9uIHJlbmRlckpvaW4obXNnLCBjb2RlKSB7CiAgICBzdG9wTG9vcHMoKTsKICAgIFMgPSBudWxsOyBjZmcgPSBudWxsOwogICAgY29uc3QgcGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyhsb2NhdGlvbi5zZWFyY2gpOwogICAgY29uc3QgYyA9IGNvZGUgfHwgKHBhcmFtcy5nZXQoJ2tvZCcpIHx8ICcnKS50b1VwcGVyQ2FzZSgpOwogICAgYXBwLmlubmVySFRNTCA9IGAKICAgICAgPGRpdiBjbGFzcz0id3JhcCBuYXJyb3ciPjxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgIDxoMT5UZXN0Z2Ega2lyaXNoPC9oMT4KICAgICAgICA8bGFiZWwgZm9yPSJjb2RlIj5UZXN0IGtvZGk8L2xhYmVsPgogICAgICAgIDxpbnB1dCBpZD0iY29kZSIgbWF4bGVuZ3RoPSI4IiBhdXRvY29tcGxldGU9Im9mZiIgYXV0b2NhcGl0YWxpemU9ImNoYXJhY3RlcnMiIHZhbHVlPSIke2VzYyhjKX0iPgogICAgICAgIDxsYWJlbCBmb3I9Im5hbWUiPklzbSB2YSBmYW1pbGl5YW5naXo8L2xhYmVsPgogICAgICAgIDxpbnB1dCBpZD0ibmFtZSIgbWF4bGVuZ3RoPSI0MCIgYXV0b2NvbXBsZXRlPSJuYW1lIiBwbGFjZWhvbGRlcj0iTWFzYWxhbjogQWxpeWV2IFZhbGkiPgogICAgICAgIDxidXR0b24gaWQ9ImdvIiBjbGFzcz0icHJpbWFyeSI+S2lyaXNoPC9idXR0b24+CiAgICAgICAgPHAgY2xhc3M9ImVyciIgaWQ9ImVyciI+JHtlc2MobXNnIHx8ICcnKX08L3A+CiAgICAgIDwvZGl2PjwvZGl2PmA7CiAgICBjb25zdCBnbyA9ICQoJyNnbycpOwogICAgY29uc3Qgc3VibWl0ID0gYXN5bmMgKCkgPT4gewogICAgICBjb25zdCBjb2RlID0gJCgnI2NvZGUnKS52YWx1ZS50cmltKCkudG9VcHBlckNhc2UoKTsKICAgICAgY29uc3QgbmFtZSA9ICQoJyNuYW1lJykudmFsdWUudHJpbSgpOwogICAgICBpZiAoIWNvZGUpIHJldHVybiAoJCgnI2VycicpLnRleHRDb250ZW50ID0gJ1Rlc3Qga29kaW5pIGtpcml0aW5nJyk7CiAgICAgIGdvLmRpc2FibGVkID0gdHJ1ZTsKICAgICAgJCgnI2VycicpLnRleHRDb250ZW50ID0gJyc7CiAgICAgIHRyeSB7IGF3YWl0IGpvaW4oY29kZSwgbmFtZSk7IH0KICAgICAgY2F0Y2ggKGUpIHsgJCgnI2VycicpLnRleHRDb250ZW50ID0gZS5tZXNzYWdlOyBnby5kaXNhYmxlZCA9IGZhbHNlOyB9CiAgICB9OwogICAgZ28ub25jbGljayA9IHN1Ym1pdDsKICAgIGFwcC5vbmtleWRvd24gPSAoZSkgPT4geyBpZiAoZS5rZXkgPT09ICdFbnRlcicgJiYgJCgnI2dvJykpIHN1Ym1pdCgpOyB9OwogICAgKGMgPyAkKCcjbmFtZScpIDogJCgnI2NvZGUnKSkuZm9jdXMoKTsKICB9CgogIGFzeW5jIGZ1bmN0aW9uIGpvaW4oY29kZSwgbmFtZSkgewogICAgY29uc3Qgc2F2ZWQgPSBzdG9yZS5nZXQoJ3F1aXpfJyArIGNvZGUpOwogICAgY29uc3QgciA9IGF3YWl0IGFwaSgnUE9TVCcsICcvYXBpL2pvaW4nLCB7IGNvZGUsIG5hbWUsIHRva2VuOiBzYXZlZCAmJiBzYXZlZC50b2tlbiB9KTsKICAgIGNmZyA9IHsgY29kZSwgdG9rZW46IHIudG9rZW4sIG5hbWU6IHIubmFtZSB9OwogICAgc3RvcmUuc2V0KCdxdWl6XycgKyBjb2RlLCBjZmcpOwogICAgc3RvcmUuc2V0KCdxdWl6X2xhc3QnLCBjb2RlKTsKICAgIGN1ciA9IDA7IHNlbGVjdGVkID0gbnVsbDsKICAgIGF3YWl0IHJlZnJlc2godHJ1ZSk7CiAgICBzdGFydExvb3BzKCk7CiAgfQoKICAvLyAtLS0tLS0tLS0tIEhvbGF0bmkgb2xpc2ggLS0tLS0tLS0tLQogIGFzeW5jIGZ1bmN0aW9uIHJlZnJlc2goZm9yY2UpIHsKICAgIGNvbnN0IHIgPSBhd2FpdCBhcGkoJ0dFVCcsIGAvYXBpL3Nlc3Npb24/Y29kZT0ke2VuYyhjZmcuY29kZSl9JnRva2VuPSR7ZW5jKGNmZy50b2tlbil9YCk7CiAgICBvZmZzZXQgPSByLm5vdyAtIERhdGUubm93KCk7CiAgICBjb25zdCBwcmV2ID0gUzsKICAgIFMgPSByOwogICAgaWYgKGZvcmNlIHx8ICFwcmV2IHx8IHByZXYuc3RhdHVzICE9PSByLnN0YXR1cyB8fCBwcmV2LmZpbmlzaGVkICE9PSByLmZpbmlzaGVkKSByZW5kZXIoKTsKICB9CgogIGZ1bmN0aW9uIHN0YXJ0TG9vcHMoKSB7CiAgICBzdG9wTG9vcHMoKTsKICAgIHBvbGxUaW1lciA9IHNldEludGVydmFsKGFzeW5jICgpID0+IHsKICAgICAgaWYgKFMgJiYgUy5zdGF0dXMgPT09ICdlbmRlZCcgJiYgUy5yZXZpZXcpIHJldHVybjsgLy8gaGFtbWFzaSB5YWt1bmxhbmdhbiwgc28ncmFzaCBzaGFydCBlbWFzCiAgICAgIHRyeSB7IGF3YWl0IHJlZnJlc2goKTsgfSBjYXRjaCAoZSkgeyBvbkZhdGFsKGUpOyB9CiAgICB9LCAzMDAwKTsKICAgIHRpY2tUaW1lciA9IHNldEludGVydmFsKHRpY2ssIDI1MCk7CiAgICB0aWNrKCk7CiAgfQogIGxldCB0aWNrVGltZXIgPSBudWxsOwogIGZ1bmN0aW9uIHN0b3BMb29wcygpIHsgY2xlYXJJbnRlcnZhbChwb2xsVGltZXIpOyBjbGVhckludGVydmFsKHRpY2tUaW1lcik7IH0KCiAgZnVuY3Rpb24gb25GYXRhbChlKSB7CiAgICBpZiAoWzQwMSwgNDA0LCA0MTBdLmluY2x1ZGVzKGUuc3RhdHVzKSkgewogICAgICBjb25zdCBjb2RlID0gY2ZnICYmIGNmZy5jb2RlOwogICAgICBpZiAoY29kZSkgc3RvcmUuZGVsKCdxdWl6XycgKyBjb2RlKTsKICAgICAgcmVuZGVySm9pbihlLm1lc3NhZ2UsIGNvZGUpOwogICAgfQogICAgLy8gYm9zaHFhIHhhdG9sYXIgKHRhcm1vcSB1emlsaXNoaSk6IGppbSwga2V5aW5naSBzbydyb3ZkYSBxYXl0YSB1cmluYWRpCiAgfQoKICBmdW5jdGlvbiByZW1haW5pbmdTZWMoKSB7IHJldHVybiAoUy5lbmRzQXQgLSAoRGF0ZS5ub3coKSArIG9mZnNldCkpIC8gMTAwMDsgfQoKICBsZXQgdGlja0J1c3kgPSBmYWxzZTsKICBmdW5jdGlvbiB0aWNrKCkgewogICAgaWYgKCFTIHx8ICFTLmVuZHNBdCkgcmV0dXJuOwogICAgY29uc3QgcmVtID0gcmVtYWluaW5nU2VjKCk7CiAgICBjb25zdCBlbCA9ICQoJyN0aW1lcicpOwogICAgaWYgKGVsKSB7CiAgICAgIGVsLnRleHRDb250ZW50ID0gZm10VGltZShyZW0pOwogICAgICBlbC5jbGFzc0xpc3QudG9nZ2xlKCd3YXJuJywgcmVtIDwgNjApOwogICAgfQogICAgaWYgKHJlbSA8PSAwICYmIFMuc3RhdHVzID09PSAncnVubmluZycgJiYgIXRpY2tCdXN5KSB7CiAgICAgIHRpY2tCdXN5ID0gdHJ1ZTsgLy8gdmFxdCB0dWdhZGk6IHNlcnZlcmRhbiB5YWt1bml5IGhvbGF0bmkgc28ncmF5bWl6CiAgICAgIHJlZnJlc2goKS5jYXRjaChvbkZhdGFsKS5maW5hbGx5KCgpID0+IHNldFRpbWVvdXQoKCkgPT4geyB0aWNrQnVzeSA9IGZhbHNlOyB9LCAxMDAwKSk7CiAgICB9CiAgfQoKICAvLyAtLS0tLS0tLS0tIEVrcmFubGFyIC0tLS0tLS0tLS0KICBmdW5jdGlvbiByZW5kZXIoKSB7CiAgICBpZiAoIVMpIHJldHVybjsKICAgIGlmIChTLnN0YXR1cyA9PT0gJ2xvYmJ5JykgcmV0dXJuIHJlbmRlckxvYmJ5KCk7CiAgICBpZiAoUy5maW5pc2hlZCkgcmV0dXJuIHJlbmRlckRvbmUoKTsKICAgIGN1ciA9IE1hdGgubWluKGN1ciwgUy50b3RhbCAtIDEpOwogICAgcmV0dXJuIHJlbmRlclRlc3QoKTsKICB9CgogIGZ1bmN0aW9uIHJlbmRlckxvYmJ5KCkgewogICAgYXBwLmlubmVySFRNTCA9IGAKICAgICAgPGRpdiBjbGFzcz0id3JhcCBuYXJyb3ciPjxkaXYgY2xhc3M9ImNhcmQgY2VudGVyIj4KICAgICAgICA8aDE+JHtlc2MoUy50aXRsZSl9PC9oMT4KICAgICAgICA8cD5TYWxvbSwgPGI+JHtlc2MoUy5uYW1lKX08L2I+ITwvcD4KICAgICAgICA8cD5TaXogcm8neXhhdGRhbiBvJ3RkaW5naXouIFRlc3QgZWdhc2kgYm9zaGxhc2hpbmkga3V0aW5nIOKAlCBzYWhpZmEgYXZ0b21hdGlrIG9jaGlsYWRpLjwvcD4KICAgICAgICA8cCBjbGFzcz0ibXV0ZWQiPlRlc3QgdmFxdGk6ICR7Uy5kdXJhdGlvbk1pbn0gZGFxaXFhIMK3IFNhdm9sbGFyOiAke1MudG90YWx9IHRhPC9wPgogICAgICA8L2Rpdj48L2Rpdj5gOwogIH0KCiAgZnVuY3Rpb24gbmV4dFVuYW5zd2VyZWQoZnJvbSkgewogICAgZm9yIChsZXQgayA9IDE7IGsgPD0gUy50b3RhbDsgaysrKSB7CiAgICAgIGNvbnN0IGkgPSAoZnJvbSArIGspICUgUy50b3RhbDsKICAgICAgaWYgKFMuYW5zd2Vyc1tpXSA9PT0gdW5kZWZpbmVkKSByZXR1cm4gaTsKICAgIH0KICAgIHJldHVybiAtMTsKICB9CgogIGZ1bmN0aW9uIHJlbmRlclRlc3QoKSB7CiAgICBjb25zdCBxID0gUy5xdWVzdGlvbnNbY3VyXTsKICAgIGNvbnN0IGFucyA9IFMuYW5zd2Vyc1tjdXJdOwogICAgY29uc3QgbG9ja2VkID0gYW5zICE9PSB1bmRlZmluZWQ7CiAgICBjb25zdCBkb25lID0gT2JqZWN0LmtleXMoUy5hbnN3ZXJzKS5sZW5ndGg7CiAgICBhcHAuaW5uZXJIVE1MID0gYAogICAgICA8ZGl2IGNsYXNzPSJ0b3BiYXIiPgogICAgICAgIDxkaXY+PGI+JHtlc2MoUy50aXRsZSl9PC9iPjxkaXYgY2xhc3M9Im11dGVkIj4ke2VzYyhTLm5hbWUpfSDCtyAke2RvbmV9LyR7Uy50b3RhbH0gamF2b2IgYmVyaWxkaTwvZGl2PjwvZGl2PgogICAgICAgIDxkaXYgY2xhc3M9InRpbWVyIiBpZD0idGltZXIiPjwvZGl2PgogICAgICA8L2Rpdj4KICAgICAgPGRpdiBjbGFzcz0id3JhcCI+CiAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCI+JHtjdXIgKyAxfS1zYXZvbCAvICR7Uy50b3RhbH08L2Rpdj4KICAgICAgICAgIDxoMj4ke2VzYyhxLnRleHQpfTwvaDI+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJvcHRzIj4KICAgICAgICAgICAgJHtxLm9wdGlvbnMubWFwKChvLCBpKSA9PiBgCiAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0ib3B0ICR7bG9ja2VkID8gKGFucyA9PT0gaSA/ICdsb2NrZWQnIDogJ2RpbScpIDogKHNlbGVjdGVkID09PSBpID8gJ3NlbCcgOiAnJyl9IgogICAgICAgICAgICAgICAgICAgICAgZGF0YS1pPSIke2l9IiAke2xvY2tlZCA/ICdkaXNhYmxlZCcgOiAnJ30+CiAgICAgICAgICAgICAgICA8c3BhbiBjbGFzcz0ibHRyIj4ke0xFVFRFUlNbaV19PC9zcGFuPjxzcGFuPiR7ZXNjKG8pfTwvc3Bhbj4KICAgICAgICAgICAgICA8L2J1dHRvbj5gKS5qb2luKCcnKX0KICAgICAgICAgIDwvZGl2PgogICAgICAgICAgJHtsb2NrZWQKICAgICAgICAgICAgPyBgPHAgY2xhc3M9Im11dGVkIj7wn5SSIEphdm9iaW5naXogcWFidWwgcWlsaW5kaSwgdW5pIG8nemdhcnRpcmliIGJvJ2xtYXlkaS48L3A+YAogICAgICAgICAgICA6IGA8YnV0dG9uIGlkPSJjb25maXJtIiBjbGFzcz0icHJpbWFyeSIgJHtzZWxlY3RlZCA9PT0gbnVsbCA/ICdkaXNhYmxlZCcgOiAnJ30+SmF2b2JuaSB0YXNkaXFsYXNoPC9idXR0b24+CiAgICAgICAgICAgICAgIDxwIGNsYXNzPSJtdXRlZCBjZW50ZXIiPlRhc2RpcWxhbmdhbmRhbiBrZXlpbiBqYXZvYm5pIG8nemdhcnRpcmliIGJvJ2xtYXlkaS48L3A+YH0KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJuYXYiPgogICAgICAgICAgPGJ1dHRvbiBpZD0icHJldiIgJHtjdXIgPT09IDAgPyAnZGlzYWJsZWQnIDogJyd9PuKGkCBPbGRpbmdpPC9idXR0b24+CiAgICAgICAgICA8YnV0dG9uIGlkPSJuZXh0IiAke2N1ciA9PT0gUy50b3RhbCAtIDEgPyAnZGlzYWJsZWQnIDogJyd9PktleWluZ2kg4oaSPC9idXR0b24+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iZG90cyI+CiAgICAgICAgICAke1MucXVlc3Rpb25zLm1hcCgoXywgaSkgPT4gYAogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJkb3QgJHtTLmFuc3dlcnNbaV0gIT09IHVuZGVmaW5lZCA/ICdkb25lJyA6ICcnfSAke2kgPT09IGN1ciA/ICdjdXInIDogJyd9IiBkYXRhLWdvPSIke2l9Ij4ke2kgKyAxfTwvYnV0dG9uPmApLmpvaW4oJycpfQogICAgICAgIDwvZGl2PgogICAgICAgIDxidXR0b24gaWQ9ImZpbmlzaCIgY2xhc3M9ImZpbmlzaC1idG4iPlRlc3RuaSB5YWt1bmxhc2g8L2J1dHRvbj4KICAgICAgPC9kaXY+YDsKCiAgICAkJCgnLm9wdCcpLmZvckVhY2goKGIpID0+IHsgYi5vbmNsaWNrID0gKCkgPT4geyBzZWxlY3RlZCA9IE51bWJlcihiLmRhdGFzZXQuaSk7IHJlbmRlclRlc3QoKTsgfTsgfSk7CiAgICBjb25zdCBjID0gJCgnI2NvbmZpcm0nKTsgaWYgKGMpIGMub25jbGljayA9IGNvbmZpcm1BbnN3ZXI7CiAgICAkKCcjcHJldicpLm9uY2xpY2sgPSAoKSA9PiBnbyhjdXIgLSAxKTsKICAgICQoJyNuZXh0Jykub25jbGljayA9ICgpID0+IGdvKGN1ciArIDEpOwogICAgJCQoJy5kb3QnKS5mb3JFYWNoKChiKSA9PiB7IGIub25jbGljayA9ICgpID0+IGdvKE51bWJlcihiLmRhdGFzZXQuZ28pKTsgfSk7CiAgICAkKCcjZmluaXNoJykub25jbGljayA9IGZpbmlzaDsKICAgIHRpY2soKTsKICB9CgogIGZ1bmN0aW9uIGdvKGkpIHsKICAgIGlmIChpIDwgMCB8fCBpID49IFMudG90YWwpIHJldHVybjsKICAgIGN1ciA9IGk7IHNlbGVjdGVkID0gbnVsbDsgcmVuZGVyVGVzdCgpOwogIH0KCiAgYXN5bmMgZnVuY3Rpb24gY29uZmlybUFuc3dlcigpIHsKICAgIGlmIChidXN5IHx8IHNlbGVjdGVkID09PSBudWxsKSByZXR1cm47CiAgICBidXN5ID0gdHJ1ZTsKICAgICQoJyNjb25maXJtJykuZGlzYWJsZWQgPSB0cnVlOwogICAgdHJ5IHsKICAgICAgYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvYW5zd2VyJywgeyBjb2RlOiBjZmcuY29kZSwgdG9rZW46IGNmZy50b2tlbiwgcTogY3VyLCBjaG9pY2U6IHNlbGVjdGVkIH0pOwogICAgICBTLmFuc3dlcnNbY3VyXSA9IHNlbGVjdGVkOwogICAgICBzZWxlY3RlZCA9IG51bGw7CiAgICAgIGNvbnN0IG4gPSBuZXh0VW5hbnN3ZXJlZChjdXIpOwogICAgICBpZiAobiAhPT0gLTEpIGN1ciA9IG47CiAgICB9IGNhdGNoIChlKSB7CiAgICAgIGlmIChlLnN0YXR1cyA9PT0gNDA5KSBhd2FpdCByZWZyZXNoKCkuY2F0Y2gob25GYXRhbCk7IC8vIGFsbGFxYWNob24gamF2b2IgYmVyaWxnYW4geW9raSB2YXF0IHR1Z2FnYW4KICAgICAgZWxzZSBhbGVydChlLm1lc3NhZ2UpOwogICAgfQogICAgYnVzeSA9IGZhbHNlOwogICAgaWYgKFMgJiYgUy5zdGF0dXMgPT09ICdydW5uaW5nJyAmJiAhUy5maW5pc2hlZCkgcmVuZGVyVGVzdCgpOwogIH0KCiAgYXN5bmMgZnVuY3Rpb24gZmluaXNoKCkgewogICAgY29uc3QgbGVmdCA9IFMudG90YWwgLSBPYmplY3Qua2V5cyhTLmFuc3dlcnMpLmxlbmd0aDsKICAgIGNvbnN0IG1zZyA9IGxlZnQKICAgICAgPyBgJHtsZWZ0fSB0YSBzYXZvbGdhIGhhbGkgamF2b2IgYmVybWFkaW5naXouIEJhcmliaXIgeWFrdW5sYXlzaXptaT8gS2V5aW4gcWF5dGliIGJvJ2xtYXlkaS5gCiAgICAgIDogIlRlc3RuaSB5YWt1bmxheXNpem1pPyBLZXlpbiBxYXl0aWIgYm8nbG1heWRpLiI7CiAgICBpZiAoIWNvbmZpcm0obXNnKSkgcmV0dXJuOwogICAgdHJ5IHsKICAgICAgYXdhaXQgYXBpKCdQT1NUJywgJy9hcGkvZmluaXNoJywgeyBjb2RlOiBjZmcuY29kZSwgdG9rZW46IGNmZy50b2tlbiB9KTsKICAgICAgYXdhaXQgcmVmcmVzaCh0cnVlKTsKICAgIH0gY2F0Y2ggKGUpIHsgYWxlcnQoZS5tZXNzYWdlKTsgfQogIH0KCiAgZnVuY3Rpb24gcmVuZGVyRG9uZSgpIHsKICAgIGNvbnN0IGVuZGVkID0gUy5zdGF0dXMgPT09ICdlbmRlZCc7CiAgICBhcHAuaW5uZXJIVE1MID0gYAogICAgICA8ZGl2IGNsYXNzPSJ3cmFwIG5hcnJvdyIgc3R5bGU9Im1heC13aWR0aDo3NjBweDtwYWRkaW5nLXRvcDoyNHB4Ij4KICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIGNlbnRlciI+CiAgICAgICAgICA8aDE+JHtlbmRlZCA/ICdUZXN0IHlha3VubGFuZGknIDogJ0phdm9ibGFyaW5naXogcWFidWwgcWlsaW5kaSd9PC9oMT4KICAgICAgICAgIDxwIGNsYXNzPSJtdXRlZCI+JHtlc2MoUy5uYW1lKX08L3A+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJzY29yZSI+JHtTLnNjb3JlfS8ke1MudG90YWx9PC9kaXY+CiAgICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCI+JHtTLnBlcmNlbnR9JSB0bydnJ3JpPC9kaXY+CiAgICAgICAgICAke2VuZGVkID8gJycgOiBgPHA+SGFtbWEgdWNodW4gdGVzdCB0dWdhc2hpZ2E6IDxiIGNsYXNzPSJ0aW1lciIgaWQ9InRpbWVyIj48L2I+PGJyPgogICAgICAgICAgICA8c3BhbiBjbGFzcz0ibXV0ZWQiPlRvJ2cncmkgamF2b2JsYXIgdGVzdCB0dWdhZ2FjaCBzaHUgeWVyZGEga28ncmluYWRpLjwvc3Bhbj48L3A+YH0KICAgICAgICA8L2Rpdj4KICAgICAgICAke2VuZGVkICYmIFMucmV2aWV3ID8gcmV2aWV3SHRtbCgpIDogJyd9CiAgICAgICAgJHtTLmNvZGVVbnRpbCA/IGA8cCBjbGFzcz0ibXV0ZWQgY2VudGVyIj5Lb2QgJHtmbXRDbG9jayhTLmNvZGVVbnRpbCl9IGdhY2hhIGFtYWwgcWlsYWRpLCBzaHVuZGFuIGtleWluIGJ1IHNhaGlmYSBvY2hpbG1heWRpLjwvcD5gIDogJyd9CiAgICAgIDwvZGl2PmA7CiAgICB0aWNrKCk7CiAgfQoKICBmdW5jdGlvbiByZXZpZXdIdG1sKCkgewogICAgcmV0dXJuIFMucmV2aWV3Lm1hcCgocSwgaSkgPT4gYAogICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICA8ZGl2IGNsYXNzPSJtdXRlZCI+JHtpICsgMX0tc2F2b2w8L2Rpdj4KICAgICAgICA8aDM+JHtlc2MocS50ZXh0KX08L2gzPgogICAgICAgIDxkaXYgY2xhc3M9Im9wdHMiPgogICAgICAgICAgJHtxLm9wdGlvbnMubWFwKChvLCBqKSA9PiB7CiAgICAgICAgICAgIGNvbnN0IGNscyA9IGogPT09IHEuY29ycmVjdCA/ICdyaWdodCcgOiAoaiA9PT0gcS5taW5lID8gJ3dyb25nJyA6ICdkaW0nKTsKICAgICAgICAgICAgcmV0dXJuIGA8YnV0dG9uIGNsYXNzPSJvcHQgJHtjbHN9IiBkaXNhYmxlZD48c3BhbiBjbGFzcz0ibHRyIj4ke0xFVFRFUlNbal19PC9zcGFuPjxzcGFuPiR7ZXNjKG8pfSR7CiAgICAgICAgICAgICAgaiA9PT0gcS5taW5lID8gJyA8aT4oc2l6bmluZyBqYXZvYmluZ2l6KTwvaT4nIDogJyd9PC9zcGFuPjwvYnV0dG9uPmA7CiAgICAgICAgICB9KS5qb2luKCcnKX0KICAgICAgICA8L2Rpdj4KICAgICAgICAke3EubWluZSA9PT0gbnVsbCA/ICc8cCBjbGFzcz0ibXV0ZWQiPkJ1IHNhdm9sZ2EgamF2b2IgYmVybWFnYW5zaXouPC9wPicgOiAnJ30KICAgICAgPC9kaXY+YCkuam9pbignJyk7CiAgfQoKICAvLyAtLS0tLS0tLS0tIEJvc2hsYXNoIC0tLS0tLS0tLS0KICAoYXN5bmMgZnVuY3Rpb24gaW5pdCgpIHsKICAgIGNvbnN0IHBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMobG9jYXRpb24uc2VhcmNoKTsKICAgIGNvbnN0IGNvZGUgPSAocGFyYW1zLmdldCgna29kJykgfHwgc3RvcmUuZ2V0KCdxdWl6X2xhc3QnKSB8fCAnJykudG9VcHBlckNhc2UoKTsKICAgIGNvbnN0IHNhdmVkID0gY29kZSAmJiBzdG9yZS5nZXQoJ3F1aXpfJyArIGNvZGUpOwogICAgaWYgKHNhdmVkICYmIHNhdmVkLnRva2VuKSB7CiAgICAgIC8vIFNhaGlmYSB5YW5naWxhbmdhbiBibydsc2EsIGF2dG9tYXRpayBkYXZvbSBldHRpcmFtaXoKICAgICAgY2ZnID0gc2F2ZWQ7CiAgICAgIHRyeSB7IGF3YWl0IHJlZnJlc2godHJ1ZSk7IHN0YXJ0TG9vcHMoKTsgcmV0dXJuOyB9CiAgICAgIGNhdGNoIChlKSB7IGlmICghWzQwMSwgNDA0LCA0MTBdLmluY2x1ZGVzKGUuc3RhdHVzKSkgeyBzdGFydExvb3BzKCk7IHJldHVybjsgfSBzdG9yZS5kZWwoJ3F1aXpfJyArIGNvZGUpOyByZW5kZXJKb2luKGUubWVzc2FnZSwgY29kZSk7IHJldHVybjsgfQogICAgfQogICAgcmVuZGVySm9pbignJywgY29kZSk7CiAgfSkoKTsKfSkoKTsK","/apple-touch-icon.png":"iVBORw0KGgoAAAANSUhEUgAAALQAAAC0CAIAAACyr5FlAAAEQUlEQVR4Xu3cUVLcMBCEYZHiCFyBXAyOxcm4AjlEHlzlonbXa7WsGWlG//ca49hS09KSiJf3j58CPPKHYcERwgHCAR3NAZoDOpoDNAd0NAdoDuhoDtAc0NEcoDmgozlAc0BHc4DmgI7mAM0BHc0BmgM6mgM0B3Q0B2gO6GgO0BzQ0Rw49Dp8bL6/3oY/w7T+fv4b+Gwvo07ZkwnJkJQMCAexaOYcEe89B8m4wnn0XMPh/G4peY6hXzg83yo3t5F0Cofb+yzCZzw9wuHzJqtxGFXzcDi8w7Ksx9Y2HNZPD9MRtg0HQjMMh2mosbMbZ8NwIDrCgUNW4bDrOtwzGm2rcCABwgH3ZQUJ0BygOaCjOUBzQEdzgOaAjuYAzQEdzQGaAzqaAzQHdONP2S/i/pir0X/C6IhlxcPDA9DOp6IbEA5zT0IweT4Ih63T6T+9YCDCYahy4isv80c4wEdZ6GgOK9MuFvUIh4kEySiFcBhQkzHtT8Nojs7SJIPm6CxTMgjHSNOuJjuWlW7U2pgf4ehDTcb8tcGy0kfKZBCODrImg3BclTgZhMNViH3Gb2xI26m1EQ7haKQmI1xtsKw0WiEZhKPFIskgHOYiriY79hwaqTZCJ4Pm0EjJSIDmqKUmI3ptlBLkOOTws4QLJiPGsjL8LOGayQgQjnBnCROsJjE+rZx+y55ecJ3DXzGteTeklbNSeVkb9eaZaiPAsjLQ4slIEg51Fmuo90zWGZt5lxWJOpfPqXdLmYw84ShFntFesiZj6nA0DLr6Hf9Ql5vkMPWy4p8PNRkNTxjI1OEopWX01QneqV+YOxlTLyu7hjlQp7lhy9LwVOHM3hyb7683dTIa8lFPfZigYoRjj4g0yvX5qL+ybaULKlI4jCZGSsZSgoVDzcfpxJ9ecGORBWUTLxwd80EyngsZji75IBmnooajSz7qLbWa7AKH40o+1NpYU+xwtOVDTcaatRF1Q3rlEwTJqBe+OUwt2xmBP8res5hFi3vGkqc5+s5l37sFlScc6uYUp1KFo1c+qI1Ue47fLk7txS/PJFtzbJonuPkLU8oZjrZ8kIwbacOh5oNk3MscDjUfWKg56vcf1MZDyZujJh8k48jr4Z/ksiXg5l/diMVzq4SjpkKw3J4DzZbYc6AN4cAhwgHCAR3NAZoDOpoDNAd0NAdoDuhoDtAc0NEcoDmgs2oO9TA7rjAabatwIAHCgRF7DqOuww27caY5MKI5Gn7bPFR2teHxO8FMn35x1mPrsaxYv8OaHEbVIxysL905JMNjWdn5vM8K3EbSqTk2bm+VmOcYuoaDfFzkmYxSysv7x8/FJ27DIWaJcyw2w8KxIyVPDMnEbnw4MC3vPQcCIRw4RDhAOKCjOUBzQEdzgOaAjuYAzQEdzQGaAzqaAzQHdDQHaA7oaA7QHNDRHKA5oKM5QHNAR3OA5oCO5gDNAR3NgUP/Ad5GKOD+Fp/dAAAAAElFTkSuQmCC","/common.js":"Ly8gSWtrYWxhIHNhaGlmYSAodGVzdCB2YSBhZG1pbikgdWNodW4gdW11bWl5IHlvcmRhbWNoaWxhcgpjb25zdCAkID0gKHNlbCwgZWwgPSBkb2N1bWVudCkgPT4gZWwucXVlcnlTZWxlY3RvcihzZWwpOwpjb25zdCAkJCA9IChzZWwsIGVsID0gZG9jdW1lbnQpID0+IFsuLi5lbC5xdWVyeVNlbGVjdG9yQWxsKHNlbCldOwoKLy8gWFNTIGRhbiBoaW1veWE6IGZveWRhbGFudXZjaGkga2lyaXRnYW4gaGFyIHFhbmRheSBtYXRuIEhUTUwgZ2EgZmFxYXQgc2h1IGZ1bmtzaXlhIG9ycWFsaSBxbyd5aWxhZGkKY29uc3QgZXNjID0gKHMpID0+IFN0cmluZyhzKS5yZXBsYWNlKC9bJjw+IiddL2csIChjKSA9PiAoCiAgeyAnJic6ICcmYW1wOycsICc8JzogJyZsdDsnLCAnPic6ICcmZ3Q7JywgJyInOiAnJnF1b3Q7JywgIiciOiAnJiMzOTsnIH1bY10KKSk7Cgphc3luYyBmdW5jdGlvbiBhcGkobWV0aG9kLCB1cmwsIGJvZHkpIHsKICBjb25zdCByID0gYXdhaXQgZmV0Y2godXJsLCB7CiAgICBtZXRob2QsCiAgICBoZWFkZXJzOiBib2R5ID8geyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0gOiB7fSwKICAgIGJvZHk6IGJvZHkgPyBKU09OLnN0cmluZ2lmeShib2R5KSA6IHVuZGVmaW5lZCwKICAgIGNyZWRlbnRpYWxzOiAnc2FtZS1vcmlnaW4nLAogIH0pOwogIGxldCBkYXRhID0ge307CiAgdHJ5IHsgZGF0YSA9IGF3YWl0IHIuanNvbigpOyB9IGNhdGNoIChfKSB7IC8qIGJvJ3NoIGphdm9iICovIH0KICBpZiAoIXIub2spIHsKICAgIGNvbnN0IGUgPSBuZXcgRXJyb3IoZGF0YS5lcnJvciB8fCAnWGF0b2xpayAnICsgci5zdGF0dXMpOwogICAgZS5zdGF0dXMgPSByLnN0YXR1czsKICAgIHRocm93IGU7CiAgfQogIHJldHVybiBkYXRhOwp9CgpmdW5jdGlvbiBmbXRUaW1lKHNlYykgewogIHNlYyA9IE1hdGgubWF4KDAsIE1hdGgucm91bmQoc2VjKSk7CiAgcmV0dXJuIFN0cmluZyhNYXRoLmZsb29yKHNlYyAvIDYwKSkucGFkU3RhcnQoMiwgJzAnKSArICc6JyArIFN0cmluZyhzZWMgJSA2MCkucGFkU3RhcnQoMiwgJzAnKTsKfQoKZnVuY3Rpb24gZm10Q2xvY2sodHMpIHsKICByZXR1cm4gbmV3IERhdGUodHMpLnRvTG9jYWxlVGltZVN0cmluZygndXotVVonLCB7IGhvdXI6ICcyLWRpZ2l0JywgbWludXRlOiAnMi1kaWdpdCcgfSk7Cn0KCmZ1bmN0aW9uIHRvYXN0KG1zZykgewogIGNvbnN0IHQgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdkaXYnKTsKICB0LmNsYXNzTmFtZSA9ICd0b2FzdCc7CiAgdC50ZXh0Q29udGVudCA9IG1zZzsKICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHQpOwogIHNldFRpbWVvdXQoKCkgPT4gdC5yZW1vdmUoKSwgMjIwMCk7Cn0K","/icon-192.png":"iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAIAAADdvvtQAAAEkklEQVR4Xu3c4XHaQBRFYZNJCW7Bacwuy5W5BaeITEYzDAMYVvfuvtV7e76fCRAkHd4Kx9Lp7f37BVD9Up8I/EdAsBAQLAQECwHBQkCwEBAsBAQLAcFCQLAQECwEBAsBwUJAsBAQLAQECwHBQkCwEBAsBAQLAcFCQLAQECwEBAsBwUJAsBAQLAQECwHBQkCw/Lae3dXX52vX16vsz8ffg2zeafr9gejGNDemmQGRTkezMpp2DkQ9fc3anxMm0KxNXUTwKIqeQNQzWvAeDg0oeNuWFbmf4wKK3CqE7e24gFBSUEBhHwicxezziIBitgS3AvZ8REAobHhAAR8CPDB6/w8PCLURECxjAxo9P9Fi6FEYGxDKIyBYCAgWAoKFgGAhIFgICBYCgoWAYCEgWAgIFgKChYBgISBYCAgWAoLlQPcHWtbl1exDf/lrBAKa6fZGCNufJMqIJWyaB7fRePBXR0NAczxN5OkDDoKAJsgSRwsCOq4UnRFQtBRZtCOgUMXqeXkhoED16iGgOEI9KX4axBIWQagnCwI6qBTjhyUsgjB+stRDQMMJ9eTCEjaQVk+i8cMEGmiFegjoWHLNng1L2BDC+MlYDwENsU49BNSfUE9qLGE9afUkXbw4B+pswXpYwiZLPXuYQD0J46dAPUygPoR6yuAk2qXVU2P8MIFci9dDQBOUmT2blJc2H+RicmH8FKsnX0DHuZicevJ9jT/OxeRCPVWl+Rb29Jg9fUAv2j9Ub/HKN4GOgHqu5JhAjYet8WHBqs6emhNoaEPCi9eup+bPgYTD3GLQy2aXYwnbq/vB1l6w/PipOYE22iG/S3upFepJE1C6g5HuDctqLmEdh5AwftapJ80Eku98Kxz+S8LTl6onU0DxDQn1LCjZEvb1+Sp8xIUUhKfIiaeWLKCNkNGuIHY9+Ewou4CUAZ0z2nUAtCwarVlPsnOgW3sPW0tDLY+5svdtVJJ4Amke9yHUs7j0AQmf/p8q0eoR3kAl6QPSvvvctkI9mgoB9Wpor8Vnz6ZIQGZDwvihnmoBaQ1p/29PPWd1JtBm76EVZg8uVQtIaGivvY3WVjCgoQ1Rz5WaAQ1qiHpulQ2oe0PUc1flgLo3hLUmkPa97C7Gz0+KT6AuqOeBJQJyCnCeu4IlApJPhqjnqVUCEhqinhYLBSQ0hKfWCqi9IcZPo+UCammIetqtGNDjhqhnl5S3+e1iC+Xy1zlIR7BuQBuiMS26hKEXAoKFgGAhIFgICBYCgoWAYCEgWAgIFgKChYBgISBYCAgWAoJlbEDcPOUIhh6FsQGhPAKChYCKG7p+Rdxkc/QGYC4mECwRATGEZgnY8xEBabfShSmgnohzIEwRU09oQGGbhEhBS9iGhmJE7ufT2/t3zFadcTHoOJHpbCYEtCGj7uLrCT0HujJlawubtT+nTSBWtC5mdXM2PyBKEkzv5ogBIaPQr/Goh4BgISBYCAgWAoKFgGAhIFgICBYCgoWAYCEgWAgIFgKChYBgISBYCAgWAoKFgGAhIFgICBYCgoWAYCEgWAgIFgKChYBgISBYCAgWAoLlH1zKPgT4WbALAAAAAElFTkSuQmCC","/icon-512.png":"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","/icon-maskable-512.png":"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","/index.html":"PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9InV6Ij4KPGhlYWQ+CiAgPG1ldGEgY2hhcnNldD0idXRmLTgiPgogIDxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MSwgdmlld3BvcnQtZml0PWNvdmVyIj4KICA8bWV0YSBuYW1lPSJ0aGVtZS1jb2xvciIgY29udGVudD0iIzI1NjNlYiI+CiAgPG1ldGEgbmFtZT0ibW9iaWxlLXdlYi1hcHAtY2FwYWJsZSIgY29udGVudD0ieWVzIj4KICA8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC1jYXBhYmxlIiBjb250ZW50PSJ5ZXMiPgogIDxtZXRhIG5hbWU9ImFwcGxlLW1vYmlsZS13ZWItYXBwLXRpdGxlIiBjb250ZW50PSJUZXN0Ij4KICA8bWV0YSBuYW1lPSJhcHBsZS1tb2JpbGUtd2ViLWFwcC1zdGF0dXMtYmFyLXN0eWxlIiBjb250ZW50PSJkZWZhdWx0Ij4KICA8bGluayByZWw9Im1hbmlmZXN0IiBocmVmPSIvbWFuaWZlc3Qud2VibWFuaWZlc3QiPgogIDxsaW5rIHJlbD0iYXBwbGUtdG91Y2gtaWNvbiIgaHJlZj0iL2FwcGxlLXRvdWNoLWljb24ucG5nIj4KICA8bGluayByZWw9Imljb24iIHR5cGU9ImltYWdlL3BuZyIgaHJlZj0iL2ljb24tMTkyLnBuZyI+CiAgPHRpdGxlPlRlc3QgdG9wc2hpcmlzaDwvdGl0bGU+CiAgPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIvc3R5bGUuY3NzIj4KPC9oZWFkPgo8Ym9keT4KICA8ZGl2IGlkPSJhcHAiPjwvZGl2PgogIDxzY3JpcHQgc3JjPSIvY29tbW9uLmpzIj48L3NjcmlwdD4KICA8c2NyaXB0IHNyYz0iL2FwcC5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9Ii9wd2EuanMiPjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K","/manifest.webmanifest":"ewogICJuYW1lIjogIlRlc3QgdG9wc2hpcmlzaCIsCiAgInNob3J0X25hbWUiOiAiVGVzdCIsCiAgImRlc2NyaXB0aW9uIjogIktvZCBvcnFhbGkgb25sYXluIHRlc3QgdG9wc2hpcmlzaCIsCiAgImxhbmciOiAidXoiLAogICJzdGFydF91cmwiOiAiLyIsCiAgInNjb3BlIjogIi8iLAogICJkaXNwbGF5IjogInN0YW5kYWxvbmUiLAogICJvcmllbnRhdGlvbiI6ICJwb3J0cmFpdCIsCiAgImJhY2tncm91bmRfY29sb3IiOiAiI2Y0ZjZmYiIsCiAgInRoZW1lX2NvbG9yIjogIiMyNTYzZWIiLAogICJpY29ucyI6IFsKICAgIHsgInNyYyI6ICIvaWNvbi0xOTIucG5nIiwgInNpemVzIjogIjE5MngxOTIiLCAidHlwZSI6ICJpbWFnZS9wbmciIH0sCiAgICB7ICJzcmMiOiAiL2ljb24tNTEyLnBuZyIsICJzaXplcyI6ICI1MTJ4NTEyIiwgInR5cGUiOiAiaW1hZ2UvcG5nIiB9LAogICAgeyAic3JjIjogIi9pY29uLW1hc2thYmxlLTUxMi5wbmciLCAic2l6ZXMiOiAiNTEyeDUxMiIsICJ0eXBlIjogImltYWdlL3BuZyIsICJwdXJwb3NlIjogIm1hc2thYmxlIiB9CiAgXQp9Cg==","/pwa.js":"Ly8gUFdBOiBzZXJ2aWNlIHdvcmtlciArICJFa3JhbmdhIG8ncm5hdGlzaCIgdHVnbWFzaSAoQW5kcm9pZCkgdmEga28ncnNhdG1hIChpUGhvbmUpCihmdW5jdGlvbiAoKSB7CiAgaWYgKCdzZXJ2aWNlV29ya2VyJyBpbiBuYXZpZ2F0b3IpIHsKICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdsb2FkJywgKCkgPT4gbmF2aWdhdG9yLnNlcnZpY2VXb3JrZXIucmVnaXN0ZXIoJy9zdy5qcycpLmNhdGNoKCgpID0+IHt9KSk7CiAgfQoKICBjb25zdCBzdGFuZGFsb25lID0gd2luZG93Lm1hdGNoTWVkaWEoJyhkaXNwbGF5LW1vZGU6IHN0YW5kYWxvbmUpJykubWF0Y2hlcyB8fCBuYXZpZ2F0b3Iuc3RhbmRhbG9uZSA9PT0gdHJ1ZTsKICBpZiAoc3RhbmRhbG9uZSkgcmV0dXJuOyAvLyBhbGxhcWFjaG9uIG8ncm5hdGlsZ2FuCgogIGNvbnN0IGlzSU9TID0gL2lwaG9uZXxpcGFkfGlwb2QvaS50ZXN0KG5hdmlnYXRvci51c2VyQWdlbnQpIHx8CiAgICAobmF2aWdhdG9yLnBsYXRmb3JtID09PSAnTWFjSW50ZWwnICYmIG5hdmlnYXRvci5tYXhUb3VjaFBvaW50cyA+IDEpOwogIGxldCBkZWZlcnJlZCA9IG51bGw7CgogIGNvbnN0IGJveCA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2RpdicpOwogIGJveC5pZCA9ICdpbnN0YWxsLWhpbnQnOwogIGJveC5oaWRkZW4gPSB0cnVlOwogIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYm94KTsKCiAgZnVuY3Rpb24gZGlzbWlzc2VkKCkgeyB0cnkgeyByZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ2luc3RhbGxfaGludF9vZmYnKSA9PT0gJzEnOyB9IGNhdGNoIChfKSB7IHJldHVybiBmYWxzZTsgfSB9CiAgZnVuY3Rpb24gZGlzbWlzcygpIHsgdHJ5IHsgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ2luc3RhbGxfaGludF9vZmYnLCAnMScpOyB9IGNhdGNoIChfKSB7fSBib3guaGlkZGVuID0gdHJ1ZTsgfQoKICBmdW5jdGlvbiBzaG93KGh0bWwsIHdpdGhCdG4pIHsKICAgIGlmIChkaXNtaXNzZWQoKSkgcmV0dXJuOwogICAgYm94LmlubmVySFRNTCA9IGA8ZGl2IGNsYXNzPSJpaC10ZXh0Ij4ke2h0bWx9PC9kaXY+YCArCiAgICAgICh3aXRoQnRuID8gJzxidXR0b24gaWQ9ImloLWluc3RhbGwiIGNsYXNzPSJzbWFsbCBwcmltYXJ5LWJ0biI+T1wncm5hdGlzaDwvYnV0dG9uPicgOiAnJykgKwogICAgICAnPGJ1dHRvbiBpZD0iaWgtY2xvc2UiIGNsYXNzPSJzbWFsbCIgYXJpYS1sYWJlbD0iWW9waXNoIj7inJU8L2J1dHRvbj4nOwogICAgYm94LmhpZGRlbiA9IGZhbHNlOwogICAgJCgnI2loLWNsb3NlJywgYm94KS5vbmNsaWNrID0gZGlzbWlzczsKICAgIGNvbnN0IGIgPSAkKCcjaWgtaW5zdGFsbCcsIGJveCk7CiAgICBpZiAoYikgYi5vbmNsaWNrID0gYXN5bmMgKCkgPT4gewogICAgICBpZiAoIWRlZmVycmVkKSByZXR1cm47CiAgICAgIGRlZmVycmVkLnByb21wdCgpOwogICAgICBhd2FpdCBkZWZlcnJlZC51c2VyQ2hvaWNlLmNhdGNoKCgpID0+IHt9KTsKICAgICAgZGVmZXJyZWQgPSBudWxsOyBib3guaGlkZGVuID0gdHJ1ZTsKICAgIH07CiAgfQoKICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignYmVmb3JlaW5zdGFsbHByb21wdCcsIChlKSA9PiB7CiAgICBlLnByZXZlbnREZWZhdWx0KCk7CiAgICBkZWZlcnJlZCA9IGU7CiAgICBzaG93KCfwn5OyIFRlc3RuaSBpbG92YSBzaWZhdGlkYSBla3JhbmdhIG9cJ3JuYXRpbmcnLCB0cnVlKTsKICB9KTsKICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignYXBwaW5zdGFsbGVkJywgKCkgPT4geyBib3guaGlkZGVuID0gdHJ1ZTsgfSk7CgogIGlmIChpc0lPUykgewogICAgLy8gaVBob25lJ2RhIGF2dG9tYXRpayBvJ3JuYXRpc2ggdHVnbWFzaSB5bydxOiBTYWZhcmknZGEgcW8nbGRhIHFpbGluYWRpCiAgICBzZXRUaW1lb3V0KCgpID0+IHNob3coCiAgICAgICfwn5OyIGlQaG9uZTogU2FmYXJpIHBhc3RpZGFnaSA8Yj5VbGFzaGlzaDwvYj4gPHNwYW4gY2xhc3M9ImloLWljbyI+4o6LPC9zcGFuPiB0dWdtYXNpbmkgYm9zaW5nIOKGkiA8Yj7Cq0VrcmFuZ2EgcW9cJ3NoaXNowrs8L2I+JywKICAgICAgZmFsc2UKICAgICksIDE1MDApOwogIH0KfSkoKTsK","/style.css":"OnJvb3QgewogIC0tYmc6ICNmNGY2ZmI7IC0tY2FyZDogI2ZmZmZmZjsgLS10ZXh0OiAjMWIyMzMzOyAtLW11dGVkOiAjNmI3NDg4OyAtLWxpbmU6ICNlM2U3ZjA7CiAgLS1wcmltYXJ5OiAjMjU2M2ViOyAtLXByaW1hcnktZGFyazogIzFkNGVkODsgLS1vazogIzE2YTM0YTsgLS1va2JnOiAjZThmN2VlOwogIC0tZXJyOiAjZGMyNjI2OyAtLWVycmJnOiAjZmRlY2VjOyAtLXdhcm46ICNkOTc3MDY7IC0td2FybmJnOiAjZmZmNGUwOwp9CiogeyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9Cmh0bWwgeyAtd2Via2l0LXRleHQtc2l6ZS1hZGp1c3Q6IDEwMCU7IH0KYm9keSB7CiAgbWFyZ2luOiAwOyBiYWNrZ3JvdW5kOiB2YXIoLS1iZyk7IGNvbG9yOiB2YXIoLS10ZXh0KTsKICBmb250OiAxNnB4LzEuNSBzeXN0ZW0tdWksIC1hcHBsZS1zeXN0ZW0sICJTZWdvZSBVSSIsIFJvYm90bywgc2Fucy1zZXJpZjsKfQpoMSB7IGZvbnQtc2l6ZTogMS41cmVtOyBtYXJnaW46IDAgMCAuNzVyZW07IH0KaDIgeyBmb250LXNpemU6IDEuMnJlbTsgbWFyZ2luOiAuMjVyZW0gMCAxcmVtOyBsaW5lLWhlaWdodDogMS4zNTsgfQpoMyB7IGZvbnQtc2l6ZTogMS4wNXJlbTsgbWFyZ2luOiAwIDAgLjVyZW07IH0KLndyYXAgeyBtYXgtd2lkdGg6IDg2MHB4OyBtYXJnaW46IDAgYXV0bzsgcGFkZGluZzogMTZweDsgfQoud3JhcC5uYXJyb3cgeyBtYXgtd2lkdGg6IDQ2MHB4OyBwYWRkaW5nLXRvcDogOHZoOyB9Ci5jYXJkIHsKICBiYWNrZ3JvdW5kOiB2YXIoLS1jYXJkKTsgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tbGluZSk7IGJvcmRlci1yYWRpdXM6IDE0cHg7CiAgcGFkZGluZzogMThweDsgbWFyZ2luLWJvdHRvbTogMTRweDsgYm94LXNoYWRvdzogMCAxcHggMnB4IHJnYmEoMjAsIDMwLCA2MCwgLjA0KTsKfQouY2VudGVyIHsgdGV4dC1hbGlnbjogY2VudGVyOyB9Ci5tdXRlZCB7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IGZvbnQtc2l6ZTogLjlyZW07IH0KLmVyciB7IGNvbG9yOiB2YXIoLS1lcnIpOyBtaW4taGVpZ2h0OiAxLjRlbTsgbWFyZ2luOiAuNnJlbSAwIDA7IGZvbnQtc2l6ZTogLjk1cmVtOyB9Ci5vay10ZXh0IHsgY29sb3I6IHZhcigtLW9rKTsgfQoKbGFiZWwgeyBkaXNwbGF5OiBibG9jazsgZm9udC13ZWlnaHQ6IDYwMDsgbWFyZ2luOiAxMnB4IDAgNHB4OyBmb250LXNpemU6IC45MnJlbTsgfQppbnB1dCwgdGV4dGFyZWEsIHNlbGVjdCB7CiAgd2lkdGg6IDEwMCU7IHBhZGRpbmc6IDExcHggMTJweDsgYm9yZGVyOiAxcHggc29saWQgI2NkZDNlMDsgYm9yZGVyLXJhZGl1czogMTBweDsKICBmb250OiBpbmhlcml0OyBiYWNrZ3JvdW5kOiAjZmZmOyBjb2xvcjogaW5oZXJpdDsKfQp0ZXh0YXJlYSB7IHJlc2l6ZTogdmVydGljYWw7IG1pbi1oZWlnaHQ6IDcwcHg7IH0KaW5wdXQ6Zm9jdXMsIHRleHRhcmVhOmZvY3VzIHsgb3V0bGluZTogMnB4IHNvbGlkICNiY2QwZmY7IGJvcmRlci1jb2xvcjogdmFyKC0tcHJpbWFyeSk7IH0KaW5wdXRbdHlwZT0icmFkaW8iXSB7IHdpZHRoOiBhdXRvOyBhY2NlbnQtY29sb3I6IHZhcigtLW9rKTsgdHJhbnNmb3JtOiBzY2FsZSgxLjI1KTsgfQojY29kZSB7IHRleHQtdHJhbnNmb3JtOiB1cHBlcmNhc2U7IGxldHRlci1zcGFjaW5nOiAuMmVtOyBmb250LXdlaWdodDogNzAwOyB0ZXh0LWFsaWduOiBjZW50ZXI7IGZvbnQtc2l6ZTogMS4zcmVtOyB9CgpidXR0b24gewogIGZvbnQ6IGluaGVyaXQ7IGZvbnQtd2VpZ2h0OiA2MDA7IGN1cnNvcjogcG9pbnRlcjsgcGFkZGluZzogMTBweCAxNnB4OyBib3JkZXItcmFkaXVzOiAxMHB4OwogIGJvcmRlcjogMXB4IHNvbGlkICNjZGQzZTA7IGJhY2tncm91bmQ6ICNmZmY7IGNvbG9yOiB2YXIoLS10ZXh0KTsKfQpidXR0b246aG92ZXI6bm90KDpkaXNhYmxlZCkgeyBiYWNrZ3JvdW5kOiAjZjBmM2ZhOyB9CmJ1dHRvbjpkaXNhYmxlZCB7IG9wYWNpdHk6IC40NTsgY3Vyc29yOiBub3QtYWxsb3dlZDsgfQpidXR0b24ucHJpbWFyeSB7IGJhY2tncm91bmQ6IHZhcigtLXByaW1hcnkpOyBib3JkZXItY29sb3I6IHZhcigtLXByaW1hcnkpOyBjb2xvcjogI2ZmZjsgd2lkdGg6IDEwMCU7IG1hcmdpbi10b3A6IDE0cHg7IH0KYnV0dG9uLnByaW1hcnk6aG92ZXI6bm90KDpkaXNhYmxlZCkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5LWRhcmspOyB9CmJ1dHRvbi5zbWFsbCB7IHBhZGRpbmc6IDZweCAxMXB4OyBmb250LXNpemU6IC44OHJlbTsgfQpidXR0b24uZGFuZ2VyIHsgY29sb3I6IHZhcigtLWVycik7IGJvcmRlci1jb2xvcjogI2YxYjliOTsgfQpidXR0b24uZGFuZ2VyOmhvdmVyOm5vdCg6ZGlzYWJsZWQpIHsgYmFja2dyb3VuZDogdmFyKC0tZXJyYmcpOyB9CmJ1dHRvbi5zdWNjZXNzIHsgYmFja2dyb3VuZDogdmFyKC0tb2spOyBib3JkZXItY29sb3I6IHZhcigtLW9rKTsgY29sb3I6ICNmZmY7IH0KYnV0dG9uLnN1Y2Nlc3M6aG92ZXI6bm90KDpkaXNhYmxlZCkgeyBiYWNrZ3JvdW5kOiAjMTI4MDNhOyB9Ci5idG5zIHsgZGlzcGxheTogZmxleDsgZmxleC13cmFwOiB3cmFwOyBnYXA6IDhweDsgbWFyZ2luLXRvcDogMTJweDsgfQouYnRucyBidXR0b24ucHJpbWFyeSB7IHdpZHRoOiBhdXRvOyBtYXJnaW4tdG9wOiAwOyB9CgovKiAtLS0tIFRlc3Qgc2FoaWZhc2kgLS0tLSAqLwoudG9wYmFyIHsKICBwb3NpdGlvbjogc3RpY2t5OyB0b3A6IDA7IHotaW5kZXg6IDU7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgYWxpZ24taXRlbXM6IGNlbnRlcjsKICBnYXA6IDEycHg7IHBhZGRpbmc6IDEwcHggMTZweDsgYmFja2dyb3VuZDogI2ZmZjsgYm9yZGVyLWJvdHRvbTogMXB4IHNvbGlkIHZhcigtLWxpbmUpOwp9Ci50aW1lciB7IGZvbnQtdmFyaWFudC1udW1lcmljOiB0YWJ1bGFyLW51bXM7IGZvbnQtd2VpZ2h0OiA4MDA7IGZvbnQtc2l6ZTogMS41cmVtOyBjb2xvcjogdmFyKC0tcHJpbWFyeSk7IH0KLnRpbWVyLndhcm4geyBjb2xvcjogdmFyKC0tZXJyKTsgfQoub3B0cyB7IGRpc3BsYXk6IGdyaWQ7IGdhcDogMTBweDsgfQoub3B0IHsKICBkaXNwbGF5OiBmbGV4OyBhbGlnbi1pdGVtczogY2VudGVyOyBnYXA6IDEycHg7IHRleHQtYWxpZ246IGxlZnQ7IHdpZHRoOiAxMDAlOwogIHBhZGRpbmc6IDEzcHggMTRweDsgYm9yZGVyLXJhZGl1czogMTJweDsgYm9yZGVyOiAycHggc29saWQgdmFyKC0tbGluZSk7IGJhY2tncm91bmQ6ICNmZmY7IGZvbnQtd2VpZ2h0OiA1MDA7Cn0KLm9wdCAubHRyIHsKICBmbGV4OiAwIDAgYXV0bzsgd2lkdGg6IDMwcHg7IGhlaWdodDogMzBweDsgYm9yZGVyLXJhZGl1czogNTAlOyBkaXNwbGF5OiBncmlkOyBwbGFjZS1pdGVtczogY2VudGVyOwogIGJhY2tncm91bmQ6ICNlZWYxZjg7IGZvbnQtd2VpZ2h0OiA3MDA7IGZvbnQtc2l6ZTogLjlyZW07Cn0KLm9wdC5zZWwgeyBib3JkZXItY29sb3I6IHZhcigtLXByaW1hcnkpOyBiYWNrZ3JvdW5kOiAjZWVmM2ZmOyB9Ci5vcHQuc2VsIC5sdHIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5KTsgY29sb3I6ICNmZmY7IH0KLm9wdC5sb2NrZWQgeyBib3JkZXItY29sb3I6IHZhcigtLXByaW1hcnkpOyBiYWNrZ3JvdW5kOiAjZWVmM2ZmOyBvcGFjaXR5OiAxOyB9Ci5vcHQubG9ja2VkIC5sdHIgeyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5KTsgY29sb3I6ICNmZmY7IH0KLm9wdC5kaW0geyBvcGFjaXR5OiAuNTsgfQoub3B0LnJpZ2h0IHsgYm9yZGVyLWNvbG9yOiB2YXIoLS1vayk7IGJhY2tncm91bmQ6IHZhcigtLW9rYmcpOyB9Ci5vcHQucmlnaHQgLmx0ciB7IGJhY2tncm91bmQ6IHZhcigtLW9rKTsgY29sb3I6ICNmZmY7IH0KLm9wdC53cm9uZyB7IGJvcmRlci1jb2xvcjogdmFyKC0tZXJyKTsgYmFja2dyb3VuZDogdmFyKC0tZXJyYmcpOyB9Ci5vcHQud3JvbmcgLmx0ciB7IGJhY2tncm91bmQ6IHZhcigtLWVycik7IGNvbG9yOiAjZmZmOyB9Ci5vcHQ6ZGlzYWJsZWQgeyBjdXJzb3I6IGRlZmF1bHQ7IH0KLm5hdiB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgZ2FwOiAxMHB4OyBtYXJnaW4tYm90dG9tOiAxNHB4OyB9Ci5uYXYgYnV0dG9uIHsgZmxleDogMTsgfQouZG90cyB7IGRpc3BsYXk6IGZsZXg7IGZsZXgtd3JhcDogd3JhcDsgZ2FwOiA2cHg7IG1hcmdpbi1ib3R0b206IDE4cHg7IH0KLmRvdCB7IHdpZHRoOiAzOHB4OyBwYWRkaW5nOiA2cHggMDsgYm9yZGVyLXJhZGl1czogOHB4OyBmb250LXNpemU6IC45cmVtOyB9Ci5kb3QuZG9uZSB7IGJhY2tncm91bmQ6ICNkYmU3ZmY7IGJvcmRlci1jb2xvcjogI2E5YzNmZjsgfQouZG90LmN1ciB7IG91dGxpbmU6IDJweCBzb2xpZCB2YXIoLS1wcmltYXJ5KTsgfQouc2NvcmUgeyBmb250LXNpemU6IDMuMnJlbTsgZm9udC13ZWlnaHQ6IDgwMDsgY29sb3I6IHZhcigtLXByaW1hcnkpOyBsaW5lLWhlaWdodDogMS4xOyB9Ci5maW5pc2gtYnRuIHsgd2lkdGg6IDEwMCU7IGNvbG9yOiB2YXIoLS1lcnIpOyBib3JkZXItY29sb3I6ICNmMWI5Yjk7IH0KCi8qIC0tLS0gQWRtaW4gLS0tLSAqLwouYWRtaW4taGVhZCB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAxMHB4OyBmbGV4LXdyYXA6IHdyYXA7IG1hcmdpbi1ib3R0b206IDE0cHg7IH0KLmFkbWluLWhlYWQgaDEgeyBtYXJnaW46IDA7IH0KLnN0YXRzIHsgZGlzcGxheTogZ3JpZDsgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOiByZXBlYXQoYXV0by1maXQsIG1pbm1heCgxNTBweCwgMWZyKSk7IGdhcDogMTJweDsgbWFyZ2luLWJvdHRvbTogMTRweDsgfQouc3RhdCB7IGJhY2tncm91bmQ6IHZhcigtLWNhcmQpOyBib3JkZXI6IDFweCBzb2xpZCB2YXIoLS1saW5lKTsgYm9yZGVyLXJhZGl1czogMTRweDsgcGFkZGluZzogMTRweDsgfQouc3RhdCBiIHsgZGlzcGxheTogYmxvY2s7IGZvbnQtc2l6ZTogMS44cmVtOyBsaW5lLWhlaWdodDogMS4yOyB9Ci5zdGF0IHNwYW4geyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBmb250LXNpemU6IC44OHJlbTsgfQp0YWJsZSB7IHdpZHRoOiAxMDAlOyBib3JkZXItY29sbGFwc2U6IGNvbGxhcHNlOyBmb250LXNpemU6IC45M3JlbTsgfQp0aCwgdGQgeyB0ZXh0LWFsaWduOiBsZWZ0OyBwYWRkaW5nOiA5cHggOHB4OyBib3JkZXItYm90dG9tOiAxcHggc29saWQgdmFyKC0tbGluZSk7IH0KdGggeyBjb2xvcjogdmFyKC0tbXV0ZWQpOyBmb250LXdlaWdodDogNjAwOyBmb250LXNpemU6IC44MnJlbTsgfQoudGJsLXdyYXAgeyBvdmVyZmxvdy14OiBhdXRvOyB9CnRyLmNsaWNrIHsgY3Vyc29yOiBwb2ludGVyOyB9CnRyLmNsaWNrOmhvdmVyIHsgYmFja2dyb3VuZDogI2Y1ZjhmZjsgfQouYmFkZ2UgeyBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7IHBhZGRpbmc6IDJweCAxMHB4OyBib3JkZXItcmFkaXVzOiA5OXB4OyBmb250LXNpemU6IC44cmVtOyBmb250LXdlaWdodDogNzAwOyB9Ci5iYWRnZS5sb2JieSB7IGJhY2tncm91bmQ6IHZhcigtLXdhcm5iZyk7IGNvbG9yOiB2YXIoLS13YXJuKTsgfQouYmFkZ2UucnVubmluZyB7IGJhY2tncm91bmQ6IHZhcigtLW9rYmcpOyBjb2xvcjogdmFyKC0tb2spOyB9Ci5iYWRnZS5lbmRlZCB7IGJhY2tncm91bmQ6ICNlY2VmZjU7IGNvbG9yOiB2YXIoLS1tdXRlZCk7IH0KLmNvZGVib3ggewogIGRpc3BsYXk6IGlubGluZS1ibG9jazsgZm9udDogODAwIDJyZW0vMSB1aS1tb25vc3BhY2UsIE1lbmxvLCBDb25zb2xhcywgbW9ub3NwYWNlOyBsZXR0ZXItc3BhY2luZzogLjE4ZW07CiAgcGFkZGluZzogMTBweCAxNnB4OyBib3JkZXItcmFkaXVzOiAxMnB4OyBiYWNrZ3JvdW5kOiAjZWVmM2ZmOyBjb2xvcjogdmFyKC0tcHJpbWFyeS1kYXJrKTsKfQoubGlua3JvdyB7IGRpc3BsYXk6IGZsZXg7IGdhcDogOHB4OyBtYXJnaW4tdG9wOiAxMHB4OyB9Ci5saW5rcm93IGlucHV0IHsgZm9udC1zaXplOiAuOXJlbTsgfQouYmFyIHsgaGVpZ2h0OiAxMHB4OyBib3JkZXItcmFkaXVzOiA5OXB4OyBiYWNrZ3JvdW5kOiAjZWNlZmY1OyBvdmVyZmxvdzogaGlkZGVuOyB9Ci5iYXIgPiBpIHsgZGlzcGxheTogYmxvY2s7IGhlaWdodDogMTAwJTsgYmFja2dyb3VuZDogdmFyKC0tcHJpbWFyeSk7IH0KLmJhci5nb29kID4gaSB7IGJhY2tncm91bmQ6IHZhcigtLW9rKTsgfQouYmFyLmJhZCA+IGkgeyBiYWNrZ3JvdW5kOiB2YXIoLS1lcnIpOyB9Ci5iYXIubWlkID4gaSB7IGJhY2tncm91bmQ6IHZhcigtLXdhcm4pOyB9Ci5vcHRyb3cgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IDFmciA3MHB4OyBnYXA6IDEwcHg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IG1hcmdpbjogNnB4IDA7IGZvbnQtc2l6ZTogLjkycmVtOyB9Ci5vcHRyb3cgLnQgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDhweDsgYWxpZ24taXRlbXM6IGJhc2VsaW5lOyB9Ci5vcHRyb3cucmlnaHQgLnQgeyBjb2xvcjogdmFyKC0tb2spOyBmb250LXdlaWdodDogNzAwOyB9Ci5xaGVhZCB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgZ2FwOiAxMHB4OyBhbGlnbi1pdGVtczogYmFzZWxpbmU7IH0KLnRhZyB7IGZvbnQtc2l6ZTogLjc4cmVtOyBmb250LXdlaWdodDogNzAwOyBwYWRkaW5nOiAycHggOHB4OyBib3JkZXItcmFkaXVzOiA5OXB4OyB3aGl0ZS1zcGFjZTogbm93cmFwOyB9Ci50YWcuZWFzeSB7IGJhY2tncm91bmQ6IHZhcigtLW9rYmcpOyBjb2xvcjogdmFyKC0tb2spOyB9Ci50YWcubWlkIHsgYmFja2dyb3VuZDogdmFyKC0td2FybmJnKTsgY29sb3I6IHZhcigtLXdhcm4pOyB9Ci50YWcuaGFyZCB7IGJhY2tncm91bmQ6IHZhcigtLWVycmJnKTsgY29sb3I6IHZhcigtLWVycik7IH0KLnFlZGl0IC5yb3cgeyBkaXNwbGF5OiBmbGV4OyBnYXA6IDhweDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgbWFyZ2luOiA2cHggMDsgfQoucWVkaXQgLnJvdyBpbnB1dFt0eXBlPSJ0ZXh0Il0sIC5xZWRpdCAucm93IGlucHV0Om5vdChbdHlwZV0pIHsgZmxleDogMTsgfQoucWVkaXQgLnFoZWFkIHsgbWFyZ2luLWJvdHRvbTogNnB4OyB9Ci5oaW50IHsgYmFja2dyb3VuZDogI2Y3ZjlmZTsgYm9yZGVyOiAxcHggZGFzaGVkICNjOGQyZWE7IGJvcmRlci1yYWRpdXM6IDEwcHg7IHBhZGRpbmc6IDEwcHggMTJweDsgZm9udC1zaXplOiAuODhyZW07IGNvbG9yOiB2YXIoLS1tdXRlZCk7IHdoaXRlLXNwYWNlOiBwcmUtd3JhcDsgZm9udC1mYW1pbHk6IHVpLW1vbm9zcGFjZSwgTWVubG8sIENvbnNvbGFzLCBtb25vc3BhY2U7IH0KLnRvYXN0IHsgcG9zaXRpb246IGZpeGVkOyBsZWZ0OiA1MCU7IGJvdHRvbTogMjBweDsgdHJhbnNmb3JtOiB0cmFuc2xhdGVYKC01MCUpOyBiYWNrZ3JvdW5kOiAjMWIyMzMzOyBjb2xvcjogI2ZmZjsgcGFkZGluZzogMTBweCAxOHB4OyBib3JkZXItcmFkaXVzOiAxMHB4OyBmb250LXNpemU6IC45MnJlbTsgei1pbmRleDogMjA7IH0KQG1lZGlhIChtYXgtd2lkdGg6IDUyMHB4KSB7CiAgLndyYXAgeyBwYWRkaW5nOiAxMnB4OyB9CiAgLmNvZGVib3ggeyBmb250LXNpemU6IDEuNnJlbTsgfQp9CgovKiAtLS0tIFRlbGVmb24gdWNodW4gLS0tLSAqLwpodG1sIHsgLXdlYmtpdC10YXAtaGlnaGxpZ2h0LWNvbG9yOiB0cmFuc3BhcmVudDsgfQpib2R5IHsgcGFkZGluZy1ib3R0b206IGVudihzYWZlLWFyZWEtaW5zZXQtYm90dG9tKTsgb3ZlcnNjcm9sbC1iZWhhdmlvci15OiBub25lOyB9Ci50b3BiYXIgeyBwYWRkaW5nLXRvcDogY2FsYygxMHB4ICsgZW52KHNhZmUtYXJlYS1pbnNldC10b3ApKTsgcGFkZGluZy1sZWZ0OiBtYXgoMTZweCwgZW52KHNhZmUtYXJlYS1pbnNldC1sZWZ0KSk7IHBhZGRpbmctcmlnaHQ6IG1heCgxNnB4LCBlbnYoc2FmZS1hcmVhLWluc2V0LXJpZ2h0KSk7IH0KYnV0dG9uLCAub3B0LCAuZG90IHsgdG91Y2gtYWN0aW9uOiBtYW5pcHVsYXRpb247IC13ZWJraXQtdXNlci1zZWxlY3Q6IG5vbmU7IHVzZXItc2VsZWN0OiBub25lOyB9Ci5vcHQgeyBtaW4taGVpZ2h0OiA1MnB4OyB9Ci5kb3QgeyBtaW4taGVpZ2h0OiA0MHB4OyB9CiNpbnN0YWxsLWhpbnQgewogIHBvc2l0aW9uOiBmaXhlZDsgbGVmdDogMTJweDsgcmlnaHQ6IDEycHg7IGJvdHRvbTogY2FsYygxMnB4ICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTsgei1pbmRleDogMzA7CiAgZGlzcGxheTogZmxleDsgYWxpZ24taXRlbXM6IGNlbnRlcjsgZ2FwOiAxMHB4OyBwYWRkaW5nOiAxMnB4IDE0cHg7IGJvcmRlci1yYWRpdXM6IDE0cHg7CiAgYmFja2dyb3VuZDogIzFiMjMzMzsgY29sb3I6ICNmZmY7IGJveC1zaGFkb3c6IDAgNnB4IDI0cHggcmdiYSgwLDAsMCwuMjUpOyBmb250LXNpemU6IC45MnJlbTsKfQojaW5zdGFsbC1oaW50W2hpZGRlbl0geyBkaXNwbGF5OiBub25lOyB9CiNpbnN0YWxsLWhpbnQgLmloLXRleHQgeyBmbGV4OiAxOyB9CiNpbnN0YWxsLWhpbnQgYnV0dG9uIHsgYmFja2dyb3VuZDogdHJhbnNwYXJlbnQ7IGNvbG9yOiAjZmZmOyBib3JkZXItY29sb3I6ICM1NTYwN2E7IH0KI2luc3RhbGwtaGludCAucHJpbWFyeS1idG4geyBiYWNrZ3JvdW5kOiB2YXIoLS1wcmltYXJ5KTsgYm9yZGVyLWNvbG9yOiB2YXIoLS1wcmltYXJ5KTsgfQouaWgtaWNvIHsgZGlzcGxheTogaW5saW5lLWJsb2NrOyBwYWRkaW5nOiAwIDVweDsgYm9yZGVyOiAxcHggc29saWQgIzhhOTVhZDsgYm9yZGVyLXJhZGl1czogNXB4OyB9Cg==","/sw.js":"Ly8gU2VydmljZSB3b3JrZXI6IGZhcWF0IHNhaGlmYSAicW9iaWcnaW5pIiBrZXNobGF5ZGkuIC9hcGkvIHNvJ3JvdmxhcmkgSEVDSCBRQUNIT04ga2VzaGxhbm1heWRpLAovLyBzaHVuaW5nIHVjaHVuIHRheW1lciwgamF2b2JsYXIgdmEgbmF0aWphbGFyIGRvaW0gc2VydmVyZGFuIGtlbGFkaS4KY29uc3QgQ0FDSEUgPSAndGVzdC1zaGVsbC12MSc7CmNvbnN0IFNIRUxMID0gWycvJywgJy9zdHlsZS5jc3MnLCAnL2NvbW1vbi5qcycsICcvYXBwLmpzJywgJy9tYW5pZmVzdC53ZWJtYW5pZmVzdCcsICcvaWNvbi0xOTIucG5nJ107CgpzZWxmLmFkZEV2ZW50TGlzdGVuZXIoJ2luc3RhbGwnLCAoZSkgPT4gewogIGUud2FpdFVudGlsKGNhY2hlcy5vcGVuKENBQ0hFKS50aGVuKChjKSA9PiBjLmFkZEFsbChTSEVMTCkpLnRoZW4oKCkgPT4gc2VsZi5za2lwV2FpdGluZygpKSk7Cn0pOwpzZWxmLmFkZEV2ZW50TGlzdGVuZXIoJ2FjdGl2YXRlJywgKGUpID0+IHsKICBlLndhaXRVbnRpbCgKICAgIGNhY2hlcy5rZXlzKCkudGhlbigoa3MpID0+IFByb21pc2UuYWxsKGtzLmZpbHRlcigoaykgPT4gayAhPT0gQ0FDSEUpLm1hcCgoaykgPT4gY2FjaGVzLmRlbGV0ZShrKSkpKQogICAgICAudGhlbigoKSA9PiBzZWxmLmNsaWVudHMuY2xhaW0oKSkKICApOwp9KTsKc2VsZi5hZGRFdmVudExpc3RlbmVyKCdmZXRjaCcsIChlKSA9PiB7CiAgY29uc3QgcmVxID0gZS5yZXF1ZXN0OwogIGNvbnN0IHVybCA9IG5ldyBVUkwocmVxLnVybCk7CiAgaWYgKHJlcS5tZXRob2QgIT09ICdHRVQnIHx8IHVybC5vcmlnaW4gIT09IGxvY2F0aW9uLm9yaWdpbiB8fCB1cmwucGF0aG5hbWUuc3RhcnRzV2l0aCgnL2FwaS8nKSkgcmV0dXJuOwogIC8vIEF2dmFsIHRhcm1vcSAoeWFuZ2lsYW5pc2hsYXIgZGFyaG9sIGtlbHNpbiksIHRhcm1vcSBibydsbWFzYSBrZXNoCiAgZS5yZXNwb25kV2l0aCgKICAgIGZldGNoKHJlcSkudGhlbigocmVzKSA9PiB7CiAgICAgIGlmIChyZXMub2spIHsgY29uc3QgY29weSA9IHJlcy5jbG9uZSgpOyBjYWNoZXMub3BlbihDQUNIRSkudGhlbigoYykgPT4gYy5wdXQocmVxLCBjb3B5KSk7IH0KICAgICAgcmV0dXJuIHJlczsKICAgIH0pLmNhdGNoKCgpID0+IGNhY2hlcy5tYXRjaChyZXEpLnRoZW4oKHIpID0+IHIgfHwgY2FjaGVzLm1hdGNoKCcvJykpKQogICk7Cn0pOwo="};

function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (rel === '/') rel = '/index.html';
  if (rel === '/admin') rel = '/admin.html';
  if (EMBED) {
    const b64 = Object.prototype.hasOwnProperty.call(EMBED, rel) ? EMBED[rel] : null;
    if (b64 === null) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Topilmadi'); }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(rel)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    return res.end(Buffer.from(b64, 'base64'));
  }
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Topilmadi'); }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });
}

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:");
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) await api(req, res, url);
    else serveStatic(req, res, url);
  } catch (e) {
    if (res.headersSent) return;
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Server xatosi' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server ishga tushdi: http://localhost:${PORT}`);
  console.log(`Admin paneli:        http://localhost:${PORT}/admin`);
  if (!process.env.ADMIN_PASSWORD) {
    console.warn("\n⚠  ADMIN_PASSWORD berilmagan, vaqtinchalik parol 'admin123' ishlatilmoqda!");
    console.warn('   Haqiqiy foydalanishdan oldin:  ADMIN_PASSWORD="o\'z-parolingiz" node server.js\n');
  }
});
