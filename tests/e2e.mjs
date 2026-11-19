// End-to-end test: enrol, pin, ask, decide, verify, consume, replay, tamper, and a service that lies to the page.
// Drives headless Chrome with a CDP virtual authenticator that supports PRF and user verification.
//
//   HITL_URL=https://decide.example.com \
//   ADMIN="docker exec hitl python /app/server/bin/admin.py" \
//   CALLER="docker exec -e HITL_STATE=/tmp/e2e -e HITL_URL=https://decide.example.com hitl python /app/caller/hitl.py" \
//   CHROME=/usr/bin/google-chrome node tests/e2e.mjs
//
// Needs puppeteer-core (npm i puppeteer-core) and a browser that trusts the deployment's TLS certificate.
import { execSync } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import puppeteer from 'puppeteer-core';

// The test's own requests to the service, one connection each: a kept-alive socket the server has
// already closed must not decide a check.
const request = (url, init = {}) => new Promise((resolve, reject) => {
  const u = new URL(url);
  const req = (u.protocol === 'https:' ? httpsRequest : httpRequest)(u, { method: init.method || 'GET', headers: init.headers || {}, agent: false }, (res) => {
    const chunks = [];
    res.on('data', c => chunks.push(c));
    res.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      resolve({ status: res.statusCode, text: async () => text, json: async () => JSON.parse(text) });
    });
  });
  req.on('error', reject);
  req.end(init.body);
});

const { HITL_URL, ADMIN, CALLER, CHROME = '/usr/bin/google-chrome' } = process.env;
// How to put a local file where the CALLER command can read it (default: into the hitl container).
const COPY = process.env.COPY || 'docker cp';
const COPY_TARGET = process.env.COPY_TARGET ?? 'hitl:';
// Flips one byte of every blob a request claimed, directly in the service's storage (a hostile server).
const DB_PY = process.env.DB_PY || "docker exec hitl python -c";
const BLOB_TAMPER = process.env.BLOB_TAMPER || `${DB_PY} 'import sqlite3,sys; d="/var/hitl-data"; c=sqlite3.connect(d+"/hitl.sqlite")
for (i,) in c.execute("SELECT id FROM blobs WHERE request_id = ?", (sys.argv[1],)):
    p=d+"/blobs/"+i; b=bytearray(open(p,"rb").read()); b[100]^=1; open(p,"wb").write(b)'`;
// Adds a credential behind the recipient's back, directly in the service's storage (a hostile server).
const INJECT = process.env.INJECT || `${DB_PY} 'import sqlite3,sys; c=sqlite3.connect("/var/hitl-data/hitl.sqlite"); c.execute("INSERT INTO credentials (id, recipient_id, spki, alg, prf_salt, wrapped_key, wrap_nonce, label, enrolled_via, created_at) SELECT ?, recipient_id, spki, alg, prf_salt, wrapped_key, wrap_nonce, ?, ?, created_at FROM credentials WHERE recipient_id = ? LIMIT 1", (sys.argv[1], "injected", "none", sys.argv[2])); c.commit()'`;
if (!HITL_URL || !ADMIN || !CALLER) throw new Error('set HITL_URL, ADMIN and CALLER');

const run = (cmd) => execSync(cmd, { encoding: 'utf8' }).trim();
const caller = (args) => {
  try {
    return JSON.parse(run(`${CALLER} ${args}`));
  } catch (e) {
    if (e.stdout) return JSON.parse(e.stdout.trim());
    throw e;
  }
};
let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`);
  if (!ok) failures++;
};

const suffix = Date.now().toString(36);
const callerId = `e2e-caller-${suffix}`;
const recipientId = `e2e-recipient-${suffix}`;

// Caller key and registration.
const kg = caller(`keygen ${callerId}`);
check('caller keygen', kg.status === 'ok');
run(`${ADMIN} add-caller ${callerId} "E2E Caller" e2e.example ${kg.pubkey}`);

const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
const page = await browser.newPage();
page.on('console', m => { if (m.type() === 'error') console.log('  browser:', m.text()); });
// A lying service, as the page sees it: while `lie` is set, every GET of the API is fetched from the
// real service here and handed to it; what it returns is what the page receives. The client files
// themselves are untouched, which is the case tools/verify_deployment.py cannot see (R10).
let lie = null;
await page.setRequestInterception(true);
page.on('request', async (r) => {
  if (!lie || r.method() !== 'GET' || !r.url().includes('/api/v1/')) return r.continue();
  try {
    const res = await request(r.url());
    const data = await res.json();
    const told = lie(new URL(r.url()).pathname, data) ?? data;
    await r.respond({ status: res.status, contentType: 'application/json', body: JSON.stringify(told) });
  } catch (e) {
    await r.continue().catch(() => {});
  }
});
const lying = async (fn, during) => { lie = fn; try { return await during(); } finally { lie = null; } };
const cdp = await page.createCDPSession();
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
  protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
  hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true,
  automaticPresenceSimulation: true,
}});

try {
  // Enrolment.
  const enrolUrl = run(`${ADMIN} enrol-link ${recipientId} "E2E Recipient"`);
  await page.goto(enrolUrl, { waitUntil: 'networkidle0' });
  // Sessions off for the earlier checks (each unlocks explicitly); the session section turns them on.
  await page.evaluate(() => localStorage.setItem('hitl.sessionHours', '0'));
  await page.type('#label', 'virtual');
  await page.click('#enrol');
  // The device shows the list its key statement will hold before it signs it.
  await page.waitForSelector('#confirm-devices, #error', { timeout: 20000 });
  const listed = await page.$$eval('#devices li', ls => ls.map(l => l.textContent));
  check('the device list is shown before it is signed', listed.length === 1 && listed[0].startsWith('virtual'), listed.join(' | '));
  await page.click('#confirm-devices');
  await page.waitForSelector('#fingerprint, #error', { timeout: 20000 });
  const err = await page.$eval('#error', e => e.textContent).catch(() => null);
  check('enrolment', !err, err || '');
  const pageFp = await page.$eval('#fingerprint', e => e.textContent).catch(() => '');

  // Pinning: the caller replays the statement chain and computes the fingerprint itself; it pins
  // only if that equals what the recipient's device showed. There is no way to skip the comparison.
  const wrongPin = caller(`pin ${recipientId} --fingerprint "0000 0000 0000 0000 0000 0000 0000 0000"`);
  check('pin refuses a fingerprint the device did not show', wrongPin.status === 'rejected' && wrongPin.reason === 'fingerprint_mismatch', wrongPin.reason || wrongPin.status);
  const pin = caller(`pin ${recipientId} --fingerprint "${pageFp}"`);
  check('pin fingerprint matches enrolment page', pin.status === 'pinned' && pin.fingerprint === pageFp, `${pin.fingerprint || pin.reason} / ${pageFp}`);

  // Unpinned recipient is refused before anything is sent.
  const unpinned = caller(`ask nobody-${suffix} --text x`);
  check('ask refuses unpinned recipient', unpinned.status === 'error');

  // Request.
  const ask = caller(`ask ${recipientId} --title "Send the weekly report?" --text "Recipients: the whole team." --choices "A:Send,B:Edit first,cancel:Cancel" --comment 200 --ttl 3600 --ref task:42`);
  check('ask', ask.status === 'created', ask.link);
  check('check before answer is pending', caller(`check ${ask.request_id}`).status === 'pending');

  // Decision.
  await page.goto(ask.link, { waitUntil: 'networkidle0' });
  const chip = await page.$eval('#caller', e => e.textContent);
  check('requester named above the content', chip.includes('Asked by') && chip.includes('E2E Caller'));

  // A service that lies about the request. Each lie changes one thing in what the service presents;
  // the page compares it with the facts sealed in the manifest and must refuse, showing nothing to answer.
  const short = ask.link.split('/').pop();
  const refusedWhen = async (name, change) => {
    const out = await lying((path, data) => { if (path.endsWith('/requests/' + short)) change(data); return data; }, async () => {
      await page.goto(ask.link, { waitUntil: 'networkidle0' });
      await page.click('#unlock');
      await page.waitForSelector('button[data-choice="A"], #error', { timeout: 20000 });
      return { error: await page.$eval('#error', e => e.textContent).catch(() => ''), buttons: (await page.$$('button[data-choice]')).length };
    });
    check(`page refuses a request whose ${name} the service changed`, /does not match what its sender sealed/.test(out.error) && out.buttons === 0,
      out.error || `${out.buttons} answer buttons shown`);
  };
  await refusedWhen('policy', d => { d.creation_body.policy = { assurance: 'session', review: false }; });
  await refusedWhen('reference', d => { d.creation_body.caller_ref = 'task:999'; });
  await refusedWhen('answer key', d => { d.creation_body.answer_pubkey = d.recipient.enc_pubkey; });
  await refusedWhen('deadline', d => { d.creation_body.ttl = 999999; });
  await refusedWhen('creation time', d => { d.creation_body.created_at = '2099-01-01T00:00:00Z'; });
  await refusedWhen('caller', d => { d.caller.id = 'someone-else'; d.creation_body.caller_id = 'someone-else'; });
  await refusedWhen('request id', d => { d.request_id = '00000000-0000-4000-8000-000000000000'; });
  await refusedWhen('ciphertext hash', d => { d.creation_body.payload_ct_hash = d.creation_body.config_ct_hash; });
  await refusedWhen('creation body shape', d => { d.creation_body.nonce = 'x'; });

  // A sealed box does not say who sealed it and every request fact is public, so a service can seal
  // a manifest of its own, with the same facts and its own answer key, and present it in front of the
  // caller's attachments. Manifest and payload name each other, so the page refuses the pairing.
  const own = await page.evaluate(async (short) => {
    await sodium.ready;
    const req = await api('GET', '/api/v1/requests/' + short);
    const b = req.creation_body;
    const answerKey = b64u(sodium.crypto_box_keypair().publicKey);
    const manifest = { version: 3, salt: b64u(randomBytes(32)), payload_hash: b64u(randomBytes(32)), title: 'Type what you see',
      blocks: [], answers: { choices: [{ value: 'A', label: 'Send' }] },
      request: { request_id: b.request_id, caller_id: b.caller_id, caller_ref: b.caller_ref, policy: b.policy, answer_pubkey: answerKey, created_at: b.created_at, ttl: b.ttl } };
    const ct = sodium.crypto_box_seal(enc.encode(JSON.stringify(manifest)), unb64u(req.recipient.enc_pubkey));
    return { config_ct: b64u(ct), hash: b64u(await sha256(ct)), answerKey };
  }, short);
  await refusedWhen('manifest (for one of its own making, in front of the genuine payload)', d => {
    d.config_ct = own.config_ct; d.creation_body.config_ct_hash = own.hash; d.creation_body.answer_pubkey = own.answerKey;
  });

  // The encryption public key the service names is not used: the page derives it from the key it unwrapped.
  await lying((path, data) => { if (path.endsWith('/requests/' + short)) data.recipient.enc_pubkey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; return data; }, async () => {
    await page.goto(ask.link, { waitUntil: 'networkidle0' });
    await page.click('#unlock');
    await page.waitForSelector('button[data-choice="A"], #error', { timeout: 20000 });
  });
  check('a wrong encryption key named by the service changes nothing', (await page.$eval('#title', e => e.textContent).catch(() => '')) === 'Send the weekly report?');

  await page.goto(ask.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  await page.waitForSelector('button[data-choice="A"], #error', { timeout: 20000 });
  const title = await page.$eval('#title', e => e.textContent).catch(() => '');
  check('payload decrypted in the browser', title === 'Send the weekly report?', title);
  const shownRef = await page.$eval('#caller-ref', e => e.textContent).catch(() => '');
  check('the caller reference is shown from the sealed manifest', shownRef.includes('task:42'), shownRef);
  const senderDetails = await page.$eval('.technical-content', e => e.textContent).catch(() => '');
  check('registered sender identity is available in details', senderDetails.includes(callerId) && senderDetails.includes('e2e.example'));
  const shownFp = await page.$eval('#key-fingerprint', e => e.textContent).catch(() => '');
  check('an unlocked page shows the fingerprint, computed from the chain the device verified', shownFp.includes(pageFp), shownFp);
  await page.type('#comment', 'Looks fine.');
  await page.click('button[data-choice="A"]');
  await page.waitForSelector('#done, #error', { timeout: 20000 });
  check('signed answer shows a decision receipt with Close',
    !!(await page.$('.receipt-page #done')) && !!(await page.$('.receipt-choice')) && !!(await page.$('#close')));
  const signErr = await page.$eval('#error', e => e.textContent).catch(() => null);
  check('answer signed', !signErr, signErr || '');

  // Verification and single use.
  const consumed = caller(`consume ${ask.request_id}`);
  check('consume returns verified answer', consumed.status === 'answered' && consumed.answer.choice === 'A'
    && consumed.answer.comment === 'Looks fine.', JSON.stringify(consumed.answer));
  check('caller reference echoed in the signed answer', consumed.caller_ref === 'task:42' && consumed.answer_label === 'Send'
    && consumed.proof_token.startsWith('hitl-proof-v2.'), `${consumed.caller_ref} / ${consumed.answer_label}`);
  const replay = caller(`consume ${ask.request_id}`);
  check('second consume is a replay', replay.status === 'rejected' && replay.reason === 'replay');

  // Tampering: a different answer for the same request is refused by the service.
  const remote = await (await request(`${HITL_URL}/api/v1/requests/${ask.request_id}`)).json();
  check('the service holds no answer in clear', !('answer' in remote.response.record) && !JSON.stringify(remote).includes('Looks fine.')
    && typeof remote.response.record.answer_ct === 'string', Object.keys(remote.response.record).join(','));
  const forged = { ...remote.response.record, config_hash: remote.response.record.payload_hash };
  const res = await request(`${HITL_URL}/api/v1/requests/${ask.request_id}/response`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ record: forged, assertion: remote.response.assertion }),
  });
  check('service refuses a changed answer', res.status === 409, `HTTP ${res.status}`);
  const dup = await request(`${HITL_URL}/api/v1/requests/${ask.request_id}/response`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ record: remote.response.record, assertion: remote.response.assertion }),
  });
  check('same response again has one effect', dup.status === 200 && (await dup.json()).duplicate === true);

  // A signature over one request does not authorise another.
  const ask2 = caller(`ask ${recipientId} --text "Second request" --ttl 3600`);
  const moved = { ...remote.response.record, request_id: ask2.request_id };
  const res2 = await request(`${HITL_URL}/api/v1/requests/${ask2.request_id}/response`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ record: moved, assertion: remote.response.assertion }),
  });
  check('signature cannot be moved to another request', res2.status >= 400, `HTTP ${res2.status}`);

  // The reference is bound through the creation hash: a record for one creation body answers no other.
  const ask3 = caller(`ask ${recipientId} --text "Third request" --ttl 3600 --ref task:43`);
  const body3 = (await (await request(`${HITL_URL}/api/v1/requests/${ask3.request_id}`)).json()).creation_body;
  check('the reference is inside the signed creation body', body3.caller_ref === 'task:43' && body3.request_id === ask3.request_id);

  // Content blocks and forms: an image, a PDF and form fields, answered and verified.
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
  const tinyPdf = (text) => {
    const content = `BT /F1 18 Tf 20 70 Td (${text}) Tj ET`;
    const objs = ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
      `<< /Length ${content.length} >>\nstream\n${content}\nendstream`, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'];
    let out = '%PDF-1.4\n';
    const offsets = [];
    objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('');
    out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(out, 'latin1');
  };
  const { writeFileSync } = await import('node:fs');
  const put = (name, data) => { writeFileSync(`/tmp/${name}`, data); run(`${COPY} /tmp/${name} ${COPY_TARGET}/tmp/${name}`); };
  put(`e2e-label-${suffix}.png`, png);
  put(`e2e-spec-${suffix}.pdf`, tinyPdf('Label spec v2'));
  put(`e2e-manifest-${suffix}.json`, JSON.stringify({
    title: 'Approve the new label?',
    blocks: [{ type: 'text', text: 'Check the image and the spec.' },
      { type: 'html', html: '<style>.brand{color:rgb(200,30,30);font-family:Georgia,serif} body{background:url(https://example.com/bg.png)}</style>'
        + '<h2 class="brand" style="font-size:31px">Styled proposal</h2><p>' + 'Line of text. '.repeat(120) + '</p><img src="https://example.com/pixel.png" alt="">' },
      { type: 'image', ref: 'img', caption: 'Front label' },
      { type: 'pdf', ref: 'doc', name: 'spec.pdf' }],
    answers: {
      choices: [{ value: 'approve', label: 'Approve' }, { value: 'cancel', label: 'Cancel' }],
      fields: [
        { name: 'qty', label: 'Print run (thousands)', type: 'number', min: 1, max: 10, required: true },
        { name: 'colour', label: 'Foil colour', type: 'select', required: true, options: [{ value: 'gold', label: 'Gold' }, { value: 'silver', label: 'Silver' }] },
        { name: 'notes', label: 'Notes', type: 'textarea' },
        { name: 'checked', label: 'I checked the text', type: 'checkbox', required: true },
      ],
    },
  }));
  const remoteHits = [];
  // CSP blocks the load before it leaves the browser; puppeteer still reports the attempt, so count responses.
  page.on('response', r => { if (r.url().includes('example.com')) remoteHits.push(r.url()); });
  const askBlocks = caller(`ask ${recipientId} --manifest /tmp/e2e-manifest-${suffix}.json --attach img=/tmp/e2e-label-${suffix}.png --attach doc=/tmp/e2e-spec-${suffix}.pdf --ref task:77 --ttl 3600`);
  check('ask with blocks and attachments', askBlocks.status === 'created', askBlocks.reason || '');
  await page.goto(askBlocks.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  await page.waitForSelector('button[data-choice="approve"], #error', { timeout: 20000 });
  await page.waitForFunction(() => {
    const f = document.querySelector('iframe.fragment');
    return f && f.contentDocument && f.contentDocument.querySelector('h2.brand') && f.getBoundingClientRect().height > 300;
  }, { timeout: 10000 }).catch(() => {});
  const styled = await page.evaluate(() => {
    const f = document.querySelector('iframe.fragment');
    const h = f && f.contentDocument && f.contentDocument.querySelector('h2.brand');
    if (!h) return null;
    const cs = f.contentWindow.getComputedStyle(h);
    return { color: cs.color, size: cs.fontSize, height: f.getBoundingClientRect().height };
  });
  check('HTML block keeps its CSS', styled && styled.color === 'rgb(200, 30, 30)' && styled.size === '31px', JSON.stringify(styled));
  check('content frame grows to fit its document', styled && styled.height > 300, `height ${styled && Math.round(styled.height)}`);
  check('remote images in a design are never loaded', !remoteHits.length, remoteHits.join(', '));
  const imgOk = await page.waitForFunction(() => { const i = document.querySelector('img.image'); return i && i.complete && i.naturalWidth > 0; }, { timeout: 10000 }).then(() => true, () => false);
  check('image block rendered', imgOk);
  const pdfPages = await page.waitForSelector('.pdf[data-pages]', { timeout: 30000 }).then(h => h.evaluate(e => e.dataset.pages), () => null);
  const pdfCanvas = await page.$eval('.pdf canvas', c => c.width > 0 && c.height > 0).catch(() => false);
  check('pdf block rendered with pdf.js', pdfPages === '1' && pdfCanvas, `pages ${pdfPages}`);
  await page.click('button[data-choice="approve"]');
  const required = await page.waitForSelector('#error', { timeout: 5000 }).then(h => h.evaluate(e => e.textContent), () => '');
  check('required field blocks submission', required.includes('Please fill in'), required);
  await page.evaluate(() => document.getElementById('error')?.remove());
  await page.type('#field-qty', '3');
  await page.select('#field-colour', 'silver');
  await page.click('#field-checked');
  await page.click('button[data-choice="approve"]');
  await page.waitForSelector('#done, #error', { timeout: 20000 });
  const formErr = await page.$eval('#error', e => e.textContent).catch(() => null);
  check('form answer signed', !formErr, formErr || '');
  const formAnswer = caller(`consume ${askBlocks.request_id}`);
  const fa = formAnswer.answer || {};
  check('caller verifies the form answer', formAnswer.status === 'answered' && fa.choice === 'approve'
    && fa.fields && fa.fields.qty === 3 && fa.fields.colour === 'silver' && fa.fields.checked === true && !('notes' in fa.fields),
    JSON.stringify(fa));

  // A designed page (layout full): a photo picker built by the caller, answered inside the design.
  for (const n of [1, 2, 3]) put(`e2e-photo${n}-${suffix}.png`, png);
  put(`e2e-design-${suffix}.json`, JSON.stringify({
    title: 'Pick the hero photo', layout: 'full',
    blocks: [{ type: 'html', html: '<style>.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;padding:16px}'
      + 'label img{width:100%;height:80px;display:block;border:4px solid #fff;image-rendering:pixelated}input[type=radio]{display:none}'
      + 'input:checked+img{border-color:#e33}.btn{margin:0 16px;padding:10px;border:1px solid #000;display:inline-block}.hitl-selected{background:#000;color:#fff}</style>'
      + '<h1 style="padding:0 16px">Pick the hero photo</h1><div class="grid">'
      + [1, 2, 3].map(n => `<label id="ph${n}"><input type="radio" name="p" value="p${n}" data-hitl-field="photo"><img src="hitl:img${n}" alt="${n}"></label>`).join('')
      + '</div><span class="btn" id="use" data-hitl-choice="approve">Use this photo</span><span class="btn" data-hitl-choice="cancel">None of these</span>' }],
    answers: {
      choices: [{ value: 'approve', label: 'Use this photo' }, { value: 'cancel', label: 'None of these' }],
      fields: [{ name: 'photo', label: 'Photo', type: 'select', required: true, options: [1, 2, 3].map(n => ({ value: `p${n}`, label: `Photo ${n}` })) },
        { name: 'notes', label: 'Notes', type: 'text' }],
    },
  }));
  const askDesign = caller(`ask ${recipientId} --manifest /tmp/e2e-design-${suffix}.json ${[1, 2, 3].map(n => `--attach img${n}=/tmp/e2e-photo${n}-${suffix}.png`).join(' ')} --ref task:80 --ttl 3600`);
  check('ask with a designed page', askDesign.status === 'created', askDesign.reason || '');
  await page.goto(askDesign.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  await page.waitForSelector('#confirm', { timeout: 20000 });
  const designFrame = await (await page.$('iframe.fragment')).contentFrame();
  const photosOk = await designFrame.waitForFunction(() => [...document.images].length === 3 && [...document.images].every(i => i.complete && i.naturalWidth > 0 && i.src.startsWith('blob:')), { timeout: 15000 })
    .then(() => true, () => false);
  check('design shows attachments through hitl: references', photosOk);
  const disabledBefore = await page.$eval('#confirm', b => b.disabled);
  await designFrame.click('#ph2');
  await designFrame.click('#use');
  await page.waitForFunction(() => !document.querySelector('#confirm').disabled, { timeout: 5000 }).catch(() => {});
  const actions = await page.$$eval('.confirmbar .confirm-actions button', buttons =>
    buttons.map(button => ({ id: button.id, text: button.textContent.trim(), icon: !!button.querySelector('.action-icon') })));
  const unboundOffered = !!(await page.$('#field-notes'));
  check('confirm bar has two labelled actions without a duplicate answer summary',
    disabledBefore && actions.length === 2 && actions[0].id === 'cancel' && actions[0].icon
      && actions[1].id === 'confirm' && actions[1].icon && /Use this photo/.test(actions[1].text)
      && !(await page.$('#summary')) && !(await page.$('.confirmbar .fallback-choices')),
    JSON.stringify(actions));
  check('fields the design leaves out are offered by the service', unboundOffered);
  await page.click('#confirm');
  await page.waitForSelector('#done, #error', { timeout: 20000 });
  const designAnswer = caller(`consume ${askDesign.request_id}`);
  check('answer given inside the design verifies', designAnswer.status === 'answered' && designAnswer.answer.choice === 'approve'
    && designAnswer.answer.fields && designAnswer.answer.fields.photo === 'p2' && !('notes' in designAnswer.answer.fields), JSON.stringify(designAnswer.answer || designAnswer.reason));

  // Large media as blobs: a 3 MB WAV is above the inline threshold, so the caller encrypts it in
  // chunks and uploads it separately; the page downloads, checks and decrypts it for the player.
  const wav = (seconds) => {
    const rate = 8000, n = rate * seconds, buf = Buffer.alloc(44 + n * 2);
    buf.write('RIFF', 0); buf.writeUInt32LE(36 + n * 2, 4); buf.write('WAVE', 8); buf.write('fmt ', 12);
    buf.writeUInt32LE(16, 16); buf.writeUInt16LE(1, 20); buf.writeUInt16LE(1, 22); buf.writeUInt32LE(rate, 24);
    buf.writeUInt32LE(rate * 2, 28); buf.writeUInt16LE(2, 32); buf.writeUInt16LE(16, 34); buf.write('data', 36); buf.writeUInt32LE(n * 2, 40);
    for (let i = 0; i < n; i++) buf.writeInt16LE(Math.round(8000 * Math.sin(2 * Math.PI * 440 * i / rate)), 44 + i * 2);
    return buf;
  };
  put(`e2e-voice-${suffix}.wav`, wav(190));
  put(`e2e-media-${suffix}.json`, JSON.stringify({
    title: 'Listen to the voice-over', blocks: [{ type: 'audio', ref: 'voice', caption: 'Radio spot, 3 minutes' }],
    answers: { choices: [{ value: 'ok', label: 'Sounds good' }, { value: 'redo', label: 'Record again' }] },
  }));
  const askMedia = caller(`ask ${recipientId} --manifest /tmp/e2e-media-${suffix}.json --attach voice=/tmp/e2e-voice-${suffix}.wav --ref task:78 --ttl 3600`);
  check('ask with a large audio blob', askMedia.status === 'created', askMedia.reason || '');
  const blobFetches = [];
  page.on('response', r => { if (r.url().includes('/api/v1/blobs/')) blobFetches.push(r.status()); });
  await page.goto(askMedia.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  const audioOk = await page.waitForFunction(() => { const a = document.querySelector('audio'); return a && a.readyState >= 1 && a.duration > 100; }, { timeout: 60000 })
    .then(() => true, () => false);
  const audioErr = await page.$eval('.attachment .error, #error', e => e.textContent).catch(() => '');
  check('audio blob downloaded, verified, decrypted and playable', audioOk && blobFetches.includes(200), audioErr || `fetches ${blobFetches.join(',')}`);
  await page.click('button[data-choice="ok"]');
  await page.waitForSelector('#done, #error', { timeout: 20000 });
  const mediaAnswer = caller(`consume ${askMedia.request_id}`);
  check('answer on a blob request verifies', mediaAnswer.status === 'answered' && mediaAnswer.answer.choice === 'ok', mediaAnswer.reason || '');

  // A blob swapped on the server is refused by the page (its hash is inside the signed payload).
  const askSwap = caller(`ask ${recipientId} --manifest /tmp/e2e-media-${suffix}.json --attach voice=/tmp/e2e-voice-${suffix}.wav --ref task:79 --ttl 3600`);
  run(`${BLOB_TAMPER} ${askSwap.request_id}`);
  await page.goto(askSwap.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  const swapped = await page.waitForSelector('.attachment .error', { timeout: 60000 }).then(h => h.evaluate(e => e.textContent), () => '');
  check('page refuses a blob swapped on the server', swapped.includes('does not match'), swapped);

  // Review of an answered request: allowed per request by the caller's policy, read-only.
  const attachDesign = [1, 2, 3].map(n => `--attach img${n}=/tmp/e2e-photo${n}-${suffix}.png`).join(' ');
  const noReview = caller(`ask ${recipientId} --text "Review is off" --choices "A:Send,cancel:Cancel" --comment 200 --ref task:85 --ttl 3600`);
  const withReview = caller(`ask ${recipientId} --manifest /tmp/e2e-design-${suffix}.json ${attachDesign} --ref task:86 --ttl 3600 --review`);
  check('ask with review allowed', withReview.status === 'created', withReview.reason || '');
  await page.goto(noReview.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  await page.waitForSelector('button[data-choice="A"]', { timeout: 20000 });
  const dictateButtons = (await page.$$('.dictate')).length;
  check('decision form has no Dictate button', dictateButtons === 0,
    `buttons ${dictateButtons}`);
  await page.click('button[data-choice="A"]');
  await page.waitForSelector('#done, #error', { timeout: 20000 });
  await page.goto(withReview.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  await page.waitForSelector('#confirm', { timeout: 20000 });
  const reviewFrame = await (await page.$('iframe.fragment')).contentFrame();
  await reviewFrame.click('#ph3');
  await reviewFrame.click('#use');
  await page.waitForFunction(() => !document.querySelector('#confirm').disabled, { timeout: 5000 }).catch(() => {});
  await page.click('#confirm');
  await page.waitForSelector('#done, #error', { timeout: 20000 });
  await page.goto(noReview.link, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#done', { timeout: 20000 });
  check('an answered link without review only says it was answered', !(await page.$('#show-answer')) && !(await page.$('#review')));
  check('answered link uses the receipt layout and offers Close',
    !!(await page.$('.receipt-page #done')) && !!(await page.$('#close')));
  await page.goto(withReview.link, { waitUntil: 'networkidle0' });
  const offered = await page.waitForSelector('#show-answer', { timeout: 20000 }).then(() => true, () => false);
  check('an answered link with review offers to show the answer', offered);
  if (offered) {
    await page.click('#show-answer');
    await page.waitForSelector('#review, #error', { timeout: 20000 });
    const shown = await page.$eval('#review', e => e.textContent).catch(() => '');
    check('review shows the signed answer', /Use this photo/.test(shown) && /Photo 3/.test(shown), shown);
    const frame = await (await page.$('iframe.fragment')).contentFrame();
    const marked = await frame.waitForFunction(() => {
      const r = document.querySelector('#ph3 input');
      return r && r.checked && r.disabled && document.querySelector('#use').classList.contains('hitl-selected');
    }, { timeout: 10000 }).then(() => true, () => false);
    check('review marks the answer in the design, read-only', marked);
    check('review offers nothing to sign', !(await page.$('#confirm')));
  }
  const rv = caller(`consume ${withReview.request_id}`);
  check('a reviewed request still verifies once', rv.status === 'answered' && rv.answer.fields.photo === 'p3', JSON.stringify(rv.answer || rv.reason));
  caller(`consume ${noReview.request_id}`);

  // Device sessions and the caller's assurance policy. Device gestures are counted from CDP events.
  let gestures = 0;
  cdp.on('WebAuthn.credentialAsserted', () => { gestures++; });
  await page.evaluate(() => { localStorage.setItem('hitl.sessionHours', '12'); return new Promise(r => { const d = indexedDB.deleteDatabase('hitl'); d.onsuccess = d.onerror = d.onblocked = () => r(); }); });
  const askP = (ref, policy) => caller(`ask ${recipientId} --text "Session test ${ref}" --choices "A:Send,B:Hold,cancel:Cancel" --ref ${ref} --ttl 3600 ${policy}`);
  const answerLink = async (link, expectUnlock) => {
    await page.goto(link, { waitUntil: 'networkidle0' });
    await page.waitForSelector('#unlock, button[data-choice="A"]', { timeout: 20000 });
    const unlockShown = !!(await page.$('#unlock'));
    if (unlockShown) {
      await page.click('#unlock');
      await page.waitForSelector('button[data-choice="A"], #error', { timeout: 20000 });
    }
    await page.click('button[data-choice="A"]');
    await page.waitForSelector('#done, #error', { timeout: 20000 });
    return { unlockShown, error: await page.$eval('#error', e => e.textContent).catch(() => null) };
  };
  const s1 = askP('task:81', '--assurance session --max-session-age 12h');
  const s2 = askP('task:82', '--assurance session --max-session-age 12h');
  const f1 = askP('task:83', '--assurance fresh');
  let g0 = gestures;
  const r1 = await answerLink(s1.link);
  const c1 = caller(`consume ${s1.request_id}`);
  check('session request: one gesture to open, none to answer', r1.unlockShown && gestures - g0 === 1 && c1.status === 'answered' && c1.assurance === 'session',
    `gestures ${gestures - g0}, ${c1.status} ${c1.assurance || c1.reason}`);
  g0 = gestures;
  const r2 = await answerLink(s2.link);
  const c2 = caller(`consume ${s2.request_id}`);
  check('next session request: no gesture at all', !r2.unlockShown && gestures - g0 === 0 && c2.assurance === 'session',
    `gestures ${gestures - g0}, unlock ${r2.unlockShown}, ${c2.assurance || c2.reason}`);
  g0 = gestures;
  const r3 = await answerLink(f1.link);
  const c3 = caller(`consume ${f1.request_id}`);
  check('fresh request: opens from the session, answer needs a gesture', !r3.unlockShown && gestures - g0 === 1 && c3.assurance === 'fresh',
    `gestures ${gestures - g0}, ${c3.assurance || c3.reason}`);
  const f2 = askP('task:84', '--assurance fresh');
  // A correctly bound record for a fresh request, signed with the live session key in the page:
  // the service must refuse it because of the caller's policy, not because anything else is wrong.
  await page.goto(f2.link, { waitUntil: 'networkidle0' });
  await page.waitForSelector('button[data-choice="A"]', { timeout: 20000 });
  const forgedSession = await page.evaluate(async (short) => {
    const req = await api('GET', '/api/v1/requests/' + short);
    const s = await usableSession(req);
    const record = await buildRecord(await openRequest(req, await sessionKey(s, req.recipient.id)), { choice: 'A' });
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, s.signKey, enc.encode(jcs(record))));
    const r = await fetch('/api/v1/requests/' + req.request_id + '/response', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record, session: { delegation: s.delegation, assertion: s.assertion, signature: b64u(sig) } }) });
    return { status: r.status, body: await r.text() };
  }, f2.link.split('/').pop());
  check('service refuses a session answer to a fresh request', forgedSession.status === 403 && /fresh/.test(forgedSession.body),
    `HTTP ${forgedSession.status} ${forgedSession.body.slice(0, 80)}`);
  const m1 = askP('task:85', '--assurance session --max-session-age 60');
  await new Promise(r => setTimeout(r, 62000));
  g0 = gestures;
  const r5 = await answerLink(m1.link);
  const c5 = caller(`consume ${m1.request_id}`);
  check('session older than the caller allows: one new gesture, then session again', r5.unlockShown && gestures - g0 === 1 && c5.assurance === 'session',
    `gestures ${gestures - g0}, ${c5.assurance || c5.reason}`);

  // Queue and inbox: answer one, move to the next, skip one, come back to it, bulk-answer from /inbox.
  // A separate recipient, so earlier unanswered requests do not join this queue.
  const recipient2 = `e2e-queue-${suffix}`;
  await page.goto(run(`${ADMIN} enrol-link ${recipient2} "E2E Queue"`), { waitUntil: 'networkidle0' });
  await page.type('#label', 'virtual');
  await page.click('#enrol');
  await page.waitForSelector('#confirm-devices', { timeout: 20000 });
  await page.click('#confirm-devices');
  await page.waitForSelector('#fingerprint', { timeout: 20000 });
  caller(`pin ${recipient2} --fingerprint "${await page.$eval('#fingerprint', e => e.textContent)}"`);
  const askQ = (ref) => caller(`ask ${recipient2} --text "Queue test ${ref}" --choices "A:Send,B:Hold,cancel:Cancel" --ref ${ref} --ttl 3600 --assurance session --max-session-age 12h`);
  const q1 = askQ('task:91');
  const q2 = askQ('task:92');
  const q3 = askQ('task:93');
  await answerLink(q1.link);
  g0 = gestures;
  const nextText = await page.waitForSelector('#next', { timeout: 10000 }).then(h => h.evaluate(e => e.textContent), () => '');
  check('after an answer the queue offers the next request', /2 left/.test(nextText), nextText);
  await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle0' }), page.click('#next')]);
  await page.waitForSelector('#skip', { timeout: 20000 });
  const firstInQueue = page.url().split('/r/')[1].split('?')[0];
  await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle0' }), page.click('#skip')]);
  await page.waitForSelector('button[data-choice="A"]', { timeout: 20000 });
  const secondInQueue = page.url().split('/r/')[1].split('?')[0];
  check('skip moves to another request', secondInQueue !== firstInQueue, `${firstInQueue} -> ${secondInQueue}`);
  await page.click('button[data-choice="A"]');
  const backText = await page.waitForSelector('#back-to-skipped', { timeout: 10000 }).then(h => h.evaluate(e => e.textContent), () => '');
  check('skipped request comes back at the end', /1 skipped/.test(backText) && /Return to skipped decisions/.test(backText), backText);
  await page.goto(`${HITL_URL}/inbox`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#inbox input[type=checkbox]', { timeout: 20000 });
  const inboxRows = await page.$$eval('#inbox a', as => as.map(a => a.textContent));
  check('inbox lists the pending request with its decrypted title', inboxRows.length >= 1 && inboxRows.some(t => /Queue test task:9[123]/.test(t)), inboxRows.join(' | '));
  const skippedId = [q1, q2, q3].find(q => q.link.endsWith(firstInQueue)).request_id;
  await page.click(`#inbox input[data-request="${skippedId}"]`);
  await page.waitForSelector('#bulk button[data-bulk="A"]', { timeout: 5000 });
  await Promise.all([page.waitForFunction(() => document.querySelector('#empty') || !document.querySelector('#bulk button'), { timeout: 20000 }).catch(() => {}),
    page.click('#bulk button[data-bulk="A"]')]);
  const bulkAnswer = caller(`consume ${skippedId}`);
  check('bulk answer from the inbox, no gesture', bulkAnswer.status === 'answered' && bulkAnswer.assurance === 'session' && gestures - g0 === 0,
    `${bulkAnswer.status} ${bulkAnswer.assurance || bulkAnswer.reason}, gestures ${gestures - g0}`);
  const noSession = await request(`${HITL_URL}/api/v1/inbox`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'hitl.inbox', recipient_id: recipient2, ts: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') }) });
  check('inbox is refused without a session proof', noSession.status >= 400, `HTTP ${noSession.status}`);

  // An expired session key is deleted whenever a page loads.
  await page.evaluate(() => sessionPut('stale-recipient', { delegation: { expires_at: '2020-01-01T00:00:00Z' } }));
  await page.reload({ waitUntil: 'networkidle0' });
  const stale = await page.evaluate(() => sessionGet('stale-recipient').then(v => v === undefined));
  check('an expired session key is deleted when a page loads', stale);

  // Review: the page shows a stored answer only after verifying its signature against the keys
  // this device verified. A service that alters the stored record gets a refusal, not a display.
  const reviewShort = withReview.link.split('/').pop();
  const alteredReview = await lying((path, data) => {
    if (path.endsWith('/requests/' + reviewShort) && data.response) data.response.record.signed_at = '2026-01-01T00:00:00Z';
    return data;
  }, async () => {
    await page.goto(withReview.link, { waitUntil: 'networkidle0' });
    await page.waitForSelector('#review, #error', { timeout: 20000 });
    return { error: await page.$eval('#error', e => e.textContent).catch(() => ''), shown: !!(await page.$('#review')) };
  });
  check('review refuses a stored answer the service altered', /does not verify/.test(alteredReview.error) && !alteredReview.shown, alteredReview.error);

  // Key statements (R9, R10). A service that lies while a device is being added: the existing
  // device replays the chain from its own anchor and signs nothing it cannot account for.
  const addUrl = run(`${ADMIN} enrol-link ${recipientId} "E2E Recipient"`);
  const token = addUrl.split('/').pop();
  const addRefused = async (name, fn, expected) => {
    const out = await lying(fn, async () => {
      await page.goto(addUrl, { waitUntil: 'networkidle0' });
      await page.type('#label', 'second');
      await page.click('#enrol');
      await page.waitForSelector('#confirm-devices, #error', { timeout: 20000 });
      return { error: await page.$eval('#error', e => e.textContent).catch(() => ''), asked: !!(await page.$('#confirm-devices')) };
    });
    check(name, expected.test(out.error) && !out.asked, out.error || 'the page went on to ask for a signature');
  };
  await addRefused('adding a device: a credential the service slipped into the list is never signed', (path, data) => {
    if (path.includes('/enroll/')) data.credentials = [...data.credentials, { ...data.credentials[0], id: 'c2VydmljZS1hZGRlZC1rZXk', label: 'virtual' }];
    return data;
  }, /never signed for/);
  await addRefused('adding a device: a key history the service rewrote is refused', (path, data) => {
    if (path.includes('/statements')) for (const item of data.statements) item.statement.issued_at = '2026-01-01T00:00:00Z';
    return data;
  }, /cannot verify/);
  await addRefused('adding a device: a key history the service withholds is refused', (path, data) => {
    if (path.includes('/statements')) data.statements = [];
    return data;
  }, /cannot verify/);
  await addRefused('adding a device: an encryption key the service swapped is refused', (path, data) => {
    if (path.includes('/enroll/')) data.enc_pubkey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    return data;
  }, /never signed for/);

  // Add a second device the way the enrolment page does: unlock with the first device, verify the
  // chain from its anchor, create a credential, and have the FIRST device sign the new key list.
  // Driven from the page context because one virtual authenticator refuses excludeCredentials.
  await page.goto(addUrl, { waitUntil: 'networkidle0' });
  const addDevice = async (signWithNew) => page.evaluate(async (token, signWithNew) => {
    await sodium.ready;
    const info = await api('GET', '/api/v1/enroll/' + token);
    const used = await prfGet(info.credentials);
    const blob = openBlob(info.credentials, used);
    const verified = await verifiedKeys(info.recipient_id, blob.priv, blob.anchor);
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { id: location.hostname, name: 'hitl' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: info.recipient_id, displayName: 'second' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: { eval: { first: salt } } },
    }});
    const id = b64u(cred.rawId);
    const prf = (await prfGet([{ id, prf_salt: b64u(salt) }])).prf;
    const credentials = [...verified.credentials, { id, spki: b64u(cred.response.getPublicKey()), alg: -7, label: 'second' }]
      .sort((a, b) => (a.id < b.id ? -1 : 1));
    const statement = { type: 'hitl.key-statement', version: 2, recipient_id: info.recipient_id, epoch: verified.epoch,
      seq: verified.seq + 1, prev: verified.head, enc_pubkey: verified.enc_pubkey, credentials, issued_at: rfc3339(new Date()) };
    const hash = await sha256(enc.encode(jcs(statement)));
    const sa = await navigator.credentials.get({ publicKey: { challenge: hash,
      rpId: location.hostname, userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: unb64u(signWithNew ? id : used.id) }] }});
    const nonce = sodium.randombytes_buf(24);
    const r = await fetch('/api/v1/enroll/' + token, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
      credential_id: id, spki: b64u(cred.response.getPublicKey()), alg: -7, prf_salt: b64u(salt),
      wrapped_key: b64u(sealBlob(blob.priv, { epoch: statement.epoch, seq: statement.seq, hash: b64u(hash) }, nonce, prf)),
      wrap_nonce: b64u(nonce), enc_pubkey: verified.enc_pubkey, statement,
      statement_assertion: { credential_id: b64u(sa.rawId), client_data_json: b64u(sa.response.clientDataJSON),
        authenticator_data: b64u(sa.response.authenticatorData), signature: b64u(sa.response.signature) } }) });
    return { status: r.status, id, fingerprint: fingerprintOf(hash) };
  }, token, signWithNew);

  const selfSigned = await addDevice(true);
  check('service refuses a new device that signs its own key statement', selfSigned.status === 403, `HTTP ${selfSigned.status}`);
  const added = await addDevice(false);
  check('second device added with a statement signed by the first', added.status === 200, `HTTP ${added.status}`);
  const refreshed = caller(`refresh ${recipientId}`);
  check('caller follows the signed statement', refreshed.status === 'pinned' && refreshed.devices === 2 && refreshed.seq === 2
    && refreshed.fingerprint === added.fingerprint, `seq ${refreshed.seq}, devices ${refreshed.devices}, ${refreshed.fingerprint} / ${added.fingerprint}`);
  // Either device now opens a request, and each computes the same fingerprint from its own anchor.
  const afterAdd = caller(`ask ${recipientId} --text "After the second device" --ttl 3600`);
  await page.evaluate(() => { localStorage.setItem('hitl.sessionHours', '0'); return new Promise(r => { const d = indexedDB.deleteDatabase('hitl'); d.onsuccess = d.onerror = d.onblocked = () => r(); }); });
  await page.goto(afterAdd.link, { waitUntil: 'networkidle0' });
  await page.click('#unlock');
  await page.waitForSelector('button[data-choice="A"], #error', { timeout: 20000 });
  const fpAfter = await page.$eval('#key-fingerprint', e => e.textContent).catch(() => '');
  check('after the change a device shows the fingerprint of the new statement', fpAfter.includes(added.fingerprint), fpAfter);

  // A key the service lists without a signed statement is refused.
  run(`${INJECT} injected-${suffix} ${recipientId}`);
  const injected = caller(`refresh ${recipientId}`);
  check('caller refuses a key added without a statement', injected.status === 'rejected' && injected.reason === 'keys_changed_without_statement',
    `${injected.status} ${injected.reason || ''}`);
  const askInjected = caller(`ask ${recipientId} --text "after injection" --ttl 3600`);
  check('ask refuses while the key set is unexplained', askInjected.status === 'rejected', askInjected.reason || askInjected.status);
} finally {
  await browser.close();
}

console.log(failures === 0 ? '\nall checks passed' : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
