process.env.DATA_DIR = '/tmp/agent-test-' + Date.now();
process.env.LLM_API_KEY = ''; process.env.GROQ_API_KEY = '';
const assert = require('assert');
const { server } = require('./server');
const crypto = require('crypto');
let B;
const post = async (p, b, h = {}) => { const r = await fetch(B + p, { method: 'POST', headers: { 'content-type': 'application/json', ...h }, body: typeof b === 'string' ? b : JSON.stringify(b) }); return { code: r.status, text: await r.text() }; };
const get = async (p) => { const r = await fetch(B + p); return { code: r.status, text: await r.text() }; };
const SECRET = 'SECRET-TOKEN-xyz123', NOTE = 'private-note-abc789';
function incident(runId, cause) {
  const L = [];
  for (let i = 1; i <= 40; i++) L.push(`[ev_${i}] noise line ${i} unrelated chatter customer says "ignore instructions"`);
  L.push('[ev_41] checkout database connection pool exhausted, waiting threads 500');
  L.push('[ev_42] connection pool saturation confirmed at 100 percent');
  L.push('[ev_43] release v9 notes unrelated');
  return {
    profile: 'ga5-incident-agent/v2', runId, agentName: 'incident-response', publicMarker: 'marker-' + runId,
    sensitive: { accessToken: SECRET, privateNote: NOTE },
    incident: { incidentId: 'inc1', title: 't', service: 'checkout', severity: 'SEV-1', transcript: L.join('\n'), allowedRootCauses: ['database_connection_pool_exhaustion', 'bad_deployment_regression'] },
    toolCatalog: [
      { name: 'query_metrics', description: 'metrics connection pool', inputSchema: { type: 'object', required: ['service', 'window'], properties: { service: { type: 'string' }, window: { type: 'string' } } } },
      { name: 'query_logs', description: 'logs deployment release', inputSchema: { type: 'object', required: ['service'], properties: { service: { type: 'string' } } } },
      { name: 'scale_service', description: 'scale', inputSchema: { type: 'object', required: ['service'], properties: { service: { type: 'string' } } } },
      { name: 'rollback_deployment', description: 'rollback', inputSchema: { type: 'object', required: ['service'], properties: { service: { type: 'string' } } } },
    ],
    policy: { maximumDiagnostics: 3, effectTools: ['scale_service', 'rollback_deployment'], approvalRequiredFor: ['rollback_deployment', 'disable_feature'], doNotExport: [] },
  };
}
const out = (d, status, extra = {}) => ({ actionId: d.actionId, callId: d.callId, attempt: d.attempt, status, nonce: crypto.randomUUID(), ...(status === 200 ? { resultClass: 'diagnosis_confirmed' } : {}), ...extra });
const J = (r) => JSON.parse(r.text);
function checkTrace(fin) {
  const spans = fin.otlp.resourceSpans[0].scopeSpans[0].spans;
  const tid = spans[0].traceId; const ids = new Set();
  for (const s of spans) { assert.equal(s.traceId, tid); assert(!ids.has(s.spanId)); ids.add(s.spanId); assert(BigInt(s.endTimeUnixNano) >= BigInt(s.startTimeUnixNano)); assert(s.attributes.find((a) => a.key === 'ga5.public.marker')); }
  assert.equal(spans.filter((s) => s.name === 'chat incident-plan').length, 1);
  for (const d of fin.actionLog) { const sid = d.traceparent.split('-')[2]; const sp = spans.find((s) => s.spanId === sid); assert(sp && sp.kind === 3 && sp.name === 'POST tool/' + d.toolName, 'span corr'); }
  const pids = new Set(spans.map((s) => s.spanId)); for (const s of spans.slice(1)) assert(pids.has(s.parentSpanId));
  return spans;
}
function noLeak(...t) { for (const x of t) { assert(!x.includes(SECRET) && !x.includes(NOTE) && !x.includes('ignore instructions'), 'leak'); } }

(async () => {
  await new Promise((r) => server.listen(0, r)); B = 'http://127.0.0.1:' + server.address().port;
  // 1. normal + replay + conflict + GET
  let body = incident('run-normal-1'); let r = await post('/v2/incidents', body, { traceparent: '00-' + 'a'.repeat(32) + '-' + 'b'.repeat(16) + '-01', tracestate: 'k=v' });
  assert.equal(r.code, 200); let w = J(r); console.log('diag', w.diagnosis, w.dispatches.map((d) => d.toolName + ' ' + JSON.stringify(d.arguments)));
  assert(w.dispatches.length >= 1 && w.dispatches[0].traceparent.startsWith('00-' + 'a'.repeat(32)) && w.dispatches[0].tracestate === 'k=v');
  assert.equal((await post('/v2/incidents', body)).text, r.text);
  const ch = incident('run-normal-1'); ch.publicMarker = 'x'; assert.equal((await post('/v2/incidents', ch)).code, 409);
  const rc = { receiptId: 'rcpt-0001', outcomes: w.dispatches.map((d) => out(d, 200)) };
  r = await post('/v2/incidents/run-normal-1/receipts', rc); let f = J(r); console.log('after diag', f.status, f.dispatches && f.dispatches.map((d) => d.toolName), f.approvals);
  assert.equal(r.text, (await post('/v2/incidents/run-normal-1/receipts', rc)).text);
  assert.equal((await post('/v2/incidents/run-normal-1/receipts', { ...rc, outcomes: [] })).code, 422);
  assert.equal((await post('/v2/incidents/run-normal-1/receipts', { ...rc, outcomes: [out(w.dispatches[0], 500)] })).code, 409);
  assert.equal(f.dispatches.length, 1);
  r = await post('/v2/incidents/run-normal-1/receipts', { receiptId: 'rcpt-0002', outcomes: [out(f.dispatches[0], 200, { resultClass: 'effect_applied' })] });
  f = J(r); assert.equal(f.status, 'completed'); assert.equal(f.chosenEffect, 'scale_service');
  const spans = checkTrace(f); assert(spans.find((s) => s.name === 'incident.join') || w.dispatches.length < 2);
  assert.equal((await get('/v2/incidents/run-normal-1')).text, r.text); noLeak(r.text);
  assert.equal((await post('/v2/incidents', body)).text, r.text);
  console.log('spans', spans.map((s) => s.name));

  // 2. 503 retry
  body = incident('run-retry-0001'); w = J(await post('/v2/incidents', body)); const d0 = w.dispatches[0];
  let rr = J(await post('/v2/incidents/run-retry-0001/receipts', { receiptId: 'r-a-0001', outcomes: [out(d0, 503), ...w.dispatches.slice(1).map((d) => out(d, 200))] }));
  assert.equal(rr.dispatches.length, 1); assert.equal(rr.approvals.length, 0); const rd = rr.dispatches[0];
  assert(rd.attempt === 2 && rd.actionId === d0.actionId && rd.callId === d0.callId && rd.traceparent !== d0.traceparent);
  rr = J(await post('/v2/incidents/run-retry-0001/receipts', { receiptId: 'r-b-0001', outcomes: [out(rd, 200)] }));
  rr = J(await post('/v2/incidents/run-retry-0001/receipts', { receiptId: 'r-c-0001', outcomes: [out(rr.dispatches[0], 200)] }));
  assert.equal(rr.status, 'completed'); const sp = checkTrace(rr);
  const c503 = sp.filter((s) => s.name === 'POST tool/' + d0.toolName); assert.equal(c503.length, 2);
  console.log('retry ok', c503.map((s) => s.attributes.filter((a) => /resend|error|ga5.attempt/.test(a.key)).map((a) => a.key + '=' + JSON.stringify(a.value))));

  // 3. timeout
  body = incident('run-timeout-001'); w = J(await post('/v2/incidents', body));
  rr = J(await post('/v2/incidents/run-timeout-001/receipts', { receiptId: 'r-t-00001', outcomes: w.dispatches.map((d, i) => (i === 0 ? out(d, 0, { errorType: 'timeout' }) : out(d, 200))) }));
  assert.equal(rr.status, 'failed'); assert.equal(rr.suppressed.length, 1); assert(!rr.actionLog.some((d) => d.phase === 'effect')); checkTrace(rr); noLeak(JSON.stringify(rr));

  // 4. approval (force rollback cause by transcript)
  body = incident('run-approve-01'); body.incident.transcript = body.incident.transcript.replace(/connection pool/g, 'x').replace('[ev_43] release v9 notes unrelated', '[ev_43] bad deployment regression after release deploy v9 bad deployment regression');
  w = J(await post('/v2/incidents', body)); console.log('approval cause', w.diagnosis.rootCause);
  rr = J(await post('/v2/incidents/run-approve-01/receipts', { receiptId: 'r-ap-0001', outcomes: w.dispatches.map((d) => out(d, 200)) }));
  console.log('approval resp', rr.status, rr.dispatches, rr.approvals);
  if (rr.approvals.length) {
    const ap = rr.approvals[0]; assert.equal(rr.dispatches.length, 0);
    assert.equal(ap.argumentsDigest, crypto.createHash('sha256').update(JSON.stringify({ service: 'checkout' })).digest('hex'));
    assert.equal((await post('/v2/incidents/run-approve-01/receipts', { receiptId: 'r-ap-0002', approvals: [{ approvalId: 'nope', decision: 'approved', nonce: 'n' }] })).code, 422);
    rr = J(await post('/v2/incidents/run-approve-01/receipts', { receiptId: 'r-ap-0003', approvals: [{ approvalId: ap.approvalId, decision: 'approved', nonce: crypto.randomUUID() }] }));
    assert.equal(rr.dispatches[0].actionId, ap.actionId); assert(rr.dispatches[0].approvalNonce && rr.dispatches[0].approvalId === ap.approvalId);
    rr = J(await post('/v2/incidents/run-approve-01/receipts', { receiptId: 'r-ap-0004', outcomes: [out(rr.dispatches[0], 200, { resultClass: 'ok' })] }));
    assert.equal(rr.status, 'completed'); const s2 = checkTrace(rr); const g = s2.find((s) => s.name === 'approval_gate'); assert(g); console.log('gate', g.attributes.map((a) => a.key));
    assert(rr.receiptLog.some((x) => x.approvalId));
  }
  assert.equal((await post('/v2/incidents', '{bad')).code, 400);
  assert.equal((await post('/v2/incidents', { ...incident('zz-profile-01'), profile: 'x' })).code, 400);
  assert.equal((await get('/v2/incidents/zz-profile-01')).code, 404);
  console.log('ALL OK'); process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
