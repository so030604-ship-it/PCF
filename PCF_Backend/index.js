// index.js

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// JSON 바디 파싱
app.use(express.json());

/**
 * 1단계: "간단한 메모리 DB" 준비
 *  - domains
 *  - loginEvents
 *  - deviceFingerprints
 *  - sandboxReports
 */

// 도메인 id 자동 증가용
let nextDomainId = 1;

// key: domain_name, value: { id, domain_name, domain_salt, created_at }
const domains = new Map();

// key: login_event_id, value: { id, user_token, domain_id, login_ip, login_type, created_at }
const loginEvents = new Map();

// key: `${domain_id}:${user_token}:${safe_fp}`, value: { id, domain_id, user_token, safe_fp, first_seen_at, last_seen_at }
const deviceFingerprints = new Map();

// key: login_event_id, value: { id, login_event_id, user_token, domain_id, safe_fp, security_signal, local_classification, trust_score, created_at }
const sandboxReports = new Map();

// 랜덤 ID 생성 (login_event_id, 기타 PK 용)
function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

// 도메인 조회/생성 헬퍼
function getOrCreateDomain(domainName) {
  if (domains.has(domainName)) {
    return domains.get(domainName);
  }

  const record = {
    id: nextDomainId++,
    domain_name: domainName,
    domain_salt: crypto.randomBytes(16).toString('hex'),
    created_at: new Date().toISOString(),
  };

  domains.set(domainName, record);
  console.log('[PCF] new domain registered:', record);
  return record;
}

/**
 * 2단계: /evaluate_login 구현
 *  - 브라우저(JS)가 로그인 시점에 호출
 *  - PCF가 login_event_id + domain_salt + run_sandbox 플래그 응답
 */
app.post('/evaluate_login', (req, res) => {
  const { user_token, domain, login_ip, login_type } = req.body || {};

  // 필수값 체크
  if (!user_token || !domain) {
    return res.status(400).json({
      error: 'user_token and domain are required',
    });
  }

  // 1) 도메인 조회/생성
  const domainRecord = getOrCreateDomain(domain);

  // 2) login_event_id 생성
  const login_event_id = generateId();
  const now = new Date().toISOString();

  // 3) loginEvents에 저장
  loginEvents.set(login_event_id, {
    id: login_event_id,
    user_token,
    domain_id: domainRecord.id,
    login_ip: login_ip || null,
    login_type: login_type || null,
    created_at: now,
  });

  console.log('[PCF] new login_event:', loginEvents.get(login_event_id));

  // 4) 헤더에 X-PCF-Run-Sandbox: 1 세팅
  res.set('X-PCF-Run-Sandbox', '1');

  // 5) JSON 응답 (브라우저/확장용)
  return res.json({
    login_event_id,
    run_sandbox: true,
    domain: domainRecord.domain_name,
    domain_salt: domainRecord.domain_salt,
  });
});

/**
 * 3단계: /report_fp 구현
 *  - 브라우저 확장이 샌드박스를 돌리고 결과를 PCF에 보고
 *  - PCF는:
 *    1) login_event_id로 loginEvents 찾기
 *    2) 없으면 400
 *    3) sandboxReports에 저장
 *    4) risk_score 간단 계산
 *    5) 콘솔에 /notify_sandbox_result로 보낼 값 찍기 (service 서버 연동은 나중에)
 */
app.post('/report_fp', (req, res) => {
  const {
    login_event_id,
    domain,
    safe_fp,
    security_signal,
    local_classification,
    trust_score,
  } = req.body || {};

  // 필수값 체크
  if (!login_event_id || !domain || !safe_fp) {
    return res.status(400).json({
      error: 'login_event_id, domain, safe_fp are required',
    });
  }

  // 1) login_event_id로 loginEvents에서 찾기
  const loginEvent = loginEvents.get(login_event_id);
  if (!loginEvent) {
    return res.status(400).json({
      error: 'unknown login_event_id',
    });
  }

  // 2) 도메인 조회/생성 (있어야 domain_id 얻음)
  const domainRecord = getOrCreateDomain(domain);

  // 도메인 불일치 시 경고 (완전 막지는 않고 로그만)
  if (domainRecord.id !== loginEvent.domain_id) {
    console.warn('[PCF] WARNING: domain mismatch between /report_fp and login_event', {
      report_domain: domainRecord.domain_name,
      login_event_domain_id: loginEvent.domain_id,
    });
  }

  const now = new Date().toISOString();

  // 3) deviceFingerprints upsert
  const fpKey = `${domainRecord.id}:${loginEvent.user_token}:${safe_fp}`;
  const existingFp = deviceFingerprints.get(fpKey);

  if (existingFp) {
    existingFp.last_seen_at = now;
    deviceFingerprints.set(fpKey, existingFp);
  } else {
    deviceFingerprints.set(fpKey, {
      id: generateId(),
      domain_id: domainRecord.id,
      user_token: loginEvent.user_token,
      safe_fp,
      first_seen_at: now,
      last_seen_at: now,
    });
  }

  // 4) sandboxReports 저장 (login_event_id 기준으로 1건이라고 가정)
  const report = {
    id: generateId(),
    login_event_id,
    user_token: loginEvent.user_token,
    domain_id: domainRecord.id,
    safe_fp,
    security_signal: security_signal || {},
    local_classification: local_classification || null,
    trust_score: typeof trust_score === 'number' ? trust_score : null,
    created_at: now,
  };

  sandboxReports.set(login_event_id, report);

  // 5) 위험도(risk_score) 간단 계산
  const risk_score = calculateRiskScore(local_classification);

  // 6) 서비스 서버에 보낼 payload 콘솔에 찍기 (실제 HTTP 호출은 나중에)
  const notifyPayload = {
    login_event_id,
    user_token: loginEvent.user_token,
    domain: domainRecord.domain_name,
    risk_score,
    reason: `simple_rule:${local_classification || 'unknown'}`,
  };

  notifyServiceServerSimulated(notifyPayload);

  // 7) 클라이언트(브라우저 확장)에게 응답
  return res.json({
    ok: true,
    message: 'sandbox report stored',
    risk_score,
  });
});

// local_classification 기반 위험도 계산 간단 버전
function calculateRiskScore(localClassification) {
  if (!localClassification) return 0.5;
  const lc = String(localClassification).toLowerCase();

  // 예시 규칙: local_trust / is_human → 0.1, suspicious / is_bot → 0.9, 나머지 0.5
  if (lc === 'local_trust' || lc === 'is_human') return 0.1;
  if (lc === 'suspicious' || lc === 'is_bot') return 0.9;

  return 0.5;
}

// 실제 /notify_sandbox_result HTTP 호출 대신 콘솔에만 찍는 함수
function notifyServiceServerSimulated(payload) {
  console.log('\n[PCF] === notify_to_service_server (SIMULATION) ===');
  console.log(JSON.stringify(payload, null, 2));
  console.log('[PCF] ===========================================\n');
}

// 서버 실행
app.listen(PORT, () => {
  console.log(`PCF backend listening on http://localhost:${PORT}`);
});

