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

// key: login_event_id, value: { id, user_token, domain_id, login_ip, created_at }
const loginEvents = new Map();

// key: `${domain_id}:${user_token}:${safe_fp}`, value: { id, domain_id, user_token, safe_fp, first_seen_at, last_seen_at }
const deviceFingerprints = new Map();

// key: login_event_id, value: { id, login_event_id, user_token, domain_id, safe_fp, security_signal, local_classification, is_bot, trust_score, created_at }
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
 *  - 서비스 서버가 로그인 시점에 호출한다고 가정
 *  - PCF가 login_event_id + domain_salt + run_sandbox 플래그 응답
 */
app.post('/evaluate_login', (req, res) => {
  const { user_token, domain, login_ip } = req.body || {};

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
 *  - local_classification = { is_bot, trust_score } 구조라고 가정
 *  - PCF는:
 *    1) login_event_id로 loginEvents 찾기
 *    2) sandboxReports 저장
 *    3) 사용자 히스토리 + 최근 시도 횟수 + IP 일관성 + 현재 is_bot/trust_score 모두 반영해서 risk_score 계산
 *    4) 서비스 서버에 보낼 payload 콘솔에 찍기 (service 서버 연동은 나중에)
 */
app.post('/report_fp', (req, res) => {
  const {
    login_event_id,
    domain,
    safe_fp,
    security_signal,
    local_classification,
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

  // local_classification 안에서 is_bot, trust_score 꺼내기
  const is_bot = !!(local_classification && local_classification.is_bot);
  const trust_score =
    local_classification && typeof local_classification.trust_score === 'number'
      ? local_classification.trust_score
      : null;

  // 4) sandboxReports 저장 (login_event_id 기준으로 1건이라고 가정)
  const report = {
    id: generateId(),
    login_event_id,
    user_token: loginEvent.user_token,
    domain_id: domainRecord.id,
    safe_fp,
    security_signal: security_signal || {},
    local_classification: local_classification || null,
    is_bot,
    trust_score,
    created_at: now,
  };

  sandboxReports.set(login_event_id, report);

  // 4-1) security_signal 기반 취약점 플래그 요약
  const vulnFlags = analyzeSecuritySignal(security_signal);

  // 5) 이 사용자에 대한 과거 히스토리/속도/IP 정보 계산
  const historyStats = getUserHistoryStats(loginEvent.user_token, domainRecord.id);
  const velocityStats = getUserLoginVelocity(
    loginEvent.user_token,
    domainRecord.id,
    now,
    10, // 최근 10분 기준
  );
  const ipStats = getUserIpStats(loginEvent.user_token, domainRecord.id, loginEvent.login_ip);

  // 6) 위험도(risk_score) 계산
  const risk_score = calculateRiskScore(local_classification, {
    history: historyStats,
    velocity: velocityStats,
    ip: ipStats,
  });

  // 7) 서비스 서버에 보낼 payload 콘솔에 찍기 (실제 HTTP 호출은 나중에)
  const notifyPayload = {
    login_event_id,
    user_token: loginEvent.user_token,
    domain: domainRecord.domain_name,
    risk_score,
    security_flags: vulnFlags,
    reason: {
      base: 'local_classification + history + velocity + ip_profile',
      debug: {
        local_classification,
        historyStats,
        velocityStats,
        ipStats,
      },
    },
  };

  notifyServiceServerSimulated(notifyPayload);

  // 8) 클라이언트(브라우저 확장)에게 응답
  return res.json({
    ok: true,
    message: 'sandbox report stored',
    risk_score,
  });
});

/**
 * 사용자별 과거 샌드박스 히스토리 집계
 * - 같은 user_token + domain_id 기준
 * - total: 총 샌드박스 실행 횟수
 * - botCount: is_bot == true 횟수
 * - avgTrustScore: trust_score 평균 (있는 것만)
 */
function getUserHistoryStats(user_token, domain_id) {
  let total = 0;
  let botCount = 0;
  let trustSum = 0;
  let trustCount = 0;

  for (const report of sandboxReports.values()) {
    if (report.user_token === user_token && report.domain_id === domain_id) {
      total++;
      if (report.is_bot) {
        botCount++;
      }
      if (typeof report.trust_score === 'number') {
        trustSum += report.trust_score;
        trustCount++;
      }
    }
  }

  const avgTrustScore = trustCount > 0 ? trustSum / trustCount : null;

  return { total, botCount, avgTrustScore };
}

/**
 * 짧은 시간(예: 최근 N분) 내 로그인 시도 횟수
 * - 같은 user_token + domain_id 기준
 * - windowMinutes 내에 발생한 loginEvents 개수
 */
function getUserLoginVelocity(user_token, domain_id, nowIso, windowMinutes) {
  const now = new Date(nowIso).getTime();
  const windowMs = windowMinutes * 60 * 1000;

  let recentCount = 0;
  let totalLogins = 0;

  for (const evt of loginEvents.values()) {
    if (evt.user_token === user_token && evt.domain_id === domain_id) {
      totalLogins++;

      if (evt.created_at) {
        const t = new Date(evt.created_at).getTime();
        if (!Number.isNaN(t) && now - t <= windowMs) {
          recentCount++;
        }
      }
    }
  }

  return { recentCount, windowMinutes, totalLogins };
}

/**
 * IP 일관성 정보
 * - 같은 user_token + domain_id 기준
 * - 이번 login_ip와 동일한 IP 비율, 전체 distinct IP 개수
 */
function getUserIpStats(user_token, domain_id, currentIp) {
  let totalLogins = 0;
  let sameIpCount = 0;
  const ipSet = new Set();

  for (const evt of loginEvents.values()) {
    if (evt.user_token === user_token && evt.domain_id === domain_id) {
      if (evt.login_ip) {
        ipSet.add(evt.login_ip);
      }
      totalLogins++;
      if (currentIp && evt.login_ip === currentIp) {
        sameIpCount++;
      }
    }
  }

  const sameIpRatio = totalLogins > 0 ? sameIpCount / totalLogins : null;
  const distinctIpCount = ipSet.size;

  return {
    hasIpHistory: totalLogins > 0,
    sameIpRatio,
    distinctIpCount,
  };
}

/**
 * security_signal을 보고 취약점 플래그 요약
 * - outdated_browser : 브라우저 메이저 버전이 너무 낮음 (Chrome 전제)
 * - outdated_os      : 오래된 Windows / macOS 사용
 * - agent_outdated   : 샌드박스/에이전트 버전이 너무 낮음
 */
function analyzeSecuritySignal(security_signal) {
  if (!security_signal) return {};

  const flags = {
    outdated_browser: false,
    outdated_os: false,
    agent_outdated: false,
  };

  // -----------------------------
  // 1) 브라우저 (Chrome 전제)
  // -----------------------------
  if (security_signal.browser_major !== undefined) {
    let chromeMajor = null;

    if (typeof security_signal.browser_major === 'number') {
      chromeMajor = security_signal.browser_major;
    } else {
      // "Chrome 120" 같은 문자열에서 숫자만 뽑기
      const m = String(security_signal.browser_major).match(/(\d+)/);
      if (m) chromeMajor = parseInt(m[1], 10);
    }

    if (typeof chromeMajor === 'number' && !Number.isNaN(chromeMajor)) {
      // 프로젝트 규칙: Chrome 메이저 버전 < 100 → outdated
      if (chromeMajor < 100) {
        flags.outdated_browser = true;
      }
    }
  }

  // -----------------------------
  // 2) OS (Windows / macOS)
  // -----------------------------
  if (security_signal.os_major) {
    const osStr = String(security_signal.os_major).toLowerCase();

    // 2-1) Windows 계열
    if (osStr.includes('windows')) {
      const m = osStr.match(/windows\s+(\d+)/);
      if (m) {
        const winVer = parseInt(m[1], 10);
        // 규칙: Windows 10, 11은 최신 / 그 미만은 구버전
        if (winVer < 10) {
          flags.outdated_os = true;
        }
      } else {
        // "xp", "vista", "me" 같이 숫자 안 들어간 표현 처리
        if (
          osStr.includes('xp') ||
          osStr.includes('vista') ||
          osStr.includes('me') ||
          osStr.includes('2000') ||
          osStr.includes('98') ||
          osStr.includes('95')
        ) {
          flags.outdated_os = true;
        }
      }
    }

    // 2-2) macOS / OS X 계열
    if (osStr.includes('mac os') || osStr.includes('macos') || osStr.includes('os x')) {
      // "macOS 14", "macOS 10.13", "OS X 10.11" 등 처리
      const m = osStr.match(/(mac\s?os\sx?|macos)\s*(\d+)(?:\.(\d+))?/);
      if (m) {
        const major = parseInt(m[2], 10);
        // 규칙: 10.x 계열은 outdated, 11 이상은 최신
        if (major < 11) {
          flags.outdated_os = true;
        }
      }
    }
  }

  // -----------------------------
  // 3) 에이전트 버전 (security_version)
  // -----------------------------
  const ver = security_signal.security_version;
  if (typeof ver === 'string') {
    // "v1." 로 시작해야 최신
    if (!ver.startsWith('v1.')) {
      flags.agent_outdated = true;
    }
  } else {
    // 버전 정보가 없으면 보수적으로 구버전 취급
    flags.agent_outdated = true;
  }

  return flags;
}

/**
 * local_classification + 사용자 히스토리 + 로그인 속도 + IP 일관성을
 * 모두 고려해서 0~1 사이 risk_score 산출
 */
function calculateRiskScore(localClassification, stats) {
  const history = stats.history || {};
  const velocity = stats.velocity || {};
  const ip = stats.ip || {};

  const is_bot = !!(localClassification && localClassification.is_bot);
  const trust_score =
    localClassification && typeof localClassification.trust_score === 'number'
      ? localClassification.trust_score
      : null;

  // 1) 이번 샌드박스 결과 기반 기본 risk
  let score;
  if (trust_score !== null) {
    // trust_score: 0(불신) ~ 100(신뢰)
    // -> risk_score: 0(안전) ~ 1(위험) 으로 반대로 매핑
    score = 1 - trust_score / 100;
  } else {
    score = 0.5; // 정보 없으면 중간
  }

  // is_bot이면 최소 0.8 이상으로 올리기
  if (is_bot && score < 0.8) {
    score = 0.8;
  }

  // 2) 과거 히스토리 가중치
  if (history.total >= 3) {
    const botRatio = history.botCount / history.total;
    if (botRatio >= 0.5) {
      // 과거 절반 이상이 봇 의심이면 +0.15
      score += 0.15;
    }
    if (history.avgTrustScore !== null && history.avgTrustScore >= 80) {
      // 과거 평균 trust_score가 높으면 -0.15
      score -= 0.15;
    }
  }

  // 3) 최근 시도 횟수(velocity) 반영
  if (velocity.recentCount >= 5) {
    // 최근 10분 내 5회 이상 로그인 시도 → 브루트포스 의심
    score += 0.1;
  }

  // 4) IP 일관성 반영
  if (ip.hasIpHistory) {
    if (ip.sameIpRatio !== null && ip.sameIpRatio >= 0.7) {
      // 대부분 같은 IP에서 로그인하면 약간 신뢰도 상승
      score -= 0.05;
    }
    if (ip.distinctIpCount >= 5) {
      // 너무 많은 IP에서 로그인하면 의심
      score += 0.05;
    }
  }

  // 5) 0 ~ 1 사이로 클램프
  if (score < 0) score = 0;
  if (score > 1) score = 1;

  return score;
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
