// background.js 

console.log('[PCF Extension] background service worker loaded');

// PCF 백엔드 기본 URL (나중에 실제 서버 주소로 변경 가능)
const PCF_BACKEND_BASE_URL = 'http://localhost:3000';

// 탭별 PCF 헤더 컨텍스트 저장용
// - key: tabId
// - value: { runSandbox: boolean, loginEventId: string, domainSalt: string }
const pcfContextByTab = {};

// -----------------------
// 1. 응답 헤더 후킹: X-PCF-* 읽기
// -----------------------
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = details.responseHeaders || [];

    const getHeader = (name) => {
      const h = headers.find(
        (hdr) => hdr.name && hdr.name.toLowerCase() === name.toLowerCase()
      );
      return h ? h.value : null;
    };

    const runSandboxRaw = getHeader('X-PCF-Run-Sandbox');
    const loginEventId  = getHeader('X-PCF-Login-Event-Id');
    const domainSalt    = getHeader('X-PCF-Domain-Salt');

    // PCF 관련 헤더가 전혀 없으면 무시
    if (!runSandboxRaw && !loginEventId && !domainSalt) return;

    const runSandbox =
      runSandboxRaw === '1' ||
      runSandboxRaw === 'true' ||
      runSandboxRaw === 'yes';

    pcfContextByTab[details.tabId] = {
      runSandbox,
      loginEventId,
      domainSalt,
    };

    console.log('[PCF Extension][BG] PCF 헤더 감지:', {
      runSandbox,
      loginEventId,
      domainSalt,
    });
  },
  {
    urls: ['<all_urls>'],    // 필요 시 http://localhost:4000/* 로 좁혀도 됨
    types: ['main_frame'],   // 메인 문서 응답만
  },
  ['responseHeaders']
);

// -----------------------
// 2. content.js ↔ background 메시지 처리
// -----------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    return;
  }

  // -----------------------
  // (A) content.js → "이 탭의 PCF 헤더 컨텍스트 좀 줘" 요청
  //     type: 'PCF_GET_CONTEXT'
// -----------------------
  if (message.type === 'PCF_GET_CONTEXT') {
    const tabId = sender && sender.tab && sender.tab.id;

    if (typeof tabId !== 'number') {
      console.warn(
        '[PCF Extension][BG] PCF_GET_CONTEXT: sender.tab 없음'
      );
      sendResponse({
        ok: false,
        error: 'No sender.tab for PCF_GET_CONTEXT',
      });
      return; // 동기 응답
    }

    const ctx = pcfContextByTab[tabId];

    if (!ctx) {
      console.warn(
        '[PCF Extension][BG] PCF_GET_CONTEXT: 이 탭에 PCF 컨텍스트 없음:',
        { tabId }
      );
      sendResponse({
        ok: false,
        error: 'No PCF context for this tab',
      });
      return; // 동기 응답
    }

    sendResponse({
      ok: true,
      context: ctx, // { runSandbox, loginEventId, domainSalt }
    });
    return; // 동기 응답이므로 true 리턴 필요 없음
  }

  // -----------------------
  // (B) content.js → /report_fp 요청
  //     type: 'PCF_REPORT_FP'
// -----------------------
  if (message.type !== 'PCF_REPORT_FP') {
    // 우리가 처리하지 않는 메시지 타입은 무시
    return;
  }

  const payload = message.payload || {};
  console.log(
    '[PCF Extension][BG] /report_fp 호출 준비 (raw payload):',
    payload
  );

  const {
    login_event_id,
    safe_fp,
    security_signal,
    local_classification,
  } = payload;

  // -----------------------
  // (B-1) run_sandbox 헤더 기반 탭 검증
  // -----------------------
  const tabId = sender && sender.tab && sender.tab.id;
  if (typeof tabId === 'number') {
    const ctx = pcfContextByTab[tabId];
    const allowed = ctx && ctx.runSandbox;

    // 헤더에서 run_sandbox=1 이었던 탭이 아니면 리포트 거부
    if (!allowed) {
      console.warn(
        '[PCF Extension][BG] run_sandbox=false 또는 헤더 없음 → /report_fp 무시:',
        { tabId, allowed, ctx }
      );
      sendResponse({
        ok: false,
        error:
          'run_sandbox flag is false or missing for this tab; /report_fp blocked',
      });
      return; // 동기 종료
    }
  } else {
    console.warn(
      '[PCF Extension][BG] sender.tab 정보 없음 → run_sandbox 검증 생략'
    );
  }

  // -----------------------
  // (B-2) payload 형식 검증
  // -----------------------
  // 설계서 기준으로 필요한 필드들 검증
  // login_event_id, safe_fp, security_signal, local_classification { is_bot, trust_score }
  if (
    !login_event_id ||
    !safe_fp ||
    !security_signal ||
    typeof local_classification !== 'object'
  ) {
    console.error(
      '[PCF Extension][BG] 잘못된 payload 형식:',
      payload
    );
    sendResponse({
      ok: false,
      error: 'Invalid payload for /report_fp',
    });
    return; // 이 경우는 동기 응답이므로 true 리턴 필요 없음
  }

  // -----------------------
  // (B-3) /report_fp 비동기 호출
  // -----------------------
  (async () => {
    try {
      const url = `${PCF_BACKEND_BASE_URL}/report_fp`;

      console.log('[PCF Extension][BG] /report_fp 요청 URL:', url);

      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // 보고서 스펙 그대로: login_event_id, safe_fp, security_signal, local_classification
        body: JSON.stringify({
          login_event_id,
          safe_fp,
          security_signal,
          local_classification,
        }),
      });

      const text = await resp.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (e) {
        data = { raw: text };
      }

      console.log(
        '[PCF Extension][BG] /report_fp 응답:',
        resp.status,
        data
      );

      sendResponse({
        ok: resp.ok,
        status: resp.status,
        data,
      });
    } catch (err) {
      console.error('[PCF Extension][BG] /report_fp 호출 실패:', err);
      sendResponse({
        ok: false,
        error: String(err),
      });
    }
  })();

  // 비동기 sendResponse 사용
  return true;
});
