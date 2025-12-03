// pcf-tokenizer/index.js
const crypto = require('crypto');

/**
 * 토큰 생성기 만들기
 *  - secret: 고객사가 설정하는 비밀키 (필수)
 *  - prefix: 토큰 앞에 붙일 문자열 (옵션, 예: "pcf_")
 */
function createTokenizer({ secret, prefix = 'pcf_' }) {
  if (!secret) {
    throw new Error('PCF tokenizer: secret is required');
  }

  return {
    /**
     * 실제 user_id를 안전한 user_token으로 변환
     */
    tokenize(userId) {
      const h = crypto.createHmac('sha256', secret);
      h.update(String(userId));

      // base64url로 바꾸고 길이를 적당히 자름 (32자 정도)
      const digest = h.digest('base64url').slice(0, 32);
      return prefix + digest;
    }
  };
}

module.exports = { createTokenizer };
