# WebReputation - 악성 웹사이트 분석 도구

WebReputation은 의심스러운 웹사이트에서 IOC(Indicators of Compromise)를 추출하고, VirusTotal API를 통해 평판을 조회하며, 리디렉트 체인을 분석하여 페이로드를 추출하는 자동화된 웹 분석 도구입니다.

## 주요 기능

- **IOC 자동 추출**: URL, IP 주소, 도메인, 파일 해시, 이메일 주소 추출
- **VirusTotal 연동**: 추출된 IOC에 대한 평판 조회
- **리디렉트 체인 분석**: 악성 사이트의 리디렉트 경로 추적
- **페이로드 탐지 및 다운로드**: 의심스러운 파일 자동 탐지 및 분석
- **재귀적 분석**: 발견된 URL에 대한 깊이 있는 분석
- **상세한 보고서 생성**: JSON 및 텍스트 형태의 분석 보고서

## 설치 및 설정

### 1. 의존성 설치

```bash
# 자동 설정 (권장)
python setup.py

# 또는 수동 설치
pip install -r requirements.txt
```

### 2. VirusTotal API 키 설정

1. [VirusTotal](https://www.virustotal.com/gui/join-us)에서 무료 계정 생성
2. API 키를 `config.yaml` 파일에 설정:

```yaml
virustotal:
  api_key: "YOUR_VIRUSTOTAL_API_KEY_HERE"
```

## 사용법

### 기본 사용

```bash
# 기본 분석
python webreputation.py -u https://suspicious-site.com

# 상세 보고서와 함께 분석
python webreputation.py -u https://malware.example.com --report

# 페이로드 다운로드 포함
python webreputation.py -u https://phishing.example.com --save-payloads
```

### 고급 옵션

```bash
# 사용자 정의 설정 파일 사용
python webreputation.py -u https://example.com --config custom_config.yaml

# 결과 파일 지정
python webreputation.py -u https://example.com -o analysis_results.json

# 분석 깊이 조절
python webreputation.py -u https://example.com --max-depth 10 --delay 2.0
```

### 명령줄 옵션

- `-u, --url`: 분석할 대상 URL (필수)
- `-c, --config`: 설정 파일 경로
- `-o, --output`: 결과 파일 경로
- `--report`: 사람이 읽기 쉬운 보고서 생성
- `--save-payloads`: 페이로드 파일 다운로드
- `--payload-dir`: 페이로드 저장 디렉토리
- `--max-depth`: 최대 분석 깊이
- `--delay`: 요청 간 지연 시간 (초)
- `--verbose`: 상세 출력 모드

## 분석 과정

1. **웹 스크래핑 및 리디렉트 분석**
   - 대상 URL 접근 및 콘텐츠 수집
   - 리디렉트 체인 추적 및 분석

2. **IOC 추출**
   - URL, IP 주소, 도메인명 추출
   - 파일 해시 (MD5, SHA1, SHA256) 추출
   - 의심스러운 파일 링크 탐지

3. **VirusTotal 평판 조회**
   - 추출된 IOC를 VirusTotal API로 조회
   - 악성/의심/안전 분류

4. **재귀적 URL 분석**
   - 발견된 URL들에 대한 추가 분석
   - 설정된 깊이까지 반복 분석

5. **페이로드 분석**
   - 의심스러운 파일 다운로드
   - 파일 해시 계산 및 VirusTotal 조회

## 출력 결과

### JSON 결과 파일
```json
{
  "analysis_info": {
    "target_url": "https://example.com",
    "start_time": "2024-01-01T12:00:00",
    "duration_seconds": 45.2
  },
  "summary": {
    "total_urls_analyzed": 5,
    "malicious_indicators": 2,
    "suspicious_indicators": 1,
    "payloads_found": 3
  },
  "web_scraping": { /* 웹 스크래핑 결과 */ },
  "ioc_extraction": { /* 추출된 IOC */ },
  "virustotal_analysis": { /* VirusTotal 분석 */ },
  "payload_analysis": [ /* 페이로드 분석 */ ]
}
```

### 텍스트 보고서
```
================================================================================
WEB REPUTATION ANALYSIS REPORT
================================================================================

Target URL: https://suspicious-site.com
Analysis Time: 2024-01-01T12:00:00
Duration: 45.20 seconds

SUMMARY:
  URLs Analyzed: 5
  Malicious Indicators: 2
  Suspicious Indicators: 1
  Payloads Found: 3
```

## 설정 파일

`config.yaml` 파일을 통해 도구의 동작을 사용자 정의할 수 있습니다:

```yaml
# VirusTotal API 설정
virustotal:
  api_key: "YOUR_API_KEY"

# 웹 스크래핑 설정
web_scraper:
  timeout: 30
  max_redirects: 10
  user_agent: "Mozilla/5.0 ..."

# 분석 설정
analysis:
  max_depth: 5
  delay_between_requests: 1
  save_payloads: true
  payload_directory: "./payloads"
```

## 보안 고려사항

⚠️ **중요**: 이 도구는 악성 사이트를 분석하므로 다음 사항을 주의하세요:

- 격리된 환경(VM, 샌드박스)에서 실행 권장
- 다운로드된 페이로드는 악성 파일일 수 있음
- 분석 중 실제 악성 사이트에 접근할 수 있음
- 네트워크 모니터링 및 방화벽 설정 권장

## 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다.

## 기여

버그 리포트, 기능 요청, 코드 기여를 환영합니다. GitHub Issues를 통해 문의해 주세요.

## 지원

- GitHub Issues: 버그 리포트 및 기능 요청
- 이메일: 보안상 중요한 문제는 직접 연락

---

**면책조항**: 이 도구는 교육 및 연구 목적으로만 사용되어야 합니다. 사용자는 관련 법률을 준수하고 악의적인 목적으로 사용해서는 안 됩니다.