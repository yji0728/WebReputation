#!/usr/bin/env python3
"""
Basic demo of WebReputation functionality using only standard library
"""

import sys
import os
import re
import json
from urllib.parse import urlparse, urljoin
from datetime import datetime


class BasicIOCExtractor:
    """Simplified IOC extractor using only standard library."""
    
    def __init__(self):
        self.patterns = {
            'url': re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE),
            'ip': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        }
    
    def extract_all_iocs(self, content, base_url=None):
        """Extract IOCs from content."""
        return {
            'urls': list(set(self.patterns['url'].findall(content))),
            'ips': list(set(self.patterns['ip'].findall(content))),
            'domains': list(set(self.patterns['domain'].findall(content))),
            'emails': list(set(self.patterns['email'].findall(content))),
            'file_hashes': {
                'md5': list(set(self.patterns['md5'].findall(content))),
                'sha256': list(set(self.patterns['sha256'].findall(content)))
            },
            'suspicious_files': self._find_suspicious_files(content, base_url)
        }
    
    def _find_suspicious_files(self, content, base_url):
        """Find references to suspicious files."""
        suspicious_extensions = ['.exe', '.dll', '.bat', '.scr', '.zip', '.rar']
        suspicious_files = []
        
        for ext in suspicious_extensions:
            pattern = rf'(?:href|src)=["\']([^"\']*{re.escape(ext)}[^"\']*)["\']'
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                suspicious_files.append({
                    'filename': match.split('/')[-1],
                    'url': urljoin(base_url or '', match) if base_url else match,
                    'extension': ext
                })
        
        return suspicious_files


def demo_ioc_extraction():
    """Demonstrate IOC extraction."""
    print("=" * 60)
    print("WebReputation 악성 웹사이트 분석 도구 - 기본 데모")
    print("=" * 60)
    
    print("\n[1] IOC 추출 데모")
    print("-" * 30)
    
    extractor = BasicIOCExtractor()
    
    # 한국어 악성 사이트 예시 콘텐츠
    malicious_content = """
    <html>
    <head><title>무료 소프트웨어 다운로드</title></head>
    <body>
        <h1>⚠️ 위험한 다운로드 사이트 (데모용)</h1>
        <p>이 사이트는 악성코드를 유포합니다!</p>
        
        <a href="https://malware.evil-site.com/trojan.exe">💀 무료 안티바이러스 다운로드</a><br>
        <a href="http://phishing.badsite.org/keylogger.zip">🎁 무료 게임 다운로드</a><br>
        
        <p>문의: admin@evil-hacker.net</p>
        <p>서버 IP: 198.51.100.123</p>
        <p>백업 서버: 203.0.113.456</p>
        
        <script src="https://cdn.malicious.net/js/steal-passwords.js"></script>
        
        <form action="https://phishing.badsite.org/steal-login" method="post">
            <input type="text" name="username" placeholder="사용자명" />
            <input type="password" name="password" placeholder="비밀번호" />
            <input type="submit" value="로그인" />
        </form>
        
        <p>파일 해시: 5d41402abc4b2a76b9719d911017c592</p>
        <p>SHA256: aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f</p>
    </body>
    </html>
    """
    
    # IOC 추출
    iocs = extractor.extract_all_iocs(malicious_content, "https://fake-malware-site.com")
    
    print("추출된 IOC (위험 지표):")
    
    print(f"\n📍 URL ({len(iocs['urls'])}개):")
    for i, url in enumerate(iocs['urls'], 1):
        print(f"  {i}. {url}")
    
    print(f"\n🌐 도메인 ({len(iocs['domains'])}개):")
    for i, domain in enumerate(iocs['domains'][:10], 1):  # 처음 10개만
        print(f"  {i}. {domain}")
    
    print(f"\n🔢 IP 주소 ({len(iocs['ips'])}개):")
    for i, ip in enumerate(iocs['ips'], 1):
        print(f"  {i}. {ip}")
    
    print(f"\n📧 이메일 ({len(iocs['emails'])}개):")
    for i, email in enumerate(iocs['emails'], 1):
        print(f"  {i}. {email}")
    
    print(f"\n🔐 파일 해시:")
    print(f"  MD5: {len(iocs['file_hashes']['md5'])}개")
    for hash_val in iocs['file_hashes']['md5']:
        print(f"    - {hash_val}")
    print(f"  SHA256: {len(iocs['file_hashes']['sha256'])}개")
    for hash_val in iocs['file_hashes']['sha256']:
        print(f"    - {hash_val}")
    
    print(f"\n💀 의심스러운 파일 ({len(iocs['suspicious_files'])}개):")
    for i, file_info in enumerate(iocs['suspicious_files'], 1):
        print(f"  {i}. {file_info['filename']} ({file_info['extension']})")
        print(f"     URL: {file_info['url']}")
    
    return iocs


def demo_analysis_workflow():
    """Demonstrate the analysis workflow."""
    print(f"\n[2] 분석 워크플로우 데모")
    print("-" * 30)
    
    # 가상의 분석 결과
    analysis_results = {
        'analysis_info': {
            'target_url': 'https://fake-malware-site.com',
            'start_time': datetime.now().isoformat(),
            'duration_seconds': 23.5,
            'analyzer_version': '1.0.0'
        },
        'summary': {
            'total_urls_analyzed': 5,
            'malicious_indicators': 3,
            'suspicious_indicators': 2,
            'payloads_found': 4,
            'redirect_depth': 2
        },
        'web_scraping': {
            'final_url': 'https://malware-payload.evil-site.com/download',
            'status_code': 200,
            'content_type': 'text/html; charset=utf-8',
            'page_title': '무료 소프트웨어 다운로드',
            'redirect_chain': [
                'https://fake-malware-site.com',
                'https://redirect.evil-site.com/go?id=123',
                'https://malware-payload.evil-site.com/download'
            ]
        },
        'virustotal_analysis': {
            'summary': {
                'total_malicious': 3,
                'total_suspicious': 2,
                'total_clean': 0,
                'total_unknown': 1
            }
        },
        'payload_analysis': [
            {
                'payload_info': {
                    'type': 'linked_payload',
                    'url': 'https://malware.evil-site.com/trojan.exe',
                    'filename': 'trojan.exe'
                },
                'download_result': {
                    'success': True,
                    'filepath': './payloads/trojan.exe',
                    'size': 245760,
                    'md5': '5d41402abc4b2a76b9719d911017c592',
                    'sha256': 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'
                },
                'classification': 'MALICIOUS - Trojan detected by 45/70 engines'
            }
        ]
    }
    
    print("분석 워크플로우:")
    print("1. ✅ 웹 스크래핑 및 리디렉트 추적")
    print("2. ✅ IOC 추출 (URL, IP, 도메인, 해시)")
    print("3. ⚠️  VirusTotal 평판 조회 (API 키 필요)")
    print("4. ✅ 페이로드 탐지 및 분석")
    print("5. ✅ 재귀적 URL 분석")
    
    print(f"\n📊 분석 결과 요약:")
    summary = analysis_results['summary']
    print(f"  분석된 URL 수: {summary['total_urls_analyzed']}")
    print(f"  🚨 악성 지표: {summary['malicious_indicators']}")
    print(f"  ⚠️  의심 지표: {summary['suspicious_indicators']}")
    print(f"  💀 발견된 페이로드: {summary['payloads_found']}")
    print(f"  🔄 리디렉트 깊이: {summary['redirect_depth']}")
    
    print(f"\n🔄 리디렉트 체인:")
    for i, url in enumerate(analysis_results['web_scraping']['redirect_chain'], 1):
        print(f"  {i}. {url}")
    
    print(f"\n💀 페이로드 분석:")
    for i, payload in enumerate(analysis_results['payload_analysis'], 1):
        payload_info = payload['payload_info']
        download_result = payload.get('download_result', {})
        
        print(f"  페이로드 {i}:")
        print(f"    파일명: {payload_info['filename']}")
        print(f"    URL: {payload_info['url']}")
        if download_result.get('success'):
            print(f"    크기: {download_result['size']:,} bytes")
            print(f"    MD5: {download_result['md5']}")
            print(f"    분류: {payload.get('classification', 'Unknown')}")
    
    return analysis_results


def demo_report_generation(analysis_results):
    """Generate a sample report."""
    print(f"\n[3] 보고서 생성 데모")
    print("-" * 30)
    
    # 한국어 보고서 생성
    report_lines = [
        "="*80,
        "웹 평판 분석 보고서 (Web Reputation Analysis Report)",
        "="*80,
        "",
        f"🎯 분석 대상: {analysis_results['analysis_info']['target_url']}",
        f"⏰ 분석 시간: {analysis_results['analysis_info']['start_time']}",
        f"⌛ 소요 시간: {analysis_results['analysis_info']['duration_seconds']:.1f}초",
        "",
        "📊 분석 요약:",
        f"  • 분석된 URL: {analysis_results['summary']['total_urls_analyzed']}개",
        f"  • 🚨 악성 지표: {analysis_results['summary']['malicious_indicators']}개",
        f"  • ⚠️  의심 지표: {analysis_results['summary']['suspicious_indicators']}개", 
        f"  • 💀 페이로드: {analysis_results['summary']['payloads_found']}개",
        f"  • 🔄 리디렉트: {analysis_results['summary']['redirect_depth']}단계",
        "",
        "🔗 리디렉트 체인:",
    ]
    
    for i, url in enumerate(analysis_results['web_scraping']['redirect_chain'], 1):
        report_lines.append(f"  {i}. {url}")
    
    report_lines.extend([
        "",
        "💀 발견된 페이로드:",
    ])
    
    for i, payload in enumerate(analysis_results['payload_analysis'], 1):
        payload_info = payload['payload_info']
        report_lines.append(f"  페이로드 {i}: {payload_info['filename']}")
        report_lines.append(f"    • URL: {payload_info['url']}")
        report_lines.append(f"    • 분류: {payload.get('classification', '분석 중...')}")
    
    report_lines.extend([
        "",
        "⚠️  보안 권고사항:",
        "  • 이 사이트는 악성코드를 유포하는 것으로 판단됩니다",
        "  • 해당 URL 및 관련 도메인 접근을 차단하세요",
        "  • 다운로드된 파일은 격리된 환경에서만 분석하세요",
        "  • 네트워크 모니터링을 강화하세요",
        "",
        "="*80
    ])
    
    report = "\n".join(report_lines)
    print(report)
    
    # 보고서 파일로 저장
    report_filename = f"malware_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n💾 보고서가 저장되었습니다: {report_filename}")
    except Exception as e:
        print(f"보고서 저장 실패: {e}")
    
    return report


def main():
    """Run the complete demo."""
    try:
        # IOC 추출 데모
        iocs = demo_ioc_extraction()
        
        # 분석 워크플로우 데모
        analysis_results = demo_analysis_workflow()
        
        # 보고서 생성 데모
        report = demo_report_generation(analysis_results)
        
        print(f"\n" + "="*60)
        print("✅ 데모 완료!")
        print("="*60)
        print("\n실제 사용법:")
        print("1. 의존성 설치: pip install beautifulsoup4 lxml tldextract pyyaml")
        print("2. VirusTotal API 키 설정 (config.yaml)")
        print("3. 실행: python webreputation.py -u <URL> --report")
        print("\n⚠️  주의: 실제 악성 사이트 분석 시 격리된 환경 사용 권장")
        
    except Exception as e:
        print(f"❌ 데모 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()