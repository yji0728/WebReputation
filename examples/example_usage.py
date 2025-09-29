#!/usr/bin/env python3
"""
Example usage of WebReputation library
"""

import sys
import os
import json

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from webreputation.analyzer import WebReputationAnalyzer


def example_basic_analysis():
    """Example of basic URL analysis."""
    print("Example 1: Basic Analysis")
    print("-" * 30)
    
    # Initialize analyzer
    analyzer = WebReputationAnalyzer()
    
    # Analyze a safe test URL
    target_url = "https://httpbin.org/html"
    
    print(f"Analyzing: {target_url}")
    
    try:
        results = analyzer.analyze_url(target_url)
        
        # Print summary
        summary = results.get('summary', {})
        print(f"\nResults Summary:")
        print(f"  URLs analyzed: {summary.get('total_urls_analyzed', 0)}")
        print(f"  Malicious indicators: {summary.get('malicious_indicators', 0)}")
        print(f"  Suspicious indicators: {summary.get('suspicious_indicators', 0)}")
        print(f"  Payloads found: {summary.get('payloads_found', 0)}")
        
        # Save results
        analyzer.save_results(results, "example_results.json")
        print(f"Results saved to: example_results.json")
        
    except Exception as e:
        print(f"Analysis failed: {e}")


def example_ioc_extraction():
    """Example of IOC extraction from content."""
    print("\nExample 2: IOC Extraction")
    print("-" * 30)
    
    from webreputation.ioc_extractor import IOCExtractor
    
    extractor = IOCExtractor()
    
    # Sample malicious content
    sample_content = """
    <html>
    <head><title>Suspicious Site</title></head>
    <body>
        <h1>Download Area</h1>
        <a href="https://malware.example.com/trojan.exe">Click here for free software!</a>
        <p>Contact: support@evil-site.org</p>
        <p>Server IP: 203.0.113.123</p>
        <p>Backup server: 198.51.100.456</p>
        <script src="https://cdn.malicious.net/js/payload.js"></script>
        <form action="https://phishing.example.net/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
    </body>
    </html>
    """
    
    # Extract IOCs
    iocs = extractor.extract_all_iocs(sample_content, "https://suspicious.example.com")
    
    print("Extracted IOCs:")
    print(f"  URLs: {len(iocs['urls'])}")
    for url in iocs['urls']:
        print(f"    - {url}")
    
    print(f"  Domains: {len(iocs['domains'])}")
    for domain in iocs['domains'][:5]:  # Show first 5
        print(f"    - {domain}")
    
    print(f"  IPs: {len(iocs['ips'])}")
    for ip in iocs['ips']:
        print(f"    - {ip}")
    
    print(f"  Emails: {len(iocs['emails'])}")
    for email in iocs['emails']:
        print(f"    - {email}")
    
    print(f"  Suspicious files: {len(iocs['suspicious_files'])}")
    for file_info in iocs['suspicious_files']:
        print(f"    - {file_info['filename']} ({file_info['url']})")


def example_report_generation():
    """Example of generating a human-readable report."""
    print("\nExample 3: Report Generation")
    print("-" * 30)
    
    # Sample results data
    sample_results = {
        'analysis_info': {
            'target_url': 'https://example.malware.com',
            'start_time': '2024-01-01T12:00:00',
            'duration_seconds': 45.7
        },
        'summary': {
            'total_urls_analyzed': 3,
            'malicious_indicators': 2,
            'suspicious_indicators': 1,
            'payloads_found': 2,
            'redirect_depth': 2
        },
        'web_scraping': {
            'final_url': 'https://malware-payload.example.com/download',
            'status_code': 200,
            'content_type': 'text/html',
            'page_title': 'Malicious Download Site',
            'redirect_chain': [
                'https://example.malware.com',
                'https://redirect.malware.com/go',
                'https://malware-payload.example.com/download'
            ]
        },
        'virustotal_analysis': {
            'summary': {
                'total_malicious': 2,
                'total_suspicious': 1,
                'total_clean': 0,
                'total_unknown': 0
            },
            'urls': [
                {
                    'resource': 'https://example.malware.com',
                    'classification': 'malicious',
                    'malicious_count': 15,
                    'total_engines': 70
                }
            ]
        },
        'payload_analysis': [
            {
                'payload_info': {
                    'type': 'linked_payload',
                    'url': 'https://malware-payload.example.com/trojan.exe',
                    'filename': 'trojan.exe'
                },
                'download_result': {
                    'success': True,
                    'filepath': './payloads/trojan.exe',
                    'size': 245760,
                    'md5': '5d41402abc4b2a76b9719d911017c592',
                    'sha256': 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f'
                }
            }
        ]
    }
    
    # Generate report
    analyzer = WebReputationAnalyzer()
    report = analyzer.generate_report(sample_results)
    
    print("Generated Report:")
    print(report)


def main():
    """Run all examples."""
    print("WebReputation - Example Usage")
    print("=" * 40)
    
    try:
        # Run examples that don't require external dependencies
        example_ioc_extraction()
        
        example_report_generation()
        
        # This example requires network access and external dependencies
        print(f"\nTo run the full analysis example, ensure you have:")
        print("1. External dependencies installed (beautifulsoup4, lxml, tldextract, pyyaml)")
        print("2. Network access")
        print("3. Optional: VirusTotal API key configured")
        print("\nThen run: python examples/example_usage.py --full")
        
        if len(sys.argv) > 1 and '--full' in sys.argv:
            example_basic_analysis()
        
        print(f"\n✅ Examples completed successfully!")
        
    except Exception as e:
        print(f"❌ Example failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()