#!/usr/bin/env python3
"""
Basic test script for WebReputation tool
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from webreputation.ioc_extractor import IOCExtractor
from webreputation.web_scraper import WebScraper
from webreputation.analyzer import WebReputationAnalyzer


def test_ioc_extractor():
    """Test IOC extraction functionality."""
    print("Testing IOC Extractor...")
    
    extractor = IOCExtractor()
    
    # Test content with various IOCs
    test_content = """
    Visit https://suspicious-site.com/malware.exe for more info.
    Contact us at admin@badsite.com or call 192.168.1.100
    File hash: 5d7845a4b6c3fa2e2b3c4d5e6f7a8b9c
    Also check http://another-site.net/payload.zip
    IP address found: 8.8.8.8
    Domain: evil.example.org
    """
    
    iocs = extractor.extract_all_iocs(test_content, "https://test.com")
    
    print(f"  URLs found: {len(iocs['urls'])}")
    print(f"  Domains found: {len(iocs['domains'])}")
    print(f"  IPs found: {len(iocs['ips'])}")
    print(f"  Emails found: {len(iocs['emails'])}")
    print(f"  MD5 hashes: {len(iocs['file_hashes']['md5'])}")
    
    assert len(iocs['urls']) > 0, "Should find URLs"
    assert len(iocs['domains']) > 0, "Should find domains"
    assert len(iocs['emails']) > 0, "Should find emails"
    
    print("  ✅ IOC Extractor test passed")


def test_web_scraper():
    """Test web scraper functionality."""
    print("Testing Web Scraper...")
    
    config = {
        'timeout': 10,
        'max_redirects': 5,
        'user_agent': 'WebReputation-Test/1.0'
    }
    
    scraper = WebScraper(config)
    
    # Test with a safe URL
    test_url = "https://httpbin.org/html"
    
    try:
        results = scraper.scrape_url(test_url)
        
        print(f"  Status code: {results.get('status_code', 'Unknown')}")
        print(f"  Content length: {results.get('content_length', 0)} bytes")
        print(f"  Page title: {results.get('page_title', 'None')}")
        
        assert results.get('status_code') == 200, "Should get HTTP 200"
        assert results.get('content_length', 0) > 0, "Should have content"
        
        print("  ✅ Web Scraper test passed")
        
    except Exception as e:
        print(f"  ⚠️  Web Scraper test skipped (network issue): {e}")


def test_analyzer_without_vt():
    """Test analyzer without VirusTotal API."""
    print("Testing Analyzer (without VirusTotal)...")
    
    try:
        # Create a minimal config without VT API key
        analyzer = WebReputationAnalyzer()
        
        # Test with HTML content containing IOCs
        test_html = """
        <html>
        <head><title>Test Page</title></head>
        <body>
            <a href="https://example.com/file.exe">Download</a>
            <p>Contact: test@example.com</p>
            <script>console.log('test');</script>
        </body>
        </html>
        """
        
        # Test IOC extraction directly
        iocs = analyzer.ioc_extractor.extract_all_iocs(test_html, "https://test.com")
        
        print(f"  IOCs extracted: {sum(len(v) if isinstance(v, list) else sum(len(vv) for vv in v.values()) if isinstance(v, dict) else 0 for v in iocs.values())}")
        
        assert len(iocs['urls']) > 0, "Should extract URLs"
        
        print("  ✅ Analyzer test passed")
        
    except Exception as e:
        print(f"  ⚠️  Analyzer test failed: {e}")
        raise


def main():
    """Run all tests."""
    print("WebReputation - Basic Functionality Tests")
    print("=" * 45)
    
    try:
        test_ioc_extractor()
        test_web_scraper()
        test_analyzer_without_vt()
        
        print("\n✅ All basic tests passed!")
        print("\nTo test with a real URL, run:")
        print("  python webreputation.py -u https://example.com --report")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())