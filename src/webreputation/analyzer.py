"""
Web Reputation Analyzer

Main orchestrator that coordinates IOC extraction, VirusTotal analysis,
and web scraping to provide comprehensive malicious site analysis.
"""

import os
import json
import yaml
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from .ioc_extractor import IOCExtractor
from .virustotal_client import VirusTotalClient
from .web_scraper import WebScraper


class WebReputationAnalyzer:
    """Main analyzer for comprehensive web reputation analysis."""
    
    def __init__(self, config_path: str = None):
        """
        Initialize the analyzer.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.ioc_extractor = IOCExtractor()
        
        # Initialize VirusTotal client if API key is provided
        self.vt_client = None
        vt_api_key = self.config.get('virustotal', {}).get('api_key')
        if vt_api_key and vt_api_key != "YOUR_VIRUSTOTAL_API_KEY_HERE":
            try:
                self.vt_client = VirusTotalClient(vt_api_key)
                print("VirusTotal client initialized successfully")
            except Exception as e:
                print(f"Warning: Failed to initialize VirusTotal client: {e}")
        else:
            print("Warning: VirusTotal API key not configured. VT analysis will be skipped.")
        
        # Initialize web scraper
        scraper_config = self.config.get('web_scraper', {})
        self.web_scraper = WebScraper(scraper_config)
        
        # Analysis configuration
        self.analysis_config = self.config.get('analysis', {})
        self.max_depth = self.analysis_config.get('max_depth', 5)
        self.delay_between_requests = self.analysis_config.get('delay_between_requests', 1)
        self.save_payloads = self.analysis_config.get('save_payloads', True)
        self.payload_directory = self.analysis_config.get('payload_directory', './payloads')
        
        # Results storage
        self.results = {}
        self.analyzed_urls = set()
    
    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """Load configuration from file."""
        if config_path is None:
            # Look for config in current directory or parent
            current_dir = os.getcwd()
            possible_paths = [
                os.path.join(current_dir, 'config.yaml'),
                os.path.join(os.path.dirname(current_dir), 'config.yaml'),
                os.path.join(os.path.dirname(__file__), '..', '..', 'config.yaml')
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    break
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                print(f"Loaded configuration from: {config_path}")
                return config
            except Exception as e:
                print(f"Error loading config file {config_path}: {e}")
        
        # Return default configuration
        print("Using default configuration")
        return {
            'web_scraper': {
                'timeout': 30,
                'max_redirects': 10,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            'analysis': {
                'max_depth': 5,
                'delay_between_requests': 1,
                'save_payloads': True,
                'payload_directory': './payloads'
            }
        }
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a suspicious URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Complete analysis results
        """
        print(f"\n{'='*60}")
        print(f"Starting analysis of: {url}")
        print(f"{'='*60}")
        
        analysis_start_time = datetime.now()
        
        # Initialize results structure
        results = {
            'analysis_info': {
                'target_url': url,
                'start_time': analysis_start_time.isoformat(),
                'analyzer_version': '1.0.0'
            },
            'web_scraping': {},
            'ioc_extraction': {},
            'virustotal_analysis': {},
            'redirect_chain_analysis': {},
            'payload_analysis': [],
            'summary': {
                'total_urls_analyzed': 0,
                'malicious_indicators': 0,
                'suspicious_indicators': 0,
                'payloads_found': 0,
                'redirect_depth': 0
            }
        }
        
        # Step 1: Scrape initial URL and analyze redirects
        print("\n[1] Web Scraping and Redirect Analysis")
        scraping_results = self.web_scraper.scrape_url(url)
        results['web_scraping'] = scraping_results
        
        if scraping_results.get('error'):
            print(f"Error scraping URL: {scraping_results['error']}")
            results['analysis_info']['error'] = scraping_results['error']
            return results
        
        # Analyze redirect chain
        redirect_analysis = self.web_scraper.analyze_redirect_chain(url)
        results['redirect_chain_analysis'] = redirect_analysis
        results['summary']['redirect_depth'] = redirect_analysis.get('total_redirects', 0)
        
        # Collect all URLs to analyze (original + redirects + extracted URLs)
        urls_to_analyze = set([url])
        if redirect_analysis.get('chain'):
            urls_to_analyze.update(redirect_analysis['chain'])
        
        # Step 2: Extract IOCs from scraped content
        print("\n[2] IOC Extraction")
        if scraping_results.get('content'):
            iocs = self.ioc_extractor.extract_all_iocs(
                scraping_results['content'], 
                scraping_results.get('final_url', url)
            )
            results['ioc_extraction'] = iocs
            
            # Add extracted URLs to analysis queue
            urls_to_analyze.update(iocs.get('urls', []))
            
            print(f"Extracted IOCs:")
            print(f"  - URLs: {len(iocs.get('urls', []))}")
            print(f"  - Domains: {len(iocs.get('domains', []))}")
            print(f"  - IP addresses: {len(iocs.get('ips', []))}")
            print(f"  - File hashes: {sum(len(v) for v in iocs.get('file_hashes', {}).values())}")
            print(f"  - Suspicious files: {len(iocs.get('suspicious_files', []))}")
        
        # Step 3: VirusTotal Analysis
        print("\n[3] VirusTotal Reputation Analysis")
        if self.vt_client and results.get('ioc_extraction'):
            try:
                vt_results = self.vt_client.analyze_iocs(results['ioc_extraction'])
                results['virustotal_analysis'] = vt_results
                
                # Update summary with VT results
                vt_summary = vt_results.get('summary', {})
                results['summary']['malicious_indicators'] = vt_summary.get('total_malicious', 0)
                results['summary']['suspicious_indicators'] = vt_summary.get('total_suspicious', 0)
                
                print(f"VirusTotal Analysis Summary:")
                print(f"  - Malicious: {vt_summary.get('total_malicious', 0)}")
                print(f"  - Suspicious: {vt_summary.get('total_suspicious', 0)}")
                print(f"  - Clean: {vt_summary.get('total_clean', 0)}")
                print(f"  - Unknown: {vt_summary.get('total_unknown', 0)}")
                
            except Exception as e:
                print(f"Error in VirusTotal analysis: {e}")
                results['virustotal_analysis'] = {'error': str(e)}
        else:
            print("VirusTotal analysis skipped (no API key or no IOCs)")
        
        # Step 4: Recursive analysis of redirect chain and extracted URLs
        print("\n[4] Recursive Analysis of Discovered URLs")
        analyzed_count = 1  # Count the original URL
        
        # Limit analysis to prevent infinite loops
        urls_to_analyze = list(urls_to_analyze)[:self.max_depth]
        
        for discovered_url in urls_to_analyze[1:]:  # Skip the original URL
            if discovered_url != url and discovered_url not in self.analyzed_urls:
                print(f"\nAnalyzing discovered URL: {discovered_url}")
                
                # Add delay between requests
                if analyzed_count > 1:
                    time.sleep(self.delay_between_requests)
                
                # Scrape discovered URL
                discovered_results = self.web_scraper.scrape_url(discovered_url)
                
                # Extract IOCs from discovered URL
                if discovered_results.get('content'):
                    discovered_iocs = self.ioc_extractor.extract_all_iocs(
                        discovered_results['content'],
                        discovered_url
                    )
                    
                    # Analyze with VirusTotal if available
                    if self.vt_client:
                        try:
                            discovered_vt = self.vt_client.analyze_iocs(discovered_iocs)
                            # Add to main results
                            if 'discovered_urls' not in results:
                                results['discovered_urls'] = {}
                            
                            results['discovered_urls'][discovered_url] = {
                                'scraping': discovered_results,
                                'iocs': discovered_iocs,
                                'virustotal': discovered_vt
                            }
                            
                        except Exception as e:
                            print(f"Error analyzing {discovered_url}: {e}")
                
                self.analyzed_urls.add(discovered_url)
                analyzed_count += 1
                
                if analyzed_count >= self.max_depth:
                    print(f"Reached maximum analysis depth ({self.max_depth})")
                    break
        
        results['summary']['total_urls_analyzed'] = analyzed_count
        
        # Step 5: Payload Analysis and Download
        print("\n[5] Payload Analysis")
        payloads = scraping_results.get('payloads', [])
        
        # Also check for payloads in discovered URLs
        if 'discovered_urls' in results:
            for disc_url, disc_data in results['discovered_urls'].items():
                payloads.extend(disc_data.get('scraping', {}).get('payloads', []))
        
        results['summary']['payloads_found'] = len(payloads)
        
        if payloads and self.save_payloads:
            print(f"Found {len(payloads)} potential payloads")
            
            for i, payload in enumerate(payloads):
                print(f"\nAnalyzing payload {i+1}/{len(payloads)}: {payload.get('url', 'Unknown')}")
                
                if payload.get('type') == 'direct_download':
                    # Payload is already downloaded (was the response content)
                    payload_analysis = {
                        'payload_info': payload,
                        'download_attempted': False,
                        'reason': 'Direct download - content already captured'
                    }
                    
                    if self.vt_client:
                        # Check hash with VirusTotal
                        file_hash = payload.get('sha256', payload.get('md5'))
                        if file_hash:
                            try:
                                vt_report = self.vt_client.get_file_report(file_hash)
                                payload_analysis['virustotal_report'] = vt_report
                            except Exception as e:
                                payload_analysis['virustotal_error'] = str(e)
                    
                elif payload.get('type') == 'linked_payload':
                    # Attempt to download linked payload
                    download_result = self.web_scraper.download_payload(
                        payload['url'], 
                        self.payload_directory
                    )
                    payload_analysis = {
                        'payload_info': payload,
                        'download_result': download_result
                    }
                    
                    if download_result.get('success') and self.vt_client:
                        # Check downloaded file with VirusTotal
                        file_hash = download_result.get('sha256')
                        if file_hash:
                            try:
                                vt_report = self.vt_client.get_file_report(file_hash)
                                payload_analysis['virustotal_report'] = vt_report
                            except Exception as e:
                                payload_analysis['virustotal_error'] = str(e)
                
                results['payload_analysis'].append(payload_analysis)
        
        # Finalize results
        analysis_end_time = datetime.now()
        results['analysis_info']['end_time'] = analysis_end_time.isoformat()
        results['analysis_info']['duration_seconds'] = (analysis_end_time - analysis_start_time).total_seconds()
        
        print(f"\n{'='*60}")
        print(f"Analysis completed in {results['analysis_info']['duration_seconds']:.2f} seconds")
        print(f"URLs analyzed: {results['summary']['total_urls_analyzed']}")
        print(f"Malicious indicators: {results['summary']['malicious_indicators']}")
        print(f"Suspicious indicators: {results['summary']['suspicious_indicators']}")
        print(f"Payloads found: {results['summary']['payloads_found']}")
        print(f"{'='*60}")
        
        return results
    
    def save_results(self, results: Dict[str, Any], output_path: str) -> None:
        """
        Save analysis results to file.
        
        Args:
            results: Analysis results to save
            output_path: Output file path
        """
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\nResults saved to: {output_path}")
            
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def generate_report(self, results: Dict[str, Any]) -> str:
        """
        Generate a human-readable report from analysis results.
        
        Args:
            results: Analysis results
            
        Returns:
            Formatted report string
        """
        report = []
        
        # Header
        report.append("="*80)
        report.append("WEB REPUTATION ANALYSIS REPORT")
        report.append("="*80)
        
        # Analysis info
        info = results.get('analysis_info', {})
        report.append(f"\nTarget URL: {info.get('target_url', 'Unknown')}")
        report.append(f"Analysis Time: {info.get('start_time', 'Unknown')}")
        report.append(f"Duration: {info.get('duration_seconds', 0):.2f} seconds")
        
        # Summary
        summary = results.get('summary', {})
        report.append(f"\nSUMMARY:")
        report.append(f"  URLs Analyzed: {summary.get('total_urls_analyzed', 0)}")
        report.append(f"  Malicious Indicators: {summary.get('malicious_indicators', 0)}")
        report.append(f"  Suspicious Indicators: {summary.get('suspicious_indicators', 0)}")
        report.append(f"  Payloads Found: {summary.get('payloads_found', 0)}")
        report.append(f"  Redirect Depth: {summary.get('redirect_depth', 0)}")
        
        # Web scraping results
        scraping = results.get('web_scraping', {})
        if scraping:
            report.append(f"\nWEB SCRAPING:")
            report.append(f"  Final URL: {scraping.get('final_url', 'Unknown')}")
            report.append(f"  Status Code: {scraping.get('status_code', 'Unknown')}")
            report.append(f"  Content Type: {scraping.get('content_type', 'Unknown')}")
            report.append(f"  Page Title: {scraping.get('page_title', 'None')}")
            
            if scraping.get('redirect_chain'):
                report.append(f"  Redirect Chain ({len(scraping['redirect_chain'])} steps):")
                for i, redirect_url in enumerate(scraping['redirect_chain']):
                    report.append(f"    {i+1}. {redirect_url}")
        
        # VirusTotal results
        vt_analysis = results.get('virustotal_analysis', {})
        if vt_analysis and 'error' not in vt_analysis:
            vt_summary = vt_analysis.get('summary', {})
            report.append(f"\nVIRUSTOTAL ANALYSIS:")
            report.append(f"  Total Malicious: {vt_summary.get('total_malicious', 0)}")
            report.append(f"  Total Suspicious: {vt_summary.get('total_suspicious', 0)}")
            report.append(f"  Total Clean: {vt_summary.get('total_clean', 0)}")
            report.append(f"  Total Unknown: {vt_summary.get('total_unknown', 0)}")
            
            # Show malicious URLs
            malicious_urls = []
            for url_result in vt_analysis.get('urls', []):
                if url_result.get('classification') == 'malicious':
                    malicious_urls.append(url_result.get('resource', 'Unknown'))
            
            if malicious_urls:
                report.append(f"\n  Malicious URLs:")
                for url in malicious_urls:
                    report.append(f"    - {url}")
        
        # Payload analysis
        payload_analysis = results.get('payload_analysis', [])
        if payload_analysis:
            report.append(f"\nPAYLOAD ANALYSIS:")
            for i, payload in enumerate(payload_analysis):
                payload_info = payload.get('payload_info', {})
                report.append(f"  Payload {i+1}:")
                report.append(f"    URL: {payload_info.get('url', 'Unknown')}")
                report.append(f"    Type: {payload_info.get('type', 'Unknown')}")
                
                if 'download_result' in payload:
                    download = payload['download_result']
                    if download.get('success'):
                        report.append(f"    Downloaded: {download.get('filepath', 'Unknown')}")
                        report.append(f"    Size: {download.get('size', 0)} bytes")
                        report.append(f"    MD5: {download.get('md5', 'Unknown')}")
                        report.append(f"    SHA256: {download.get('sha256', 'Unknown')}")
        
        report.append("\n" + "="*80)
        
        return "\n".join(report)