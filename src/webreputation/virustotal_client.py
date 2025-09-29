"""
VirusTotal API Client

This module provides a client for querying VirusTotal API to get reputation
information for URLs, domains, IPs, and file hashes.
"""

import requests
import time
import hashlib
import base64
from typing import Dict, Any, Optional, List
import json


class VirusTotalClient:
    """Client for VirusTotal API v3."""
    
    def __init__(self, api_key: str):
        """
        Initialize VirusTotal client.
        
        Args:
            api_key: VirusTotal API key
        """
        if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
            raise ValueError("Valid VirusTotal API key is required")
            
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "X-Apikey": self.api_key,
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Rate limiting (free tier: 4 requests per minute)
        self.request_delay = 15  # seconds between requests
        self.last_request_time = 0
    
    def _make_request(self, endpoint: str, method: str = "GET", data: Dict = None) -> Dict[str, Any]:
        """
        Make a request to VirusTotal API with rate limiting.
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            data: Request data for POST requests
            
        Returns:
            API response as dictionary
        """
        # Rate limiting
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.request_delay:
            sleep_time = self.request_delay - time_since_last_request
            print(f"Rate limiting: waiting {sleep_time:.1f} seconds...")
            time.sleep(sleep_time)
        
        url = f"{self.base_url}/{endpoint}"
        
        try:
            if method == "GET":
                response = self.session.get(url)
            elif method == "POST":
                response = self.session.post(url, data=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Resource not found", "status_code": 404}
            elif response.status_code == 429:
                # Rate limited
                print("Rate limited by VirusTotal. Waiting 60 seconds...")
                time.sleep(60)
                return self._make_request(endpoint, method, data)
            else:
                return {
                    "error": f"API request failed with status {response.status_code}",
                    "status_code": response.status_code,
                    "response": response.text
                }
                
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning and get analysis results.
        
        Args:
            url: URL to scan
            
        Returns:
            Analysis results
        """
        # First, submit URL for scanning
        data = {"url": url}
        submission_result = self._make_request("urls", "POST", data)
        
        if "error" in submission_result:
            return submission_result
        
        # Get the analysis ID
        analysis_id = submission_result.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "Failed to get analysis ID"}
        
        # Wait a bit for analysis to complete
        time.sleep(10)
        
        # Get analysis results
        return self._make_request(f"analyses/{analysis_id}")
    
    def get_url_report(self, url: str) -> Dict[str, Any]:
        """
        Get existing report for a URL.
        
        Args:
            url: URL to check
            
        Returns:
            URL report
        """
        # Encode URL for API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return self._make_request(f"urls/{url_id}")
    
    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Get report for a domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Domain report
        """
        return self._make_request(f"domains/{domain}")
    
    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """
        Get report for an IP address.
        
        Args:
            ip: IP address to check
            
        Returns:
            IP report
        """
        return self._make_request(f"ip_addresses/{ip}")
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get report for a file hash.
        
        Args:
            file_hash: File hash (MD5, SHA1, or SHA256)
            
        Returns:
            File report
        """
        return self._make_request(f"files/{file_hash}")
    
    def analyze_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a collection of IOCs.
        
        Args:
            iocs: Dictionary of IOCs from IOCExtractor
            
        Returns:
            Comprehensive analysis results
        """
        results = {
            "urls": [],
            "domains": [],
            "ips": [],
            "file_hashes": {
                "md5": [],
                "sha1": [],
                "sha256": []
            },
            "summary": {
                "total_malicious": 0,
                "total_suspicious": 0,
                "total_clean": 0,
                "total_unknown": 0
            }
        }
        
        # Analyze URLs
        print(f"Analyzing {len(iocs.get('urls', []))} URLs...")
        for url in iocs.get('urls', []):
            print(f"Checking URL: {url}")
            report = self.get_url_report(url)
            analysis = self._analyze_report(report, 'url')
            analysis['resource'] = url
            results['urls'].append(analysis)
            self._update_summary(results['summary'], analysis)
        
        # Analyze domains
        print(f"Analyzing {len(iocs.get('domains', []))} domains...")
        for domain in iocs.get('domains', []):
            print(f"Checking domain: {domain}")
            report = self.get_domain_report(domain)
            analysis = self._analyze_report(report, 'domain')
            analysis['resource'] = domain
            results['domains'].append(analysis)
            self._update_summary(results['summary'], analysis)
        
        # Analyze IPs
        print(f"Analyzing {len(iocs.get('ips', []))} IP addresses...")
        for ip in iocs.get('ips', []):
            print(f"Checking IP: {ip}")
            report = self.get_ip_report(ip)
            analysis = self._analyze_report(report, 'ip')
            analysis['resource'] = ip
            results['ips'].append(analysis)
            self._update_summary(results['summary'], analysis)
        
        # Analyze file hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            hashes = iocs.get('file_hashes', {}).get(hash_type, [])
            print(f"Analyzing {len(hashes)} {hash_type.upper()} hashes...")
            for file_hash in hashes:
                print(f"Checking {hash_type.upper()}: {file_hash}")
                report = self.get_file_report(file_hash)
                analysis = self._analyze_report(report, 'file')
                analysis['resource'] = file_hash
                analysis['hash_type'] = hash_type.upper()
                results['file_hashes'][hash_type].append(analysis)
                self._update_summary(results['summary'], analysis)
        
        return results
    
    def _analyze_report(self, report: Dict[str, Any], resource_type: str) -> Dict[str, Any]:
        """
        Analyze a VirusTotal report and extract key information.
        
        Args:
            report: VirusTotal API response
            resource_type: Type of resource (url, domain, ip, file)
            
        Returns:
            Analyzed report with classification
        """
        analysis = {
            "classification": "unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "total_engines": 0,
            "first_seen": None,
            "last_seen": None,
            "reputation": 0,
            "raw_report": report
        }
        
        if "error" in report:
            analysis["error"] = report["error"]
            return analysis
        
        # Extract data from report
        data = report.get("data", {})
        attributes = data.get("attributes", {})
        
        # Get detection statistics
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        if last_analysis_stats:
            analysis["malicious_count"] = last_analysis_stats.get("malicious", 0)
            analysis["suspicious_count"] = last_analysis_stats.get("suspicious", 0)
            analysis["clean_count"] = last_analysis_stats.get("harmless", 0) + last_analysis_stats.get("undetected", 0)
            analysis["total_engines"] = sum(last_analysis_stats.values())
        
        # Classification logic
        if analysis["malicious_count"] > 0:
            analysis["classification"] = "malicious"
        elif analysis["suspicious_count"] > 0:
            analysis["classification"] = "suspicious"
        elif analysis["clean_count"] > 0:
            analysis["classification"] = "clean"
        else:
            analysis["classification"] = "unknown"
        
        # Get timestamps
        analysis["first_seen"] = attributes.get("first_submission_date")
        analysis["last_seen"] = attributes.get("last_modification_date")
        
        # Get reputation score
        analysis["reputation"] = attributes.get("reputation", 0)
        
        # Resource-specific information
        if resource_type == "url":
            analysis["final_url"] = attributes.get("last_final_url")
            analysis["redirect_chain"] = attributes.get("redirection_chain", [])
        elif resource_type == "domain":
            analysis["registrar"] = attributes.get("registrar")
            analysis["creation_date"] = attributes.get("creation_date")
        elif resource_type == "file":
            analysis["file_type"] = attributes.get("type_description")
            analysis["file_size"] = attributes.get("size")
            analysis["file_names"] = attributes.get("names", [])
        
        return analysis
    
    def _update_summary(self, summary: Dict[str, int], analysis: Dict[str, Any]) -> None:
        """Update summary statistics."""
        classification = analysis.get("classification", "unknown")
        if classification == "malicious":
            summary["total_malicious"] += 1
        elif classification == "suspicious":
            summary["total_suspicious"] += 1
        elif classification == "clean":
            summary["total_clean"] += 1
        else:
            summary["total_unknown"] += 1