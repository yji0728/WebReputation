"""
Web Scraper with Redirect Following

This module provides web scraping capabilities with support for:
- Following redirect chains
- Extracting page content
- Payload detection and download
- Header analysis
"""

import requests
import os
import hashlib
import mimetypes
from urllib.parse import urlparse, urljoin, urlunparse
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional, Tuple
import time


class WebScraper:
    """Web scraper with redirect following and payload extraction."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize web scraper.
        
        Args:
            config: Configuration dictionary with scraper settings
        """
        self.timeout = config.get('timeout', 30)
        self.max_redirects = config.get('max_redirects', 10)
        self.user_agent = config.get('user_agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        self.headers = config.get('headers', {})
        self.headers['User-Agent'] = self.user_agent
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.max_redirects = self.max_redirects
        
        # Results storage
        self.redirect_chain = []
        self.payloads = []
        self.scraped_content = {}
    
    def scrape_url(self, url: str, follow_redirects: bool = True) -> Dict[str, Any]:
        """
        Scrape a URL and analyze its content.
        
        Args:
            url: URL to scrape
            follow_redirects: Whether to follow redirects
            
        Returns:
            Scraping results including content, redirects, and payloads
        """
        results = {
            'original_url': url,
            'final_url': url,
            'redirect_chain': [],
            'status_code': None,
            'headers': {},
            'content': '',
            'content_type': '',
            'content_length': 0,
            'page_title': '',
            'payloads': [],
            'suspicious_elements': [],
            'javascript_code': [],
            'forms': [],
            'error': None
        }
        
        try:
            print(f"Scraping URL: {url}")
            
            # Configure session for this request
            if follow_redirects:
                self.session.max_redirects = self.max_redirects
            else:
                self.session.max_redirects = 0
            
            # Make request
            response = self.session.get(url, timeout=self.timeout, allow_redirects=follow_redirects)
            
            # Update results with response info
            results['final_url'] = response.url
            results['status_code'] = response.status_code
            results['headers'] = dict(response.headers)
            results['content'] = response.text
            results['content_type'] = response.headers.get('content-type', '')
            results['content_length'] = len(response.content)
            
            # Build redirect chain
            if response.history:
                results['redirect_chain'] = [resp.url for resp in response.history]
                results['redirect_chain'].append(response.url)
            
            # Parse content if it's HTML
            if 'text/html' in results['content_type'].lower():
                soup = BeautifulSoup(response.text, 'html.parser')
                results.update(self._analyze_html_content(soup, response.url))
            
            # Check for potential payloads
            results['payloads'] = self._detect_payloads(response, results['final_url'])
            
            print(f"Scraping completed. Final URL: {results['final_url']}")
            
        except requests.exceptions.Timeout:
            results['error'] = f"Timeout after {self.timeout} seconds"
        except requests.exceptions.ConnectionError:
            results['error'] = "Connection error"
        except requests.exceptions.TooManyRedirects:
            results['error'] = f"Too many redirects (>{self.max_redirects})"
        except Exception as e:
            results['error'] = f"Scraping failed: {str(e)}"
        
        return results
    
    def _analyze_html_content(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """
        Analyze HTML content for suspicious elements.
        
        Args:
            soup: BeautifulSoup object
            base_url: Base URL for resolving relative links
            
        Returns:
            Dictionary with analyzed HTML elements
        """
        analysis = {
            'page_title': '',
            'suspicious_elements': [],
            'javascript_code': [],
            'forms': []
        }
        
        # Extract page title
        title_tag = soup.find('title')
        if title_tag:
            analysis['page_title'] = title_tag.get_text().strip()
        
        # Extract JavaScript code
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                js_code = script.string.strip()
                if js_code:
                    analysis['javascript_code'].append({
                        'code': js_code,
                        'length': len(js_code),
                        'suspicious_keywords': self._find_suspicious_js_keywords(js_code)
                    })
            elif script.get('src'):
                analysis['javascript_code'].append({
                    'src': urljoin(base_url, script.get('src')),
                    'external': True
                })
        
        # Analyze forms
        forms = soup.find_all('form')
        for form in forms:
            form_info = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_info = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'id': inp.get('id', ''),
                    'value': inp.get('value', '')
                }
                form_info['inputs'].append(input_info)
            
            analysis['forms'].append(form_info)
        
        # Find suspicious elements
        suspicious_elements = []
        
        # Look for suspicious links
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href')
            if href and self._is_suspicious_link(href):
                suspicious_elements.append({
                    'type': 'suspicious_link',
                    'element': 'a',
                    'href': urljoin(base_url, href),
                    'text': link.get_text().strip()
                })
        
        # Look for embedded objects
        objects = soup.find_all(['object', 'embed', 'iframe'])
        for obj in objects:
            src = obj.get('src') or obj.get('data')
            if src:
                suspicious_elements.append({
                    'type': 'embedded_object',
                    'element': obj.name,
                    'src': urljoin(base_url, src),
                    'attributes': dict(obj.attrs)
                })
        
        analysis['suspicious_elements'] = suspicious_elements
        
        return analysis
    
    def _find_suspicious_js_keywords(self, js_code: str) -> List[str]:
        """Find suspicious keywords in JavaScript code."""
        suspicious_keywords = [
            'eval', 'document.write', 'innerHTML', 'outerHTML',
            'createElement', 'appendChild', 'XMLHttpRequest',
            'ActiveXObject', 'WScript.Shell', 'Shell.Application',
            'unescape', 'String.fromCharCode', 'atob', 'btoa',
            'location.href', 'window.open', 'document.location'
        ]
        
        found_keywords = []
        js_lower = js_code.lower()
        
        for keyword in suspicious_keywords:
            if keyword.lower() in js_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def _is_suspicious_link(self, href: str) -> bool:
        """Check if a link is suspicious."""
        suspicious_patterns = [
            '.exe', '.bat', '.cmd', '.scr', '.pif', '.com',
            '.zip', '.rar', '.7z', '.jar', '.vbs', '.ps1'
        ]
        
        href_lower = href.lower()
        return any(pattern in href_lower for pattern in suspicious_patterns)
    
    def _detect_payloads(self, response: requests.Response, url: str) -> List[Dict[str, Any]]:
        """
        Detect potential payloads in the response.
        
        Args:
            response: HTTP response object
            url: URL that was scraped
            
        Returns:
            List of detected payloads
        """
        payloads = []
        
        content_type = response.headers.get('content-type', '').lower()
        
        # Check if response itself is a payload
        if self._is_payload_content_type(content_type):
            payload_info = {
                'type': 'direct_download',
                'url': url,
                'content_type': content_type,
                'size': len(response.content),
                'md5': hashlib.md5(response.content).hexdigest(),
                'sha256': hashlib.sha256(response.content).hexdigest(),
                'headers': dict(response.headers)
            }
            payloads.append(payload_info)
        
        # If HTML content, look for download links
        elif 'text/html' in content_type:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find download links
            links = soup.find_all('a', href=True)
            for link in links:
                href = link.get('href')
                if href and self._is_potential_payload_link(href):
                    payload_info = {
                        'type': 'linked_payload',
                        'url': urljoin(url, href),
                        'link_text': link.get_text().strip(),
                        'discovered_on': url
                    }
                    payloads.append(payload_info)
        
        return payloads
    
    def _is_payload_content_type(self, content_type: str) -> bool:
        """Check if content type indicates a potential payload."""
        payload_types = [
            'application/octet-stream',
            'application/x-msdownload',
            'application/x-executable',
            'application/zip',
            'application/x-zip-compressed',
            'application/x-rar-compressed',
            'application/java-archive'
        ]
        
        return any(payload_type in content_type for payload_type in payload_types)
    
    def _is_potential_payload_link(self, href: str) -> bool:
        """Check if a link potentially points to a payload."""
        payload_extensions = [
            '.exe', '.msi', '.bat', '.cmd', '.scr', '.pif', '.com',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.jar', '.apk',
            '.vbs', '.ps1', '.dll', '.sys', '.bin'
        ]
        
        href_lower = href.lower()
        return any(href_lower.endswith(ext) for ext in payload_extensions)
    
    def download_payload(self, payload_url: str, output_dir: str) -> Dict[str, Any]:
        """
        Download a payload file for analysis.
        
        Args:
            payload_url: URL of the payload to download
            output_dir: Directory to save the payload
            
        Returns:
            Download results
        """
        result = {
            'url': payload_url,
            'success': False,
            'filename': '',
            'filepath': '',
            'size': 0,
            'md5': '',
            'sha256': '',
            'content_type': '',
            'error': None
        }
        
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            print(f"Downloading payload: {payload_url}")
            
            # Download the file
            response = self.session.get(payload_url, timeout=self.timeout, stream=True)
            response.raise_for_status()
            
            # Determine filename
            filename = self._get_filename_from_response(response, payload_url)
            filepath = os.path.join(output_dir, filename)
            
            # Download and save file
            content = b''
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        content += chunk
            
            # Calculate hashes
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            
            result.update({
                'success': True,
                'filename': filename,
                'filepath': filepath,
                'size': len(content),
                'md5': md5_hash,
                'sha256': sha256_hash,
                'content_type': response.headers.get('content-type', '')
            })
            
            print(f"Payload downloaded successfully: {filepath}")
            print(f"MD5: {md5_hash}")
            print(f"SHA256: {sha256_hash}")
            
        except Exception as e:
            result['error'] = f"Download failed: {str(e)}"
            print(f"Failed to download payload: {str(e)}")
        
        return result
    
    def _get_filename_from_response(self, response: requests.Response, url: str) -> str:
        """Extract filename from response headers or URL."""
        # Try to get filename from Content-Disposition header
        content_disposition = response.headers.get('content-disposition', '')
        if 'filename=' in content_disposition:
            filename = content_disposition.split('filename=')[1].strip('"\'')
            return filename
        
        # Fall back to URL path
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        
        if not filename or '.' not in filename:
            # Generate filename based on content type
            content_type = response.headers.get('content-type', '').split(';')[0]
            extension = mimetypes.guess_extension(content_type) or '.bin'
            filename = f"payload_{int(time.time())}{extension}"
        
        return filename
    
    def analyze_redirect_chain(self, url: str) -> Dict[str, Any]:
        """
        Analyze the complete redirect chain for a URL.
        
        Args:
            url: Starting URL
            
        Returns:
            Analysis of the complete redirect chain
        """
        chain_analysis = {
            'original_url': url,
            'chain': [],
            'final_url': url,
            'total_redirects': 0,
            'suspicious_redirects': [],
            'domains_in_chain': [],
            'error': None
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Build redirect chain
            if response.history:
                chain = [url]
                for resp in response.history:
                    chain.append(resp.url)
                chain.append(response.url)
                
                chain_analysis['chain'] = chain
                chain_analysis['final_url'] = response.url
                chain_analysis['total_redirects'] = len(response.history)
                
                # Extract domains
                domains = set()
                for chain_url in chain:
                    parsed = urlparse(chain_url)
                    if parsed.netloc:
                        domains.add(parsed.netloc.lower())
                
                chain_analysis['domains_in_chain'] = list(domains)
                
                # Analyze for suspicious patterns
                suspicious = []
                for i, chain_url in enumerate(chain):
                    if self._is_suspicious_redirect_url(chain_url):
                        suspicious.append({
                            'position': i,
                            'url': chain_url,
                            'reason': 'Suspicious URL pattern'
                        })
                
                chain_analysis['suspicious_redirects'] = suspicious
            
        except Exception as e:
            chain_analysis['error'] = f"Redirect analysis failed: {str(e)}"
        
        return chain_analysis
    
    def _is_suspicious_redirect_url(self, url: str) -> bool:
        """Check if a redirect URL is suspicious."""
        suspicious_patterns = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',  # URL shorteners
            'redirect', 'redir', 'goto', 'link',  # Redirect keywords
            'download', 'payload', 'malware'  # Suspicious keywords
        ]
        
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in suspicious_patterns)