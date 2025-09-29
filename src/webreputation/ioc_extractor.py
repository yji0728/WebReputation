"""
IOC (Indicators of Compromise) Extractor

This module extracts various IOCs from web content including:
- URLs
- IP addresses
- Domain names
- File hashes (MD5, SHA1, SHA256)
"""

import re
import ipaddress
import tldextract
from typing import List, Dict, Set, Any
from urllib.parse import urlparse, urljoin


class IOCExtractor:
    """Extract IOCs from web content and HTML."""
    
    def __init__(self):
        # Regex patterns for different IOC types
        self.patterns = {
            'url': re.compile(
                r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?[\w&=%.]*)?)?' 
                r'|ftp://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?',
                re.IGNORECASE | re.MULTILINE
            ),
            'ip': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            'domain': re.compile(
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            ),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        }
        
        # Common file extensions that might contain payloads
        self.payload_extensions = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.pdf', '.doc', '.docx',
            '.xls', '.xlsx', '.ppt', '.pptx', '.scr', '.com', '.pif'
        }
    
    def extract_all_iocs(self, content: str, base_url: str = None) -> Dict[str, List[str]]:
        """
        Extract all types of IOCs from content.
        
        Args:
            content: The content to extract IOCs from
            base_url: Base URL for resolving relative URLs
            
        Returns:
            Dictionary containing lists of different IOC types
        """
        iocs = {
            'urls': self.extract_urls(content, base_url),
            'ips': self.extract_ips(content),
            'domains': self.extract_domains(content),
            'file_hashes': self.extract_file_hashes(content),
            'emails': self.extract_emails(content),
            'suspicious_files': self.extract_suspicious_files(content, base_url)
        }
        
        return iocs
    
    def extract_urls(self, content: str, base_url: str = None) -> List[str]:
        """Extract URLs from content."""
        urls = set()
        
        # Find URLs using regex
        matches = self.patterns['url'].findall(content)
        for match in matches:
            urls.add(match.strip())
        
        # If base_url is provided, resolve relative URLs
        if base_url:
            # Look for relative URLs in href and src attributes
            relative_patterns = [
                r'href=["\']([^"\']+)["\']',
                r'src=["\']([^"\']+)["\']',
                r'action=["\']([^"\']+)["\']'
            ]
            
            for pattern in relative_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if not match.startswith(('http://', 'https://', 'ftp://', 'mailto:', 'javascript:', '#')):
                        try:
                            full_url = urljoin(base_url, match)
                            if self._is_valid_url(full_url):
                                urls.add(full_url)
                        except Exception:
                            continue
        
        return list(urls)
    
    def extract_ips(self, content: str) -> List[str]:
        """Extract IP addresses from content."""
        ips = set()
        matches = self.patterns['ip'].findall(content)
        
        for match in matches:
            try:
                # Validate IP address
                ipaddress.ip_address(match)
                # Exclude private and loopback addresses for external analysis
                ip_obj = ipaddress.ip_address(match)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast):
                    ips.add(match)
            except ValueError:
                continue
                
        return list(ips)
    
    def extract_domains(self, content: str) -> List[str]:
        """Extract domain names from content."""
        domains = set()
        matches = self.patterns['domain'].findall(content)
        
        for match in matches:
            # Use tldextract to validate and clean domains
            try:
                extracted = tldextract.extract(match.lower())
                if extracted.domain and extracted.suffix:
                    domain = f"{extracted.domain}.{extracted.suffix}"
                    if len(extracted.domain) >= 2:  # Minimum domain length
                        domains.add(domain)
            except Exception:
                continue
                
        return list(domains)
    
    def extract_file_hashes(self, content: str) -> Dict[str, List[str]]:
        """Extract file hashes from content."""
        hashes = {
            'md5': list(set(self.patterns['md5'].findall(content))),
            'sha1': list(set(self.patterns['sha1'].findall(content))),
            'sha256': list(set(self.patterns['sha256'].findall(content)))
        }
        
        return hashes
    
    def extract_emails(self, content: str) -> List[str]:
        """Extract email addresses from content."""
        emails = set(self.patterns['email'].findall(content))
        return list(emails)
    
    def extract_suspicious_files(self, content: str, base_url: str = None) -> List[Dict[str, str]]:
        """Extract references to potentially suspicious files."""
        suspicious_files = []
        
        # Look for file references in various attributes
        file_patterns = [
            r'href=["\']([^"\']*\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|zip|rar|7z|scr|com|pif)[^"\']*)["\']',
            r'src=["\']([^"\']*\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|zip|rar|7z|scr|com|pif)[^"\']*)["\']',
            r'action=["\']([^"\']*\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|zip|rar|7z|scr|com|pif)[^"\']*)["\']'
        ]
        
        for pattern in file_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                file_info = {
                    'filename': match.split('/')[-1],
                    'url': match if match.startswith(('http://', 'https://')) else urljoin(base_url or '', match),
                    'extension': '.' + match.split('.')[-1].lower() if '.' in match else ''
                }
                suspicious_files.append(file_info)
        
        return suspicious_files
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if a URL is valid."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def get_unique_domains_from_urls(self, urls: List[str]) -> List[str]:
        """Extract unique domains from a list of URLs."""
        domains = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    extracted = tldextract.extract(parsed.netloc.lower())
                    if extracted.domain and extracted.suffix:
                        domain = f"{extracted.domain}.{extracted.suffix}"
                        domains.add(domain)
            except Exception:
                continue
                
        return list(domains)