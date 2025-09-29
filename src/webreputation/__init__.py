"""
WebReputation - Automated Malicious Site Analysis Tool

This package provides tools for:
- IOC extraction from suspicious websites
- VirusTotal reputation lookups
- Redirect chain analysis
- Payload extraction and analysis
"""

from .analyzer import WebReputationAnalyzer
from .ioc_extractor import IOCExtractor
from .virustotal_client import VirusTotalClient
from .web_scraper import WebScraper

__all__ = [
    'WebReputationAnalyzer',
    'IOCExtractor', 
    'VirusTotalClient',
    'WebScraper'
]