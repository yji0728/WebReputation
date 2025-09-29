#!/usr/bin/env python3
"""
WebReputation - Malicious Site Analysis Tool

Command-line interface for comprehensive web reputation analysis.
"""

import sys
import os
import argparse
from datetime import datetime
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from webreputation.analyzer import WebReputationAnalyzer


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description='WebReputation - Automated Malicious Site Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webreputation.py -u https://suspicious-site.com
  python webreputation.py -u https://malware.example.com -o results.json --save-payloads
  python webreputation.py -u https://phishing.example.com --config custom_config.yaml --report

This tool will:
1. Scrape the target URL and follow redirects
2. Extract IOCs (URLs, IPs, domains, file hashes)
3. Query VirusTotal for reputation information
4. Analyze payload files
5. Generate comprehensive analysis report
        """
    )
    
    # Required arguments
    parser.add_argument(
        '-u', '--url',
        required=True,
        help='Target URL to analyze'
    )
    
    # Optional arguments
    parser.add_argument(
        '-c', '--config',
        help='Path to configuration file (default: config.yaml)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path for results (default: results_<timestamp>.json)'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate and display human-readable report'
    )
    
    parser.add_argument(
        '--save-payloads',
        action='store_true',
        help='Download and save payload files'
    )
    
    parser.add_argument(
        '--payload-dir',
        default='./payloads',
        help='Directory to save payloads (default: ./payloads)'
    )
    
    parser.add_argument(
        '--max-depth',
        type=int,
        default=5,
        help='Maximum analysis depth for discovered URLs (default: 5)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=1.0,
        help='Delay between requests in seconds (default: 1.0)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate URL
    if not (args.url.startswith('http://') or args.url.startswith('https://')):
        print("Error: URL must start with http:// or https://")
        return 1
    
    # Setup output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"results_{timestamp}.json"
    
    print("WebReputation - Malicious Site Analysis Tool")
    print("=" * 50)
    print(f"Target URL: {args.url}")
    print(f"Output file: {args.output}")
    
    if args.save_payloads:
        print(f"Payload directory: {args.payload_dir}")
    
    print(f"Max analysis depth: {args.max_depth}")
    print(f"Request delay: {args.delay}s")
    print()
    
    try:
        # Initialize analyzer
        analyzer = WebReputationAnalyzer(config_path=args.config)
        
        # Override configuration with CLI arguments if provided
        if args.save_payloads:
            analyzer.save_payloads = True
            analyzer.payload_directory = args.payload_dir
        
        if args.max_depth:
            analyzer.max_depth = args.max_depth
        
        if args.delay:
            analyzer.delay_between_requests = args.delay
        
        # Perform analysis
        results = analyzer.analyze_url(args.url)
        
        # Save results
        analyzer.save_results(results, args.output)
        
        # Generate report if requested
        if args.report:
            print("\n" + "="*80)
            print("ANALYSIS REPORT")
            print("="*80)
            report = analyzer.generate_report(results)
            print(report)
            
            # Save report to text file
            report_path = args.output.replace('.json', '_report.txt')
            try:
                with open(report_path, 'w') as f:
                    f.write(report)
                print(f"\nReport saved to: {report_path}")
            except Exception as e:
                print(f"Warning: Could not save report: {e}")
        
        # Display summary
        print(f"\nAnalysis completed successfully!")
        summary = results.get('summary', {})
        
        if summary.get('malicious_indicators', 0) > 0:
            print(f"⚠️  MALICIOUS INDICATORS DETECTED: {summary['malicious_indicators']}")
            return 2  # Exit code 2 for malicious content
        elif summary.get('suspicious_indicators', 0) > 0:
            print(f"⚠️  SUSPICIOUS INDICATORS DETECTED: {summary['suspicious_indicators']}")
            return 1  # Exit code 1 for suspicious content
        else:
            print("✅ No malicious indicators detected")
            return 0  # Exit code 0 for clean content
        
    except KeyboardInterrupt:
        print("\n\nAnalysis interrupted by user")
        return 130
    except Exception as e:
        print(f"\nError during analysis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def check_requirements():
    """Check if required dependencies are installed."""
    required_modules = [
        'requests', 'beautifulsoup4', 'lxml', 'tldextract', 'pyyaml'
    ]
    
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module.replace('-', '_'))
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print("Error: Missing required dependencies:")
        for module in missing_modules:
            print(f"  - {module}")
        print("\nPlease install them using:")
        print(f"  pip install {' '.join(missing_modules)}")
        return False
    
    return True


if __name__ == '__main__':
    # Check requirements first
    if not check_requirements():
        sys.exit(1)
    
    # Run main function
    exit_code = main()
    sys.exit(exit_code)