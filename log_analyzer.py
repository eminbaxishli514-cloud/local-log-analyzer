#!/usr/bin/env python3
"""
Local Log Analyzer - Summarizes patterns in logs.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional


class LogAnalyzer:
    ERROR_PATTERNS = [
        r'\berror\b', r'\bERROR\b', r'\bError\b',
        r'\bfatal\b', r'\bFATAL\b', r'\bFatal\b',
        r'\bfailed\b', r'\bFAILED\b', r'\bFailed\b',
        r'\bexception\b', r'\bEXCEPTION\b', r'\bException\b',
        r'\bcritical\b', r'\bCRITICAL\b', r'\bCritical\b'
    ]
    
    WARNING_PATTERNS = [
        r'\bwarn\b', r'\bWARN\b', r'\bWarn\b',
        r'\bwarning\b', r'\bWARNING\b', r'\bWarning\b',
        r'\balert\b', r'\bALERT\b', r'\bAlert\b',
        r'\bnotice\b', r'\bNOTICE\b', r'\bNotice\b'
    ]
    
    def __init__(self, log_file: Path):
        self.log_file = Path(log_file)
        self.entries = []
        self.errors = []
        self.warnings = []
        self.error_counts = Counter()
        self.warning_counts = Counter()
        self.patterns = defaultdict(int)
    
    def parse_syslog(self, line: str) -> Optional[Dict]:
        """Parse syslog format entry."""
        # Syslog format: MMM DD HH:MM:SS hostname service: message
        pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+?):\s+(.+)$'
        match = re.match(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'service': match.group(3),
                'message': match.group(4),
                'raw': line
            }
        return None
    
    def parse_apache(self, line: str) -> Optional[Dict]:
        """Parse Apache access log format."""
        # Common Apache format: IP - - [timestamp] "method path protocol" status size
        pattern = r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)'
        match = re.match(pattern, line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(4),
                'request': match.group(5),
                'status': match.group(6),
                'size': match.group(7),
                'raw': line
            }
        return None
    
    def parse_json(self, line: str) -> Optional[Dict]:
        """Parse JSON log format."""
        try:
            data = json.loads(line)
            return {'data': data, 'raw': line}
        except json.JSONDecodeError:
            return None
    
    def parse_generic(self, line: str) -> Dict:
        """Parse generic log format."""
        return {'raw': line, 'message': line}
    
    def load_logs(self, log_format: str = 'auto'):
        """Load and parse log file."""
        if not self.log_file.exists():
            raise FileNotFoundError(f"Log file not found: {self.log_file}")
        
        print(f"Loading log file: {self.log_file}")
        
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                entry = None
                
                if log_format == 'auto':
                    # Try to auto-detect format
                    if self.parse_syslog(line):
                        entry = self.parse_syslog(line)
                    elif self.parse_apache(line):
                        entry = self.parse_apache(line)
                    elif self.parse_json(line):
                        entry = self.parse_json(line)
                    else:
                        entry = self.parse_generic(line)
                elif log_format == 'syslog':
                    entry = self.parse_syslog(line) or self.parse_generic(line)
                elif log_format == 'apache':
                    entry = self.parse_apache(line) or self.parse_generic(line)
                elif log_format == 'nginx':
                    entry = self.parse_apache(line) or self.parse_generic(line)  # Similar format
                elif log_format == 'json':
                    entry = self.parse_json(line) or self.parse_generic(line)
                else:
                    entry = self.parse_generic(line)
                
                entry['line_number'] = line_num
                self.entries.append(entry)
        
        print(f"Loaded {len(self.entries)} log entries")
    
    def analyze(self):
        """Analyze log entries for errors, warnings, and patterns."""
        print("Analyzing log entries...")
        
        for entry in self.entries:
            message = entry.get('message', entry.get('raw', ''))
            
            # Check for errors
            is_error = any(re.search(pattern, message, re.IGNORECASE) 
                          for pattern in self.ERROR_PATTERNS)
            
            # Check for warnings
            is_warning = any(re.search(pattern, message, re.IGNORECASE) 
                           for pattern in self.WARNING_PATTERNS)
            
            if is_error:
                self.errors.append(entry)
                # Extract error message pattern (first 100 chars)
                error_msg = message[:100].strip()
                self.error_counts[error_msg] += 1
            
            if is_warning:
                self.warnings.append(entry)
                # Extract warning message pattern
                warning_msg = message[:100].strip()
                self.warning_counts[warning_msg] += 1
            
            # Extract common patterns
            # IP addresses
            ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            if re.search(ip_pattern, message):
                self.patterns['Contains IP address'] += 1
            
            # HTTP status codes
            status_pattern = r'\b(4\d{2}|5\d{2})\b'
            if re.search(status_pattern, message):
                status = re.search(status_pattern, message).group()
                self.patterns[f'HTTP {status}'] += 1
            
            # Timestamps
            time_pattern = r'\d{2}:\d{2}:\d{2}'
            if re.search(time_pattern, message):
                self.patterns['Contains timestamp'] += 1
        
        print(f"Found {len(self.errors)} errors and {len(self.warnings)} warnings")
    
    def generate_report(self, top_n: int = 10, errors_only: bool = False, 
                       warnings_only: bool = False, output_file: Optional[str] = None) -> str:
        """Generate analysis report."""
        lines = []
        lines.append("=" * 70)
        lines.append("LOG ANALYSIS REPORT")
        lines.append("=" * 70)
        lines.append(f"Log File: {self.log_file}")
        lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 70)
        lines.append(f"Total Log Entries: {len(self.entries)}")
        lines.append(f"Total Errors: {len(self.errors)}")
        lines.append(f"Total Warnings: {len(self.warnings)}")
        lines.append("")
        
        # Errors
        if not warnings_only:
            lines.append("ERRORS")
            lines.append("-" * 70)
            if self.errors:
                lines.append(f"\nTop {min(top_n, len(self.error_counts))} Most Frequent Errors:")
                for i, (error_msg, count) in enumerate(self.error_counts.most_common(top_n), 1):
                    lines.append(f"  {i}. [{count}x] {error_msg[:80]}")
                
                if len(self.errors) > top_n:
                    lines.append(f"\n... and {len(self.errors) - top_n} more error entries")
            else:
                lines.append("No errors found.")
            lines.append("")
        
        # Warnings
        if not errors_only:
            lines.append("WARNINGS")
            lines.append("-" * 70)
            if self.warnings:
                lines.append(f"\nTop {min(top_n, len(self.warning_counts))} Most Frequent Warnings:")
                for i, (warning_msg, count) in enumerate(self.warning_counts.most_common(top_n), 1):
                    lines.append(f"  {i}. [{count}x] {warning_msg[:80]}")
                
                if len(self.warnings) > top_n:
                    lines.append(f"\n... and {len(self.warnings) - top_n} more warning entries")
            else:
                lines.append("No warnings found.")
            lines.append("")
        
        # Patterns
        if self.patterns:
            lines.append("PATTERNS")
            lines.append("-" * 70)
            for pattern, count in sorted(self.patterns.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  {pattern}: {count}")
            lines.append("")
        
        # Error rate
        if len(self.entries) > 0:
            error_rate = (len(self.errors) / len(self.entries)) * 100
            warning_rate = (len(self.warnings) / len(self.entries)) * 100
            lines.append("STATISTICS")
            lines.append("-" * 70)
            lines.append(f"Error Rate: {error_rate:.2f}%")
            lines.append(f"Warning Rate: {warning_rate:.2f}%")
        
        report_text = "\n".join(lines)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"\nReport saved to: {output_file}")
        else:
            print("\n" + report_text)
        
        return report_text


def main():
    parser = argparse.ArgumentParser(
        description='Local Log Analyzer - Analyze log files for errors and patterns'
    )
    parser.add_argument('log_file', type=str, help='Log file to analyze')
    parser.add_argument('--output', '-o', type=str, help='Output file for report')
    parser.add_argument('--format', '-f', choices=['auto', 'syslog', 'apache', 'nginx', 'json'],
                        default='auto', help='Log format')
    parser.add_argument('--top', type=int, default=10,
                        help='Show top N errors/warnings')
    parser.add_argument('--errors-only', action='store_true',
                        help='Show only errors')
    parser.add_argument('--warnings-only', action='store_true',
                        help='Show only warnings')
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.log_file)
    
    try:
        analyzer.load_logs(args.format)
        analyzer.analyze()
        analyzer.generate_report(
            top_n=args.top,
            errors_only=args.errors_only,
            warnings_only=args.warnings_only,
            output_file=args.output
        )
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

