# Local Log Analyzer

Summarizes patterns in logs: frequent errors, warnings, or repeated events.

## Features

- **Error Detection**: Identifies and counts error messages
- **Warning Detection**: Tracks warning messages
- **Pattern Analysis**: Finds repeated patterns and events
- **Time-based Analysis**: Analyzes log entries by timestamp
- **Summary Reports**: Generates comprehensive analysis reports
- **Multiple Log Formats**: Supports common log formats (syslog, apache, nginx, etc.)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python log_analyzer.py [OPTIONS] LOG_FILE
```

### Options

- `--output FILE`: Save analysis report to file
- `--format FORMAT`: Log format (auto, syslog, apache, nginx, json) - default: auto
- `--top N`: Show top N most frequent errors/warnings
- `--time-range START END`: Analyze logs within time range
- `--errors-only`: Show only error messages
- `--warnings-only`: Show only warning messages

### Examples

```bash
# Analyze a log file
python log_analyzer.py /var/log/syslog

# Show top 10 errors
python log_analyzer.py app.log --top 10 --errors-only

# Analyze Apache access logs
python log_analyzer.py access.log --format apache

# Save report to file
python log_analyzer.py app.log --output analysis.txt
```

## Output

The analyzer provides:
- Total log entries
- Error count and list
- Warning count and list
- Most frequent error messages
- Most frequent warning messages
- Time-based patterns
- Unique error patterns

