import argparse
import logging
import sys

from log_parser import read_log_file
from llm_engine import extract_iocs
from report_writer import display_report

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="AI-powered OSINT Threat Analyzer")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to the log file to analyze")
    args = parser.parse_args()

    try:
        raw_log_data = read_log_file(args.file)
        logger.info(f"Analyzing {args.file}...")
        
        result = extract_iocs(raw_log_data)
        display_report(result)
        
    except Exception as e:
        logger.error(f"Execution failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()