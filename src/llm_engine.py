import json
import logging
from typing import List
from pydantic import BaseModel
import ollama

# Configure basic logging for the module
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Separate configuration from logic
SYSTEM_PROMPT = """
Analyse the following raw data dump. 
Extract indicators of compromise (IoCs) including IP addresses, domains, and threat actor aliases.
Output strictly in the requested JSON format.
"""

class ThreatReport(BaseModel):
    suspicious_ips: List[str]
    malicious_domains: List[str]
    threat_actor_aliases: List[str]
    risk_level: str
    analysis_summary: str

def extract_iocs(raw_text: str, model_name: str = "llama3") -> str:
    """
    Processes raw text through a local LLM to extract structured IoCs.
    """
    try:
        response = ollama.chat(
            model=model_name,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': raw_text}
            ],
            format=ThreatReport.model_json_schema()
        )
        
        return response['message']['content']
        
    except Exception as e:
        logger.error(f"Local LLM Engine failed to connect: {e}")
        return json.dumps({"error": "LLM extraction failed", "details": str(e)})

if __name__ == "__main__":
    sample_log = "User 'DarkEagle' attempted login from 192.168.1.105. Connecting to payload server at evil-domain.net."
    logger.info("Executing local model inference...")
    
    result = extract_iocs(sample_log)
    print(json.dumps(json.loads(result), indent=2)) # Formats the output for readability