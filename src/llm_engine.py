import json
import logging
from typing import List
from pydantic import BaseModel, ValidationError
import ollama

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
Analyse the raw data dump and extract indicators of compromise (IoCs) including IP addresses, domains, and threat actor aliases.
"""

class ThreatReport(BaseModel):
    suspicious_ips: List[str]
    malicious_domains: List[str]
    threat_actor_aliases: List[str]
    risk_level: str
    analysis_summary: str

def extract_iocs(raw_text: str, model_name: str = "llama3") -> dict:
    try:
        response = ollama.chat(
            model=model_name,
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                {'role': 'user', 'content': raw_text}
            ],
            format=ThreatReport.model_json_schema()
        )
        
        return ThreatReport.model_validate_json(response['message']['content']).model_dump()
        
    except ollama.ResponseError as e:
        logger.error(f"Ollama API error: {e}")
        raise
    except ValidationError as e:
        logger.error(f"Failed to parse model output into expected schema: {e}")
        raise

if __name__ == "__main__":
    sample_log = "User 'DarkEagle' attempted login from 192.168.1.105. Connecting to payload server at evil-domain.net."
    
    try:
        result = extract_iocs(sample_log)
        print(json.dumps(result, indent=2))
    except Exception:
        logger.error("IoC extraction failed.")