import logging
from typing import List
from pydantic import BaseModel, ValidationError
import ollama

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.console import Group

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

def display_report(data: dict):
    console = Console()
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Indicator Type", style="cyan", width=20)
    table.add_column("Extracted Value", style="green")

    for ip in data.get("suspicious_ips", []):
        table.add_row("Suspicious IP", ip)
    for domain in data.get("malicious_domains", []):
        table.add_row("Malicious Domain", domain)
    for alias in data.get("threat_actor_aliases", []):
        table.add_row("Actor Alias", alias)

    risk = data.get("risk_level", "UNKNOWN").upper()
    risk_color = "red" if risk in ["HIGH", "CRITICAL"] else "yellow" if risk == "MEDIUM" else "green"

    summary = f"\n[bold white]Analysis Summary:[/bold white] {data.get('analysis_summary', 'N/A')}\n"
    summary += f"[bold white]Calculated Risk:[/bold white] [bold {risk_color}]{risk}[/bold {risk_color}]"

    panel = Panel(
        Group(table, summary), 
        title="[bold blue]🛡️ OSINT Threat Intelligence Report[/bold blue]", 
        border_style="blue", 
        expand=False
    )
    console.print(panel)

if __name__ == "__main__":
    sample_log = "User 'DarkEagle' attempted login from 192.168.1.105. Connecting to payload server at evil-domain.net."
    
    try:
        logger.info("Executing local model inference...")
        result = extract_iocs(sample_log)
        display_report(result)
    except Exception:
        logger.error("IoC extraction failed.")