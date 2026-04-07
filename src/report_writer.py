from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.console import Group

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