from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from scan_engine.analytics import AnalyticsService
from scan_engine.intel.models import VulnerabilityState

class PipelineVisualizer:
    def __init__(self):
        self.console = Console()
        self.analytics = AnalyticsService()

    def display_dashboard(self):
        kpis = self.analytics.get_kpis()
        avg_fix_time = self.analytics.get_avg_fix_time_seconds()
        health_score = self.analytics.get_health_score()
        trend_data = self.analytics.get_trend_data()

        self.console.clear()
        self.console.rule("[bold blue]Self-Healing Security Dashboard")
        self.console.print("")

        # Top Grid: KPIs + Health
        grid = Table.grid(expand=True, padding=(1, 2))
        grid.add_column()
        grid.add_column()
        
        # KPI Table
        kpi_table = Table(show_header=False, box=box.SIMPLE)
        kpi_table.add_column("Metric")
        kpi_table.add_column("Value")
        kpi_table.add_row("Total Vulns", f"[cyan]{kpis['total']}[/]")
        kpi_table.add_row("Auto-Fixed", f"[green]{kpis['fixed']}[/]")
        kpi_table.add_row("Active", f"[yellow]{kpis['pending']}[/]")
        kpi_table.add_row("Success Rate", f"[magenta]{kpis['success_rate']}%[/]")
        kpi_table.add_row("Avg Fix Time", f"[blue]{avg_fix_time}s[/]")
        
        # Health Score Panel
        color = "green" if health_score > 80 else "yellow" if health_score > 50 else "red"
        health_panel = Panel(
            f"[{color} bold]{health_score}/100[/]", 
            title="[b]Security Health[/b]", 
            border_style=color,
            width=20,
            height=7
        )

        # Activity Feed (Simulated Trend)
        activity_text = Text()
        for action in trend_data[-5:]:
            if "FIXED" in action:
                activity_text.append(f"✅ {action}\n", style="green")
            elif "DETECTED" in action:
                activity_text.append(f"⚠️ {action}\n", style="yellow")
            else:
                activity_text.append(f"⏺ {action}\n", style="white")
        
        activity_panel = Panel(activity_text, title="Recent Activity", border_style="blue")
        
        # layout
        layout_table = Table.grid(expand=True, padding=2)
        layout_table.add_column(ratio=2)
        layout_table.add_column(ratio=1)
        layout_table.add_row(Panel(kpi_table, title="KPIs"), health_panel) 
        
        self.console.print(layout_table)
        self.console.print(activity_panel)
        self.console.print("")

        # Bottom Section: Pipeline View
        pipeline_table = Table(title="Vulnerability Pipeline", box=box.ROUNDED)
        pipeline_table.add_column("ID", style="dim", width=8)
        pipeline_table.add_column("Vulnerability")
        pipeline_table.add_column("Severity")
        pipeline_table.add_column("Review Stage", justify="center")
        pipeline_table.add_column("Status", justify="center")

        vulns = self.analytics.get_pipeline_data()
        
        for vuln in vulns:
            # Determine visual indicator for stage
            stage_style = "white"
            icon = "⏺"
            
            if vuln.state == VulnerabilityState.FIXED:
                stage_style = "green"
                icon = "✅"
            elif vuln.state == VulnerabilityState.REJECTED:
                stage_style = "red"
                icon = "❌"
            elif vuln.state == VulnerabilityState.VALIDATED:
                stage_style = "cyan"
                icon = "⚡" # Ready for review
            elif vuln.state == VulnerabilityState.FIX_GENERATED:
                stage_style = "blue"
                icon = "🤖" # AI Working
            
            pipeline_table.add_row(
                vuln.id[:8],
                vuln.name,
                vuln.severity,
                f"[{stage_style}]{vuln.state.value}[/]",
                icon
            )

        self.console.print(pipeline_table)
