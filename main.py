import typer
import json
import os
from scan_engine.core import ScanEngine

app = typer.Typer()

@app.command()
def scan(
    path: str = typer.Option(".", "--path", "-p", help="Path to the source code to scan"),
    type: str = typer.Option("manual", "--type", "-t", help="Type of scan (manual/ci)"),
    output: str = typer.Option("scan_results.json", "--output", "-o", help="Output file for results")
):
    """
    Trigger a vulnerability scan on the specified path.
    """
    if not os.path.exists(path):
        typer.echo(f"Error: Path '{path}' does not exist.")
        raise typer.Exit(code=1)

    engine = ScanEngine()
    result = engine.run_scan(path, type)

    # Convert to dictionary and save to JSON
    # using model_dump if pydantic v2, or dict() if v1
    # assuming pydantic v2 or compatible
    try:
        data = result.model_dump(mode='json')
    except AttributeError:
        data = result.dict() 
        # Manual datetime conversion if needed for v1, but generic should handle it usually or use json=True

    with open(output, "w") as f:
        json.dump(data, f, indent=4, default=str)

    typer.echo(f"Scan complete. Found {len(result.vulnerabilities)} vulnerabilities.")
    typer.echo(f"Results saved to {output}")

@app.command()
def patch(
    vuln_id: str = typer.Option(..., "--id", "-i", help="Vulnerability ID to patch"),
    role: str = typer.Option("ADMIN", "--role", help="User Role (ADMIN/DEVELOPER/VIEWER)")
):
    """
    Generate a patch for a specific vulnerability ID.
    """
    
    from scan_engine.auth import AuthService
    auth = AuthService()
    if not auth.check_permission(role, "patch"):
        typer.echo(f"⛔ Access Denied: Role {role} cannot generate patches.")
        raise typer.Exit(1)
        
    from scan_engine.patching.generator import PatchGenerator
    
    generator = PatchGenerator()
    try:
        suggestion = generator.generate_patch(vuln_id)
        
        typer.echo(f"Patch generated for {vuln_id}")
        typer.echo("---------------------------------------------------")
        typer.echo(f"Confidence: {suggestion.confidence_score}% | Risk: {suggestion.risk_level}")
        typer.echo(f"Explanation: {suggestion.explanation}")
        typer.echo("---------------------------------------------------")
        typer.echo("Diff:")
        typer.echo(suggestion.diff)
        
    except Exception as e:
        typer.echo(f"Error generating patch: {e}")

@app.command()
def review(
    role: str = typer.Option("ADMIN", "--role", help="User Role (ADMIN/DEVELOPER/VIEWER)")
):
    """
    Interactive AI Patch Lab. Review pending patches.
    """
    from scan_engine.auth import AuthService
    auth = AuthService()
    if not auth.check_permission(role, "review"):
        typer.echo(f"⛔ Access Denied: Role {role} cannot review patches.")
        raise typer.Exit(1)
        
    from scan_engine.intel.db import get_session
    from scan_engine.intel.models import VulnerabilityRecord, VulnerabilityState
    from scan_engine.patching.models import PatchSuggestion
    from scan_engine.intel.lifecycle import LifecycleManager
    from scan_engine.patching.feedback import FeedbackService

    session = get_session()
    lifecycle = LifecycleManager()
    feedback_service = FeedbackService()
    
    # Get vulns with VALIDATED or FIX_GENERATED state
    vulns = session.query(VulnerabilityRecord).filter(
        VulnerabilityRecord.state.in_([VulnerabilityState.VALIDATED, VulnerabilityState.FIX_GENERATED])
    ).all()
    
    if not vulns:
        typer.echo("No patches pending review.")
        return

    for vuln in vulns:
        # Get latest patch
        patch = session.query(PatchSuggestion).filter(
            PatchSuggestion.vulnerability_id == vuln.id
        ).order_by(PatchSuggestion.created_at.desc()).first()
        
        if not patch:
            continue
            
        typer.clear()
        typer.echo("===================================================")
        typer.echo(f"PATCH LAB REVIEW | Vulnerability: {vuln.name}")
        typer.echo("===================================================")
        typer.echo(f"Severity: {vuln.severity} | State: {vuln.state.value}")
        typer.echo(f"Validation: {patch.validation_status} | Msg: {patch.validation_message}")
        typer.echo(f"Risk: {patch.risk_level} (Conf: {patch.confidence_score}%)")
        typer.echo("---------------------------------------------------")
        typer.echo("Diff:")
        typer.echo(patch.diff)
        typer.echo("---------------------------------------------------")
        
        choice = typer.prompt("Action? [A]pprove, [R]eject, [S]kip").lower()
        
        if choice == 'a':
            lifecycle.transition_state(vuln.id, VulnerabilityState.FIXED, "Patch Approved in Lab")
            feedback_service.record_feedback(patch.id, "APPROVE", "Correct fix")
            typer.echo("Patch APPROVED.")
        elif choice == 'r':
            reason = typer.prompt("Reason for rejection?")
            lifecycle.transition_state(vuln.id, VulnerabilityState.REJECTED, f"Patch Rejected: {reason}")
            feedback_service.record_feedback(patch.id, "REJECT", reason)
            typer.echo("Patch REJECTED.")
        else:
            typer.echo("Skipped.")
            
        input("Press Enter to continue...")

@app.command()
def dashboard(
   role: str = typer.Option("ADMIN", "--role", help="User Role")
):
    """
    Show Self-Healing Security Dashboard.
    """
    # Anyone can view dashboard, but we just show support for the flag
    from scan_engine.visualization import PipelineVisualizer
    viz = PipelineVisualizer()
    viz.display_dashboard()
    input("\nPress Enter to exit...")

@app.command()
def export_audit(
    role: str = typer.Option("ADMIN", "--role", help="User Role")
):
    """
    Export System Audit Logs (Admin Only).
    """
    from scan_engine.auth import AuthService
    auth = AuthService()
    if not auth.check_permission(role, "export_audit"):
        typer.echo(f"⛔ Access Denied: Role {role} cannot export audit logs.")
        raise typer.Exit(1)
    
    from scan_engine.audit import AuditService
    svc = AuditService()
    print(svc.export_logs_json())

if __name__ == "__main__":
    app()
