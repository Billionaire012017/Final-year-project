import typer
import json
import os
from scan_engine.core import ScanEngine

app = typer.Typer()

@app.command()
def scan(
    path: str = typer.Option(..., "--path", "-p", help="Path to the source code to scan"),
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
    vuln_id: str = typer.Option(..., "--id", "-i", help="Vulnerability ID to patch")
):
    """
    Generate a patch for a specific vulnerability ID.
    """
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

if __name__ == "__main__":
    app()
