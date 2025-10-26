"""Generate combined dashboard reports."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from tcpviz.src.logging_utils import get_logger
from tcpviz.src.viz.summary import render_summary
from tcpviz.src.viz.timeline import render as render_timeline

LOGGER = get_logger(__name__)


def generate_report(events_path: str | Path, output_dir: str | Path | None = None) -> Path:
    """Generate a combined timeline + summary dashboard."""

    events_file = Path(events_path)
    target_dir = Path(output_dir) if output_dir else events_file.parent
    target_dir.mkdir(parents=True, exist_ok=True)

    timeline_path = render_timeline(events_file, output_dir=target_dir)
    summary_path = render_summary(events_file, output_dir=target_dir)

    timeline_html = timeline_path.read_text(encoding="utf-8")
    summary_html = summary_path.read_text(encoding="utf-8")

    report_path = target_dir / "report.html"
    report_path.write_text(
        _compose_dashboard(timeline_html, summary_html),
        encoding="utf-8",
    )

    LOGGER.info("Wrote combined report to %s", report_path)
    return report_path


def _compose_dashboard(timeline_html: str, summary_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>tcpviz dashboard</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
    header {{ padding: 1.5rem; background: #1f2933; color: #fff; }}
    main {{ display: flex; flex-direction: column; gap: 2rem; padding: 1.5rem; }}
    section {{ background: #fff; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); overflow: hidden; }}
    .section-body {{ padding: 1rem; }}
    iframe {{ width: 100%; border: none; min-height: 480px; }}
  </style>
</head>
<body>
  <header>
    <h1>tcpviz dashboard</h1>
    <p>Combined timeline and summary for the selected capture.</p>
  </header>
  <main>
    <section>
      <div class="section-body">
        <h2>Timeline</h2>
        {timeline_html}
      </div>
    </section>
    <section>
      <div class="section-body">
        <h2>Flow Summary</h2>
        {summary_html}
      </div>
    </section>
  </main>
</body>
</html>
"""


__all__ = ["generate_report"]
