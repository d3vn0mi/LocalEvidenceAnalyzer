"""Rich-based progress display for Kagami."""

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

SEVERITY_STYLES = {
    "Critical": "bold red",
    "High": "bold bright_red",
    "Medium": "bold yellow",
    "Low": "bold blue",
    "Info": "dim",
}


class AnalysisProgress:
    """Manages a rich live display for the analysis pipeline."""

    def __init__(self, console=None):
        self.console = console or Console(stderr=True)
        self._hosts = []
        self._model = ""
        self._kb_enabled = False
        self._kb_chunks = 0
        self._total_findings = 0
        self._severity_counts = {}
        self._checkpoint_status = ""
        self._current_file = ""
        self._current_host = ""
        self._file_log = []  # (filepath, n_findings, status)
        self._phase = "init"

        # Phase 1 progress bar
        self._file_progress = Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold cyan]Phase 1[/]"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("files"),
            TimeElapsedColumn(),
            console=self.console,
            expand=False,
        )
        self._file_task = None
        self._file_total = 0

        # Phase 2 progress bar
        self._phase2_progress = Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold magenta]Phase 2[/]"),
            TextColumn("{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
            expand=False,
        )
        self._phase2_task = None

        self._live = None

    def _build_layout(self):
        """Build the full rich renderable for the live display."""
        # Header panel
        info_parts = []
        if self._hosts:
            hosts_str = ", ".join(self._hosts)
            info_parts.append(f"[bold]Hosts:[/] {hosts_str}")
        if self._model:
            info_parts.append(f"[bold]Model:[/] {self._model}")
        features = []
        if self._kb_enabled:
            features.append(f"KB ({self._kb_chunks} chunks)")
        if self._checkpoint_status:
            features.append(f"Checkpoint: {self._checkpoint_status}")
        if features:
            info_parts.append("[bold]Features:[/] " + " | ".join(features))

        header = Panel(
            "\n".join(info_parts) if info_parts else "Starting...",
            title="[bold white]Kagami[/]",
            border_style="cyan",
            expand=False,
            width=60,
        )

        # Main table layout
        layout = Table.grid(padding=(0, 0))
        layout.add_row(header)
        layout.add_row("")  # spacer

        # Progress bar
        if self._phase == "phase1" and self._file_task is not None:
            layout.add_row(self._file_progress)
        elif self._phase == "phase2" and self._phase2_task is not None:
            layout.add_row(self._phase2_progress)

        layout.add_row("")  # spacer

        # Recent file log (last 8 files)
        if self._file_log:
            log_table = Table(
                show_header=False, show_edge=False, box=None, padding=(0, 1),
                expand=False,
            )
            log_table.add_column("status", width=2)
            log_table.add_column("file", min_width=30)
            log_table.add_column("findings", justify="right", min_width=14)

            visible = self._file_log[-8:]
            for filepath, n_findings, status in visible:
                if status == "done":
                    icon = "[green]✓[/]"
                    findings_text = self._format_findings_count(n_findings)
                elif status == "analyzing":
                    icon = "[yellow]⠋[/]"
                    findings_text = "[dim]analyzing...[/]"
                elif status == "skipped":
                    icon = "[dim]–[/]"
                    findings_text = "[dim]checkpoint[/]"
                else:
                    icon = " "
                    findings_text = ""
                log_table.add_row(icon, filepath, findings_text)

            layout.add_row(log_table)
            layout.add_row("")

        # Findings summary bar
        if self._total_findings > 0 or self._phase != "init":
            summary = self._build_severity_summary()
            layout.add_row(summary)

        return layout

    def _format_findings_count(self, n):
        if n == 0:
            return "[dim]0 findings[/]"
        return f"[bold]{n}[/] finding{'s' if n != 1 else ''}"

    def _build_severity_summary(self):
        parts = [f"[bold]Findings:[/] {self._total_findings} raw"]
        for sev in ("Critical", "High", "Medium", "Low", "Info"):
            count = self._severity_counts.get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLES.get(sev, "")
                parts.append(f"[{style}]{sev}: {count}[/]")
        return Text.from_markup("  ".join(parts))

    def start(self):
        self._live = Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.start()

    def stop(self):
        if self._live:
            self._live.stop()
            self._live = None

    def _refresh(self):
        if self._live:
            self._live.update(self._build_layout())

    def set_config(self, model, kb_enabled=False, kb_chunks=0):
        self._model = model
        self._kb_enabled = kb_enabled
        self._kb_chunks = kb_chunks
        self._refresh()

    def set_checkpoint_status(self, status):
        self._checkpoint_status = status
        self._refresh()

    def start_host(self, host_name, n_files, n_skipped):
        if host_name not in self._hosts:
            self._hosts.append(host_name)
        self._current_host = host_name
        self._phase = "phase1"
        self._file_total += n_files
        if self._file_task is None:
            self._file_task = self._file_progress.add_task(
                "Analyzing", total=self._file_total,
            )
        else:
            self._file_progress.update(self._file_task, total=self._file_total)
        self._refresh()

    def start_file(self, filepath):
        self._current_file = filepath
        display = f"{self._current_host}/{filepath}"
        # Replace any prior "analyzing" entry for this file
        self._file_log = [
            entry for entry in self._file_log if entry[2] != "analyzing"
        ]
        self._file_log.append((display, 0, "analyzing"))
        self._refresh()

    def skip_file(self, filepath):
        display = f"{self._current_host}/{filepath}"
        self._file_log.append((display, 0, "skipped"))
        if self._file_task is not None:
            self._file_progress.advance(self._file_task)
        self._refresh()

    def finish_file(self, filepath, n_findings):
        display = f"{self._current_host}/{filepath}"
        # Replace the "analyzing" entry with "done"
        self._file_log = [
            entry for entry in self._file_log
            if not (entry[0] == display and entry[2] == "analyzing")
        ]
        self._file_log.append((display, n_findings, "done"))
        if self._file_task is not None:
            self._file_progress.advance(self._file_task)
        self._refresh()

    def add_findings(self, findings):
        """Track severity counts from a list of finding dicts."""
        self._total_findings += len(findings)
        for f in findings:
            sev = f.get("severity", "Info")
            self._severity_counts[sev] = self._severity_counts.get(sev, 0) + 1
        self._refresh()

    def start_phase2(self):
        self._phase = "phase2"
        self._file_log = [
            entry for entry in self._file_log if entry[2] != "analyzing"
        ]
        self._phase2_task = self._phase2_progress.add_task(
            "Consolidating & deduplicating...",
        )
        self._refresh()

    def finish_phase2(self, n_consolidated):
        if self._phase2_task is not None:
            self._phase2_progress.update(
                self._phase2_task,
                description=f"Consolidated to [bold]{n_consolidated}[/] findings",
            )
        self._refresh()

    def print_final_summary(self, findings, output_path=None):
        """Print a styled final summary after the report is generated."""
        self.stop()

        # Build severity table
        table = Table(title="Final Report Summary", border_style="green", expand=False)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        counts = {}
        for f in findings:
            sev = getattr(f, "severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1

        for sev in severity_order:
            count = counts.get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLES.get(sev, "")
                table.add_row(f"[{style}]{sev}[/]", f"[{style}]{count}[/]")

        total = sum(counts.values())
        table.add_section()
        table.add_row("[bold]Total[/]", f"[bold]{total}[/]")

        self.console.print()
        self.console.print(table)
        if output_path:
            self.console.print(f"\n[bold green]Report saved to:[/] {output_path}")
        self.console.print()


class QuietProgress:
    """No-op progress display for non-verbose mode or when stdout is used."""

    def start(self): pass
    def stop(self): pass
    def set_config(self, *a, **kw): pass
    def set_checkpoint_status(self, *a, **kw): pass
    def start_host(self, *a, **kw): pass
    def start_file(self, *a, **kw): pass
    def skip_file(self, *a, **kw): pass
    def finish_file(self, *a, **kw): pass
    def add_findings(self, *a, **kw): pass
    def start_phase2(self): pass
    def finish_phase2(self, *a, **kw): pass
    def print_final_summary(self, *a, **kw): pass
