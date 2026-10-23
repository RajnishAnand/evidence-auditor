"""Curses-based terminal UI for local reconnaissance."""

import asyncio
import curses
import json
import textwrap
from collections.abc import Callable

from backend.app.config import settings
from backend.app.scanning.reconnaissance import Reconnaissance
from backend.app.scanning.intelligence import find_candidates
from backend.app.scanning.schemas import ScanResult
from backend.app.storage import ScanStore


def _result_lines(result: ScanResult, width: int = 100) -> list[str]:
    """Turn a result into readable TUI rows, not a raw JSON dump."""
    lines = [
        "SCAN SUMMARY",
        f"  Status       {result.status}",
        f"  Target       {result.target}",
        f"  Final URL    {result.final_url or '—'}",
        f"  HTTP status  {result.http_status or '—'}",
        "",
        "TECHNOLOGY OBSERVATIONS",
    ]
    if result.technologies:
        for technology in result.technologies:
            version = f" {technology.version}" if technology.version else " version unknown"
            lines.append(f"  • {technology.product}{version} [{technology.category}; confidence {technology.confidence:.2f}]")
            lines.append(f"    {technology.evidence_source}: {technology.observed_value}")
    else:
        lines.append("  None detected")
    lines.append("")
    lines.append("VULNERABILITY CANDIDATES")
    if result.vulnerabilities:
        for candidate in result.vulnerabilities:
            score = f"CVSS {candidate.cvss_score}" if candidate.cvss_score is not None else "CVSS unknown"
            version = f" {candidate.matched_version}" if candidate.matched_version else " version unknown"
            lines.append(f"  • {candidate.cve_id} [{candidate.source}; {candidate.severity or 'severity unknown'}; {score}]")
            lines.append(f"    {candidate.product}{version}: {candidate.summary[:150]}")
            lines.append(f"    {candidate.advisory_url}")
            lines.append(f"    Limitation: {candidate.limitation}")
    else:
        lines.append("  None looked up")
    lines.append("")
    sections: list[tuple[str, object]] = [
        ("REDIRECTS", result.redirects),
        ("ERRORS / LIMITATIONS", result.errors),
        ("RESPONSE HEADERS", result.headers),
        ("COOKIES", result.cookies),
        ("HTML METADATA", result.metadata),
        ("REFERENCED ASSETS", result.referenced_assets),
        ("EVIDENCE", [item.model_dump(mode="json") for item in result.evidence]),
    ]
    for title, value in sections:
        lines.append(title)
        if not value:
            lines.append("  None observed")
        elif isinstance(value, dict):
            for key, item in value.items():
                lines.append(f"  {key}: {item}")
        elif isinstance(value, list):
            for item in value:
                rendered = item if isinstance(item, str) else json.dumps(item, sort_keys=True)
                lines.extend(textwrap.wrap(f"  • {rendered}", width=110) or ["  •"])
        lines.append("")
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        wrapped.extend(textwrap.wrap(
            line,
            width=max(40, width),
            replace_whitespace=False,
            drop_whitespace=False,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""])
    return wrapped


def display_result(result: ScanResult, output: Callable[[str], None] = print) -> None:
    """Compatibility renderer useful for tests and non-curses logs."""
    output("\n".join(_result_lines(result)))


async def scan_once(
    target: str,
    authorized: bool,
    follow_redirects: bool | None = True,
    redirect_decider: Callable[[str, str], bool] | None = None,
    progress: Callable[[str], None] | None = None,
    deep_scan: bool = False,
) -> ScanResult:
    return await Reconnaissance(settings).scan(target, authorized, follow_redirects, redirect_decider, progress, deep_scan)


class AuditorTUI:
    def __init__(self, screen: curses.window) -> None:
        self.screen = screen
        self.target = ""
        self.authorized = False
        self.deep_scan = False
        self.focus = 0  # 0 target, 1 authorization, 2 deep scan, 3 scan
        self.page = "target"
        self.message = "Tab: move focus   Space: toggle   Enter: scan   q: quit"
        self.result: ScanResult | None = None
        self.scroll = 0
        self.lines: list[str] = []
        self.spinner_index = 0
        self.spinner_frames = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
        self.scan_stage = "Preparing scan"

    def run(self) -> None:
        curses.curs_set(1)
        self.screen.keypad(True)
        self._colors()
        while True:
            self.draw()
            key = self.screen.get_wch()
            if self.result is not None:
                if key in ("q", "Q"):
                    return
                if key in ("r", "R", "n", "N"):
                    self.result = None
                    self.lines = []
                    self.scroll = 0
                    self.authorized = False
                    self.deep_scan = False
                    self.focus = 0
                    self.page = "target"
                    self.message = "New scan: review target and options"
                    continue
                if key == curses.KEY_UP:
                    self.scroll = max(0, self.scroll - 1)
                elif key == curses.KEY_DOWN:
                    self.scroll = min(max(0, len(self.lines) - 1), self.scroll + 1)
                elif key == curses.KEY_NPAGE:
                    self.scroll = min(max(0, len(self.lines) - 1), self.scroll + max(1, self.screen.getmaxyx()[0] - 10))
                elif key == curses.KEY_PPAGE:
                    self.scroll = max(0, self.scroll - max(1, self.screen.getmaxyx()[0] - 10))
                elif key == curses.KEY_HOME:
                    self.scroll = 0
                elif key == curses.KEY_END:
                    self.scroll = max(0, len(self.lines) - max(1, self.screen.getmaxyx()[0] - 10))
                elif key in ("v", "V"):
                    self._lookup_vulnerabilities()
                continue
            if key in ("q", "Q"):
                return
            if self.page == "target":
                if key in ("\n", "\r", curses.KEY_ENTER):
                    if self.target.strip():
                        self.page = "summary"
                        self.focus = 0
                        self.message = "Review authorization and scan options"
                    else:
                        self.message = "Enter a target URL first"
                else:
                    self._edit_target(key)
                continue
            if self.page == "scanning":
                continue
            if key in ("\t", curses.KEY_DOWN):
                self.focus = (self.focus + 1) % 3
            elif key == curses.KEY_UP:
                self.focus = (self.focus - 1) % 3
            elif key == " ":
                if self.focus == 0:
                    self.authorized = not self.authorized
                elif self.focus == 1:
                    self.deep_scan = not self.deep_scan
                elif self.focus == 2:
                    self._scan()
            elif key in ("\n", "\r", curses.KEY_ENTER):
                if self.focus == 2:
                    self._scan()
                else:
                    self.focus = min(2, self.focus + 1)

    def _colors(self) -> None:
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)

    def _edit_target(self, key: object) -> None:
        if key == "\x15":  # Ctrl-U: clear the target field.
            self.target = ""
            return
        if key in (curses.KEY_BACKSPACE, "\b", "\x7f"):
            self.target = self.target[:-1]
        elif isinstance(key, str) and key.isprintable() and len(self.target) < 200:
            self.target += key

    def _scan(self) -> None:
        if not self.target.strip():
            self.message = "Enter a target URL first."
            self.focus = 0
            return
        if not self.authorized:
            self.message = "Authorization confirmation is required."
            self.focus = 1
            return
        self.page = "scanning"
        self.scan_stage = "Starting authorized reconnaissance"
        self.spinner_index = 0
        self.message = "Scan in progress"
        self.draw()
        try:
            self.result = asyncio.run(scan_once(
                self.target,
                self.authorized,
                follow_redirects=None,
                redirect_decider=self._ask_redirect,
                progress=self._progress,
                deep_scan=self.deep_scan,
            ))
            if self.result.status == "completed":
                ScanStore(settings.database_path).save(self.result)
            self.lines = _result_lines(self.result, self._content_width())
            self.scroll = 0
            self.page = "results"
            self.message = "↑/↓ scroll   PgUp/PgDn page   v lookup   r new scan   q quit"
        except Exception as exc:  # Keep terminal state recoverable after network errors.
            self.page = "summary"
            self.message = f"Scan failed: {exc}"

    def _lookup_vulnerabilities(self) -> None:
        if self.result is None or not self.result.technologies:
            self.message = "No technology observations available for NVD lookup."
            return
        self.message = "Looking up NVD candidates…"
        self.draw()
        try:
            candidates, errors = asyncio.run(find_candidates(self.result.technologies))
            self.result.vulnerabilities = candidates
            self.result.errors.extend(errors)
            if self.result.status == "completed":
                ScanStore(settings.database_path).save(self.result)
            self.lines = _result_lines(self.result, self._content_width())
            self.scroll = 0
            self.message = "Lookup complete   ↑/↓ scroll   PgUp/PgDn page   v refresh   r new scan   q quit"
        except Exception as exc:
            self.message = f"NVD lookup failed: {exc}"

    def _progress(self, stage: str) -> None:
        self.scan_stage = stage
        self.spinner_index = (self.spinner_index + 1) % len(self.spinner_frames)
        self.message = "Scan in progress"
        self.draw()

    def _ask_redirect(self, source: str, destination: str) -> bool:
        """Ask only when a validated redirect is encountered during a scan."""
        height, width = self.screen.getmaxyx()
        self.screen.erase()
        self._box(0, 0, height - 1, width - 2)
        self._title(2, 4, " REDIRECT DETECTED ")
        self._add(4, 5, "The server requested another URL.", curses.A_BOLD)
        self._add(6, 5, f"From: {source}", curses.color_pair(3))
        self._add(7, 5, f"To:   {destination}", curses.color_pair(3))
        self._add(9, 5, "Follow this validated destination? [y/N]", curses.A_REVERSE | curses.A_BOLD)
        self._add(11, 5, "No stops the scan at the redirect. Only continue if authorized.", curses.A_DIM)
        self.screen.refresh()
        key = self.screen.get_wch()
        return key in ("y", "Y")

    def draw(self) -> None:
        self.screen.erase()
        height, width = self.screen.getmaxyx()
        if height < 18 or width < 70:
            self.screen.addstr(0, 0, "Terminal too small. Resize to at least 70x18.", curses.A_BOLD)
            self.screen.refresh()
            return
        # Avoid curses' special lower-right cell: addch() commonly returns
        # ERR there even though the rest of the terminal is drawable.
        self._box(0, 0, height - 1, width - 2)
        self._title(1, 2, " EVIDENCE AUDITOR ")
        self._add(2, 3, "Conservative website reconnaissance", 1)
        self._add(3, 3, "Only assess targets you own or are authorized to test.", curses.A_DIM)
        if self.page == "target":
            self._target_entry(height, width)
        elif self.page == "summary":
            self._summary_form(height, width)
        elif self.page == "scanning":
            self._scanning_page(height, width)
        else:
            self._result_banner(width)
            self._results(height, width)
        self._add(height - 2, 3, "q quit" if self.page == "scanning" else self.message, curses.A_REVERSE)
        self.screen.refresh()

    def _target_entry(self, height: int, width: int) -> None:
        self._add(4, 3, "TARGET", curses.A_BOLD | curses.color_pair(1))
        self._box(5, 3, 11, width - 4)
        self._add(6, 5, "Enter the website you are authorized to assess", curses.A_BOLD)
        field_attr = curses.A_REVERSE
        target = self.target or "https://example.com"
        if len(target) > width - 14:
            target = target[-(width - 14):]
        self._add(8, 5, target, field_attr)
        self._add(10, 5, "Enter continue   Ctrl-U clear   q quit", curses.A_DIM)
        self._add(13, 5, "The next page shows authorization and scan choices.", curses.A_DIM)

    def _summary_form(self, height: int, width: int) -> None:
        self._add(4, 3, "SCAN SUMMARY", curses.A_BOLD | curses.color_pair(1))
        self._box(5, 3, 14, width - 4)
        self._add(6, 5, "TARGET", curses.A_BOLD | curses.color_pair(1))
        self._add(7, 5, self.target, curses.A_REVERSE)
        self._add(9, 5, "AUTHORIZATION", curses.A_BOLD | curses.color_pair(1))
        auth_attr = curses.A_BOLD | (curses.A_REVERSE if self.focus == 0 else 0)
        self._add(10, 5, "[X]" if self.authorized else "[ ]", auth_attr)
        self._add(10, 10, "I confirm explicit authorization to assess this target", auth_attr)
        deep_attr = curses.A_BOLD | (curses.A_REVERSE if self.focus == 1 else 0)
        self._add(11, 5, "[X]" if self.deep_scan else "[ ]", deep_attr)
        self._add(11, 10, "Deep scan same-origin public assets", deep_attr)
        self._add(12, 10, "Bounded downloads inspect common version banners", curses.A_DIM)
        self._add(13, 10, "↳ Redirects ask only when encountered", curses.color_pair(3))
        button_attr = curses.A_REVERSE if self.focus == 2 else curses.A_BOLD
        self._add(13, width // 2 - 9, "  RUN RECONNAISSANCE  ", button_attr)
        self._add(15, 5, "Tab/↑↓ navigate   Space toggle   Enter activate   r change URL", curses.A_DIM)

    def _scanning_page(self, height: int, width: int) -> None:
        self._add(4, 3, "SCANNING", curses.A_BOLD | curses.color_pair(1))
        self._box(5, 3, height - 4, width - 4)
        icon = self.spinner_frames[self.spinner_index]
        self._add(8, max(5, width // 2 - 2), icon, curses.A_BOLD | curses.color_pair(3))
        self._add(10, 5, self.scan_stage, curses.A_BOLD)
        self._add(12, 5, "Authorized, bounded reconnaissance is in progress.", curses.A_DIM)
        self._add(13, 5, "Redirects will pause here for your decision.", curses.A_DIM)

    def _results(self, height: int, width: int) -> None:
        if self.result is not None:
            self.lines = _result_lines(self.result, self._content_width())
            self.scroll = min(self.scroll, max(0, len(self.lines) - max(1, height - 10)))
        self._box(5, 3, height - 4, width - 4)
        visible = height - 10
        for index, line in enumerate(self.lines[self.scroll : self.scroll + visible], start=6):
            attr = curses.A_BOLD if line and not line.startswith(" ") else curses.A_NORMAL
            if line.startswith("  Status"):
                attr |= curses.color_pair({"completed": 2, "blocked": 3, "failed": 4}.get(str(self.result.status), 3))
            elif line in {"ERRORS / LIMITATIONS", "VULNERABILITY CANDIDATES"}:
                attr |= curses.color_pair(3)
            self._add(index, 5, line, attr)
        end = min(len(self.lines), self.scroll + visible)
        self._add(height - 3, 5, f"Lines {self.scroll + 1}-{end} of {len(self.lines)}", curses.A_DIM)

    def _result_banner(self, width: int) -> None:
        """Render a compact dashboard summary above the scrollable report."""
        assert self.result is not None
        status = str(self.result.status).upper()
        banner = (
            f" {status}  •  {len(self.result.technologies)} technologies  •  "
            f"{len(self.result.vulnerabilities)} candidates  •  {len(self.result.errors)} limitations "
        )
        attr = curses.A_BOLD | curses.color_pair({"COMPLETED": 2, "BLOCKED": 3, "FAILED": 4}.get(status, 3))
        self._add(4, 3, banner[: max(1, width - 8)], attr)

    def _box(self, top: int, left: int, bottom: int, right: int) -> None:
        try:
            self.screen.addch(top, left, curses.ACS_ULCORNER)
            self.screen.addch(top, right, curses.ACS_URCORNER)
            self.screen.addch(bottom, left, curses.ACS_LLCORNER)
            self.screen.addch(bottom, right, curses.ACS_LRCORNER)
            self.screen.hline(top, left + 1, curses.ACS_HLINE, right - left - 1)
            self.screen.hline(bottom, left + 1, curses.ACS_HLINE, right - left - 1)
            self.screen.vline(top + 1, left, curses.ACS_VLINE, bottom - top - 1)
            self.screen.vline(top + 1, right, curses.ACS_VLINE, bottom - top - 1)
        except curses.error:
            # A concurrent terminal resize can invalidate one drawing call;
            # the next refresh redraws the complete frame.
            pass

    def _title(self, row: int, col: int, text: str) -> None:
        self._add(row, col, text, curses.A_BOLD | curses.color_pair(1))

    def _add(self, row: int, col: int, text: str, attr: int = curses.A_NORMAL) -> None:
        try:
            self.screen.addnstr(row, col, text, max(0, self.screen.getmaxyx()[1] - col - 2), attr)
        except curses.error:
            pass

    def _content_width(self) -> int:
        return max(40, self.screen.getmaxyx()[1] - 14)


def run() -> None:
    curses.wrapper(lambda screen: AuditorTUI(screen).run())


if __name__ == "__main__":
    run()
