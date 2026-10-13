//! Interactive terminal UI for a single audit.
//!
//! The TUI reads normalized [`StreamEvent`]s from the provider task over a
//! channel and renders one scrolling content area with a compact status line.
//! All terminal I/O is isolated in [`run_audit`]; [`App`] and
//! [`render`] contain no terminal state, so they are validated headlessly with
//! `ratatui`'s `TestBackend`.

use crate::{
    context::Context,
    protocol::{Request, Response},
    provider::{
        self,
        events::{EventSink, StreamEvent, Usage},
        LlmOptions,
    },
};
use anyhow::{Context as _, Result};
use clap::ValueEnum;
use ratatui::{
    backend::CrosstermBackend,
    buffer::Buffer,
    crossterm::{
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::Paragraph,
    Frame, Terminal,
};
use std::{
    cell::Cell,
    collections::VecDeque,
    io,
    sync::mpsc::{self, Sender},
    time::{Duration, Instant},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const MAX_ACTIVITY: usize = 200;
const MAX_PANE_LINES: usize = 2_000;
const MAX_PARTIAL_BYTES: usize = 8_192;

/// Initial TUI view; number keys or Tab can change it during a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TuiView {
    Overview,
    Reasoning,
    Answer,
    Findings,
}

impl TuiView {
    fn next(self) -> Self {
        match self {
            Self::Overview => Self::Reasoning,
            Self::Reasoning => Self::Answer,
            Self::Answer => Self::Findings,
            Self::Findings => Self::Overview,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Reasoning => "reasoning",
            Self::Answer => "answer",
            Self::Findings => "findings",
        }
    }
}

/// TUI state. Pure with respect to the terminal.
pub struct App {
    pub target: String,
    pub model: String,
    pub status: String,
    pub reasoning: Vec<String>,
    pub output: Vec<String>,
    pub findings: Vec<String>,
    pub usage: Usage,
    pub elapsed_ms: u64,
    pub done: bool,
    pub failed: bool,
    pub view: TuiView,
    pub verbose: bool,
    started: Instant,
    partial_reasoning: String,
    partial_output: String,
    activity: VecDeque<String>,
    content_revision: u64,
    scroll_top: Cell<Option<usize>>,
    last_start: Cell<usize>,
    last_max_start: Cell<usize>,
}

impl App {
    pub fn new(target: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            model: model.into(),
            status: "running".into(),
            reasoning: Vec::new(),
            output: Vec::new(),
            findings: Vec::new(),
            usage: Usage::default(),
            elapsed_ms: 0,
            done: false,
            failed: false,
            view: TuiView::Overview,
            verbose: false,
            started: Instant::now(),
            partial_reasoning: String::new(),
            partial_output: String::new(),
            activity: VecDeque::new(),
            content_revision: 0,
            scroll_top: Cell::new(None),
            last_start: Cell::new(0),
            last_max_start: Cell::new(0),
        }
    }

    pub fn with_presentation(mut self, view: TuiView, verbose: bool) -> Self {
        self.view = view;
        self.verbose = verbose;
        self
    }

    fn handle_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Tab => self.view = self.view.next(),
            KeyCode::Char('1') => self.view = TuiView::Overview,
            KeyCode::Char('2') => self.view = TuiView::Reasoning,
            KeyCode::Char('3') => self.view = TuiView::Answer,
            KeyCode::Char('4') => self.view = TuiView::Findings,
            KeyCode::Char('v') => self.verbose = !self.verbose,
            KeyCode::Up => self.scroll_up(1),
            KeyCode::Down => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(10),
            KeyCode::PageDown => self.scroll_down(10),
            KeyCode::Home => self.scroll_top.set(Some(0)),
            KeyCode::End => self.scroll_top.set(None),
            _ => {}
        }
        if matches!(
            code,
            KeyCode::Tab | KeyCode::Char('1'..='4') | KeyCode::Char('v')
        ) {
            self.scroll_top.set(None);
        }
    }

    fn scroll_up(&self, rows: usize) {
        let start = self.scroll_top.get().unwrap_or(self.last_start.get());
        self.scroll_top.set(Some(start.saturating_sub(rows)));
    }

    fn scroll_down(&self, rows: usize) {
        let start = self.scroll_top.get().unwrap_or(self.last_start.get());
        let next = start.saturating_add(rows);
        self.scroll_top
            .set((next < self.last_max_start.get()).then_some(next));
    }

    fn record_activity(&mut self, event: &StreamEvent) {
        let line = match event {
            StreamEvent::Operation { name, details } => {
                let detail = match name.as_str() {
                    "run_start" => format!(
                        "{} · {}",
                        details["model"].as_str().unwrap_or("model"),
                        details["target"].as_str().unwrap_or("target")
                    ),
                    "turn_start" => format!("turn {}", details["turn"]),
                    "http_response" => format!("HTTP {}", details["status"]),
                    "stream_start" => "streaming".into(),
                    "heartbeat" => format!(
                        "{} · {} ms",
                        details["phase"].as_str().unwrap_or("running"),
                        details["elapsed_ms"]
                    ),
                    "run_end" => details["outcome"].as_str().unwrap_or("finished").into(),
                    _ => truncate_tail(&details.to_string(), 160),
                };
                format!("{name}: {detail}")
            }
            StreamEvent::ToolStart { name, .. } => format!("tool {name}: started"),
            StreamEvent::ToolEnd {
                name,
                is_error,
                elapsed_ms,
                ..
            } => format!(
                "tool {name}: {} ({elapsed_ms} ms)",
                if *is_error { "error" } else { "complete" }
            ),
            StreamEvent::Usage(usage) => format!(
                "tokens {}/{}/{}",
                usage.prompt_tokens, usage.completion_tokens, usage.total_tokens
            ),
            StreamEvent::Reasoning { .. }
            | StreamEvent::Text { .. }
            | StreamEvent::Debug { .. }
            | StreamEvent::Done => return,
        };
        if self.activity.len() == MAX_ACTIVITY {
            self.activity.pop_front();
        }
        self.activity
            .push_back(truncate_tail(&line, MAX_PARTIAL_BYTES));
    }

    fn push(lines: &mut Vec<String>, partial: &mut String, chunk: &str) {
        for segment in chunk.split_inclusive('\n') {
            if let Some(line) = segment.strip_suffix('\n') {
                append_bounded(partial, line, MAX_PARTIAL_BYTES);
                lines.push(std::mem::take(partial));
            } else {
                append_bounded(partial, segment, MAX_PARTIAL_BYTES);
            }
        }
        if lines.len() > MAX_PANE_LINES {
            lines.drain(..lines.len() - MAX_PANE_LINES);
        }
    }

    fn flush_partials(&mut self) {
        if !self.partial_reasoning.is_empty() {
            self.reasoning
                .push(std::mem::take(&mut self.partial_reasoning));
        }
        if !self.partial_output.is_empty() {
            self.output.push(std::mem::take(&mut self.partial_output));
        }
        self.reasoning
            .drain(..self.reasoning.len().saturating_sub(MAX_PANE_LINES));
        self.output
            .drain(..self.output.len().saturating_sub(MAX_PANE_LINES));
    }

    fn append_lines(out: &mut String, lines: &[String], partial: &str) {
        for (index, line) in lines.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            out.push_str(line);
        }
        if !partial.is_empty() {
            if !lines.is_empty() {
                out.push('\n');
            }
            out.push_str(partial);
        }
    }

    fn append_section(out: &mut String, title: &str, lines: &[String], partial: &str) {
        if (lines.is_empty() || (lines.len() == 1 && lines[0].is_empty())) && partial.is_empty() {
            return;
        }
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(title);
        out.push('\n');
        Self::append_lines(out, lines, partial);
    }

    fn write_view_text(&self, out: &mut String) {
        out.clear();
        if self.verbose && !self.activity.is_empty() {
            out.push_str("Activity\n");
            for (index, line) in self.activity.iter().enumerate() {
                if index > 0 {
                    out.push('\n');
                }
                out.push_str(line);
            }
        }
        match self.view {
            TuiView::Overview => {
                Self::append_section(out, "Reasoning", &self.reasoning, &self.partial_reasoning);
                Self::append_section(out, "Answer", &self.output, &self.partial_output);
                Self::append_section(out, "Findings", &self.findings, "");
            }
            TuiView::Reasoning | TuiView::Answer | TuiView::Findings => {
                let (lines, partial, waiting) = match self.view {
                    TuiView::Reasoning => (
                        self.reasoning.as_slice(),
                        self.partial_reasoning.as_str(),
                        "Waiting for reasoning…",
                    ),
                    TuiView::Answer => (
                        self.output.as_slice(),
                        self.partial_output.as_str(),
                        "Waiting for answer…",
                    ),
                    TuiView::Findings => (self.findings.as_slice(), "", "No findings yet."),
                    TuiView::Overview => unreachable!(),
                };
                if !out.is_empty() {
                    out.push_str("\n\n");
                }
                if lines.is_empty() && partial.is_empty() {
                    out.push_str(waiting);
                } else {
                    Self::append_lines(out, lines, partial);
                }
            }
        }
        if out.is_empty() {
            out.push_str("Waiting for events…");
        }
    }

    /// Apply one streaming event.
    pub fn handle_event(&mut self, event: &StreamEvent) {
        if self.done {
            return;
        }
        let content_changed = match event {
            StreamEvent::Reasoning { .. } | StreamEvent::Text { .. } => true,
            StreamEvent::ToolStart { .. } => self.verbose || !self.partial_output.is_empty(),
            StreamEvent::Done => {
                !self.partial_reasoning.is_empty() || !self.partial_output.is_empty()
            }
            StreamEvent::Operation { .. } | StreamEvent::ToolEnd { .. } | StreamEvent::Usage(_) => {
                self.verbose
            }
            StreamEvent::Debug { .. } => false,
        };
        if content_changed {
            self.content_revision = self.content_revision.wrapping_add(1);
        }
        self.record_activity(event);
        match event {
            StreamEvent::Reasoning { text } => {
                Self::push(&mut self.reasoning, &mut self.partial_reasoning, text);
            }
            StreamEvent::Text { text } => {
                Self::push(&mut self.output, &mut self.partial_output, text);
            }
            StreamEvent::Operation { name, details } => {
                self.status = match name.as_str() {
                    "heartbeat" => format!(
                        "{} ({} ms)",
                        details["phase"].as_str().unwrap_or("running"),
                        details["elapsed_ms"]
                    ),
                    "retry" => format!(
                        "retry {} in {} ms",
                        details["next_attempt"], details["delay_ms"]
                    ),
                    "run_end" => details["outcome"].as_str().unwrap_or("finished").to_owned(),
                    _ => name.replace('_', " "),
                };
            }
            StreamEvent::Debug { .. } => {}
            StreamEvent::Usage(usage) => self.usage = *usage,
            StreamEvent::ToolStart { name, .. } => {
                if !self.partial_output.is_empty() {
                    self.output.push(std::mem::take(&mut self.partial_output));
                    self.output
                        .drain(..self.output.len().saturating_sub(MAX_PANE_LINES));
                }
                self.status = format!("running {name}");
            }
            StreamEvent::ToolEnd { .. } => self.status = "running".into(),
            StreamEvent::Done => {
                self.flush_partials();
                self.status = "finalizing".into();
            }
        }
    }

    /// Populate the findings pane from the final response.
    pub fn on_finish(&mut self, response: &Response) {
        self.content_revision = self.content_revision.wrapping_add(1);
        self.flush_partials();
        self.findings = response
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "[{}] {}:{} {} — {}",
                    finding.severity.as_str(),
                    finding.path,
                    finding.line,
                    finding.cwe,
                    finding.title
                )
            })
            .collect();
        self.done = true;
        self.elapsed_ms = self.started.elapsed().as_millis() as u64;
        self.status = if self.findings.is_empty() {
            "complete · no findings".into()
        } else {
            format!("complete · {} findings", self.findings.len())
        };
    }

    fn on_error(&mut self, error: &anyhow::Error) {
        self.content_revision = self.content_revision.wrapping_add(1);
        self.flush_partials();
        self.done = true;
        self.failed = true;
        self.elapsed_ms = self.started.elapsed().as_millis() as u64;
        self.status = if error.is::<provider::AuditTimeout>() {
            "timed out".into()
        } else {
            "failed".into()
        };
    }

    fn footer(&self) -> String {
        let mut footer = format!("{} · {} ms", self.status, self.elapsed_ms);
        if !self.usage.is_empty() {
            if !self.verbose {
                footer.push_str(&format!(" · {} tokens", self.usage.total_tokens));
                return footer;
            }
            footer.push_str(&format!(
                " · tokens {}/{}/{}",
                self.usage.prompt_tokens, self.usage.completion_tokens, self.usage.total_tokens
            ));
        }
        footer
    }
}

impl EventSink for App {
    fn on_event(&mut self, event: &StreamEvent) {
        self.handle_event(event);
    }
}

/// Wrap body text only when content, view, verbosity, or terminal width changes.
#[derive(Default)]
struct RenderCache {
    key: Option<(u64, u16, TuiView, bool)>,
    text: String,
    rows: Vec<String>,
}

impl RenderCache {
    fn prepare(&mut self, app: &App, width: u16) -> bool {
        let key = (app.content_revision, width, app.view, app.verbose);
        if self.key == Some(key) {
            return false;
        }
        app.write_view_text(&mut self.text);
        self.rows = display_rows(&self.text, width as usize);
        self.key = Some(key);
        true
    }
}

/// Render one frame. Split out so it can be validated with `TestBackend`.
pub fn render(frame: &mut Frame, app: &App) {
    render_cached(frame, app, &mut RenderCache::default());
}

fn render_cached(frame: &mut Frame, app: &App, cache: &mut RenderCache) {
    if frame.area().width == 0 || frame.area().height == 0 {
        return;
    }
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(frame.area());

    let header = if frame.area().width >= 75 {
        format!(
            "Audit Alchemist · {} · {} · {}",
            safe_line(&app.target),
            safe_line(&app.model),
            app.view.label()
        )
    } else if frame.area().width >= 40 {
        format!(
            "Audit Alchemist · {} · {}",
            app.view.label(),
            safe_line(&app.target)
        )
    } else {
        format!("Audit · {}", app.view.label())
    };
    frame.render_widget(
        Paragraph::new(ellipsize(&header, chunks[0].width as usize))
            .style(Style::default().add_modifier(Modifier::BOLD)),
        chunks[0],
    );

    let body = chunks[1];
    if body.width > 0 && body.height > 0 {
        cache.prepare(app, body.width);
        let rows = &cache.rows;
        let max_start = rows.len().saturating_sub(body.height as usize);
        let start = app.scroll_top.get().unwrap_or(max_start).min(max_start);
        let end = (start + body.height as usize).min(rows.len());
        app.last_start.set(start);
        app.last_max_start.set(max_start);
        frame.render_widget(Paragraph::new(rows[start..end].join("\n")), body);
    }

    let controls = if frame.area().width >= 110 {
        " 1-4 views · ↑↓/Pg scroll · End live · v details · q quit"
    } else if frame.area().width >= 55 {
        " Tab view · ↑↓ scroll · q quit"
    } else {
        " q quit"
    };
    let footer_chunks = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(controls.width().min(frame.area().width as usize) as u16),
    ])
    .split(chunks[2]);
    let status = if frame.area().width >= 80 {
        app.footer()
    } else {
        app.status.clone()
    };
    frame.render_widget(
        Paragraph::new(ellipsize(
            &safe_line(&status),
            footer_chunks[0].width as usize,
        ))
        .style(Style::default().fg(Color::DarkGray)),
        footer_chunks[0],
    );
    frame.render_widget(
        Paragraph::new(controls).style(Style::default().fg(Color::DarkGray)),
        footer_chunks[1],
    );
}

fn safe_line(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn truncate_tail(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut start = text.len() - max_bytes;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].to_owned()
}

fn append_bounded(out: &mut String, fragment: &str, max_bytes: usize) {
    if fragment.len() >= max_bytes {
        let mut start = fragment.len() - max_bytes;
        while !fragment.is_char_boundary(start) {
            start += 1;
        }
        out.clear();
        out.push_str(&fragment[start..]);
    } else {
        out.push_str(fragment);
        if out.len() > max_bytes {
            let mut start = out.len() - max_bytes;
            while !out.is_char_boundary(start) {
                start += 1;
            }
            out.drain(..start);
        }
    }
}

fn ellipsize(text: &str, width: usize) -> String {
    if text.width() <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut visible = String::new();
    let mut cells = 0;
    for ch in text.chars() {
        let char_width = ch.width().unwrap_or(0);
        if cells + char_width >= width {
            break;
        }
        visible.push(ch);
        cells += char_width;
    }
    visible.push('…');
    visible
}

/// Hard-wrap with display-cell widths so scrolling counts terminal rows.
fn display_rows(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
    let mut row = String::new();
    let mut cells = 0;
    for ch in text.chars() {
        if ch == '\n' {
            rows.push(std::mem::take(&mut row));
            cells = 0;
            continue;
        }
        let ch = if ch.is_control() { ' ' } else { ch };
        let char_width = ch.width().unwrap_or(0);
        if char_width > width {
            row.push('?');
            continue;
        }
        if cells + char_width > width {
            rows.push(std::mem::take(&mut row));
            cells = 0;
        }
        row.push(ch);
        cells += char_width;
    }
    rows.push(row);
    rows
}

/// Collect a buffer into a plain string, useful for headless validation.
pub fn buffer_to_string(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut out = String::new();
    for y in area.y..area.y.saturating_add(area.height) {
        for x in area.x..area.x.saturating_add(area.width) {
            if let Some(cell) = buffer.cell((x, y)) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}

struct ChannelSink {
    tx: Sender<StreamEvent>,
}

impl EventSink for ChannelSink {
    fn on_event(&mut self, event: &StreamEvent) {
        let _ = self.tx.send(event.clone());
    }
}

/// Run an audit inside the TUI and return the final response.
pub async fn run_audit(
    mut app: App,
    options: LlmOptions,
    request: Request,
    context: Context,
    root: std::path::PathBuf,
    timeout: Duration,
) -> Result<Response> {
    let (tx, rx) = mpsc::channel::<StreamEvent>();
    let mut sink = ChannelSink { tx };
    // Poll the provider future and the UI loop together so the sink does not
    // need to be `Send`.
    let mut future = std::pin::pin!(provider::audit_with(
        &options, &request, &context, &root, timeout, &mut sink
    ));

    let mut terminal = setup()?;
    let mut render_cache = RenderCache::default();
    let mut outcome: Option<Result<Response>> = None;
    let mut cancelled = false;
    loop {
        while let Ok(event) = rx.try_recv() {
            app.handle_event(&event);
        }
        if !app.done {
            app.elapsed_ms = app.started.elapsed().as_millis() as u64;
        }
        terminal
            .terminal
            .draw(|frame| render_cached(frame, &app, &mut render_cache))?;
        if outcome.is_some() {
            break;
        }
        tokio::select! {
            result = &mut future => outcome = Some(result),
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                for _ in 0..32 {
                    if !event::poll(Duration::ZERO).context("poll terminal input")? {
                        break;
                    }
                    let input = event::read().context("read terminal input")?;
                    if is_cancel_key(&input) {
                        cancelled = true;
                        break;
                    }
                    if let Event::Key(key) = input {
                        if key.kind == KeyEventKind::Press {
                            app.handle_key(key.code);
                        }
                    }
                }
                if cancelled { break; }
            }
        }
    }

    if cancelled {
        terminal.restore()?;
        eprintln!("Audit Alchemist · cancelled");
        anyhow::bail!("audit cancelled");
    }

    let result = match outcome {
        Some(result) => result,
        None => (&mut future).await,
    };
    while let Ok(event) = rx.try_recv() {
        app.handle_event(&event);
    }
    match &result {
        Ok(response) => app.on_finish(response),
        Err(error) => app.on_error(error),
    }
    let _ = terminal
        .terminal
        .draw(|frame| render_cached(frame, &app, &mut render_cache));
    terminal.restore()?;
    eprintln!("{}", final_summary(&app));
    if let Err(error) = &result {
        eprintln!("{}", safe_line(&format!("{error:#}")));
    }
    result
}

fn is_cancel_key(event: &Event) -> bool {
    matches!(event, Event::Key(key) if key.kind == KeyEventKind::Press
        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))))
}

fn final_summary(app: &App) -> String {
    let mut lines = vec![format!("Audit Alchemist · {}", safe_line(&app.footer()))];
    lines.extend(app.findings.iter().map(|finding| safe_line(finding)));
    lines.join("\n")
}

struct TerminalSession {
    terminal: Terminal<CrosstermBackend<io::Stderr>>,
    restored: bool,
}

impl TerminalSession {
    fn restore(&mut self) -> Result<()> {
        // Try every step even if one fails so the user's terminal is left in
        // the best recoverable state.
        let raw = disable_raw_mode();
        let screen = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let cursor = self.terminal.show_cursor();
        self.restored = raw.is_ok() && screen.is_ok() && cursor.is_ok();
        raw.context("disable raw mode")?;
        screen.context("leave alternate screen")?;
        cursor.context("show cursor")?;
        Ok(())
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.restore();
        }
    }
}

fn setup() -> Result<TerminalSession> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stderr = io::stderr();
    if let Err(error) = execute!(stderr, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error).context("enter alternate screen");
    }
    let backend = CrosstermBackend::new(stderr);
    match Terminal::new(backend) {
        Ok(terminal) => {
            let mut session = TerminalSession {
                terminal,
                restored: false,
            };
            session.terminal.hide_cursor().context("hide cursor")?;
            Ok(session)
        }
        Err(error) => {
            let _ = execute!(io::stderr(), LeaveAlternateScreen);
            let _ = disable_raw_mode();
            Err(error).context("create terminal")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Finding, Severity, VERSION};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyEvent, KeyModifiers};
    use serde_json::json;

    fn frame_text(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        buffer_to_string(terminal.backend().buffer())
    }

    fn finding() -> Finding {
        Finding {
            cwe: "CWE-78".into(),
            path: "sources/x.py".into(),
            line: 4,
            severity: Severity::High,
            title: "Command injection".into(),
            evidence: "name reaches shell".into(),
        }
    }

    #[test]
    fn renders_target_reasoning_output_and_findings() {
        let mut app = App::new("sources/x.py", "model-x");
        app.handle_event(&StreamEvent::Reasoning {
            text: "because input\n".into(),
        });
        app.handle_event(&StreamEvent::Text {
            text: "the answer\n".into(),
        });
        app.on_finish(&Response {
            schema_version: VERSION,
            findings: vec![finding()],
        });

        let content = frame_text(&app, 100, 40);

        assert!(content.contains("sources/x.py"));
        assert!(content.contains("model-x"));
        assert!(content.contains("because input"));
        assert!(content.contains("the answer"));
        assert!(content.contains("CWE-78"));
        assert!(content.contains("Command injection"));
    }

    #[test]
    fn reports_no_findings_status() {
        let mut app = App::new("safe.py", "model");
        app.on_finish(&Response {
            schema_version: VERSION,
            findings: vec![],
        });
        assert!(app.footer().contains("no findings"));
    }

    #[test]
    fn streaming_chunks_are_visible_and_kept_in_order() {
        let mut app = App::new("entry.py", "model");
        app.handle_event(&StreamEvent::Reasoning {
            text: "reason".into(),
        });
        app.handle_event(&StreamEvent::Text {
            text: "first".into(),
        });
        let live = frame_text(&app, 100, 40);
        assert!(live.contains("reason"));
        assert!(live.contains("first"));

        app.handle_event(&StreamEvent::Text {
            text: " line\nsecond".into(),
        });
        app.handle_event(&StreamEvent::ToolStart {
            name: "read_file".into(),
            call_id: "call-1".into(),
        });
        app.handle_event(&StreamEvent::ToolEnd {
            name: "read_file".into(),
            call_id: "call-1".into(),
            is_error: false,
            elapsed_ms: 12,
        });
        app.handle_event(&StreamEvent::Text {
            text: "after tool".into(),
        });
        assert_eq!(app.output, ["first line", "second"]);
        assert!(frame_text(&app, 100, 40).contains("after tool"));

        app.handle_event(&StreamEvent::Done);
        assert_eq!(app.reasoning, ["reason"]);
        assert_eq!(app.output.last().unwrap(), "after tool");
        assert_eq!(app.status, "finalizing");
        assert!(!app.done);
    }

    #[test]
    fn streamed_lines_keep_blank_lines_and_unicode_when_bounded() {
        let mut app = App::new("entry.py", "model").with_presentation(TuiView::Answer, false);
        app.handle_event(&StreamEvent::Text {
            text: "first\n\n界".into(),
        });
        app.handle_event(&StreamEvent::Text { text: "限".into() });
        let mut text = String::new();
        app.write_view_text(&mut text);
        assert_eq!(text, "first\n\n界限");

        app.handle_event(&StreamEvent::Text {
            text: "界".repeat(MAX_PARTIAL_BYTES),
        });
        assert!(app.partial_output.len() <= MAX_PARTIAL_BYTES);
        assert!(app.partial_output.chars().all(|ch| ch == '界'));
        app.handle_event(&StreamEvent::Text {
            text: "\nend".into(),
        });
        assert!(app.output.last().unwrap().len() <= MAX_PARTIAL_BYTES);
        assert_eq!(app.partial_output, "end");
    }

    #[test]
    fn tool_boundaries_keep_output_history_bounded() {
        let mut app = App::new("entry.py", "model");
        for _ in 0..=MAX_PANE_LINES {
            app.handle_event(&StreamEvent::Text { text: "x".into() });
            app.handle_event(&StreamEvent::ToolStart {
                name: "bash".into(),
                call_id: "test".into(),
            });
        }
        assert_eq!(app.output.len(), MAX_PANE_LINES);
    }

    #[test]
    fn render_cache_reuses_rows_until_content_view_or_width_changes() {
        let mut app = App::new("entry.py", "model");
        app.handle_event(&StreamEvent::Text {
            text: "first\n".into(),
        });
        let mut cache = RenderCache::default();
        assert!(cache.prepare(&app, 80));
        assert!(!cache.prepare(&app, 80));
        app.elapsed_ms = 100;
        assert!(!cache.prepare(&app, 80));
        app.handle_event(&StreamEvent::Operation {
            name: "heartbeat".into(),
            details: json!({"phase":"model", "elapsed_ms":100}),
        });
        assert!(!cache.prepare(&app, 80));

        app.handle_event(&StreamEvent::Text {
            text: "second\n".into(),
        });
        assert!(cache.prepare(&app, 80));
        assert!(cache.text.contains("second"));
        app.handle_key(KeyCode::Char('3'));
        assert!(cache.prepare(&app, 80));
        assert!(cache.prepare(&app, 40));
        app.handle_key(KeyCode::Char('v'));
        assert!(cache.prepare(&app, 40));
    }

    #[test]
    #[ignore = "manual status-frame throughput comparison"]
    fn compare_status_frame_render_cost() {
        let mut app = App::new("entry.py", "model");
        app.handle_event(&StreamEvent::Text {
            text: (0..MAX_PANE_LINES)
                .map(|index| format!("line {index:04}: streamed audit detail\n"))
                .collect(),
        });
        let mut uncached = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let start = Instant::now();
        for tick in 0..200 {
            app.elapsed_ms = tick;
            uncached.draw(|frame| render(frame, &app)).unwrap();
        }
        let uncached_time = start.elapsed();

        let mut cached = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut cache = RenderCache::default();
        let start = Instant::now();
        for tick in 0..200 {
            app.elapsed_ms = tick;
            cached
                .draw(|frame| render_cached(frame, &app, &mut cache))
                .unwrap();
        }
        eprintln!(
            "200 status frames: uncached {uncached_time:?}, cached {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn lifecycle_events_usage_and_debug_update_only_intended_state() {
        let mut app = App::new("entry.py", "model");
        app.handle_event(&StreamEvent::Operation {
            name: "heartbeat".into(),
            details: json!({"phase":"exploring","elapsed_ms":120}),
        });
        assert_eq!(app.status, "exploring (120 ms)");
        app.handle_event(&StreamEvent::Operation {
            name: "retry".into(),
            details: json!({"next_attempt":2,"delay_ms":500}),
        });
        assert_eq!(app.status, "retry 2 in 500 ms");
        app.handle_event(&StreamEvent::ToolStart {
            name: "bash".into(),
            call_id: "call-1".into(),
        });
        assert_eq!(app.status, "running bash");
        app.handle_event(&StreamEvent::ToolEnd {
            name: "bash".into(),
            call_id: "call-1".into(),
            is_error: true,
            elapsed_ms: 8,
        });
        assert!(app.output.is_empty());
        assert!(app.activity.back().unwrap().contains("tool bash: error"));
        assert_eq!(app.status, "running");
        app.handle_event(&StreamEvent::Usage(Usage {
            prompt_tokens: 10,
            completion_tokens: 4,
            total_tokens: 14,
            ..Usage::default()
        }));
        assert!(app.footer().contains("14 tokens"));
        app.verbose = true;
        assert!(app.footer().contains("tokens 10/4/14"));
        app.handle_event(&StreamEvent::Debug {
            stage: "response".into(),
            content: "secret payload".into(),
        });
        assert!(!frame_text(&app, 100, 40).contains("secret payload"));
        app.handle_event(&StreamEvent::Done);
        assert_eq!(app.status, "finalizing");
        app.handle_event(&StreamEvent::Operation {
            name: "run_end".into(),
            details: json!({"outcome":"success"}),
        });
        assert_eq!(app.status, "success");
        assert!(!app.done);
    }

    #[test]
    fn final_response_and_errors_flush_pending_text() {
        let mut success = App::new("entry.py", "model");
        success.handle_event(&StreamEvent::Text {
            text: "last chunk".into(),
        });
        success.on_finish(&Response {
            schema_version: VERSION,
            findings: vec![finding()],
        });
        assert_eq!(success.output, ["last chunk"]);
        assert!(success.done);
        assert!(!success.failed);
        assert_eq!(success.status, "complete · 1 findings");

        let mut failed = App::new("entry.py", "model");
        failed.handle_event(&StreamEvent::Reasoning {
            text: "partial".into(),
        });
        failed.on_error(&anyhow::anyhow!("provider failed"));
        assert_eq!(failed.reasoning, ["partial"]);
        assert!(failed.done && failed.failed);
        assert_eq!(failed.status, "failed");
        failed.handle_event(&StreamEvent::Done);
        assert_eq!(failed.status, "failed");

        let mut timed_out = App::new("entry.py", "model");
        timed_out.on_error(&provider::AuditTimeout.into());
        assert_eq!(timed_out.status, "timed out");
    }

    #[test]
    fn narrow_frames_do_not_panic() {
        let mut app = App::new("entry.py", "model");
        app.handle_event(&StreamEvent::Text {
            text: "some output".into(),
        });
        for (width, height) in [(1, 1), (8, 3), (20, 8)] {
            let _ = frame_text(&app, width, height);
        }
    }

    #[test]
    fn quit_hint_remains_visible_with_long_status_at_normal_width() {
        let mut app = App::new("entry.py", "model");
        app.status = "retrying after a long provider status message".into();
        app.elapsed_ms = 12_345;
        let frame = frame_text(&app, 80, 24);
        assert!(frame.lines().last().unwrap().contains("q quit"));
    }

    #[test]
    fn narrow_header_keeps_view_and_footer_separates_help() {
        let mut app = App::new("sources/command_unsafe.py", "fixture-model")
            .with_presentation(TuiView::Findings, false);
        app.status = "model (20003 ms)".into();
        let frame = frame_text(&app, 55, 18);
        let mut rows = frame.lines();
        assert!(rows.next().unwrap().contains("findings"));
        let footer = rows.last().unwrap();
        assert!(footer.contains("model (20003 ms)"));
        assert!(footer.contains(" Tab view"));
        assert!(footer.ends_with("q quit"));
    }

    #[test]
    fn scrolling_follows_end_and_reaches_earlier_rows() {
        let mut app = App::new("entry.py", "model").with_presentation(TuiView::Answer, false);
        app.handle_event(&StreamEvent::Text {
            text: (0..25).map(|n| format!("line-{n:02}\n")).collect(),
        });
        let live = frame_text(&app, 24, 8);
        assert!(live.contains("line-24"));
        assert!(!live.contains("line-00"));

        app.handle_key(KeyCode::Home);
        let first = frame_text(&app, 24, 8);
        assert!(first.contains("line-00"));
        assert!(!first.contains("line-24"));
        app.handle_key(KeyCode::Down);
        assert!(frame_text(&app, 24, 8).contains("line-01"));
        assert!(!frame_text(&app, 24, 8).contains("line-00"));
        app.handle_key(KeyCode::End);
        assert!(frame_text(&app, 24, 8).contains("line-24"));
        app.handle_key(KeyCode::PageUp);
        assert!(!frame_text(&app, 24, 8).contains("line-24"));
        app.handle_key(KeyCode::PageDown);
        assert!(frame_text(&app, 24, 8).contains("line-24"));

        app.handle_key(KeyCode::Home);
        app.handle_event(&StreamEvent::Text {
            text: "line-25\n".into(),
        });
        let anchored = frame_text(&app, 24, 8);
        assert!(anchored.contains("line-00"));
        assert!(!anchored.contains("line-25"));
        app.handle_key(KeyCode::End);
        assert!(frame_text(&app, 24, 8).contains("line-25"));
    }

    #[test]
    fn wraps_display_cells_and_neutralizes_terminal_controls() {
        assert_eq!(display_rows("a界b\ncd", 3), ["a界", "b", "cd"]);
        let mut app = App::new("entry\x1b[31m.py", "model");
        app.handle_event(&StreamEvent::Text {
            text: "good\x1b[2J\rnext\n".into(),
        });
        let frame = frame_text(&app, 40, 8);
        assert!(!frame.contains('\x1b'));
        assert!(!frame.contains('\r'));
        assert!(frame.contains("good [2J next"));
    }

    #[test]
    fn final_summary_is_one_line_per_finding_and_safe() {
        let mut app = App::new("entry.py", "model");
        app.findings = vec!["[high] x.py:1 CWE-78 title\x1b[31m\nmore".into()];
        let summary = final_summary(&app);
        assert_eq!(summary.lines().count(), 2);
        assert!(!summary.contains('\x1b'));
        assert!(summary.contains("[high] x.py:1"));
    }

    #[test]
    fn only_pressed_quit_keys_cancel() {
        for code in [KeyCode::Char('q'), KeyCode::Esc] {
            assert!(is_cancel_key(&Event::Key(KeyEvent::new(
                code,
                KeyModifiers::NONE
            ))));
        }
        assert!(!is_cancel_key(&Event::Key(KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::NONE
        ))));
        assert!(is_cancel_key(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        ))));
        assert!(!is_cancel_key(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::NONE
        ))));
        let mut released = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        released.kind = KeyEventKind::Release;
        assert!(!is_cancel_key(&Event::Key(released)));
        assert!(!is_cancel_key(&Event::Resize(80, 24)));
    }

    #[test]
    fn views_and_verbose_mode_change_visible_panes() {
        let mut app = App::new("entry.py", "model").with_presentation(TuiView::Answer, false);
        app.handle_event(&StreamEvent::Reasoning {
            text: "reason-marker".into(),
        });
        app.handle_event(&StreamEvent::Text {
            text: "answer-marker".into(),
        });
        app.handle_event(&StreamEvent::Operation {
            name: "run_start".into(),
            details: json!({"phase":"starting"}),
        });
        app.on_finish(&Response {
            schema_version: VERSION,
            findings: vec![finding()],
        });
        let answer = frame_text(&app, 100, 40);
        assert!(answer.contains("answer-marker"));
        assert!(!answer.contains("reason-marker"));
        assert!(!answer.contains("CWE-78"));
        assert!(!answer.contains("run_start"));

        app.handle_key(KeyCode::Tab);
        assert_eq!(app.view, TuiView::Findings);
        assert!(frame_text(&app, 100, 40).contains("CWE-78"));
        app.handle_key(KeyCode::Char('2'));
        assert_eq!(app.view, TuiView::Reasoning);
        assert!(frame_text(&app, 100, 40).contains("reason-marker"));
        app.handle_key(KeyCode::Char('v'));
        assert!(app.verbose);
        assert!(frame_text(&app, 100, 40).contains("run_start"));
        app.handle_key(KeyCode::Char('1'));
        assert_eq!(app.view, TuiView::Overview);
    }

    #[test]
    fn verbose_activity_is_bounded_and_omits_debug_payloads() {
        let mut app = App::new("entry.py", "model").with_presentation(TuiView::Overview, true);
        for index in 0..=MAX_ACTIVITY {
            app.handle_event(&StreamEvent::Operation {
                name: format!("event_{index}"),
                details: json!({}),
            });
        }
        app.handle_event(&StreamEvent::Debug {
            stage: "response".into(),
            content: "secret-marker".into(),
        });
        assert_eq!(app.activity.len(), MAX_ACTIVITY);
        assert!(!app.activity.iter().any(|line| line.contains("event_0")));
        assert!(app.activity.back().unwrap().contains("event_200"));
        let frame = frame_text(&app, 100, 40);
        assert!(frame.contains("event_200"));
        assert!(!frame.contains("secret-marker"));
    }

    #[test]
    fn verbose_activity_summarizes_run_metadata() {
        let mut app = App::new("entry.py", "model").with_presentation(TuiView::Overview, true);
        app.handle_event(&StreamEvent::Operation {
            name: "run_start".into(),
            details: json!({"model":"fixture", "target":"entry.py", "instruction_sha256":"private-marker"}),
        });
        let frame = frame_text(&app, 80, 24);
        assert!(frame.contains("run_start: fixture"));
        assert!(!frame.contains("private-marker"));
    }
}
