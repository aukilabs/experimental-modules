use authentication::{current_time_ms, Action, Client, Config, Credentials, Event};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event as CEvent, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        canvas::{Canvas, Map, MapResolution, Points},
        Block, Borders, List, ListItem, Paragraph, Tabs,
    },
    Frame, Terminal,
};
use reqwest;
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

// Domain structures from DDS API
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainServer {
    id: String,
    organization_id: String,
    name: String,
    url: String,
    version: String,
    status: String,
    mode: String,
    variants: Vec<String>,
    ip: String,
    latitude: f64,
    longitude: f64,
    cloud_region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AvailableDomain {
    id: String,
    name: String,
    organization_id: String,
    domain_server_id: String,
    owner_wallet_address: String,
    domain_server: DomainServer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainsResponse {
    domains: Vec<AvailableDomain>,
}

// Application state
struct App {
    // Config fields
    api_url: String,
    dds_url: String,
    client_id: String,
    refresh_threshold_ms: String,

    // Credential type
    credential_type: CredentialType,

    // Credential fields
    email: String,
    password: String,
    app_key: String,
    app_secret: String,
    opaque_token: String,
    opaque_expiry: String,

    // Current input focus
    focused_field: InputField,

    // Logs
    logs: Vec<String>,

    // Selected tab
    selected_tab: Tab,

    // Available domains from DDS
    available_domains: Vec<AvailableDomain>,
    selected_domain_index: usize,

    // Authenticated domains (domain_id -> (token, expires_at, server_info))
    authenticated_domains: std::collections::HashMap<String, (String, u64, DomainServer)>,

    // Status
    is_connecting: bool,
    is_fetching_domains: bool,

    // Input mode
    input_mode: bool,

    // Authentication client
    auth_client: Option<Client>,
    http_client: reqwest::Client,

    // Token information for display
    network_token: Option<String>,
    network_token_expires: Option<u64>,
    discovery_token: Option<String>,
    discovery_token_expires: Option<u64>,

    // Last tick time
    last_tick: u64,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum CredentialType {
    EmailPassword,
    AppKey,
    Opaque,
}

#[derive(Clone, Copy, PartialEq)]
enum InputField {
    ApiUrl,
    DdsUrl,
    ClientId,
    RefreshThreshold,
    Email,
    Password,
    AppKey,
    AppSecret,
    OpaqueToken,
    OpaqueExpiry,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Status,
    Domains,
    Console,
    WorldMap,
}

impl App {
    fn new() -> Self {
        Self {
            api_url: "https://api.aukiverse.com".to_string(),
            dds_url: "https://dds.posemesh.org".to_string(),
            client_id: "rust-tui".to_string(),
            refresh_threshold_ms: "300000".to_string(),
            credential_type: CredentialType::EmailPassword,
            email: String::new(),
            password: String::new(),
            app_key: String::new(),
            app_secret: String::new(),
            opaque_token: String::new(),
            opaque_expiry: String::new(),
            focused_field: InputField::Email,
            logs: vec![">>> SYSTEM INITIALIZED <<<".to_string()],
            selected_tab: Tab::Status,
            available_domains: Vec::new(),
            selected_domain_index: 0,
            authenticated_domains: std::collections::HashMap::new(),
            is_connecting: false,
            is_fetching_domains: false,
            input_mode: true,
            auth_client: None,
            http_client: reqwest::Client::new(),
            network_token: None,
            network_token_expires: None,
            discovery_token: None,
            discovery_token_expires: None,
            last_tick: current_time_ms(),
        }
    }

    fn add_log(&mut self, msg: String) {
        self.logs.push(format!("[{}] {}", current_time_ms(), msg));
        // Keep only last 1000 logs
        if self.logs.len() > 1000 {
            self.logs.drain(0..100);
        }
    }

    fn cycle_credential_type(&mut self) {
        self.credential_type = match self.credential_type {
            CredentialType::EmailPassword => CredentialType::AppKey,
            CredentialType::AppKey => CredentialType::Opaque,
            CredentialType::Opaque => CredentialType::EmailPassword,
        };
        self.add_log(format!("Credential type changed to: {:?}", self.credential_type));
    }

    fn next_field(&mut self) {
        self.focused_field = match self.focused_field {
            InputField::ApiUrl => InputField::DdsUrl,
            InputField::DdsUrl => InputField::ClientId,
            InputField::ClientId => InputField::RefreshThreshold,
            InputField::RefreshThreshold => match self.credential_type {
                CredentialType::EmailPassword => InputField::Email,
                CredentialType::AppKey => InputField::AppKey,
                CredentialType::Opaque => InputField::OpaqueToken,
            },
            InputField::Email => InputField::Password,
            InputField::Password => InputField::ApiUrl,
            InputField::AppKey => InputField::AppSecret,
            InputField::AppSecret => InputField::ApiUrl,
            InputField::OpaqueToken => InputField::OpaqueExpiry,
            InputField::OpaqueExpiry => InputField::ApiUrl,
        };
    }

    fn prev_field(&mut self) {
        self.focused_field = match self.focused_field {
            InputField::ApiUrl => match self.credential_type {
                CredentialType::EmailPassword => InputField::Password,
                CredentialType::AppKey => InputField::AppSecret,
                CredentialType::Opaque => InputField::OpaqueExpiry,
            },
            InputField::DdsUrl => InputField::ApiUrl,
            InputField::ClientId => InputField::DdsUrl,
            InputField::RefreshThreshold => InputField::ClientId,
            InputField::Email => InputField::RefreshThreshold,
            InputField::Password => InputField::Email,
            InputField::AppKey => InputField::RefreshThreshold,
            InputField::AppSecret => InputField::AppKey,
            InputField::OpaqueToken => InputField::RefreshThreshold,
            InputField::OpaqueExpiry => InputField::OpaqueToken,
        };
    }

    fn get_focused_value_mut(&mut self) -> &mut String {
        match self.focused_field {
            InputField::ApiUrl => &mut self.api_url,
            InputField::DdsUrl => &mut self.dds_url,
            InputField::ClientId => &mut self.client_id,
            InputField::RefreshThreshold => &mut self.refresh_threshold_ms,
            InputField::Email => &mut self.email,
            InputField::Password => &mut self.password,
            InputField::AppKey => &mut self.app_key,
            InputField::AppSecret => &mut self.app_secret,
            InputField::OpaqueToken => &mut self.opaque_token,
            InputField::OpaqueExpiry => &mut self.opaque_expiry,
        }
    }

    fn get_credentials(&self) -> Result<Credentials, String> {
        match self.credential_type {
            CredentialType::EmailPassword => {
                if self.email.is_empty() || self.password.is_empty() {
                    return Err("Email and password required".to_string());
                }
                Ok(Credentials::EmailPassword {
                    email: self.email.clone(),
                    password: self.password.clone(),
                })
            }
            CredentialType::AppKey => {
                if self.app_key.is_empty() || self.app_secret.is_empty() {
                    return Err("App key and secret required".to_string());
                }
                Ok(Credentials::AppKey {
                    app_key: self.app_key.clone(),
                    app_secret: self.app_secret.clone(),
                })
            }
            CredentialType::Opaque => {
                if self.opaque_token.is_empty() || self.opaque_expiry.is_empty() {
                    return Err("Opaque token and expiry required".to_string());
                }
                let expiry_ms = self
                    .opaque_expiry
                    .parse::<u64>()
                    .map_err(|_| "Invalid expiry timestamp".to_string())?;
                Ok(Credentials::Opaque {
                    token: self.opaque_token.clone(),
                    refresh_token: None,
                    expiry_ms,
                    refresh_token_expiry_ms: None,
                    oidc_client_id: None,
                })
            }
        }
    }

    fn get_config(&self) -> Result<Config, String> {
        let refresh_threshold_ms = self
            .refresh_threshold_ms
            .parse::<u64>()
            .map_err(|_| "Invalid refresh threshold".to_string())?;

        Ok(Config {
            api_url: self.api_url.clone(),
            refresh_url: format!("{}/user/refresh", self.api_url),
            dds_url: self.dds_url.clone(),
            client_id: self.client_id.clone(),
            refresh_threshold_ms,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = Arc::new(Mutex::new(App::new()));

    // Run the app
    let res = run_app(&mut terminal, app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error: {:?}", err);
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app_arc: Arc<Mutex<App>>,
) -> io::Result<()> {
    // Create a 1-second interval for ticking
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        // Draw UI
        terminal.draw(|f| ui(f, &app_arc))?;

        // Use tokio::select to handle both events and ticks
        tokio::select! {
            _ = interval.tick() => {
                // On each tick, try to update authentication state
                let app_clone = Arc::clone(&app_arc);
                tokio::spawn(async move {
                    tick_update(app_clone).await;
                });
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Check for keyboard input
                if event::poll(Duration::from_millis(0))? {
                    if let CEvent::Key(key) = event::read()? {
                        let input_mode = {
                            let app = app_arc.lock().unwrap();
                            app.input_mode
                        };

                        match key.code {
                            KeyCode::Char('q') if !input_mode => return Ok(()),
                            KeyCode::Esc => {
                                if input_mode {
                                    let mut app = app_arc.lock().unwrap();
                                    app.input_mode = false;
                                } else {
                                    return Ok(());
                                }
                            }
                            KeyCode::Char('i') if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.input_mode = true;
                            }
                            KeyCode::Tab if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.next_field();
                            }
                            KeyCode::BackTab if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.prev_field();
                            }
                            KeyCode::Char('t') if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.selected_tab = match app.selected_tab {
                                    Tab::Status => Tab::Domains,
                                    Tab::Domains => Tab::Console,
                                    Tab::Console => Tab::WorldMap,
                                    Tab::WorldMap => Tab::Status,
                                };
                            }
                            KeyCode::Up if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                if app.selected_tab == Tab::Domains && !app.available_domains.is_empty() {
                                    if app.selected_domain_index > 0 {
                                        app.selected_domain_index -= 1;
                                    }
                                }
                            }
                            KeyCode::Down if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                if app.selected_tab == Tab::Domains && !app.available_domains.is_empty() {
                                    if app.selected_domain_index < app.available_domains.len() - 1 {
                                        app.selected_domain_index += 1;
                                    }
                                }
                            }
                            KeyCode::Char(' ') if !input_mode => {
                                // Space bar to authenticate to selected domain
                                let selected_tab = {
                                    let app = app_arc.lock().unwrap();
                                    app.selected_tab
                                };

                                if selected_tab == Tab::Domains {
                                    let is_connecting = {
                                        let app = app_arc.lock().unwrap();
                                        app.is_connecting
                                    };

                                    if !is_connecting {
                                        let app_clone = Arc::clone(&app_arc);
                                        tokio::spawn(async move {
                                            authenticate_to_selected_domain(app_clone).await;
                                        });
                                    }
                                }
                            }
                            KeyCode::Char('f') if !input_mode => {
                                // 'f' to fetch available domains
                                let is_fetching = {
                                    let app = app_arc.lock().unwrap();
                                    app.is_fetching_domains
                                };

                                if !is_fetching {
                                    let app_clone = Arc::clone(&app_arc);
                                    tokio::spawn(async move {
                                        fetch_available_domains(app_clone).await;
                                    });
                                }
                            }
                            KeyCode::Char('c') if !input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.cycle_credential_type();
                            }
                            KeyCode::Enter => {
                                if input_mode {
                                    let mut app = app_arc.lock().unwrap();
                                    app.input_mode = false;
                                } else {
                                    let is_connecting = {
                                        let app = app_arc.lock().unwrap();
                                        app.is_connecting
                                    };
                                    if !is_connecting {
                                        let app_clone = Arc::clone(&app_arc);
                                        tokio::spawn(async move {
                                            authenticate(app_clone).await;
                                        });
                                    }
                                }
                            }
                            KeyCode::Char(c) if input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.get_focused_value_mut().push(c);
                            }
                            KeyCode::Backspace if input_mode => {
                                let mut app = app_arc.lock().unwrap();
                                app.get_focused_value_mut().pop();
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &Arc<Mutex<App>>) {
    let app = app.lock().unwrap();

    // Main layout: left panel and right panel
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(f.size());

    // Left panel - inputs
    render_input_panel(f, chunks[0], &app);

    // Right panel - tabs (console/map)
    render_right_panel(f, chunks[1], &app);
}

fn render_input_panel(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title("[ CONFIG ]")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(2), // API URL
                Constraint::Length(2), // DDS URL
                Constraint::Length(2), // Client ID
                Constraint::Length(2), // Refresh threshold
                Constraint::Length(2), // Credential type selector
                Constraint::Length(6), // Credential fields
                Constraint::Min(1),    // Help text
            ]
            .as_ref(),
        )
        .split(inner);

    // Config fields
    render_input_field(
        f,
        chunks[0],
        "API URL",
        &app.api_url,
        app.focused_field == InputField::ApiUrl,
        app.input_mode,
    );
    render_input_field(
        f,
        chunks[1],
        "DDS URL",
        &app.dds_url,
        app.focused_field == InputField::DdsUrl,
        app.input_mode,
    );
    render_input_field(
        f,
        chunks[2],
        "Client ID",
        &app.client_id,
        app.focused_field == InputField::ClientId,
        app.input_mode,
    );
    render_input_field(
        f,
        chunks[3],
        "Refresh (ms)",
        &app.refresh_threshold_ms,
        app.focused_field == InputField::RefreshThreshold,
        app.input_mode,
    );

    // Credential type selector
    let cred_type_text = match app.credential_type {
        CredentialType::EmailPassword => "[Email/Pass] AppKey Opaque",
        CredentialType::AppKey => "Email/Pass [AppKey] Opaque",
        CredentialType::Opaque => "Email/Pass AppKey [Opaque]",
    };
    let cred_paragraph = Paragraph::new(cred_type_text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center);
    f.render_widget(cred_paragraph, chunks[4]);

    // Credential fields based on type
    match app.credential_type {
        CredentialType::EmailPassword => {
            let cred_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Length(2)].as_ref())
                .split(chunks[5]);
            render_input_field(
                f,
                cred_chunks[0],
                "Email",
                &app.email,
                app.focused_field == InputField::Email,
                app.input_mode,
            );
            render_input_field(
                f,
                cred_chunks[1],
                "Password",
                &"*".repeat(app.password.len()),
                app.focused_field == InputField::Password,
                app.input_mode,
            );
        }
        CredentialType::AppKey => {
            let cred_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Length(2)].as_ref())
                .split(chunks[5]);
            render_input_field(
                f,
                cred_chunks[0],
                "App Key",
                &app.app_key,
                app.focused_field == InputField::AppKey,
                app.input_mode,
            );
            render_input_field(
                f,
                cred_chunks[1],
                "App Secret",
                &"*".repeat(app.app_secret.len()),
                app.focused_field == InputField::AppSecret,
                app.input_mode,
            );
        }
        CredentialType::Opaque => {
            let cred_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Length(2)].as_ref())
                .split(chunks[5]);
            render_input_field(
                f,
                cred_chunks[0],
                "Token",
                &app.opaque_token,
                app.focused_field == InputField::OpaqueToken,
                app.input_mode,
            );
            render_input_field(
                f,
                cred_chunks[1],
                "Expiry (ms)",
                &app.opaque_expiry,
                app.focused_field == InputField::OpaqueExpiry,
                app.input_mode,
            );
        }
    }

    // Help text
    let mode_text = if app.input_mode {
        "-- INSERT --"
    } else {
        "-- NORMAL --"
    };

    let help_text = if app.input_mode {
        vec![
            Line::from(vec![
                Span::styled(mode_text, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("ESC", Style::default().fg(Color::Yellow)),
                Span::raw(": Exit input mode"),
            ]),
            Line::from(vec![
                Span::styled("ENTER", Style::default().fg(Color::Yellow)),
                Span::raw(": Confirm input"),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled(mode_text, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("I", Style::default().fg(Color::Yellow)),
                Span::raw(": Enter input mode"),
            ]),
            Line::from(vec![
                Span::styled("TAB", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate fields"),
            ]),
            Line::from(vec![
                Span::styled("C", Style::default().fg(Color::Yellow)),
                Span::raw(": Cycle credentials  "),
                Span::styled("F", Style::default().fg(Color::Yellow)),
                Span::raw(": Fetch domains"),
            ]),
            Line::from(vec![
                Span::styled("T", Style::default().fg(Color::Yellow)),
                Span::raw(": Toggle view  "),
                Span::styled("SPACE", Style::default().fg(Color::Yellow)),
                Span::raw(": Auth domain"),
            ]),
            Line::from(vec![
                Span::styled("ENTER", Style::default().fg(Color::Yellow)),
                Span::raw(": Connect  "),
                Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
                Span::raw(": Navigate domains"),
            ]),
            Line::from(vec![
                Span::styled("Q/ESC", Style::default().fg(Color::Yellow)),
                Span::raw(": Quit"),
            ]),
        ]
    };

    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Left);
    f.render_widget(help, chunks[6]);
}

fn render_input_field(f: &mut Frame, area: Rect, label: &str, value: &str, focused: bool, input_mode: bool) {
    let (style, prefix) = if focused && input_mode {
        (Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD), ">>> ")
    } else if focused {
        (Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD), "→ ")
    } else {
        (Style::default().fg(Color::Green), "  ")
    };

    let cursor = if focused && input_mode { "█" } else { "" };
    let text = format!("{}{}: {}{}", prefix, label, value, cursor);
    let paragraph = Paragraph::new(text).style(style);
    f.render_widget(paragraph, area);
}

fn render_right_panel(f: &mut Frame, area: Rect, app: &App) {
    let tabs = vec!["[ STATUS ]", "[ DOMAINS ]", "[ CONSOLE ]", "[ WORLD MAP ]"];
    let selected = match app.selected_tab {
        Tab::Status => 0,
        Tab::Domains => 1,
        Tab::Console => 2,
        Tab::WorldMap => 3,
    };

    let tabs_widget = Tabs::new(tabs)
        .select(selected)
        .style(Style::default().fg(Color::Green))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(area);

    f.render_widget(tabs_widget, chunks[0]);

    match app.selected_tab {
        Tab::Status => render_status(f, chunks[1], app),
        Tab::Domains => render_domains(f, chunks[1], app),
        Tab::Console => render_console(f, chunks[1], app),
        Tab::WorldMap => render_world_map(f, chunks[1], app),
    }
}

fn render_status(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title("[ AUTHENTICATION STATUS ]")
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split into three sections: pipeline, tokens, and timers
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Pipeline visualization
            Constraint::Min(10),    // Token details
            Constraint::Length(3),  // Status bar
        ])
        .split(inner);

    // Get current time for expiry calculations
    let now = current_time_ms();

    // Render authentication pipeline
    let has_network = app.network_token.is_some();
    let has_discovery = app.discovery_token.is_some();
    let domain_count = app.authenticated_domains.len();

    let network_status = if has_network { "✓" } else { "○" };
    let discovery_status = if has_discovery { "✓" } else { "○" };
    let domain_status = if domain_count > 0 {
        format!("✓ {}", domain_count)
    } else {
        "○".to_string()
    };

    let network_color = if has_network { Color::Green } else { Color::DarkGray };
    let discovery_color = if has_discovery { Color::Green } else { Color::DarkGray };
    let domain_color = if domain_count > 0 { Color::Green } else { Color::DarkGray };

    let pipeline = vec![
        Line::from(vec![
            Span::raw("  "),
            Span::styled(network_status, Style::default().fg(network_color).add_modifier(Modifier::BOLD)),
            Span::raw(" NETWORK"),
            Span::raw("  ──→  "),
            Span::styled(discovery_status, Style::default().fg(discovery_color).add_modifier(Modifier::BOLD)),
            Span::raw(" DISCOVERY"),
            Span::raw("  ──→  "),
            Span::styled(domain_status, Style::default().fg(domain_color).add_modifier(Modifier::BOLD)),
            Span::raw(" DOMAINS"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Authentication Pipeline", Style::default().fg(Color::Cyan)),
            Span::raw("  "),
            Span::styled("○", Style::default().fg(Color::DarkGray)),
            Span::raw(" Not authenticated  "),
            Span::styled("✓", Style::default().fg(Color::Green)),
            Span::raw(" Authenticated  "),
            Span::styled("✓ N", Style::default().fg(Color::Green)),
            Span::raw(" N domains"),
        ]),
    ];

    let pipeline_widget = Paragraph::new(pipeline)
        .style(Style::default().bg(Color::Black))
        .alignment(Alignment::Left);
    f.render_widget(pipeline_widget, chunks[0]);

    // Render token details
    let mut token_lines = vec![
        Line::from(vec![
            Span::styled("╔═══════════════════════════════════════════════════════════════════╗", Style::default().fg(Color::Green)),
        ]),
    ];

    // Network token
    if let Some(ref token) = app.network_token {
        let truncated = if token.len() > 50 {
            format!("{}...", &token[..50])
        } else {
            token.clone()
        };

        let expiry_info = if let Some(expires) = app.network_token_expires {
            let remaining_ms = expires.saturating_sub(now);
            let remaining_secs = remaining_ms / 1000;
            let remaining_mins = remaining_secs / 60;
            if remaining_ms > 0 {
                format!("expires in {}m {}s", remaining_mins, remaining_secs % 60)
            } else {
                "EXPIRED".to_string()
            }
        } else {
            "never expires".to_string()
        };

        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::styled("NETWORK TOKEN", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::raw("  Token: "),
            Span::styled(truncated, Style::default().fg(Color::Yellow)),
        ]));
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::raw("  Status: "),
            Span::styled(expiry_info, Style::default().fg(Color::Green)),
        ]));
    } else {
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::styled("NETWORK TOKEN", Style::default().fg(Color::DarkGray)),
            Span::raw(": "),
            Span::styled("Not authenticated", Style::default().fg(Color::Red)),
        ]));
    }

    token_lines.push(Line::from(vec![
        Span::styled("║                                                                   ║", Style::default().fg(Color::Green)),
    ]));

    // Discovery token
    if let Some(ref token) = app.discovery_token {
        let truncated = if token.len() > 50 {
            format!("{}...", &token[..50])
        } else {
            token.clone()
        };

        let expiry_info = if let Some(expires) = app.discovery_token_expires {
            let remaining_ms = expires.saturating_sub(now);
            let remaining_secs = remaining_ms / 1000;
            let remaining_mins = remaining_secs / 60;
            if remaining_ms > 0 {
                format!("expires in {}m {}s", remaining_mins, remaining_secs % 60)
            } else {
                "EXPIRED".to_string()
            }
        } else {
            "unknown expiry".to_string()
        };

        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::styled("DISCOVERY TOKEN", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ]));
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::raw("  Token: "),
            Span::styled(truncated, Style::default().fg(Color::Yellow)),
        ]));
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::raw("  Status: "),
            Span::styled(expiry_info, Style::default().fg(Color::Green)),
        ]));
    } else {
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::styled("DISCOVERY TOKEN", Style::default().fg(Color::DarkGray)),
            Span::raw(": "),
            Span::styled("Not authenticated", Style::default().fg(Color::Red)),
        ]));
    }

    token_lines.push(Line::from(vec![
        Span::styled("║                                                                   ║", Style::default().fg(Color::Green)),
    ]));

    // Domain access tokens
    if app.authenticated_domains.is_empty() {
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::styled("DOMAIN ACCESS", Style::default().fg(Color::DarkGray)),
            Span::raw(": "),
            Span::styled("No domains authenticated", Style::default().fg(Color::Red)),
        ]));
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::raw("  Press F in Domains tab to fetch available domains"),
        ]));
    } else {
        token_lines.push(Line::from(vec![
            Span::styled("║ ", Style::default().fg(Color::Green)),
            Span::styled("DOMAIN ACCESS TOKENS", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" ({} domains)", app.authenticated_domains.len())),
        ]));

        // Show up to 3 domains (to avoid overflow)
        let domains_to_show: Vec<_> = app.authenticated_domains.iter().take(3).collect();

        for (domain_id, (token, expires_at, _server)) in domains_to_show {
            // Find the domain name from available_domains if possible
            let domain_name = app.available_domains
                .iter()
                .find(|d| &d.id == domain_id)
                .map(|d| d.name.as_str())
                .unwrap_or_else(|| &domain_id[..8]);

            let truncated_token = if token.len() > 30 {
                format!("{}...", &token[..30])
            } else {
                token.clone()
            };

            let remaining_ms = expires_at.saturating_sub(now);
            let remaining_secs = remaining_ms / 1000;
            let remaining_mins = remaining_secs / 60;
            let expiry_info = if remaining_ms > 0 {
                format!("{}m {}s", remaining_mins, remaining_secs % 60)
            } else {
                "EXPIRED".to_string()
            };
            let expiry_color = if remaining_ms > 0 { Color::Green } else { Color::Red };

            token_lines.push(Line::from(vec![
                Span::styled("║ ", Style::default().fg(Color::Green)),
                Span::raw("  "),
                Span::styled(domain_name, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(": "),
                Span::styled(truncated_token, Style::default().fg(Color::DarkGray)),
                Span::raw(" ("),
                Span::styled(expiry_info, Style::default().fg(expiry_color)),
                Span::raw(")"),
            ]));
        }

        // If there are more domains, show count
        if app.authenticated_domains.len() > 3 {
            let remaining = app.authenticated_domains.len() - 3;
            token_lines.push(Line::from(vec![
                Span::styled("║ ", Style::default().fg(Color::Green)),
                Span::raw(format!("  ... and {} more domain(s)", remaining)),
            ]));
        }
    }

    token_lines.push(Line::from(vec![
        Span::styled("╚═══════════════════════════════════════════════════════════════════╝", Style::default().fg(Color::Green)),
    ]));

    let tokens_widget = Paragraph::new(token_lines)
        .style(Style::default().bg(Color::Black))
        .alignment(Alignment::Left);
    f.render_widget(tokens_widget, chunks[1]);

    // Status bar at bottom
    let status_text = if app.is_connecting {
        vec![Line::from(vec![
            Span::styled("⟳ ", Style::default().fg(Color::Yellow)),
            Span::styled("Authenticating...", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ])]
    } else if domain_count > 0 {
        let plural = if domain_count == 1 { "domain" } else { "domains" };
        vec![Line::from(vec![
            Span::styled("✓ ", Style::default().fg(Color::Green)),
            Span::styled(format!("Authenticated to {} {} - Auto-refreshing network/discovery tokens", domain_count, plural), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ])]
    } else if has_discovery {
        vec![Line::from(vec![
            Span::styled("✓ ", Style::default().fg(Color::Yellow)),
            Span::styled("Network + Discovery authenticated - Press F in Domains tab to fetch domains", Style::default().fg(Color::Yellow)),
        ])]
    } else {
        vec![Line::from(vec![
            Span::styled("○ ", Style::default().fg(Color::DarkGray)),
            Span::styled("Press ENTER to authenticate to network + discovery", Style::default().fg(Color::DarkGray)),
        ])]
    };

    let status_widget = Paragraph::new(status_text)
        .style(Style::default().bg(Color::Black))
        .alignment(Alignment::Center);
    f.render_widget(status_widget, chunks[2]);
}

fn render_console(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Show last N logs that fit in the area
    let log_height = inner.height as usize;
    let start_idx = app.logs.len().saturating_sub(log_height);
    let logs_to_show = &app.logs[start_idx..];

    let items: Vec<ListItem> = logs_to_show
        .iter()
        .map(|log| {
            let style = if log.contains("SUCCESS") || log.contains("✓") {
                Style::default().fg(Color::Green)
            } else if log.contains("FAILED") || log.contains("✗") || log.contains("ERROR") {
                Style::default().fg(Color::Red)
            } else if log.contains(">>>") {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Green)
            };
            ListItem::new(log.as_str()).style(style)
        })
        .collect();

    let list = List::new(items).style(Style::default().bg(Color::Black));
    f.render_widget(list, inner);
}

fn render_domains(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title("[ AVAILABLE DOMAINS ]")
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.is_fetching_domains {
        let loading = Paragraph::new("Fetching available domains...")
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);
        f.render_widget(loading, inner);
        return;
    }

    if app.available_domains.is_empty() {
        let help_lines = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("No domains available", Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::DarkGray)),
                Span::styled("F", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(" to fetch available domains", Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(vec![
                Span::styled("(Requires discovery authentication)", Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
            ]),
        ];
        let help = Paragraph::new(help_lines).alignment(Alignment::Center);
        f.render_widget(help, inner);
        return;
    }

    // Split into help and list
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(4)])
        .split(inner);

    // Render domain list
    let items: Vec<ListItem> = app
        .available_domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            let is_selected = i == app.selected_domain_index;
            let is_authenticated = app.authenticated_domains.contains_key(&domain.id);

            let status = if is_authenticated { "✓" } else { "○" };
            let status_color = if is_authenticated { Color::Green } else { Color::DarkGray };

            let line = if is_selected {
                Line::from(vec![
                    Span::styled("> ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::styled(status, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                    Span::raw(" "),
                    Span::styled(&domain.name, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                    Span::raw(" ("),
                    Span::styled(&domain.id[..8], Style::default().fg(Color::DarkGray)),
                    Span::raw("...)"),
                ])
            } else {
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(status, Style::default().fg(status_color)),
                    Span::raw(" "),
                    Span::styled(&domain.name, Style::default().fg(Color::Green)),
                    Span::raw(" ("),
                    Span::styled(&domain.id[..8], Style::default().fg(Color::DarkGray)),
                    Span::raw("...)"),
                ])
            };

            let mut content = vec![line];

            // Add server info for selected domain
            if is_selected {
                content.push(Line::from(vec![
                    Span::raw("    Server: "),
                    Span::styled(&domain.domain_server.name, Style::default().fg(Color::Yellow)),
                    Span::raw(" @ "),
                    Span::styled(&domain.domain_server.cloud_region, Style::default().fg(Color::Magenta)),
                ]));
                content.push(Line::from(vec![
                    Span::raw("    Location: "),
                    Span::styled(format!("{:.2}, {:.2}", domain.domain_server.latitude, domain.domain_server.longitude), Style::default().fg(Color::Cyan)),
                ]));
            }

            ListItem::new(content)
        })
        .collect();

    let list = List::new(items).style(Style::default().bg(Color::Black));
    f.render_widget(list, chunks[0]);

    // Help text
    let help_lines = vec![
        Line::from(vec![
            Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
            Span::raw(": Navigate  "),
            Span::styled("SPACE", Style::default().fg(Color::Yellow)),
            Span::raw(": Authenticate  "),
            Span::styled("F", Style::default().fg(Color::Yellow)),
            Span::raw(": Refresh list"),
        ]),
        Line::from(vec![
            Span::styled("○", Style::default().fg(Color::DarkGray)),
            Span::raw(" Not authenticated  "),
            Span::styled("✓", Style::default().fg(Color::Green)),
            Span::raw(" Authenticated"),
        ]),
    ];
    let help = Paragraph::new(help_lines)
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);
    f.render_widget(help, chunks[1]);
}

fn render_world_map(f: &mut Frame, area: Rect, app: &App) {
    // Collect all domain locations for rendering
    let available_domains = app.available_domains.clone();
    let authenticated_domains = app.authenticated_domains.clone();

    let canvas = Canvas::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green))
                .title("[ WORLD MAP ]")
                .style(Style::default().bg(Color::Black)),
        )
        .x_bounds([-180.0, 180.0])
        .y_bounds([-90.0, 90.0])
        .paint(move |ctx| {
            // Draw the world map
            ctx.draw(&Map {
                color: Color::Green,
                resolution: MapResolution::High,
            });

            if available_domains.is_empty() {
                // No domain data message
                ctx.print(
                    0.0,
                    0.0,
                    "No domains - Press F to fetch available domains".dark_gray(),
                );
                return;
            }

            // Draw all available domains
            for domain in &available_domains {
                let lat = domain.domain_server.latitude;
                let lon = domain.domain_server.longitude;
                let is_authenticated = authenticated_domains.contains_key(&domain.id);

                // Draw marker
                let color = if is_authenticated { Color::Red } else { Color::Yellow };
                ctx.draw(&Points {
                    coords: &[(lon, lat)],
                    color,
                });

                // Draw label for authenticated domains
                if is_authenticated {
                    let label = format!("✓ {}", &domain.name);
                    ctx.print(lon, lat + 5.0, label.red().bold());
                }
            }

            // Draw legend
            ctx.print(-170.0, -85.0, "Yellow: Available  Red: Authenticated".yellow());
        });

    f.render_widget(canvas, area);
}


async fn tick_update(app: Arc<Mutex<App>>) {
    let now = current_time_ms();

    // Take ownership of the client temporarily
    let (mut client, http_client) = {
        let mut app = app.lock().unwrap();

        // Update last tick time
        app.last_tick = now;

        // Don't tick if already connecting
        if app.is_connecting {
            return;
        }

        // Check if we have a client
        if app.auth_client.is_none() {
            return;
        }

        // Take ownership of the client
        let client = app.auth_client.take().unwrap();
        (client, app.http_client.clone())
    };

    // Refresh network and discovery tokens if needed
    let actions = client.authenticate(now);

    for action in actions {
        if let Action::HttpRequest {
            url,
            method,
            headers,
            body,
        } = action
        {
            let mut request = match method.as_str() {
                "GET" => http_client.get(&url),
                "POST" => http_client.post(&url),
                _ => continue,
            };

            for (key, value) in headers {
                request = request.header(key, value);
            }

            if let Some(body_str) = body {
                request = request.body(body_str);
            }

            if let Ok(response) = request.send().await {
                let status = response.status().as_u16();
                let body_text = response.text().await.unwrap_or_default();

                let _events = client.handle_response(status, &body_text);
                // Events handled silently in tick_update
            }
        }
    }

    // Also refresh discovery token if needed
    let discovery_actions = client.authenticate_discovery(now);
    for action in discovery_actions {
        if let Action::HttpRequest {
            url,
            method,
            headers,
            body,
        } = action
        {
            let mut request = match method.as_str() {
                "GET" => http_client.get(&url),
                "POST" => http_client.post(&url),
                _ => continue,
            };

            for (key, value) in headers {
                request = request.header(key, value);
            }

            if let Some(body_str) = body {
                request = request.body(body_str);
            }

            if let Ok(response) = request.send().await {
                let status = response.status().as_u16();
                let body_text = response.text().await.unwrap_or_default();
                let _events = client.handle_response(status, &body_text);
                // Events handled silently in tick_update
            }
        }
    }

    // Update token information from client
    {
        let mut app = app.lock().unwrap();

        if let Some(network_token) = client.network_token() {
            app.network_token = Some(network_token.token.clone());
            app.network_token_expires = Some(network_token.expires_at);
        }

        if let Some(discovery_token) = client.discovery_token() {
            app.discovery_token = Some(discovery_token.token.clone());
            app.discovery_token_expires = Some(discovery_token.expires_at);
        }

        // Update the client in app
        app.auth_client = Some(client);
    }
}

async fn authenticate(app: Arc<Mutex<App>>) {
    let (credentials, config) = {
        let mut app = app.lock().unwrap();
        app.is_connecting = true;
        app.add_log(">>> AUTHENTICATION SEQUENCE INITIATED <<<".to_string());

        let credentials = match app.get_credentials() {
            Ok(c) => c,
            Err(e) => {
                app.add_log(format!("✗ ERROR: {}", e));
                app.is_connecting = false;
                return;
            }
        };

        let config = match app.get_config() {
            Ok(c) => c,
            Err(e) => {
                app.add_log(format!("✗ ERROR: {}", e));
                app.is_connecting = false;
                return;
            }
        };

        (credentials, config)
    };

    let mut client = Client::new(config);
    client.set_credentials(credentials);
    let http_client = reqwest::Client::new();
    let now = current_time_ms();

    // Authenticate to network
    {
        let mut app = app.lock().unwrap();
        app.add_log(">>> PHASE 1: NETWORK AUTHENTICATION <<<".to_string());
    }

    let actions = client.authenticate(now);
    for action in actions {
        if let Action::HttpRequest {
            url,
            method,
            headers,
            body,
        } = action
        {
            {
                let mut app = app.lock().unwrap();
                app.add_log(format!("→ {} {}", method, url));
            }

            let mut request = match method.as_str() {
                "GET" => http_client.get(&url),
                "POST" => http_client.post(&url),
                "PUT" => http_client.put(&url),
                "DELETE" => http_client.delete(&url),
                _ => {
                    let mut app = app.lock().unwrap();
                    app.add_log(format!("✗ Unsupported method: {}", method));
                    continue;
                }
            };

            for (key, value) in headers {
                request = request.header(key, value);
            }

            if let Some(body_str) = body {
                request = request.body(body_str);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body_text = response.text().await.unwrap_or_default();

                    {
                        let mut app = app.lock().unwrap();
                        app.add_log(format!("← Status: {}", status));
                    }

                    let events = client.handle_response(status, &body_text);
                    for event in events {
                        let mut app = app.lock().unwrap();
                        match event {
                            Event::NetworkAuthSuccess { expires_at, .. } => {
                                app.add_log(format!("✓ Network auth SUCCESS (expires: {})", expires_at));
                            }
                            Event::NetworkAuthFailed { reason, .. } => {
                                app.add_log(format!("✗ Network auth FAILED: {}", reason));
                                app.is_connecting = false;
                                return;
                            }
                            _ => {
                                app.add_log(format!("Event: {:?}", event));
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut app = app.lock().unwrap();
                    app.add_log(format!("✗ Request ERROR: {}", e));
                    app.is_connecting = false;
                    return;
                }
            }
        }
    }

    // Authenticate to discovery
    {
        let mut app = app.lock().unwrap();
        app.add_log(">>> PHASE 2: DISCOVERY AUTHENTICATION <<<".to_string());
    }

    let actions = client.authenticate_discovery(now);
    for action in actions {
        if let Action::HttpRequest {
            url,
            method,
            headers,
            body,
        } = action
        {
            {
                let mut app = app.lock().unwrap();
                app.add_log(format!("→ {} {}", method, url));
            }

            let mut request = match method.as_str() {
                "GET" => http_client.get(&url),
                "POST" => http_client.post(&url),
                _ => {
                    let mut app = app.lock().unwrap();
                    app.add_log(format!("✗ Unsupported method: {}", method));
                    continue;
                }
            };

            for (key, value) in headers {
                request = request.header(key, value);
            }

            if let Some(body_str) = body {
                request = request.body(body_str);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body_text = response.text().await.unwrap_or_default();

                    {
                        let mut app = app.lock().unwrap();
                        app.add_log(format!("← Status: {}", status));
                    }

                    let events = client.handle_response(status, &body_text);
                    for event in events {
                        let mut app = app.lock().unwrap();
                        match event {
                            Event::DiscoveryAuthSuccess { expires_at, .. } => {
                                app.add_log(format!(
                                    "✓ Discovery auth SUCCESS (expires: {})",
                                    expires_at
                                ));
                            }
                            Event::DiscoveryAuthFailed { reason } => {
                                app.add_log(format!("✗ Discovery auth FAILED: {}", reason));
                                app.is_connecting = false;
                                return;
                            }
                            _ => {
                                app.add_log(format!("Event: {:?}", event));
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut app = app.lock().unwrap();
                    app.add_log(format!("✗ Request ERROR: {}", e));
                    app.is_connecting = false;
                    return;
                }
            }
        }
    }

    {
        let mut app = app.lock().unwrap();
        app.add_log(">>> AUTHENTICATION SEQUENCE COMPLETE <<<".to_string());
        app.add_log("Press F to fetch available domains, then use SPACE to authenticate to domains".to_string());

        // Update token information from client before moving it
        if let Some(network_token) = client.network_token() {
            app.network_token = Some(network_token.token.clone());
            app.network_token_expires = Some(network_token.expires_at);
        }

        if let Some(discovery_token) = client.discovery_token() {
            app.discovery_token = Some(discovery_token.token.clone());
            app.discovery_token_expires = Some(discovery_token.expires_at);
        }

        // Store the client in app state for tick updates (move happens here)
        app.auth_client = Some(client);

        app.is_connecting = false;
    }
}

async fn fetch_available_domains(app: Arc<Mutex<App>>) {
    // Mark as fetching
    {
        let mut app = app.lock().unwrap();
        app.is_fetching_domains = true;
        app.add_log(">>> FETCHING AVAILABLE DOMAINS <<<".to_string());
    }

    // Get discovery token and DDS URL
    let (discovery_token, dds_url, http_client) = {
        let app = app.lock().unwrap();

        match &app.discovery_token {
            Some(token) => (token.clone(), app.dds_url.clone(), app.http_client.clone()),
            None => {
                let mut app_mut = app;
                app_mut.add_log("✗ ERROR: No discovery token - authenticate first".to_string());
                app_mut.is_fetching_domains = false;
                return;
            }
        }
    };

    // Make request to DDS API
    let url = format!("{}/api/v1/domains?with=domain_server", dds_url);

    {
        let mut app = app.lock().unwrap();
        app.add_log(format!("→ GET {}", url));
    }

    match http_client
        .get(&url)
        .header("Authorization", format!("Bearer {}", discovery_token))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status().as_u16();

            {
                let mut app = app.lock().unwrap();
                app.add_log(format!("← Status: {}", status));
            }

            if status == 200 {
                match response.json::<DomainsResponse>().await {
                    Ok(domains_response) => {
                        let mut app = app.lock().unwrap();
                        let count = domains_response.domains.len();
                        app.add_log(format!("✓ Fetched {} available domains", count));
                        app.available_domains = domains_response.domains;
                        app.selected_domain_index = 0;
                    }
                    Err(e) => {
                        let mut app = app.lock().unwrap();
                        app.add_log(format!("✗ Failed to parse response: {}", e));
                    }
                }
            } else {
                let body = response.text().await.unwrap_or_default();
                let mut app = app.lock().unwrap();
                app.add_log(format!("✗ Request failed: {}", body));
            }
        }
        Err(e) => {
            let mut app = app.lock().unwrap();
            app.add_log(format!("✗ Request ERROR: {}", e));
        }
    }

    {
        let mut app = app.lock().unwrap();
        app.is_fetching_domains = false;
    }
}

async fn authenticate_to_selected_domain(app: Arc<Mutex<App>>) {
    // Get selected domain
    let (domain_id, domain_name, mut client, http_client) = {
        let mut app = app.lock().unwrap();

        if app.available_domains.is_empty() {
            app.add_log("✗ ERROR: No domains available".to_string());
            return;
        }

        if app.selected_domain_index >= app.available_domains.len() {
            app.add_log("✗ ERROR: Invalid domain selection".to_string());
            return;
        }

        let domain = &app.available_domains[app.selected_domain_index];
        let domain_id = domain.id.clone();
        let domain_name = domain.name.clone();

        // Check if already authenticated
        if app.authenticated_domains.contains_key(&domain_id) {
            app.add_log(format!("✓ Already authenticated to domain: {}", domain_name));
            return;
        }

        match app.auth_client.take() {
            Some(client) => {
                app.is_connecting = true;
                app.add_log(format!(">>> AUTHENTICATING TO DOMAIN: {} <<<", domain_name));
                (domain_id, domain_name, client, app.http_client.clone())
            }
            None => {
                app.add_log("✗ ERROR: No auth client - authenticate to network first".to_string());
                return;
            }
        }
    };

    let now = current_time_ms();
    let actions = client.get_domain_access(&domain_id, now);

    for action in actions {
        if let Action::HttpRequest {
            url,
            method,
            headers,
            body,
        } = action
        {
            {
                let mut app = app.lock().unwrap();
                app.add_log(format!("→ {} {}", method, url));
            }

            let mut request = match method.as_str() {
                "GET" => http_client.get(&url),
                "POST" => http_client.post(&url),
                _ => {
                    let mut app = app.lock().unwrap();
                    app.add_log(format!("✗ Unsupported method: {}", method));
                    continue;
                }
            };

            for (key, value) in headers {
                request = request.header(key, value);
            }

            if let Some(body_str) = body {
                request = request.body(body_str);
            }

            match request.send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body_text = response.text().await.unwrap_or_default();

                    {
                        let mut app = app.lock().unwrap();
                        app.add_log(format!("← Status: {}", status));
                    }

                    let events = client.handle_response(status, &body_text);
                    for event in events {
                        let mut app = app.lock().unwrap();
                        match &event {
                            Event::DomainAccessGranted { domain } => {
                                app.add_log(format!("✓ Domain access GRANTED: {}", domain.name));
                                app.add_log(format!("  Server: {}", domain.domain_server.name));
                                app.add_log(format!("  Location: {}, {}", domain.domain_server.latitude, domain.domain_server.longitude));

                                // Store authenticated domain
                                app.authenticated_domains.insert(
                                    domain.id.clone(),
                                    (
                                        domain.access_token.clone(),
                                        domain.expires_at,
                                        DomainServer {
                                            id: domain.domain_server.id.clone(),
                                            organization_id: domain.domain_server.organization_id.clone(),
                                            name: domain.domain_server.name.clone(),
                                            url: domain.domain_server.url.clone(),
                                            version: domain.domain_server.version.clone(),
                                            status: domain.domain_server.status.clone(),
                                            mode: domain.domain_server.mode.clone(),
                                            variants: domain.domain_server.variants.clone(),
                                            ip: domain.domain_server.ip.clone(),
                                            latitude: domain.domain_server.latitude,
                                            longitude: domain.domain_server.longitude,
                                            cloud_region: domain.domain_server.cloud_region.clone(),
                                        },
                                    ),
                                );
                            }
                            Event::DomainAccessDenied { domain_id, reason } => {
                                app.add_log(format!("✗ Domain access DENIED [{}]: {}", domain_id, reason));
                            }
                            _ => {
                                app.add_log(format!("Event: {:?}", event));
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut app = app.lock().unwrap();
                    app.add_log(format!("✗ Request ERROR: {}", e));
                }
            }
        }
    }

    {
        let mut app = app.lock().unwrap();
        app.add_log(format!(">>> DOMAIN AUTHENTICATION COMPLETE: {} <<<", domain_name));
        app.auth_client = Some(client);
        app.is_connecting = false;
    }
}
