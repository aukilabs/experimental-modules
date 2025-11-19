# Examples

## Basic Example

The basic example demonstrates the authentication library with real HTTP requests using reqwest.

```bash
# Create .env file from template
cp .env.example .env

# Edit .env with your credentials
# Then run:
cargo run --example basic
```

## TUI Example

A retro hacker-style Terminal User Interface (TUI) for interacting with the Auki authentication system.

### Features

- **Left Panel**: Configuration and credential inputs
  - API URL, DDS URL, Client ID configuration
  - Toggle between credential types (Email/Password, AppKey, Opaque)

- **Right Panel**: Multiple tabs for different views
  - **Status Tab**: Authentication pipeline status, token information with expiry countdowns
  - **Domains Tab**: List of available domains with selection and multi-domain authentication
  - **Console Tab**: Real-time authentication flow logs showing HTTP requests, responses, and events
  - **World Map Tab**: ASCII world map showing all available domains and authenticated domains

- **Multi-Domain Support**: Authenticate to multiple domains simultaneously to test the library's multi-domain token management

- **Retro Aesthetic**: Dark green-on-black terminal style reminiscent of classic hacker terminals

### Running the TUI

```bash
cargo run --example tui
```

### Keyboard Controls

The TUI has two modes, similar to Vim:

#### Normal Mode (default)
- **I**: Enter input mode to edit fields
- **TAB** / **SHIFT+TAB**: Navigate between input fields
- **C**: Cycle through credential types (Email/Password → AppKey → Opaque)
- **T**: Toggle between tabs (Status → Domains → Console → World Map)
- **F**: Fetch available domains from Discovery service (requires discovery authentication)
- **↑** / **↓**: Navigate domains list (in Domains tab)
- **SPACE**: Authenticate to selected domain (in Domains tab)
- **ENTER**: Start full authentication sequence (network → discovery → domain)
- **Q** / **ESC**: Quit application

#### Input Mode
- **Type normally**: Edit the focused field
- **ENTER**: Exit input mode (confirm input)
- **ESC**: Exit input mode (confirm input)
- **BACKSPACE**: Delete characters

### Usage Flow

1. Start the TUI: `cargo run --example tui`
2. The app starts in **Input Mode** on the Email field
3. Fill in configuration and credentials (see fields below)
4. Press **ESC** to exit input mode, then press **ENTER** to start initial authentication (network + discovery)
5. Watch the authentication progress in the **Status** tab
6. Press **T** to navigate to the **Domains** tab
7. Press **F** to fetch available domains (requires discovery token)
8. Use **↑/↓** to navigate the domains list
9. Press **SPACE** to authenticate to the selected domain
10. Repeat steps 8-9 to authenticate to multiple domains
11. Press **T** to view the **World Map** tab - see all domains plotted with authenticated ones highlighted in red
12. View detailed logs in the **Console** tab

### Configuration Fields

Fill in all required fields:
- **API URL** (default: https://api.aukiverse.com)
- **DDS URL** (default: https://dds.posemesh.org)
- **Client ID** (default: rust-tui)
- **Refresh Threshold** in milliseconds (default: 300000)
- **Credentials** based on selected type:
  - **Email/Password**: Email and password
  - **AppKey**: App key and app secret
  - **Opaque**: Opaque token and expiry timestamp

### Features in Action

The TUI demonstrates the full authentication flow:
1. **Network authentication**: Authenticate with the Auki API (press ENTER)
2. **Discovery service authentication**: Get discovery token (automatic with network auth)
3. **Fetch available domains**: Query DDS API for domains you have access to (press F in Domains tab)
4. **Multi-domain authentication**: Authenticate to multiple domains simultaneously (press SPACE on selected domains)

All requests, responses, and events are logged in real-time with color coding:
- **Green**: Success messages and authenticated items
- **Red**: Errors and failures
- **Yellow**: Warnings and available (not authenticated) items
- **Cyan**: System messages and selected items

The **World Map** tab shows:
- **Yellow dots**: Available domains (not authenticated)
- **Red dots with labels**: Authenticated domains with domain name
