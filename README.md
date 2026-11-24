<p align="center">
  <img src="src/TheFirewall.App/Assets/Logo.png" width="96" alt="TheFirewall logo" />
</p>

<h1 align="center">TheFirewall</h1>

<p align="center">
  Stops brute-force attacks on Windows servers and PCs.<br />
  Watches your logs for failed sign-ins and bans attackers with Windows Defender Firewall.<br />
  <b>.NET 10 · Windows service · Fluent WPF app with tray icon · MIT licensed</b>
</p>

---

TheFirewall is a modern, open-source take on [IPBan](https://github.com/DigitalRuby/IPBan): a background Windows
service that detects repeated failed logins (Remote Desktop, SSH, SQL Server, Exchange and other mail servers, FTP,
RD Web, VPN, VNC, MySQL, PostgreSQL and your own apps) and blocks the offending IP addresses. It comes with an
easy-to-use control panel and a tray icon that shows at a glance whether you are protected.

## Features

- **Automatic banning** – ban an address after *N* failed logins (default 5 within a day). Repeat offenders get
  longer bans (1 day → 7 days → 30 days by default, or permanent).
- **Everything IPBan detects on Windows**, plus IIS FTP and hMailServer:
  Windows logon / RDP (4625, 4768, 6273, 4653, RdpCoreTS), OpenSSH, Microsoft SQL Server, MySQL / MariaDB,
  PostgreSQL, phpMyAdmin, Exchange (event log and protocol logs), SmarterMail, MailEnable, hMailServer,
  RD Web Access, IIS FTP, Apache / Tomcat, VNC, RRAS / VPN, VisualSVN – and successful sign-ins for the activity feed.
- **Custom login monitors** – watch any event log (XPath + regex) or text log file (glob paths + regex), with a
  built-in tester. Your own apps can simply write `thefirewall failed login, ip address: 1.2.3.4, source: MyApp, user: bob`
  to a log file or the Application event log (IPBan's format works too).
- **Custom firewall rules** – allow or block ports, protocols, addresses and programs, inbound or outbound.
- **Whitelist and blacklist** – addresses, CIDR blocks, ranges and wildcards; local networks are never banned by default.
- **Country blocking** – block selected countries, or allow only the countries you work from, on all or specific ports
  (free DB-IP database, updated monthly).
- **Threat feeds** – optionally pre-block known attackers from public lists (Emerging Threats, Spamhaus DROP,
  blocklist.de, CINS Army, IPsum) or any URL.
- **User name rules** – instant-ban names such as `admin`/`root`, more forgiving limits for your real user names.
- **Live activity feed and dashboard** – charts, top attacking countries, user names tried, targeted services.
- **Tray icon** – green (protected), amber (paused), red (needs attention), grey (service not running), with
  notifications when addresses are banned and quick pause/resume.
- **Import / export** settings and bans, run your own scripts on ban/unban/sign-in, CSV export.
- **Secure by design** – the service runs as LocalSystem; the app talks to it over an ACL-protected named pipe and
  can only change settings when it runs elevated (UAC is respected).

## Screenshots

| | |
| --- | --- |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Dashboard in dark mode](docs/screenshots/dashboard-dark.png) |
| ![Live activity](docs/screenshots/live-activity.png) | ![Banned addresses](docs/screenshots/banned-addresses.png) |
| ![Login monitors](docs/screenshots/login-monitors.png) | ![Custom login monitor with tester](docs/screenshots/custom-monitor.png) |
| ![Country blocking](docs/screenshots/countries.png) | ![Firewall rules](docs/screenshots/firewall-rules.png) |

These are rendered by CI from the built-in demo mode (every page is rendered on each build as a UI smoke test).
You can explore the app without installing the service:

```bash
TheFirewall.exe --demo
```

## Install

1. Download `TheFirewall-<version>-x64.msi` from the [releases](../../releases) or the latest
   [build artifacts](../../actions/workflows/build.yml).
2. Run it. The installer adds the **TheFirewall** Windows service (starts automatically), a Start menu shortcut and the tray icon.
3. Open TheFirewall from the Start menu or the shield in the notification area.

Requirements: Windows 10 1809+ / Windows Server 2019+ (x64). Windows Defender Firewall must be on.

**Without the installer (portable)** – extract the zip anywhere and run `TheFirewall.exe`. The app always makes sure
the protection service is running:

- if the service is not installed, it installs it from the app folder and starts it (Windows asks for administrator
  permission once). From then on the service starts automatically with Windows;
- if the service is stopped, it starts it, without a UAC prompt;
- if the service still points to a copy you deleted or moved, it repairs it to use the current folder.

You can do the same from a script or an elevated prompt:

```powershell
.\TheFirewall.exe --ensure-service        # install/start the service and exit (exit code 0 = running)
.\TheFirewall.Service.exe install         # or install it directly
.\TheFirewall.Service.exe register-tray   # optional: tray icon at sign-in for every user
```

If the service ever crashes, Windows restarts it automatically.

## How it works

```
 Windows event logs ─┐                               ┌─► Windows Defender Firewall
 Text log files ─────┼─► TheFirewall service ─────────┤   (rules named TheFirewall_*)
 Threat feeds ───────┘   (ban engine + SQLite)        └─► activity history, statistics
                                 ▲
                     named pipe  │  (read-only unless elevated)
                                 ▼
                   TheFirewall app + tray icon (WPF, Fluent)
```

- Failed logins are counted per address. When an address reaches the limit it is banned by adding it to a block rule
  (`TheFirewall_Ban_0000`, `…_0001` – up to 1,000 addresses per rule).
- Expired bans are lifted automatically; addresses that stay quiet are forgotten.
- On Windows, failed RDP/SMB logons only appear in the Security log when *Audit Logon: Failure* is enabled.
  TheFirewall turns this on automatically (Settings → Advanced).

Data lives in `%ProgramData%\TheFirewall` (`settings.json`, `thefirewall.db`, logs, country database).

## Locked yourself out?

Sign in from another address (or the console) and:

- open TheFirewall → **Banned addresses**, select the address → **Unban and never ban again**, or
- run `TheFirewall.Service.exe stop` – bans stay in the firewall, so also run `TheFirewall.Service.exe remove-rules`.

Add your office/home addresses to the **whitelist** to avoid this.

## Build from source

Requires the .NET 10 SDK (Windows for the app, service and installer; the core library and tests build anywhere).

```bash
dotnet build TheFirewall.slnx
```

```bash
dotnet test tests/TheFirewall.Core.Tests
```

```powershell
./build/publish.ps1 -Version 1.0.0     # self-contained publish + MSI in ./artifacts
```

To publish a release, add release notes to `docs/releases/v<version>.md`. Then either push a `v<version>` tag, or run
the **Build** workflow by hand (Actions → Build → Run workflow) with *release_version* set. The workflow attaches the MSI,
a portable zip and SHA-256 checksums to the GitHub release.

Project layout:

| Folder | What |
| --- | --- |
| `src/TheFirewall.Core` | Ban engine, login sources, log/event matching, SQLite storage, firewall planner, GeoIP, feeds, IPC (cross-platform, unit tested) |
| `src/TheFirewall.Service` | Windows service: Windows Firewall (COM), event log monitor, named pipe server, CLI |
| `src/TheFirewall.App` | WPF Fluent control panel and tray icon |
| `installer/TheFirewall.Installer` | WiX 5 MSI |
| `tests/TheFirewall.Core.Tests` | xUnit tests |

## License

[MIT](LICENSE). See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for credits (IPBan, DB-IP and libraries).
