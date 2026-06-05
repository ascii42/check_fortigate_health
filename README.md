# check_fortigate_health

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Monitoring](https://img.shields.io/badge/Monitoring-Icinga%2FNagios-blue.svg)](https://icinga.com/)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)](CHANGELOG.md)

A comprehensive Bash-based monitoring plugin for Fortinet FortiGate firewalls, compatible with Icinga and Nagios monitoring systems. This plugin monitors system health, resources, VPN, SD-WAN, security services, licenses, certificates, and more — directly via the FortiGate REST API v2 and/or SNMP. No FortiManager required.

## Features

- **Direct API Access**: Connects to the firewall's local REST API v2 — no FortiManager or cloud dependency
- **Comprehensive Coverage**: System, CPU/memory, HA, interfaces, IPsec/SSL-VPN, NTP, SD-WAN, FortiAP, FortiSwitch, DHCP, VDOM, FortiToken, UTM, IPS/AV stats, licenses, certificates, alerts, firmware, sensors, and more
- **Flexible Authentication**: API token (recommended) or SNMP v2c/v3 (SNMP-only mode supported)
- **SNMP Fallbacks**: HA mode/sync, license info, firmware version, uptime, interface counters — all available via SNMP when REST is unavailable
- **Opt-in or Opt-out**: Use `-eX` flags to run only specific checks, or `--disable-X` to suppress individual modules from the full set
- **Granular Thresholds**: Per-metric warning/critical thresholds for CPU, memory, disk, latency, packet loss, certificate expiry, license expiry, signature age, uptime, IPS/AV detections, and more
- **SD-WAN Auto-Detection**: Automatically finds the SD-WAN VDOM when it is not in the root VDOM
- **Log Event Monitoring**: Configurable logwatch check that scans recent log entries across multiple log types in parallel
- **Blacklisting & Selection**: Skip specific interfaces, VPN tunnels, certificates, DHCP pools, or license features
- **Perfdata Output**: Full Nagios-compatible perfdata for all check modules — compatible with PNP4Nagios, Graphite, InfluxDB, etc.
- **Verbose & Silent Modes**: Tunable output verbosity for dashboards and automation

## Prerequisites

Ensure the following tools are installed on your monitoring server:

- **bash** (4.0 or higher)
- **curl** (for API communication)
- **jq** (for JSON parsing)
- **awk** (for text processing)
- **snmpget / snmpwalk** (optional — only required for SNMP mode, provided by net-snmp)

### Installation on Different Platforms

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install curl jq gawk snmp
```

**RHEL/CentOS/Rocky Linux:**
```bash
sudo dnf install curl jq gawk net-snmp-utils
```

**Gentoo:**
```bash
sudo emerge net-misc/curl app-misc/jq sys-apps/gawk net-analyzer/net-snmp
```

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ascii42/check_fortigate_health.git
   cd check_fortigate_health
   ```

2. **Make the script executable:**
   ```bash
   chmod +x check_fortigate_health.sh
   ```

3. **Copy to your monitoring plugins directory:**
   ```bash
   # For Icinga2
   sudo cp check_fortigate_health.sh /usr/lib/nagios/plugins/

   # For Nagios
   sudo cp check_fortigate_health.sh /usr/local/nagios/libexec/
   ```

## Usage

### Basic Syntax

```bash
./check_fortigate_health.sh [-h] [-V] -H <host> -T <api_token> [options] [-w <warn>] [-c <crit>]
```

### Authentication

| Method | Parameters | Description |
|--------|-----------|-------------|
| API token | `-T <token>` | Recommended — create a REST API Admin in FortiGate GUI: System › Administrators › REST API Admin |
| SNMP v2c | `-SC <community>` | Enables SNMP-based resource/uptime collection alongside or instead of REST API |
| SNMP v3 | `--snmp-user <name>` | SNMPv3 mode — security level auto-detected from provided credentials |

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `-H, --host <hostname\|IP>` | Hostname or IP address of the FortiGate |
| `-T, --token <token>` | API token |

### Enable Flags (opt-in)

If any `-eX` flag is given, **only those modules** run. When no flags are given, all modules run (equivalent to `-A`).

| Flag | Long form | Description |
|------|-----------|-------------|
| `-eSys` | `--enable-system` | System info: model, serial, hostname, FortiOS version, HA role |
| `-eRes` | `--enable-resources` | CPU%, memory%, session count and setup rate |
| `-eHA` | `--enable-ha` | HA cluster mode, member count, roles, sync state |
| `-eNI` | `--enable-interfaces` | Network interface link states; use --ifup/--ifdown for explicit expectations |
| `-eNIS` | `--enable-interface-single` | Single interface check; requires `--ifup <name>`; perfdata: link, rx/tx bytes, errors, drops |
| `-eVPN` | `--enable-vpn` | IPsec VPN tunnel status per tunnel |
| `-eSSL` | `--enable-sslvpn` | SSL-VPN active sessions and tunnel state |
| `-eNTP` | `--enable-ntp` | NTP peer reachability and clock offset |
| `-eSDWAN` | `--enable-sdwan` | SD-WAN health-check probe latency and packet loss |
| `-eAP` | `--enable-ap` | FortiAP managed AP status, clients, per-radio detail |
| `-eSW` | `--enable-switch` | FortiSwitch managed switch status |
| `-eFEX` | `--enable-fex` | FortiExtender managed extender status |
| `-eDHCP` | `--enable-dhcp` | DHCP pool usage % per server |
| `-eIPAM` | `--enable-ipam` | FortiIPAM pool/rule counts and available subnets |
| `-eVDOM` | `--enable-vdom` | Per-VDOM CPU, memory, sessions; VDOM license usage |
| `-eFTK` | `--enable-ftk` | FortiToken usage: total/activated/available per type (mobile/hardware) |
| `-eUTM` | `--enable-utm` | IPS/AV/AppCtrl signature age, license status, DoS rules; IPS+AV detection stats (SNMP) |
| `-eSD` | `--enable-storage` | Disk/storage partition usage |
| `-eLic` | `--enable-license` | FortiCare support and FortiGuard feature license expiry |
| `-eCert` | `--enable-certs` | Local certificate expiry |
| `-eAl` | `--enable-alerts` | System event alerts from disk log (emergency/alert/critical) |
| `-eUp` | `--enable-uptime` | Uptime check — alert when uptime is below threshold (reboot detection) |
| `-eFirmware` | `--enable-firmware` | Installed firmware version vs. available GA updates; includes FortiAP firmware |
| `-eSensor` | `--enable-sensors` | Hardware sensors: temperature, voltage, fan speed |
| `-eFWStats` | `--enable-fwstats` | Firewall policy byte/session/hit counters |
| `-eLogwatch` | `--enable-logwatch` | Log event monitoring — **not included in `-A`**, must be enabled explicitly |
| `-A` | `--enable-all` | Enable all checks (default when no `-eX` flag is given) |

### Disable Flags (opt-out)

Suppress individual modules when running the full check set:

```
--disable-system        --disable-resources     --disable-ha
--disable-interfaces    --disable-vpn           --disable-sslvpn
--disable-ntp           --disable-sdwan         --disable-ap
--disable-switch        --disable-fex           --disable-dhcp
--disable-ipam          --disable-vdom          --disable-ftk
--disable-utm           --disable-storage       --disable-license
--disable-certs         --disable-alerts        --disable-uptime
--disable-firmware      --disable-sensors       --disable-fwstats
```

### Threshold Options

| Option | Default | Description |
|--------|---------|-------------|
| `-w, --warning <pct>` | 80 | WARNING threshold for disk usage in % |
| `-c, --critical <pct>` | 90 | CRITICAL threshold for disk usage in % |
| `-wCPU <pct>` | 80 | WARNING threshold for CPU usage in % |
| `-cCPU <pct>` | 90 | CRITICAL threshold for CPU usage in % |
| `-wMem <pct>` | 75 | WARNING threshold for memory usage in % |
| `-cMem <pct>` | 80 | CRITICAL threshold for memory usage in % |
| `--warn-cert <days>` | 30 | WARNING threshold for certificate expiry in days |
| `--crit-cert <days>` | 15 | CRITICAL threshold for certificate expiry in days |
| `--warn-lic <days>` | 30 | WARNING threshold for license/support expiry in days |
| `--crit-lic <days>` | 15 | CRITICAL threshold for license/support expiry in days |
| `--warn-db-age <days>` | 7 | WARNING threshold for FortiGuard DB last-update age in days |
| `--crit-db-age <days>` | 30 | CRITICAL threshold for FortiGuard DB last-update age in days |
| `--warn-utm-update <days>` | 30 | WARNING threshold for UTM signature age in days |
| `--crit-utm-update <days>` | 60 | CRITICAL threshold for UTM signature age in days |
| `--warn-ips <n>` | -1 | WARNING when total IPS detections exceed N (SNMP; -1 = disabled) |
| `--crit-ips <n>` | -1 | CRITICAL when total IPS detections exceed N (SNMP; -1 = disabled) |
| `--warn-ips-high <n>` | -1 | WARNING when critical+high severity IPS detections exceed N (SNMP) |
| `--crit-ips-high <n>` | -1 | CRITICAL when critical+high severity IPS detections exceed N (SNMP) |
| `--warn-av <n>` | -1 | WARNING when AV detections exceed N (SNMP; -1 = disabled) |
| `--crit-av <n>` | -1 | CRITICAL when AV detections exceed N (SNMP; -1 = disabled) |
| `--warn-ntp-offset <ms>` | 300 | WARNING threshold for NTP clock offset in milliseconds |
| `--crit-ntp-offset <ms>` | 500 | CRITICAL threshold for NTP clock offset in milliseconds |
| `--warn-sdwan-loss <pct>` | 5 | WARNING threshold for SD-WAN packet loss in % |
| `--crit-sdwan-loss <pct>` | 20 | CRITICAL threshold for SD-WAN packet loss in % |
| `--warn-sdwan-latency <ms>` | -1 | WARNING threshold for SD-WAN latency in ms (-1 = disabled) |
| `--crit-sdwan-latency <ms>` | -1 | CRITICAL threshold for SD-WAN latency in ms (-1 = disabled) |
| `--warn-vpn-down <n>` | -1 | WARNING when N or more IPsec tunnels are down (-1 = disabled) |
| `--crit-vpn-down <n>` | 1 | CRITICAL when N or more IPsec tunnels are down |
| `--warn-ap-down <n>` | -1 | WARNING when N or more FortiAPs are down (-1 = disabled) |
| `--crit-ap-down <n>` | 1 | CRITICAL when N or more FortiAPs are down |
| `--warn-ap-clients <n>` | -1 | WARNING on total client count across all APs (-1 = disabled) |
| `--crit-ap-clients <n>` | -1 | CRITICAL on total client count across all APs (-1 = disabled) |
| `--warn-sw-down <n>` | -1 | WARNING when N or more FortiSwitches are down (-1 = disabled) |
| `--crit-sw-down <n>` | 1 | CRITICAL when N or more FortiSwitches are down |
| `--warn-dhcp-usage <pct>` | 85 | WARNING threshold for DHCP pool usage in % |
| `--crit-dhcp-usage <pct>` | 90 | CRITICAL threshold for DHCP pool usage in % |
| `--warn-vdom-cpu <pct>` | 80 | WARNING threshold for per-VDOM CPU in % |
| `--crit-vdom-cpu <pct>` | 90 | CRITICAL threshold for per-VDOM CPU in % |
| `--warn-vdom-mem <pct>` | 80 | WARNING threshold for per-VDOM memory in % |
| `--crit-vdom-mem <pct>` | 90 | CRITICAL threshold for per-VDOM memory in % |
| `--warn-vdom-sessions <n>` | -1 | WARNING threshold for per-VDOM sessions (-1 = disabled) |
| `--crit-vdom-sessions <n>` | -1 | CRITICAL threshold for per-VDOM sessions (-1 = disabled) |
| `--warn-vdom-license <pct>` | 80 | WARNING when VDOM license usage reaches this % of maximum |
| `--crit-vdom-license <pct>` | 90 | CRITICAL when VDOM license usage reaches this % of maximum |
| `--warn-ftk-available <n>` | 0 | WARNING when available FortiTokens are <= N |
| `--crit-ftk-available <n>` | -1 | CRITICAL when available FortiTokens are <= N (-1 = disabled) |
| `--warn-uptime <minutes>` | 0 | WARNING if uptime is below this value in minutes (0 = disabled) |
| `--crit-uptime <minutes>` | 0 | CRITICAL if uptime is below this value in minutes (0 = disabled) |
| `--warn-ni-errors <n>` | -1 | WARNING threshold for interface total error counter (-1 = disabled) |
| `--crit-ni-errors <n>` | -1 | CRITICAL threshold for interface total error counter (-1 = disabled) |

### Filter Options

| Option | Description |
|--------|-------------|
| `--ifup <list>` | Comma-separated interfaces that MUST be link-up — CRITICAL if any are down; required for `-eNIS` |
| `--ifdown <list>` | Comma-separated interfaces expected to be down — WARNING if unexpectedly up |
| `--blacklist-interfaces <list>` | Interface names to skip entirely (e.g. `port1,mgmt`) |
| `--blacklist-vpn <list>` | VPN tunnel names to skip |
| `--blacklist-certs <list>` | Certificate names to skip |
| `--exclude-dhcp <list>` | DHCP pool interfaces to skip |
| `--ignore-license <list>` | License feature names to skip (e.g. `appctrl,webfilter`) |
| `--ignore-all-licenses` | Suppress WARN/CRIT for all license issues — show info only |
| `--ignore-utm-status` | Suppress no_license/expired from UTM problem output |
| `--sdwan-vdom <name>` | Query SD-WAN from a specific VDOM (auto-detected when omitted) |
| `-N, --hostname <name>` | Expected hostname — exits UNKNOWN if the connected device does not match |
| `--alert-rows <n>` | Number of recent log entries to scan for alerts (default: 50) |

### Logwatch Options

The logwatch check (`-eLogwatch`) is not part of `-A` and must be enabled explicitly. It fetches recent log entries and alerts on matches.

| Option | Default | Description |
|--------|---------|-------------|
| `--logwatch-type <type[,type]>` | all for device | Log categories; comma-separated list |
| `--logwatch-subtype <system\|vpn\|...>` | none | Subtype filter — only applied to `event` and `traffic` types |
| `--logwatch-device <disk\|memory>` | disk | Log storage to query |
| `--logwatch-rows <n>` | 200 | Number of entries to scan |
| `--logwatch-eventids "id1,id2,..."` | — | Only alert on these event IDs |
| `--logwatch-actions "a1,a2,..."` | — | Only alert on these actions |
| `--warn-logwatch <n>` | 1 | Match count threshold for WARNING |
| `--crit-logwatch <n>` | -1 | Match count threshold for CRITICAL (-1 = level-based alerting) |

Default log types: **disk** → event, traffic, app-ctrl, ips, virus, webfilter, anomaly, dns, voip, dlp | **memory** → app-ctrl, ips, virus, webfilter, anomaly, dns, voip, dlp

Without `--logwatch-eventids` or `--logwatch-actions`, severity is derived from log level: `emergency/alert/critical` → CRITICAL, `error/warning` → WARNING. Each type is prefetched in parallel; types returning 404 are silently skipped.

### SNMP Options

| Option | Default | Description |
|--------|---------|-------------|
| `-SC, --snmp-community <community>` | — | SNMPv2c community string |
| `--snmp-user <name>` | — | SNMPv3 security name — enables SNMPv3 mode |
| `--snmp-auth-proto <MD5\|SHA>` | SHA | SNMPv3 authentication protocol |
| `--snmp-auth-pass <password>` | — | SNMPv3 authentication passphrase (minimum 8 characters) |
| `--snmp-priv-proto <DES\|AES>` | AES | SNMPv3 privacy protocol |
| `--snmp-priv-pass <password>` | — | SNMPv3 privacy passphrase |
| `--snmp-sec-level <level>` | auto | noAuthNoPriv / authNoPriv / authPriv (auto-detected from credentials) |
| `--snmp-port <port>` | 161 | SNMP UDP port |

### Output Options

| Option | Description |
|--------|-------------|
| `--no-perfdata` | Suppress the perfdata section entirely (no `\|` output) |
| `--perfdata` | Explicitly request perfdata output (default when not suppressed) |
| `-s, --silent` | Show only problem lines (suppress OK detail) |
| `-v, --verbose` | Print section headers and full per-item detail |
| `--append-fw-name` | Prefix every output line with the device hostname (default: hostname suppressed) |
| `-d, --debug` | Enable bash trace output (`set -x`) |

## Examples

### Full Health Check
Check everything with default thresholds:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -A -w 80 -c 90
```

### Check Specific Modules
System info, resources, and recent alerts only:
```bash
./check_fortigate_health.sh -H fw.example.com -T MyApiToken123 -eSys -eRes -eAl -v
```

### Opt-out: Full Check Without SSL-VPN
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 --disable-sslvpn -v
```

### Interface Enforcement
Require specific interfaces to be up; expect maintenance ports to be down:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eNI \
  --ifup port1,port2,wan1 --ifdown port5,port6
```

### Single Interface Monitor
Monitor a specific interface with full perfdata (link state, rx/tx bytes, errors, drops):
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eNIS --ifup wan1
# [OK] - Interface wan1: up | 1000 Mbps
```

### SD-WAN with Latency and Loss Thresholds
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eSDWAN \
  --warn-sdwan-loss 5 --crit-sdwan-loss 20 \
  --warn-sdwan-latency 100 --crit-sdwan-latency 200
```

### Certificate and License Expiry with Custom Thresholds
Warn 60 days before certificate expiry, critical at 14 days:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eCert -eLic \
  --warn-cert 60 --crit-cert 14 --warn-lic 60 --crit-lic 14
```

### IPS/AV Detection Statistics (SNMP)
Alert when IPS detections or AV events exceed thresholds since last boot:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -SC public -eUTM \
  --warn-ips 1000 --crit-ips 5000 --warn-av 100 --crit-av 500
```

### Log Event Monitoring for IPS and Anomaly
Scan the last 500 memory log entries across IPS and anomaly types:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eLogwatch \
  --logwatch-type ips,anomaly --logwatch-device memory --logwatch-rows 500
```

### Reboot Detection
Alert if the firewall has been up for less than 30 minutes:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eUp \
  --warn-uptime 30 --crit-uptime 5
```

### Full Check, Suppress Noisy Modules
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -A \
  --disable-sensors --disable-fwstats --no-perfdata
```

### SNMP-Only Mode (No REST API)
```bash
./check_fortigate_health.sh -H 10.0.0.1 -SC public -eSys -eRes -eNI -eHA
```

## Sample Output

Default (no `--append-fw-name`):
```
[OK] - FortiGate-101F | FortiOS: v7.6.1 | Role: standalone
[OK] - CPU: 12% (warn: 80%, crit: 90%)
[OK] - Memory: 54% (warn: 75%, crit: 80%) | Sessions: 18432
[OK] - HA mode: a-p | 2 member(s)
[OK] - HA Sync: synchronized
[OK] - Interfaces: 8 total, 8 up, 0 down
[OK] - Interface wan1: up | 1000 Mbps
[OK] - VPN: 4/4 tunnel(s) UP
[OK] - NTP: 2/2 reachable | offset: 1ms (warn: 300ms, crit: 500ms)
[WARNING] - SD-WAN probe-isp1/wan1: loss 8% >= warn (5%)
[OK] - License FortiCare: valid (2027-01-15, 312d left)
[OK] - Certs: 3 certificate(s) OK
[WARNING] - UTM: IPS db not updated for 35d (last: 2026-05-01)
[OK] - Firmware: current: v7.6.6 build 3652 (GA)/M
[OK] - Alerts: no critical/error events in last 50 entries
| cpu=12%;80;90;0;100 mem=54%;75;80;0;100 sessions=18432 ni_wan1_link=1 ni_wan1_rx_bytes=1556780398173 ni_wan1_tx_bytes=423190234 ni_wan1_rx_errors=0 ni_wan1_tx_errors=0 ni_wan1_rx_drops=0 ni_wan1_tx_drops=0 ...
```

With `--append-fw-name`:
```
[OK] - fw-prod: FortiGate-101F | FortiOS: v7.6.1 | Role: standalone
[OK] - CPU fw-prod: 12% (warn: 80%, crit: 90%)
[OK] - Memory fw-prod: 54% (warn: 75%, crit: 80%) | Sessions: 18432
[OK] - HA Sync fw-prod: synchronized
[OK] - Interfaces fw-prod: 8 total, 8 up, 0 down
[OK] - Interface fw-prod/wan1: up | 1000 Mbps
[WARNING] - SD-WAN fw-prod/probe-isp1/wan1: loss 8% >= warn (5%)
[OK] - NTP fw-prod/ntp.example.com: reachable | stratum: 2 | offset: 1ms
[OK] - License fw-prod/FortiCare: valid (2027-01-15, 312d left)
```

## Integration with Monitoring Systems

### Icinga2 Configuration

Create a command definition in `/etc/icinga2/conf.d/commands.conf`:

```icinga2
object CheckCommand "check_fortigate" {
    command = [ PluginDir + "/check_fortigate_health.sh" ]
    arguments = {
        "-H"  = "$fortigate_host$"
        "-T"  = "$fortigate_token$"
        "-w"  = "$fortigate_warning$"
        "-c"  = "$fortigate_critical$"
        "-A"  = {
            set_if = "$fortigate_check_all$"
        }
        "-v"  = {
            set_if = "$fortigate_verbose$"
        }
        "--warn-cert"         = "$fortigate_warn_cert$"
        "--crit-cert"         = "$fortigate_crit_cert$"
        "--warn-sdwan-loss"   = "$fortigate_warn_sdwan_loss$"
        "--crit-sdwan-loss"   = "$fortigate_crit_sdwan_loss$"
        "--disable-sslvpn"    = {
            set_if = "$fortigate_disable_sslvpn$"
        }
        "--no-perfdata" = {
            set_if = "$fortigate_no_perfdata$"
        }
    }
    vars.fortigate_warning          = 80
    vars.fortigate_critical         = 90
    vars.fortigate_warn_cert        = 30
    vars.fortigate_crit_cert        = 15
    vars.fortigate_warn_sdwan_loss  = 5
    vars.fortigate_crit_sdwan_loss  = 20
    vars.fortigate_check_all        = true
    vars.fortigate_verbose          = false
    vars.fortigate_disable_sslvpn   = false
    vars.fortigate_no_perfdata      = false
}
```

Create a service definition:

```icinga2
apply Service "FortiGate Health" {
    check_command = "check_fortigate"
    vars.fortigate_host  = host.vars.fortigate_host
    vars.fortigate_token = host.vars.fortigate_token
    vars.fortigate_warning  = 80
    vars.fortigate_critical = 90

    assign where host.vars.fortigate_host != ""
}
```

### Nagios Configuration

Add to `commands.cfg`:

```nagios
define command {
    command_name    check_fortigate
    command_line    $USER1$/check_fortigate_health.sh -H $ARG1$ -T $ARG2$ -A -w $ARG3$ -c $ARG4$
}
```

Add to `services.cfg`:

```nagios
define service {
    use                 generic-service
    host_name           fw-prod
    service_description FortiGate Health
    check_command       check_fortigate!10.0.0.1!your-api-token-here!80!90
}
```

## Security Considerations

- **API Token**: Create a dedicated read-only monitoring account in the FortiGate GUI and generate an API token for it. Avoid reusing admin credentials.
- **Credential Storage**: Store API tokens in your monitoring system's secrets store (Icinga2 constants, HashiCorp Vault, etc.) — not in plain-text config files where possible.
- **Network Access**: The monitoring server requires HTTPS (port 443) access to the FortiGate management IP. No outbound internet access is needed.
- **Self-Signed Certificates**: The plugin uses `--insecure` with curl to accept self-signed FortiGate certificates. If you have a trusted CA-signed certificate on the firewall, this has no effect on security.
- **Minimal Permissions**: The API token account only needs read access — a `Read Only` profile is sufficient for all check modules.
- **SNMP**: If using SNMP, restrict the allowed-hosts list on the FortiGate to the monitoring server IP and use SNMPv3 with authentication and privacy where possible.

## Troubleshooting

### Common Issues

**Authentication Failure (`[UNKNOWN] - Failed to retrieve system status`):**
- Verify the API token is correct and has not expired
- Confirm REST API access is permitted for the administrator profile
- Test connectivity: `curl -sk -H "Authorization: Bearer <token>" https://<host>/api/v2/monitor/system/status`
- Check that the monitoring server IP is in the trusted hosts list for the API admin

**Connection Timeout:**
- Verify network connectivity and that port 443 is open between the monitoring server and the firewall management IP
- Check that HTTPS administrative access is enabled on the management interface

**`jq: command not found` / `curl: command not found`:**
- Install the missing dependency: `apt install jq curl` / `dnf install jq curl` / `emerge app-misc/jq net-misc/curl`

**All checks run even though only `-eSDWAN` was given:**
- Fixed in version 1.4.31. Update to the latest version.

**SD-WAN shows "disabled" even though it is configured:**
- SD-WAN is likely configured in a non-root VDOM. Either pass `--sdwan-vdom <name>` explicitly, or use version ≥ 1.4.29 which auto-detects the correct VDOM.

**Uptime shows "not available" with REST API on FortiOS 7.4+:**
- FortiOS 7.4+ removed the uptime field from the REST API. Use `--snmp-community` or `--snmp-user` to provide SNMP credentials — uptime will be read via SNMP automatically.

**`-eNIS` shows UNKNOWN — no interface specified:**
- `-eNIS` requires `--ifup <interface>` to specify which interface to check.

**Logwatch returns no results for `event` type on memory device:**
- The FortiOS memory log API does not expose the `event` or `traffic` types. Use `--logwatch-device disk` or restrict `--logwatch-type` to UTM types (ips, anomaly, virus, webfilter, etc.).

### Debug Mode

Enable full bash trace output for deep troubleshooting:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -A -d 2>&1 | less
```

Or use verbose mode for readable per-module detail:
```bash
./check_fortigate_health.sh -H 10.0.0.1 -T MyApiToken123 -eSDWAN -eUTM -v
```

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-new-check`)
3. Make your changes
4. Test against a real FortiGate or a captured API JSON fixture
5. Submit a pull request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Review the troubleshooting section above
2. Check existing GitHub issues
3. Open a new issue with your FortiGate model, FortiOS version, and the full plugin output with `-d` (debug) enabled

## Author

**Felix Longardt**
- Email: monitoring@longardt.com
- GitHub: [@ascii42](https://github.com/ascii42)

## Acknowledgments

- Fortinet for the comprehensive FortiOS REST API v2 documentation
- The Icinga and Nagios communities for feedback and testing
- Contributors who have helped improve this plugin

---

**Note**: This plugin is not officially supported by Fortinet, Inc. Use at your own discretion and test thoroughly in your environment before deploying to production monitoring.
