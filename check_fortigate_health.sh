#!/bin/bash
#
# Monitor plugin for checking Fortinet FortiGate firewalls via REST API v2
#
# Author:
#   Felix Longardt <monitoring@longardt.com>
#
# Version history (compact):
# 1.0.0  2026-05-24  Initial release: -eSys -eRes -eHA -eNI -eVPN -eSSL -eSD -eLic -eCert -eAl
# 1.1.0  2026-05-25  -T token flag; --ifup/--ifdown; session detail; SNMP v2c resource collection
# 1.2.x  2026-05-25  SNMP disk/mem/uptime; cert endpoint switch; serial/model fixes; NI perf
# 1.3.x  2026-05-25  NI error perfdata; HA mode fix (7.6.x); license DB age; log disk; DNS/NTP verbose
# 1.4.0  2026-05-28  -eFirmware -eSensor -eFWStats; HA net_usage perfdata; parallel API prefetch
# 1.4.1-5  2026-05-28  Firmware/license/cert options; -eUp reboot detection; SNMPv3 support
# 1.4.6-9  2026-05-28  SNMP-only mode; OID table fixes; SNMP NI+VPN checks (IF-MIB/fgVpnTunTable)
# 1.4.10-16  2026-05-29  OID fixes; dual-OID uptime; IPv6+NPU sessions; SNMP enum; thresholds
# 1.4.17-19  2026-05-29  -eNTP -eSDWAN -eAP -eSW -eFEX; SSL-VPN 7.6.x fix; FortiAP per-radio
# 1.4.20-25  2026-05-30  -eDHCP -eIPAM -eVDOM -eFTK; -eUTM; logwatch; NTP/UTM/FTK improvements
# 1.4.26-34  2026-05-30  VDOM license; logwatch multi-type; SD-WAN auto-VDOM+crit; SNMP NI ifdown
# 1.4.35-48  2026-05-31  Logwatch (case/src/dst/pol); -eSecRating; -eCloud; firmware blacklist; HA sync
# 1.4.49-55  2026-06-05  SNMP fallbacks: HA, license, firmware, uptime (7.4+); -eUTM IPS+AV SNMP stats
# 1.4.56-60  2026-06-05  -eNIS single-interface check; interface perfdata (link/bytes/errors/drops)
# 2.0.0  2026-06-05  Hostname-free output by default: device name suppressed in all lines unless
#                    --append-fw-name is set; NI renamed to Interface throughout; -eNIS perfdata
# 2.1.0  2026-06-08  -eShaper: traffic shaper stats (dropped pkts/bytes, bandwidth usage, perfdata);
#                    auto-queries ALL VDOMs by default; --shaper-vdom to restrict to specific VDOM(s);
#                    --warn/crit-shaper-drops alert; --warn/crit-ni-drops for interface drop alerting
# 2.2.0  2026-06-08  -eShaper now uses CMDB endpoint (firewall.shaper/traffic-shaper) as primary
#                    shaper source so configured shapers are always listed even without active
#                    traffic; monitor endpoint overlaid for runtime stats when available
# 2.3.0  2026-06-08  Fix shaper monitor extraction: data under .results.data[] (FortiOS 7.x);
#                    fields: drops/dropped_bytes/current_bandwidth (bytes/sec → kbps auto-convert);
#                    _shp_mon_get tries /select, scope=vdom, and base endpoint variants in order
# 2.4.0  2026-06-08  --no-prefetch: serial API fetch mode for hardened systems; --tmp-dir <path>:
#                    use alternative temp directory when /tmp is restricted
# 2.5.0  2026-06-09  -eLB: load balancer virtual server check (server-load-balance VIPs only);
#                    per-VIP RS count/state; WARN on disabled RS, CRIT on no active RS;
#                    --lb-vdom for VDOM-specific queries; auto-queries all VDOMs by default
# 2.6.0  2026-06-09  -eLB now uses monitor/firewall/load-balance (required count= param was
#                    missing); RS health state (up/down) from health probe now reported;
#                    mode (active/standby/disabled) shown alongside health; CRIT when all RS
#                    down, WARN when some RS down or disabled; RTT and sessions in verbose
# 2.7.0  2026-06-09  -eLB: --blacklist-lb-vip to skip VIPs by name;
#                    --blacklist-lb-rs to skip real servers by IP or IP:port
# 2.8.0  2026-06-09  -eLB: bytes_processed, active_sessions, monitor_events added to verbose
#                    RS output (human-readable bytes) and perfdata (per-RS and per-VIP totals);
#                    aggregate sessions/bytes/events shown on VIP summary line; perfdata uses
#                    plain numeric values (no c-suffix) consistent with rest of plugin
# 2.9.0  2026-06-10  -eDHCP: fix threshold comparison broken when % suffix passed (bash
#                    arithmetic silently failed on "85%"); fix %% double-percent display bug;
#                    fix invalid perfdata thresholds; N% = percentage of used leases;
#                    plain number = free leases remaining (inverted: alert when free < N);
#                    perfdata: free metric with Nagios range syntax (N:) in absolute mode


## VARIABLES
PROGNAME="${0##*/}"
PROGPATH="${0%/*}"
REVISION="2.9.0"
JQ="$(which jq)"
CURL="$(which curl)"
AWK="$(which awk)"
SNMPGET="$(which snmpget 2>/dev/null)"
SNMPWALK="$(which snmpwalk 2>/dev/null)"

# Standard MIB-II OIDs
OID_UPTIME=".1.3.6.1.2.1.1.3.0"              # sysUpTime (TimeTicks, hundredths of seconds)
OID_SYSNAME=".1.3.6.1.2.1.1.5.0"             # sysName (hostname)
OID_SYSDESCR=".1.3.6.1.2.1.1.1.0"            # sysDescr (model/platform info)

# FORTINET-CORE-MIB (enterprises.12356.100 = fnCoreMib)
OID_FG_SERIAL=".1.3.6.1.4.1.12356.100.1.1.1.0"    # fnSysSerial (device serial number)

# FORTINET-FORTIGATE-MIB (verified against official MIB, last updated 2025-10-14)
# Root: enterprises.12356.101 = fnFortiGateMib; fgSystem=.4; fgSystemInfo=.4.1
OID_FG_VERSION=".1.3.6.1.4.1.12356.101.4.1.1.0"   # fgSysVersion
OID_CPU=".1.3.6.1.4.1.12356.101.4.1.3.0"           # fgSysCpuUsage (%)
OID_MEM=".1.3.6.1.4.1.12356.101.4.1.4.0"           # fgSysMemUsage (%)
OID_MEMCAP=".1.3.6.1.4.1.12356.101.4.1.5.0"        # fgSysMemCapacity (KB)
OID_DISK=".1.3.6.1.4.1.12356.101.4.1.6.0"          # fgSysDiskUsage (MB)
OID_DISK_CAP=".1.3.6.1.4.1.12356.101.4.1.7.0"      # fgSysDiskCapacity (MB)
OID_SES=".1.3.6.1.4.1.12356.101.4.1.8.0"           # fgSysSesCount
# indices 9-10: fgSysLowMemUsage / fgSysLowMemCapacity (not used)
OID_SESRATE=".1.3.6.1.4.1.12356.101.4.1.11.0"      # fgSysSesRate1 (sessions/s, 1min avg)
# indices 12-14: fgSysSesRate10/30/60 (not used)
OID_SES6=".1.3.6.1.4.1.12356.101.4.1.15.0"         # fgSysSes6Count (IPv6 sessions)
OID_SESRATE6=".1.3.6.1.4.1.12356.101.4.1.16.0"     # fgSysSes6Rate1 (IPv6 sess/s, 1min avg)
# indices 17-19: fgSysSes6Rate10/30/60 (not used)
OID_FG_UPTIME=".1.3.6.1.4.1.12356.101.4.1.20.0"    # fgSysUpTime (Counter64, centiseconds)
# indices 21-23: fgSysNeedLogPartitionScan, fgSysUpTimeDetail, fgSysRebootReason (not used)
OID_NPU_SES=".1.3.6.1.4.1.12356.101.4.1.24.0"      # fgSysNpuSesCount (NPU-offloaded sessions)
# indices 25-28: fgSysNpuSesRate1/10/30/60 (not used)
# indices 34-35: fgDataCpuUsage / fgDataMemUsage (data plane, not used)
OID_FREE_MEM=".1.3.6.1.4.1.12356.101.4.1.36.0"     # fgSysFreeMemUsage (%)

# IF-MIB (standard, table walk)
OID_IF_DESCR=".1.3.6.1.2.1.2.2.1.2"              # ifDescr
OID_IF_ADMIN=".1.3.6.1.2.1.2.2.1.7"              # ifAdminStatus (1=up 2=down)
OID_IF_OPER=".1.3.6.1.2.1.2.2.1.8"               # ifOperStatus  (1=up 2=down)
OID_IF_HIGHSPEED=".1.3.6.1.2.1.31.1.1.1.15"      # ifHighSpeed (Mbps)
OID_IF_NAME=".1.3.6.1.2.1.31.1.1.1.1"            # ifName  (actual port name: dmz, port1, wan1)
OID_IF_ALIAS=".1.3.6.1.2.1.31.1.1.1.18"          # ifAlias
OID_IF_HC_IN=".1.3.6.1.2.1.31.1.1.1.6"           # ifHCInOctets  (64-bit, default)
OID_IF_HC_OUT=".1.3.6.1.2.1.31.1.1.1.10"         # ifHCOutOctets (64-bit, default)
OID_IF_IN_OCTETS=".1.3.6.1.2.1.2.2.1.10"         # ifInOctets    (32-bit, --use-32bit-counters)
OID_IF_OUT_OCTETS=".1.3.6.1.2.1.2.2.1.16"        # ifOutOctets   (32-bit, --use-32bit-counters)
OID_IF_IN_ERR=".1.3.6.1.2.1.2.2.1.14"            # ifInErrors
OID_IF_OUT_ERR=".1.3.6.1.2.1.2.2.1.20"           # ifOutErrors
OID_IF_IN_DISC=".1.3.6.1.2.1.2.2.1.13"           # ifInDiscards
OID_IF_OUT_DISC=".1.3.6.1.2.1.2.2.1.19"          # ifOutDiscards

# FORTINET-FORTIGATE-MIB - IPsec VPN tunnel table (fgVpnTunTable)
OID_VPN_NAME=".1.3.6.1.4.1.12356.101.12.2.2.1.2"  # fgVpnTunEntPhase1Name (P1/parent tunnel)
OID_VPN_P2NAME=".1.3.6.1.4.1.12356.101.12.2.2.1.3" # fgVpnTunEntPhase2Name
OID_VPN_STATUS=".1.3.6.1.4.1.12356.101.12.2.2.1.20" # fgVpnTunEntStatus (1=down 2=up)
OID_VPN_IN=".1.3.6.1.4.1.12356.101.12.2.2.1.18"   # fgVpnTunEntInOctets  (Counter64)
OID_VPN_OUT=".1.3.6.1.4.1.12356.101.12.2.2.1.19"  # fgVpnTunEntOutOctets (Counter64)

# FORTINET-FORTIGATE-MIB - License contract table (fgLicContractTable)
# Path: fgSystem.fgSystemInfoAdvanced.fgSIAdvLicenseDetails.fgLicContracts.fgLicContractTable
# Indexed by fgVdEntIndex (VDOM); walk returns one row per VDOM
OID_LIC_CONTRACT_DESC=".1.3.6.1.4.1.12356.101.4.6.3.1.2.1.1"   # fgLicContractDesc   (DisplayString)
OID_LIC_CONTRACT_EXPIRY=".1.3.6.1.4.1.12356.101.4.6.3.1.2.1.2" # fgLicContractExpiry (DisplayString date)

# FORTINET-FORTIGATE-MIB - License version table (fgLicVersionTable)
# FortiGuard service signature versions + expiry per VDOM
OID_LIC_VER_DESC=".1.3.6.1.4.1.12356.101.4.6.3.2.2.1.1"        # fgLicVersionDesc    (service name)
OID_LIC_VER_EXPIRY=".1.3.6.1.4.1.12356.101.4.6.3.2.2.1.2"      # fgLicVersionExpiry  (DisplayString date)
OID_LIC_VER_NUM=".1.3.6.1.4.1.12356.101.4.6.3.2.2.1.3"         # fgLicVersionNumber  (signature version)
OID_LIC_VER_UPDTIME=".1.3.6.1.4.1.12356.101.4.6.3.2.2.1.4"     # fgLicVersionUpdTime (last update time)

# FORTINET-FORTIGATE-MIB - HA system info + stats table (fgHaStatsTable)
OID_HA_MODE=".1.3.6.1.4.1.12356.101.13.1.1"            # fgHaSystemMode (1=standalone 2=a-a 3=a-p)
OID_HA_SYNC=".1.3.6.1.4.1.12356.101.13.2.1.1.11"       # fgHaStatsSyncStatus (0=unsync 1=sync)
OID_HA_PEER_HOST=".1.3.6.1.4.1.12356.101.13.2.1.1.14"  # fgHaStatsHostname (member hostname)

# FORTINET-FORTIGATE-MIB - AV stats table (fgAvStatsTable) - counters per VDOM since boot
OID_AV_DETECTED=".1.3.6.1.4.1.12356.101.9.2.1.1.2"    # fgAvStatsVirusDetected
OID_AV_BLOCKED=".1.3.6.1.4.1.12356.101.9.2.1.1.3"     # fgAvStatsVirusBlocked
OID_AV_OVERSIZED=".1.3.6.1.4.1.12356.101.9.2.1.1.4"   # fgAvStatsVirusOversized
OID_AV_CRPTD=".1.3.6.1.4.1.12356.101.9.2.1.1.6"       # fgAvStatsVirusPassCrptd (passed encrypted)

# FORTINET-FORTIGATE-MIB - IPS stats table (fgIpsStatsTable) - counters per VDOM since boot
OID_IPS_DETECT=".1.3.6.1.4.1.12356.101.9.3.1.1.2"     # fgIpsStatsDetections
OID_IPS_CRIT_S=".1.3.6.1.4.1.12356.101.9.3.1.1.3"     # fgIpsStatsCritSevDetections
OID_IPS_HIGH_S=".1.3.6.1.4.1.12356.101.9.3.1.1.4"     # fgIpsStatsHighSevDetections
OID_IPS_MED_S=".1.3.6.1.4.1.12356.101.9.3.1.1.5"      # fgIpsStatsMedSevDetections
OID_IPS_LOW_S=".1.3.6.1.4.1.12356.101.9.3.1.1.6"      # fgIpsStatsLowSevDetections
OID_IPS_INFO_S=".1.3.6.1.4.1.12356.101.9.3.1.1.7"     # fgIpsStatsInfoSevDetections
OID_IPS_DROPS=".1.3.6.1.4.1.12356.101.9.3.1.1.8"      # fgIpsStatsDrops


exit_unknown() {
	echo "Unknown parameter: ${1}"
	print_usage
	exit 4
}

# Return 0 if every comma-separated token in $1 appears in $2 (also comma-separated)
_servers_subset() {
	local IFS=','
	local exp cfg found
	for exp in $1; do
		found=0
		for cfg in $2; do
			[[ "${cfg}" == "${exp}" ]] && found=1 && break
		done
		[[ "${found}" -eq 0 ]] && return 1
	done
	return 0
}


## FUNCTIONS
print_usage() {
	echo "Usage: ${PROGNAME} [-h] [-V] -H <host> -T <api_token> [-opts] [-w <warn>] [-c <crit>]"
}

print_revision() {
	echo "${1} - v${2}"
}

print_help() {
	print_revision "${PROGNAME}" "${REVISION}"
	echo ""
	print_usage
cat << EOM


 This plugin monitors Fortinet FortiGate firewalls via the REST API v2
 (https://<host>/api/v2/).

 Connects directly to the firewall - no FortiManager required.
 Uses HTTPS with --insecure to accept self-signed certificates.
 Authentication via API token (preferred) or username/password.

Options:
 -h, --help
    Print detailed help screen
 -V, --version
    Print version information

 -H, --host <hostname|IP>
    Hostname or IP address of the FortiGate
 -T, --token <token>
    API token (FortiGate GUI: System > Administrators > Create New > REST API Admin)
 -SC, --snmp-community <community>
    SNMP v2c community string - enables SNMP-based resource/uptime collection
    (uses FORTINET-FORTIGATE-MIB OIDs; requires snmpget)
 --snmp-user <username>
    SNMPv3 security name - enables SNMPv3 mode; cannot be combined with -SC
 --snmp-auth-proto <MD5|SHA>
    SNMPv3 authentication protocol (default: SHA)
 --snmp-auth-pass <password>
    SNMPv3 authentication password (implies authNoPriv or authPriv)
 --snmp-priv-proto <DES|AES>
    SNMPv3 privacy protocol (default: AES)
 --snmp-priv-pass <password>
    SNMPv3 privacy password (implies authPriv)
 --snmp-sec-level <noAuthNoPriv|authNoPriv|authPriv>
    SNMPv3 security level (auto-detected from credentials when omitted)
 --snmp-port <port>
    SNMP port (default: 161)

 -N, --hostname <name>
    Expected hostname - exits UNKNOWN if connected device does not match

 Enable flags (opt-in - if any -eX flag is given, only those checks run):
 -eSys,     --enable-system
    System info: model, serial, hostname, FortiOS version, uptime, HA role
 -eRes,     --enable-resources
    Resource usage: CPU%, memory%, sessions, session rate (thresholds: -wCPU/-cCPU, -wMem/-cMem)
    Session count: --warn-sessions/--crit-sessions (default -1=disabled, absolute count)
    Session limit %: --warn-sessions-pct/--crit-sessions-pct (default 80/90%, vs hardware session_limit)
 -eHA,      --enable-ha
    HA cluster: mode, member count, roles; sync state check via ha-checksums (default: enabled)
    CRITICAL when any member checksums differ from the active master
    --disable-hasync: skip the sync state check (member stats still shown)
 -eNI,      --enable-interfaces
    Network interface link states; use --ifup/--ifdown for explicit expectations
 -eNIS,     --enable-interface-single
    Single interface check; requires --ifup <name>; always outputs per-interface status + perfdata
 -eVPN,     --enable-vpn
    IPsec VPN tunnel status (up/down per tunnel); thresholds: --warn/crit-vpn-down
 -eSSL,     --enable-sslvpn                                              (REST only)
    SSL-VPN active session count and tunnel state
 -eNTP,     --enable-ntp                                                  (REST only)
    NTP timesync: reachable peers, max clock offset; thresholds: --warn/crit-ntp-offset (ms)
 -eSDWAN,   --enable-sdwan                                               (REST only)
    SD-WAN health-check probe status, latency, packet loss; thresholds: --warn/crit-sdwan-loss
    --warn/crit-sdwan-latency (ms, default -1 = disabled)
    --sdwan-vdom <name>: query SD-WAN from a specific vdom (default: root)
 -eAP,      --enable-ap                                                  (REST only)
    FortiAP managed APs: status, clients, per-radio detail; thresholds: --warn/crit-ap-down/clients
    (AP firmware update info shown in -eFirmware section when both -eAP and -eFirmware are active)
 -eSW,      --enable-switch                                              (REST only)
    FortiSwitch managed switches: status, firmware version (verbose); thresholds: --warn/crit-sw-down
 -eFEX,     --enable-fex                                                 (REST only)
    FortiExtender managed extenders: status
    (FEX firmware version shown in -eFirmware verbose section)
 -eDHCP,    --enable-dhcp                                                (REST only)
    DHCP pool usage per server (pool size via ip-range, active leases);
    --warn/crit-dhcp-usage: percentage threshold (e.g. 85%) or absolute lease count (e.g. 100);
    Exclude specific pools: --exclude-dhcp "iface1,iface2"
 -eIPAM,    --enable-ipam                                                (REST only)
    FortiIPAM status: enabled/disabled, server type, pool/rule counts, allocated/available subnets,
    usage%; thresholds: --warn-ipam-usage/--crit-ipam-usage (default 80/90%)
 -eVDOM,    --enable-vdom                                                (REST only)
    Per-VDOM resource usage: cpu, memory, sessions; thresholds: --warn/crit-vdom-cpu (default 80/90)
    --warn/crit-vdom-mem (default 80/90) --warn/crit-vdom-sessions (default -1/-1)
    VDOM license usage: --warn/crit-vdom-license (% of max vdoms, default 80/90)
 -eFTK,     --enable-ftk                                                 (REST only)
    FortiToken usage: total/activated/available per type (mobile/hardware)
    --warn-ftk-available N   WARN when available tokens <= N (default: 0)
    --crit-ftk-available N   CRIT when available tokens <= N (default: -1=off)
 -eUTM,     --enable-utm
    IPS/AV/AppCtrl: signature db version, age, engine version, license status;
    DoS protection: total rules, blocking/log-only breakdown;
    IPS/AV detection statistics (cumulative since boot, per VDOM summed);  (SNMP only)
    thresholds: --warn/crit-utm-update (days, applies to all services with a known db date)
    --warn-ips N / --crit-ips N       WARN/CRIT when total IPS detections exceed N (default: -1=off)
    --warn-ips-high N / --crit-ips-high N  WARN/CRIT when crit+high severity IPS detections exceed N
    --warn-av N / --crit-av N         WARN/CRIT when AV detections exceed N (default: -1=off)
 -eSD,      --enable-storage
    Disk/storage partition usage; thresholds: --warn-disk / --crit-disk (default 80/90%)
 -eLic,     --enable-license
    FortiCare support and FortiGuard feature license expiry
 -eCloud,   --enable-forticloud                                          (REST only)
    FortiCloud connection status, log storage, sandbox and staging disk usage;
    --warn/crit-cloud-log-usage (default 80/90%): log storage alert
    --warn/crit-cloud-sandbox (default 80/90%): daily sandbox file quota alert
    --warn/crit-cloud-staging (default 80/90%): staging disk usage alert
    --cloud-domain <name>: alert when connected domain differs from expected
 -eCert,    --enable-certs                                               (REST only)
    Local certificate expiry (thresholds: --warn-cert / --crit-cert days)
 -eAl,      --enable-alerts                                              (REST only)
    System event alerts from disk log (emergency/alert/critical)
    --alerts-vdom <vdom>: query event log from specific VDOM (default: global/root)
 -eUp,      --enable-uptime                        (SNMP only on FortiOS 7.4+; REST for 6.x/7.0)
    Uptime check: alert when uptime is below threshold (reboot detection)
 -eFirmware,--enable-firmware
    Firmware version: installed FG version; separate WARN for patch/minor/major GA updates;
    FortiAP per-model update check (data from -eAP) with WARN when update available;
    FortiSwitch current firmware version in verbose (data from -eSW)
    --no-firmware-updates-warn: suppress all update warnings (informational only)
    --no-firmware-major-warn:   suppress WARN for major version (e.g. v7 -> v8)
    --no-firmware-minor-warn:   suppress WARN for minor and patch updates; only major warns
    --firmware-mature-only:     only warn on maturity=M (Mature) releases; skips Fresh/Beta
    --firmware-blacklist <v1>[,v2,...]: skip specific versions from update warnings
                                (FG and FortiAP); comma-separated; partial match supported
 -eSensor,  --enable-sensors                                             (REST only)
    Hardware sensors: temperature, voltage, fan speed (appliance-defined thresholds)
 -eFWStats, --enable-fwstats                                             (REST only)
    Firewall policy statistics: aggregate byte/session/hit counters; --check-policy-cleanup
 -eShaper,  --enable-shaper                                              (REST only)
    Traffic shaper statistics: per-shaper total packets/bytes, bandwidth usage, active sessions,
    dropped packets/bytes; alert thresholds: --warn-shaper-drops/--crit-shaper-drops (default: -1)
    --shaper-vdom <vdom[,vdom,...]>  query specific VDOM(s) only; comma-separated;
 -eLB,      --enable-lb                                                 (REST only)
    Load balancer virtual server health: per-VIP real server health (up/down from health
    probes) and mode (active/standby/disabled); CRIT when all RS are down, WARN when some
    RS down or disabled; RTT and active sessions shown in verbose mode;
    --lb-vdom <vdom[,vdom,...]>  query specific VDOM(s); default: all VDOMs
 -eSecRating,--enable-secrating                                          (REST only)
    Security Fabric security rating: overall score, grade, per-category pass/warn/fail counts,
    and failed check names; thresholds: --warn-secrating-score/--crit-secrating-score
    (default -1 = disabled; alert when score drops below N); verbose shows per-check details
 -eLogwatch,--enable-logwatch                                            (REST only)
    Log event monitoring: fetch recent log entries and alert on matches;
    --logwatch-type <type[,type...]>      log category/categories; comma-sep list
                                          default: ALL types for the device
                                          disk: event,traffic,app-ctrl,ips,
                                            virus,webfilter,anomaly,dns,voip,dlp
                                          memory: app-ctrl,ips,virus,webfilter,
                                            anomaly,dns,voip,dlp
    --logwatch-subtype <system|vpn|...>   subtype filter; only applied to event
                                          and traffic log types (default: none)
    --logwatch-device <disk|memory>       log storage (default: disk)
    --logwatch-rows N                     entries to scan (default: 200)
    --logwatch-eventids "id1,id2,..."     only alert on these event IDs (comma-sep)
    --logwatch-actions "a1,a2,..."        only alert on these actions (comma-sep)
    --warn-logwatch N / --crit-logwatch N count thresholds (default: 1/-1=level-based)
    NOTE: not included in -A; must be enabled explicitly
 -A,        --enable-all
    Enable all available checks (default when no -eX flags given)

 Disable flags (opt-out - suppress individual modules from the default -A set):
 --disable-system        --disable-resources     --disable-ha    --disable-hasync
 --disable-interfaces    --disable-vpn           --disable-sslvpn
 --disable-ntp           --disable-sdwan         --disable-ap
 --disable-switch        --disable-fex           --disable-dhcp
 --disable-ipam          --disable-vdom          --disable-ftk
 --disable-utm           --disable-storage       --disable-forticloud
 --disable-license       --disable-certs         --disable-alerts
 --disable-uptime        --disable-firmware      --disable-sensors
 --disable-fwstats       --disable-shaper        --disable-lb
 --disable-logwatch

 -w,  --warning  <integer>
    WARNING threshold for disk usage in % (default: 80)
 -c,  --critical <integer>
    CRITICAL threshold for disk usage in % (default: 90)
 -wCPU <integer>
    WARNING threshold for CPU usage in % (default: 80)
 -cCPU <integer>
    CRITICAL threshold for CPU usage in % (default: 90)
 -wMem <integer>
    WARNING threshold for memory usage in % (default: 80)
 -cMem <integer>
    CRITICAL threshold for memory usage in % (default: 90)
 --warn-disk <integer>
    WARNING threshold for disk/storage usage in % (default: 80; used by -eRes and -eSD)
 --crit-disk <integer>
    CRITICAL threshold for disk/storage usage in % (default: 90; used by -eRes and -eSD)
 --warn-cert <integer>
    WARNING threshold for certificate expiry in days (default: 30)
 --crit-cert <integer>
    CRITICAL threshold for certificate expiry in days (default: 15)
 --warn-lic <integer>
    WARNING threshold for license/support expiry in days (default: 30)
 --crit-lic <integer>
    CRITICAL threshold for license/support expiry in days (default: 15)
 --warn-db-age <integer>
    WARNING threshold for FortiGuard DB last-update age in days (default: 7)
    Only applied to features with an active license and a database component
 --crit-db-age <integer>
    CRITICAL threshold for FortiGuard DB last-update age in days (default: 30)
 --warn-ni-errors <integer>
    WARNING threshold for interface tx+rx error counter (default: disabled)
 --crit-ni-errors <integer>
    CRITICAL threshold for interface tx+rx error counter (default: disabled)
 --warn-ni-drops <integer>
    WARNING threshold for interface tx+rx drop counter (default: disabled)
 --crit-ni-drops <integer>
    CRITICAL threshold for interface tx+rx drop counter (default: disabled)
 --warn-shaper-drops <integer>
    WARNING threshold for dropped packets per shaper (default: disabled)
 --crit-shaper-drops <integer>
    CRITICAL threshold for dropped packets per shaper (default: disabled)
 --warn-uptime <minutes>
    WARNING if uptime is below this value in minutes (default: 0 = disabled)
    Use to detect unexpected reboots, e.g. --warn-uptime 60 --crit-uptime 5
 --crit-uptime <minutes>
    CRITICAL if uptime is below this value in minutes (default: 0 = disabled)
 --firmware-show-all
    In verbose mode, list all available firmware versions including older ones
    (default: only versions newer than the installed version are shown)
 --firmware-blacklist <versions>
    Comma-separated list of firmware versions to exclude from update warnings.
    Applied to both FG and FortiAP firmware. Partial match (substring) is used,
    so "7.6.5" matches "7.6.5-build1234" and "FOS-v7.6.5" alike.

 --ifup <list>
    Comma-separated interfaces that MUST be link-up - CRITICAL if any are down
    (when set, only listed interfaces are checked; others are informational)
 --ifdown <list>
    Comma-separated interfaces that are EXPECTED to be down (maintenance/unused)
    WARNING if any of these are unexpectedly link-up
 --blacklist-interfaces <list>
    Comma-separated list of interface names to skip entirely (e.g. port1,mgmt)
 --blacklist-vpn <list>
    Comma-separated list of VPN tunnel names to skip
 --blacklist-lb-vip <list>
    Comma-separated list of LB virtual server names to skip entirely (e.g. vip1,vip2)
 --blacklist-lb-rs <list>
    Comma-separated list of real server IPs or IP:port to skip (e.g. 10.0.0.1,10.0.0.2:8080)
 --blacklist-certs <list>, --blacklist-cert <list>
    Comma-separated list of certificate names to skip
 --ignore-license <list>
    Comma-separated list of license feature names to skip (e.g. appctrl,webfilter)
 --ignore-all-licenses
    Suppress WARN/CRIT for all license issues - show info only, no alert state
 --alert-rows <integer>
    Number of recent log entries to scan for alerts (default: 50)
 --append-fw-name
    Prefix per-item output lines with the firewall hostname (e.g. "Interface flofw001/wan1")
    Default: hostname omitted from per-item lines (e.g. "Interface wan1")
 --no-perfdata
    Suppress the perfdata section entirely (no | output)
 --perfdata
    Show current performance data in output
 --no-prefetch
    Disable parallel background API fetching; all calls run serially.
    Use on hardened systems where background subshells or /tmp writes are restricted.
 --tmp-dir <path>
    Use <path> instead of /tmp for temporary files (default: /tmp).
    Required when /tmp is noexec or not writable; directory must exist.
 -s,  --silent
    Show only problem lines (suppress OK detail)
 -v,  --verbose
    Print section headers and extra detail
 -d,  --debug
    Enable bash debug output (set -x)

Example: ${PROGNAME} -H 10.0.0.1 -T MyApiToken123 -A -w 80 -c 90
         ${PROGNAME} -H 10.0.0.1 -T MyApiToken123 -eNI --ifup port1,port2 --ifdown port5,port6
         ${PROGNAME} -H 10.0.0.1 -T MyApiToken123 -eSys -eRes -eAl
         ${PROGNAME} -H 10.0.0.1 -T MyApiToken123 -eNIS --ifup wan1


EOM
}


## BEGIN
# Grab command line arguments
while [[ -n "${1}" ]]; do
	case "${1}" in
	-h|--help)
		print_help
		exit 0
		;;
	-V|--version)
		print_revision "${PROGNAME}" "${REVISION}"
		exit 0
		;;
	-H|--host)
		shift
		fg_host="${1}"
		;;
	-T|--token|-a|--api-token)
		shift
		api_token="${1}"
		;;
	-SC|--snmp-community)
		shift
		snmp_community="${1}"
		;;
	--snmp-user)
		shift
		snmp_user="${1}"
		;;
	--snmp-auth-proto)
		shift
		snmp_auth_proto="${1}"
		;;
	--snmp-auth-pass)
		shift
		snmp_auth_pass="${1}"
		;;
	--snmp-priv-proto)
		shift
		snmp_priv_proto="${1}"
		;;
	--snmp-priv-pass)
		shift
		snmp_priv_pass="${1}"
		;;
	--snmp-sec-level)
		shift
		snmp_sec_level="${1}"
		;;
	--snmp-port)
		shift
		snmp_port="${1}"
		;;
	-U|--username)
		shift
		api_user="${1}"
		;;
	-P|--password)
		shift
		api_pass="${1}"
		;;
	-N|--hostname)
		shift
		hostname_filter="${1}"
		;;
	# Enable flags
	-eSys|--enable-system)
		enable_sys=1
		;;
	-eRes|--enable-resources)
		enable_res=1
		;;
	-eHA|--enable-ha)
		enable_ha=1
		;;
	-eNI|--enable-interfaces)
		enable_ni=1
		;;
	-eNIS|--enable-interface-single)
		enable_nis=1
		;;
	-eVPN|--enable-vpn)
		enable_vpn=1
		;;
	-eSSL|--enable-sslvpn)
		enable_ssl=1
		;;
	-eSD|--enable-storage)
		enable_sd=1
		;;
	-eLic|--enable-license)
		enable_lic=1
		;;
	-eCloud|--enable-forticloud)
		enable_cloud=1
		;;
	-eCert|--enable-certs)
		enable_cert=1
		;;
	-eAl|--enable-alerts)
		enable_alerts=1
		;;
	-eUp|--enable-uptime)
		enable_uptime=1
		;;
	-eFirmware|--enable-firmware)
		enable_firmware=1
		;;
	-eSensor|--enable-sensors)
		enable_sensors=1
		;;
	-eFWStats|--enable-fwstats)
		enable_fwstats=1
		;;
	-eShaper|--enable-shaper)
		enable_shaper=1
		;;
	-eLB|--enable-lb)
		enable_lb=1
		;;
	-eNTP|--enable-ntp)
		enable_ntp=1
		;;
	-eSDWAN|--enable-sdwan)
		enable_sdwan=1
		;;
	-eAP|--enable-ap)
		enable_ap=1
		;;
	-eSW|--enable-switch)
		enable_sw=1
		;;
	-eFEX|--enable-fex)
		enable_fex=1
		;;
	-eDHCP|--enable-dhcp)
		enable_dhcp=1
		;;
	-eIPAM|--enable-ipam)
		enable_ipam=1
		;;
	-eVDOM|--enable-vdom)
		enable_vdom=1
		;;
	-eFTK|--enable-ftk)
		enable_ftk=1
		;;
	-eUTM|--enable-utm)
		enable_utm=1
		;;
	-eSecRating|--enable-secrating)
		enable_secrating=1
		;;
	-eLogwatch|--enable-logwatch)
		enable_logwatch=1
		;;
	-A|--enable-all)
		enable_all=1
		;;
	# Disable flags
	--disable-system)       disable_sys=1 ;;
	--disable-resources)    disable_res=1 ;;
	--disable-ha)           disable_ha=1 ;;
	--disable-hasync)       disable_hasync=1 ;;
	--disable-interfaces)   disable_ni=1 ;;
	--disable-vpn)          disable_vpn=1 ;;
	--disable-sslvpn)       disable_ssl=1 ;;
	--disable-storage)      disable_sd=1 ;;
	--disable-license)      disable_lic=1 ;;
	--disable-forticloud)   disable_cloud=1 ;;
	--warn-cloud-log-usage)
		shift
		warn_cloud_log_usage="${1}"
		;;
	--crit-cloud-log-usage)
		shift
		crit_cloud_log_usage="${1}"
		;;
	--warn-cloud-sandbox)
		shift
		warn_cloud_sandbox="${1}"
		;;
	--crit-cloud-sandbox)
		shift
		crit_cloud_sandbox="${1}"
		;;
	--warn-cloud-staging)
		shift
		warn_cloud_staging="${1}"
		;;
	--crit-cloud-staging)
		shift
		crit_cloud_staging="${1}"
		;;
	--cloud-domain)
		shift
		cloud_domain_expected="${1}"
		;;
	--disable-certs)        disable_cert=1 ;;
	--disable-alerts)       disable_alerts=1 ;;
	--disable-uptime)       disable_uptime=1 ;;
	--disable-firmware)     disable_firmware=1 ;;
	--disable-sensors)      disable_sensors=1 ;;
	--disable-fwstats)      disable_fwstats=1 ;;
	--disable-shaper)       disable_shaper=1 ;;
	--disable-lb)           disable_lb=1 ;;
	--disable-ntp)          disable_ntp=1 ;;
	--disable-sdwan)        disable_sdwan=1 ;;
	--disable-ap)           disable_ap=1 ;;
	--disable-switch)       disable_sw=1 ;;
	--disable-fex)          disable_fex=1 ;;
	--disable-dhcp)         disable_dhcp=1 ;;
	--disable-ipam)         disable_ipam=1 ;;
	--disable-vdom)         disable_vdom=1 ;;
	--disable-ftk)          disable_ftk=1 ;;
	--warn-ftk-available)   shift ; warn_ftk_available="${1}" ;;
	--crit-ftk-available)   shift ; crit_ftk_available="${1}" ;;
	--disable-utm)          disable_utm=1 ;;
	--disable-logwatch)     disable_logwatch=1 ;;
	--disable-secrating)    disable_secrating=1 ;;
	--warn-secrating-score)
		shift
		warn_secrating_score="${1}"
		;;
	--crit-secrating-score)
		shift
		crit_secrating_score="${1}"
		;;
	--logwatch-type)
		shift
		logwatch_type="${1}"
		;;
	--logwatch-subtype)
		shift
		logwatch_subtype="${1}"
		;;
	--logwatch-device)
		shift
		logwatch_device="${1}"
		;;
	--logwatch-rows)
		shift
		logwatch_rows="${1}"
		;;
	--logwatch-eventids)
		shift
		logwatch_eventids="${1}"
		;;
	--logwatch-actions)
		shift
		logwatch_actions="${1}"
		;;
	--warn-logwatch)
		shift
		warn_logwatch="${1}"
		;;
	--crit-logwatch)
		shift
		crit_logwatch="${1}"
		;;
	--warn-uptime)
		shift
		warn_uptime="${1}"
		;;
	--crit-uptime)
		shift
		crit_uptime="${1}"
		;;
	--no-firmware-updates-warn)  no_firmware_updates_warn=1 ;;
	--no-firmware-major-warn)    no_firmware_major_warn=1 ;;
	--no-firmware-minor-warn)    no_firmware_minor_warn=1 ;;
	--firmware-mature-only)      firmware_mature_only=1 ;;
	--firmware-show-all)         firmware_show_all=1 ;;
	--firmware-blacklist)        shift ; firmware_blacklist="${1}" ;;
	# Thresholds
	-w|--warning)
		shift
		warning="${1}"
		;;
	-c|--critical)
		shift
		critical="${1}"
		;;
	-wCPU)
		shift
		warn_cpu="${1}"
		_user_set_warn_cpu=1
		;;
	-cCPU)
		shift
		crit_cpu="${1}"
		_user_set_crit_cpu=1
		;;
	-wMem)
		shift
		warn_mem="${1}"
		_user_set_warn_mem=1
		;;
	-cMem)
		shift
		crit_mem="${1}"
		_user_set_crit_mem=1
		;;
	--warn-cert)
		shift
		warn_cert="${1}"
		;;
	--crit-cert)
		shift
		crit_cert="${1}"
		;;
	--warn-lic)
		shift
		warn_lic="${1}"
		;;
	--crit-lic)
		shift
		crit_lic="${1}"
		;;
	--warn-db-age)
		shift
		warn_db_age="${1}"
		;;
	--crit-db-age)
		shift
		crit_db_age="${1}"
		;;
	--warn-ni-errors)
		shift
		warn_ni_errors="${1}"
		;;
	--crit-ni-errors)
		shift
		crit_ni_errors="${1}"
		;;
	--warn-ni-drops)
		shift
		warn_ni_drops="${1}"
		;;
	--crit-ni-drops)
		shift
		crit_ni_drops="${1}"
		;;
	--warn-shaper-drops)
		shift
		warn_shaper_drops="${1}"
		;;
	--crit-shaper-drops)
		shift
		crit_shaper_drops="${1}"
		;;
	--shaper-vdom)
		shift
		shaper_vdom="${1}"
		;;
	--lb-vdom)
		shift
		lb_vdom="${1}"
		;;
	--warn-disk)
		shift
		warn_disk="${1}"
		;;
	--crit-disk)
		shift
		crit_disk="${1}"
		;;
	--warn-sessions)
		shift
		warn_sessions="${1}"
		;;
	--crit-sessions)
		shift
		crit_sessions="${1}"
		;;
	--warn-sessions-pct)
		shift
		warn_sessions_pct="${1}"
		;;
	--crit-sessions-pct)
		shift
		crit_sessions_pct="${1}"
		;;
	--warn-vpn-down)
		shift
		warn_vpn_down="${1}"
		;;
	--crit-vpn-down)
		shift
		crit_vpn_down="${1}"
		;;
	--check-policy-cleanup)
		check_policy_cleanup=1
		;;
	--warn-ap-down)
		shift
		warn_ap_down="${1}"
		;;
	--crit-ap-down)
		shift
		crit_ap_down="${1}"
		;;
	--warn-ap-clients)
		shift
		warn_ap_clients="${1}"
		;;
	--crit-ap-clients)
		shift
		crit_ap_clients="${1}"
		;;
	--warn-dhcp-usage)
		shift
		warn_dhcp_usage="${1}"
		;;
	--crit-dhcp-usage)
		shift
		crit_dhcp_usage="${1}"
		;;
	--warn-ipam-usage)
		shift
		warn_ipam_usage="${1}"
		;;
	--crit-ipam-usage)
		shift
		crit_ipam_usage="${1}"
		;;
	--exclude-dhcp)
		shift
		dhcp_exclude="${1}"
		;;
	--warn-utm-update|--warn-sig-age)
		shift
		warn_utm_update="${1}"
		;;
	--crit-utm-update|--crit-sig-age)
		shift
		crit_utm_update="${1}"
		;;
	--ignore-utm-status)
		ignore_utm_status=1
		;;
	--warn-ips)
		shift ; warn_ips="${1}" ;;
	--crit-ips)
		shift ; crit_ips="${1}" ;;
	--warn-ips-high)
		shift ; warn_ips_high="${1}" ;;
	--crit-ips-high)
		shift ; crit_ips_high="${1}" ;;
	--warn-av)
		shift ; warn_av="${1}" ;;
	--crit-av)
		shift ; crit_av="${1}" ;;
	--warn-sw-down)
		shift
		warn_sw_down="${1}"
		;;
	--crit-sw-down)
		shift
		crit_sw_down="${1}"
		;;
	--warn-ntp-offset)
		shift
		warn_ntp_offset="${1}"
		;;
	--crit-ntp-offset)
		shift
		crit_ntp_offset="${1}"
		;;
	--warn-sdwan-loss)
		shift
		warn_sdwan_loss="${1}"
		;;
	--crit-sdwan-loss)
		shift
		crit_sdwan_loss="${1}"
		;;
	--warn-sdwan-latency)
		shift
		warn_sdwan_latency="${1}"
		;;
	--crit-sdwan-latency)
		shift
		crit_sdwan_latency="${1}"
		;;
	--sdwan-vdom)
		shift
		sdwan_vdom="${1}"
		;;
	--warn-vdom-cpu)
		shift
		warn_vdom_cpu="${1}"
		;;
	--crit-vdom-cpu)
		shift
		crit_vdom_cpu="${1}"
		;;
	--warn-vdom-mem)
		shift
		warn_vdom_mem="${1}"
		;;
	--crit-vdom-mem)
		shift
		crit_vdom_mem="${1}"
		;;
	--warn-vdom-sessions)
		shift
		warn_vdom_sessions="${1}"
		;;
	--crit-vdom-sessions)
		shift
		crit_vdom_sessions="${1}"
		;;
	--warn-vdom-license)
		shift
		warn_vdom_license="${1}"
		;;
	--crit-vdom-license)
		shift
		crit_vdom_license="${1}"
		;;
	# Interface state expectations
	--ifup)
		shift
		ni_ifup="${1}"
		;;
	--ifdown)
		shift
		ni_ifdown="${1}"
		;;
	# Blacklists / interface filters
	--blacklist-interfaces|--ignore-if|--ignore-interfaces)
		shift
		ni_blacklist="${1}"
		;;
	--ignore-down)
		ni_ignore_down=1
		;;
	--use-32bit-counters)
		snmp_32bit_counters=1
		;;
	--blacklist-vpn)
		shift
		vpn_blacklist="${1}"
		;;
	--blacklist-lb-vip)
		shift
		lb_blacklist_vip="${1}"
		;;
	--blacklist-lb-rs)
		shift
		lb_blacklist_rs="${1}"
		;;
	--blacklist-certs|--blacklist-cert)
		shift
		cert_blacklist="${1}"
		;;
	--ignore-license)
		shift
		lic_ignore="${1}"
		;;
	--ignore-all-licenses)
		lic_ignore_all=1
		;;
	--alert-rows)
		shift
		alert_rows="${1}"
		;;
	--alerts-vdom)
		shift
		alerts_vdom="${1}"
		;;
	--append-fw-name)
		append_fw_name=1
		;;
	--no-perfdata)
		no_perfdata=1
		;;
	--perfdata)
		show_perfdata=1
		;;
	--no-prefetch)
		no_prefetch=1
		;;
	--tmp-dir)
		shift
		tmp_dir="${1}"
		;;
	-s|--silent)
		silent=1
		;;
	-v|--verbose)
		verbose=1
		;;
	-d|--debug)
		debug=1
		;;
	*)
		exit_unknown "${1}"
		;;
	esac
	shift
done

# Check mandatory parameters and dependencies
[[ -z "${JQ}" ]]   && { echo "${PROGNAME}: jq is required - please install it";   exit 4; }
[[ -z "${CURL}" ]] && { echo "${PROGNAME}: curl is required - please install it"; exit 4; }
[[ -z "${AWK}" ]]  && { echo "${PROGNAME}: awk is required - please install it";  exit 4; }
[[ -z "${fg_host}" ]] && exit_unknown "FortiGate hostname or IP (-H) is required!"
[[ -z "${api_token}" && ( -z "${api_user}" || -z "${api_pass}" ) && -z "${snmp_community}" && -z "${snmp_user}" ]] && \
	exit_unknown "Authentication required: -T <api_token>  OR  -U <user> -P <pass>  OR  --snmp-community / --snmp-user (SNMP-only mode)"

# If no explicit enable flags -> enable all (opt-out mode via --disable-X)
[[
-z "${enable_sys}"      &&
-z "${enable_res}"      &&
-z "${enable_ha}"       &&
-z "${enable_ni}"       &&
-z "${enable_nis}"      &&
-z "${enable_vpn}"      &&
-z "${enable_ssl}"      &&
-z "${enable_sd}"       &&
-z "${enable_lic}"      &&
-z "${enable_cloud}"    &&
-z "${enable_cert}"     &&
-z "${enable_alerts}"   &&
-z "${enable_firmware}" &&
-z "${enable_sensors}"  &&
-z "${enable_fwstats}"  &&
-z "${enable_shaper}"   &&
-z "${enable_lb}"      &&
-z "${enable_ntp}"      &&
-z "${enable_uptime}"   &&
-z "${enable_sdwan}"    &&
-z "${enable_vdom}"     &&
-z "${enable_ftk}"      &&
-z "${enable_utm}"      &&
-z "${enable_ap}"       &&
-z "${enable_sw}"       &&
-z "${enable_fex}"      &&
-z "${enable_dhcp}"     &&
-z "${enable_ipam}"     &&
-z "${enable_logwatch}" &&
-z "${enable_all}"
]] && enable_all=1

# Defaults
[[ -z "${warning}" ]]   && warning=80
[[ -z "${critical}" ]]  && critical=90
[[ -z "${warn_cpu}" ]]  && warn_cpu=80
[[ -z "${crit_cpu}" ]]  && crit_cpu=90
[[ -z "${warn_mem}" ]]  && warn_mem=75
[[ -z "${crit_mem}" ]]  && crit_mem=80
[[ -z "${warn_cert}" ]] && warn_cert=30
[[ -z "${crit_cert}" ]] && crit_cert=15
[[ -z "${warn_lic}" ]]      && warn_lic=30
[[ -z "${crit_lic}" ]]      && crit_lic=15
[[ -z "${warn_db_age}" ]]   && warn_db_age=7
[[ -z "${crit_db_age}" ]]   && crit_db_age=30
[[ -z "${warn_uptime}" ]]    && warn_uptime=0
[[ -z "${crit_uptime}" ]]    && crit_uptime=0
[[ -z "${warn_ni_errors}" ]] && warn_ni_errors=-1
[[ -z "${crit_ni_errors}" ]] && crit_ni_errors=-1
[[ -z "${warn_ni_drops}"  ]] && warn_ni_drops=-1
[[ -z "${crit_ni_drops}"  ]] && crit_ni_drops=-1
[[ -z "${warn_shaper_drops}" ]] && warn_shaper_drops=-1
[[ -z "${crit_shaper_drops}" ]] && crit_shaper_drops=-1
[[ -z "${ni_ignore_down}" ]]      && ni_ignore_down=""
[[ -z "${snmp_32bit_counters}" ]] && snmp_32bit_counters=""
[[ -z "${warn_disk}" ]]     && warn_disk=80
[[ -z "${crit_disk}" ]]     && crit_disk=90
[[ -z "${warn_sessions}" ]]     && warn_sessions=-1
[[ -z "${crit_sessions}" ]]     && crit_sessions=-1
[[ -z "${warn_sessions_pct}" ]] && warn_sessions_pct=80
[[ -z "${crit_sessions_pct}" ]] && crit_sessions_pct=90
[[ -z "${warn_vpn_down}" ]] && warn_vpn_down=-1
[[ -z "${crit_vpn_down}" ]] && crit_vpn_down=1
[[ -z "${check_policy_cleanup}" ]] && check_policy_cleanup=""
[[ -z "${warn_ap_down}" ]]      && warn_ap_down=-1
[[ -z "${crit_ap_down}" ]]      && crit_ap_down=1
[[ -z "${warn_ap_clients}" ]]   && warn_ap_clients=-1
[[ -z "${crit_ap_clients}" ]]   && crit_ap_clients=-1
[[ -z "${warn_dhcp_usage}" ]]   && warn_dhcp_usage=85%
[[ -z "${crit_dhcp_usage}" ]]   && crit_dhcp_usage=90%
[[ -z "${warn_ipam_usage}" ]]       && warn_ipam_usage=80
[[ -z "${crit_ipam_usage}" ]]       && crit_ipam_usage=90
[[ -z "${warn_secrating_score}" ]]  && warn_secrating_score=-1
[[ -z "${crit_secrating_score}" ]]  && crit_secrating_score=-1
[[ -z "${warn_cloud_log_usage}" ]]  && warn_cloud_log_usage=80
[[ -z "${crit_cloud_log_usage}" ]]  && crit_cloud_log_usage=90
[[ -z "${warn_cloud_sandbox}" ]]    && warn_cloud_sandbox=80
[[ -z "${crit_cloud_sandbox}" ]]    && crit_cloud_sandbox=90
[[ -z "${warn_cloud_staging}" ]]    && warn_cloud_staging=80
[[ -z "${crit_cloud_staging}" ]]    && crit_cloud_staging=90
[[ -z "${cloud_domain_expected}" ]] && cloud_domain_expected=""
[[ -z "${dhcp_exclude}" ]]      && dhcp_exclude=""
[[ -z "${warn_utm_update}" ]]   && warn_utm_update=30
[[ -z "${crit_utm_update}" ]]   && crit_utm_update=60
[[ -z "${ignore_utm_status}" ]] && ignore_utm_status=""
[[ -z "${warn_ips}" ]]          && warn_ips=-1
[[ -z "${crit_ips}" ]]          && crit_ips=-1
[[ -z "${warn_ips_high}" ]]     && warn_ips_high=-1
[[ -z "${crit_ips_high}" ]]     && crit_ips_high=-1
[[ -z "${warn_av}" ]]           && warn_av=-1
[[ -z "${crit_av}" ]]           && crit_av=-1
[[ -z "${warn_sw_down}" ]]      && warn_sw_down=-1
[[ -z "${crit_sw_down}" ]]      && crit_sw_down=1
[[ -z "${warn_ntp_offset}" ]]   && warn_ntp_offset=300
[[ -z "${crit_ntp_offset}" ]]   && crit_ntp_offset=500
[[ -z "${warn_sdwan_loss}" ]]   && warn_sdwan_loss=5
[[ -z "${crit_sdwan_loss}" ]]   && crit_sdwan_loss=20
[[ -z "${warn_sdwan_latency}" ]] && warn_sdwan_latency=-1
[[ -z "${crit_sdwan_latency}" ]] && crit_sdwan_latency=-1
[[ -z "${sdwan_vdom}" ]]        && sdwan_vdom=""
[[ -z "${warn_ftk_available}" ]] && warn_ftk_available=0
[[ -z "${crit_ftk_available}" ]] && crit_ftk_available=-1
[[ -z "${warn_vdom_cpu}" ]]     && warn_vdom_cpu=80
[[ -z "${crit_vdom_cpu}" ]]     && crit_vdom_cpu=90
[[ -z "${warn_vdom_mem}" ]]     && warn_vdom_mem=80
[[ -z "${crit_vdom_mem}" ]]     && crit_vdom_mem=90
[[ -z "${warn_vdom_sessions}" ]] && warn_vdom_sessions=-1
[[ -z "${crit_vdom_sessions}" ]] && crit_vdom_sessions=-1
[[ -z "${warn_vdom_license}" ]] && warn_vdom_license=80
[[ -z "${crit_vdom_license}" ]] && crit_vdom_license=90
[[ -z "${alert_rows}" ]]    && alert_rows=50
[[ -z "${alerts_vdom}" ]]   && alerts_vdom=""
[[ -z "${logwatch_type}" ]]    && logwatch_type=""
[[ -z "${logwatch_subtype}" ]] && logwatch_subtype=""
[[ -z "${logwatch_device}" ]]  && logwatch_device="disk"
[[ -z "${logwatch_rows}" ]]    && logwatch_rows=200
[[ -z "${logwatch_eventids}" ]] && logwatch_eventids=""
[[ -z "${logwatch_actions}" ]]  && logwatch_actions=""
[[ -z "${warn_logwatch}" ]]    && warn_logwatch=1
[[ -z "${crit_logwatch}" ]]    && crit_logwatch=-1
[[ -z "${snmp_port}" ]]     && snmp_port=161

# SNMPv3 USM enforces a minimum passphrase length of 8 characters.
# Catch this early so the user gets a clear error instead of silent empty results.
if [[ -n "${snmp_user}" ]]; then
	if [[ -n "${snmp_auth_pass}" && ${#snmp_auth_pass} -lt 8 ]]; then
		echo "[UNKNOWN] - SNMPv3 auth passphrase too short (${#snmp_auth_pass} chars) - USM requires minimum 8 characters"
		exit 4
	fi
	if [[ -n "${snmp_priv_pass}" && ${#snmp_priv_pass} -lt 8 ]]; then
		echo "[UNKNOWN] - SNMPv3 priv passphrase too short (${#snmp_priv_pass} chars) - USM requires minimum 8 characters"
		exit 4
	fi
fi

# ---------------------------------------------------------------------------
# SNMP helper - defined once, used by uptime and resource checks.
# Supports v2c (--snmp-community) and v3 (--snmp-user); both can coexist
# with API credentials. Security level is auto-derived when not explicit:
#   no auth/priv -> noAuthNoPriv; auth only -> authNoPriv; both -> authPriv
# ---------------------------------------------------------------------------
_snmp_avail=""
if [[ -n "${SNMPGET}" ]]; then
	if [[ -n "${snmp_user}" ]]; then
		_snmp_avail=1
		_snmp_sec="${snmp_sec_level}"
		if [[ -z "${_snmp_sec}" ]]; then
			if [[ -n "${snmp_auth_pass}" && -n "${snmp_priv_pass}" ]]; then
				_snmp_sec="authPriv"
			elif [[ -n "${snmp_auth_pass}" ]]; then
				_snmp_sec="authNoPriv"
			else
				_snmp_sec="noAuthNoPriv"
			fi
		fi
		_snmp_get() {
			local -a _cmd=("${SNMPGET}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Ovq -t 2 -r 1)
			[[ -n "${snmp_auth_pass}" ]] && _cmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
			[[ -n "${snmp_priv_pass}" ]] && _cmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
			"${_cmd[@]}" "${fg_host}:${snmp_port}" "$1" 2>/dev/null | tr -d '"' | tr -d ' '
		}
	elif [[ -n "${snmp_community}" ]]; then
		_snmp_avail=1
		_snmp_get() {
			"${SNMPGET}" -v2c -c "${snmp_community}" -Ovq -t 2 -r 1 \
				"${fg_host}:${snmp_port}" "$1" 2>/dev/null | tr -d '"' | tr -d ' '
		}
	fi

	# _snmp_walk: same auth as _snmp_get, returns one value per line (OIDs stripped).
	# Uses -Ovqe: -q strips type prefix, -e forces enum integers numerically
	# (ifAdminStatus=1 not "up", ifOperStatus=2 not "down"), -v value-only output.
	# -t 2 -r 1: 2s timeout, 1 retry = 4s max per walk before giving up.
	if [[ -n "${_snmp_avail}" && -n "${SNMPWALK}" ]]; then
		if [[ -n "${snmp_user}" ]]; then
			_snmp_walk() {
				local -a _cmd=("${SNMPWALK}" -v3 -u "${snmp_user}" -l "${_snmp_sec}" -Ovqe -t 2 -r 1)
				[[ -n "${snmp_auth_pass}" ]] && _cmd+=(-a "${snmp_auth_proto:-SHA}" -A "${snmp_auth_pass}")
				[[ -n "${snmp_priv_pass}" ]] && _cmd+=(-x "${snmp_priv_proto:-AES}" -X "${snmp_priv_pass}")
				"${_cmd[@]}" "${fg_host}:${snmp_port}" "$1" 2>/dev/null
			}
		else
			_snmp_walk() {
				"${SNMPWALK}" -v2c -c "${snmp_community}" -Ovqe -t 2 -r 1 \
					"${fg_host}:${snmp_port}" "$1" 2>/dev/null
			}
		fi
	fi
fi

# Status labels
status_ok="[OK]"
status_warn="[WARNING]"
status_crit="[CRITICAL]"
status_unkn="[UNKNOWN]"

# Curl option block - --insecure for self-signed FortiGate certificates
CURL_OPTS="--insecure --silent --max-time 15"

fg_output=""
fg_problem_output=""
fg_perf=""

if [[ -n "${debug}" ]]; then
	echo "Debugging mode ON." 1>&2
	set -x
fi

# ---------------------------------------------------------------------------
# Base URL
# ---------------------------------------------------------------------------
FG_API="https://${fg_host}/api/v2"

# ---------------------------------------------------------------------------
# Authentication - API token, username/password, or SNMP-only (no REST API)
# ---------------------------------------------------------------------------
if [[ -n "${api_token}" ]]; then
	fg_api_get() {
		${CURL} ${CURL_OPTS} -X GET -H "Authorization: Bearer ${api_token}" "$@"
	}
elif [[ -z "${api_user}" && ( -n "${snmp_community}" || -n "${snmp_user}" ) ]]; then
	# SNMP-only mode: no REST API credentials - stub out API calls
	if [[ -z "${SNMPGET}" ]]; then
		echo "${status_unkn} - snmpget is required for SNMP mode - please install net-snmp-utils (net-snmp)"
		exit 4
	fi
	_snmp_only=1
	fg_api_get() { :; }
else
	_cookie_jar=$(mktemp /tmp/.fg_cookie_XXXXXX)
	_login_hdr=$(mktemp /tmp/.fg_header_XXXXXX)

	# Write response headers to a temp file, discard body (-o /dev/null) to avoid
	# null-byte issues in command substitution from the FortiGate HTML redirect page.
	${CURL} ${CURL_OPTS} -L -X POST \
		-c "${_cookie_jar}" \
		-D "${_login_hdr}" \
		-o /dev/null \
		-d "username=${api_user}&secretkey=${api_pass}" \
		"https://${fg_host}/logincheck" 2>/dev/null

	# Try cookie jar first (standard path)
	_csrf_token=$(grep -i 'ccsrftoken' "${_cookie_jar}" 2>/dev/null | \
		"${AWK}" '{print $NF}' | tr -d '"' | head -1)

	# Fallback: extract from response headers file
	if [[ -z "${_csrf_token}" ]]; then
		_csrf_token=$(grep -i 'ccsrftoken' "${_login_hdr}" 2>/dev/null | \
			"${AWK}" -F'ccsrftoken=' '{print $2}' | \
			"${AWK}" -F';' '{print $1}' | tr -d '"' | head -1)
	fi
	rm -f "${_login_hdr}"

	if [[ -z "${_csrf_token}" ]]; then
		rm -f "${_cookie_jar}"
		echo "${status_unkn} - Login to ${fg_host} failed - no CSRF token in response (check credentials and that REST API access is permitted)"
		exit 4
	fi

	fg_api_get() {
		${CURL} ${CURL_OPTS} -X GET \
			-b "${_cookie_jar}" \
			-H "X-CSRFTOKEN: ${_csrf_token}" \
			"$@"
	}

	_fg_cleanup() {
		${CURL} ${CURL_OPTS} -X POST \
			-b "${_cookie_jar}" \
			-H "X-CSRFTOKEN: ${_csrf_token}" \
			"https://${fg_host}/logout" >/dev/null 2>&1 || true
		rm -f "${_cookie_jar}"
	}
	trap '_fg_cleanup' EXIT
fi

# ---------------------------------------------------------------------------
# Fetch system status (shared by all checks - provides hostname/model label)
# In SNMP-only mode, populate from SNMP OIDs instead of REST API.
# ---------------------------------------------------------------------------
if [[ -n "${_snmp_only}" ]]; then
	fg_hostname=$(_snmp_get "${OID_SYSNAME}")
	if [[ -z "${fg_hostname}" ]]; then
		# SNMP not responding - redefine helpers as no-ops so all subsequent
		# _snmp_get/_snmp_walk calls return instantly without triggering timeouts.
		_snmp_avail=""
		_snmp_get()  { :; }
		_snmp_walk() { :; }
		fg_hostname="${fg_host}"
		fg_version="unknown"
		fg_model="FortiGate"
		fg_output+="${status_ok} - ${fg_host}: SNMP not responding - check credentials and FortiGate SNMP allowed-hosts config\n"
	else
		[[ "${fg_hostname}" == "0" ]] && fg_hostname="${fg_host}"
		fg_version=$(_snmp_get "${OID_FG_VERSION}")
		[[ -z "${fg_version}" || "${fg_version}" == "0" ]] && fg_version="unknown"
		fg_model=$(_snmp_get "${OID_SYSDESCR}" | cut -c1-60)
		[[ -z "${fg_model}" || "${fg_model}" == "0" ]] && fg_model="FortiGate"
		fg_serial=$(_snmp_get "${OID_FG_SERIAL}" | tr -d '"')
		[[ -z "${fg_serial}" || "${fg_serial}" == "0" ]] && fg_serial="unknown"
	fi
	[[ -z "${fg_serial}" ]] && fg_serial="unknown"
	fg_ha_role="standalone"
	_sys_buffer=""
else
	_sys_buffer=$(fg_api_get "${FG_API}/monitor/system/status")

	if [[ -z "${_sys_buffer}" || ! "${_sys_buffer}" =~ '"results"' ]]; then
		echo "${status_unkn} - Failed to retrieve system status from ${fg_host} - check host and credentials"
		exit 4
	fi

	_http_status=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r '.http_status // 200' 2>/dev/null)
	if [[ "${_http_status}" -ge 400 ]] 2>/dev/null; then
		echo "${status_unkn} - API error ${_http_status} from ${fg_host} - check credentials and REST API permissions"
		exit 4
	fi

	fg_hostname=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r '.results.hostname // "unknown"' 2>/dev/null)
	fg_serial=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r '.serial // "unknown"' 2>/dev/null)
	fg_model=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r \
		'(.results.model_name // "") + (if .results.model_number != null and .results.model_number != "" then " " + .results.model_number else "" end) | if . == "" or . == " " then (.results.model // "unknown") else . end' 2>/dev/null)
	fg_version=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r '.version // "unknown"' 2>/dev/null)
	# ha_info is absent in FortiOS 7.6.x - derive from CMDB instead
	fg_ha_role=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r \
		'.results.ha_info.role // ""' 2>/dev/null)
fi
# ---------------------------------------------------------------------------
# Parallel API prefetch - fire all needed endpoints in background, wait once.
# Avoids serial TLS handshakes; cuts runtime from ~N×RTT to ~1×RTT.
# Disabled with --no-prefetch (serial mode); --tmp-dir overrides /tmp.
# ---------------------------------------------------------------------------
if [[ -n "${tmp_dir}" ]]; then
	[[ ! -d "${tmp_dir}" ]] && exit_unknown "--tmp-dir '${tmp_dir}' does not exist or is not a directory"
	_pf=$(mktemp -d "${tmp_dir}/.fg_check_XXXXXX") \
		|| exit_unknown "Failed to create temp dir under '${tmp_dir}'"
else
	_pf=$(mktemp -d /tmp/.fg_check_XXXXXX) \
		|| exit_unknown "Failed to create temp dir under /tmp (try --tmp-dir)"
fi

# In serial mode (_pf_get runs synchronously); parallel mode fires background jobs.
_pf_get() {
	if [[ -n "${no_prefetch}" ]]; then
		fg_api_get "$1" > "${_pf}/$2" 2>/dev/null
	else
		fg_api_get "$1" > "${_pf}/$2" 2>/dev/null &
	fi
}

# Fetch shaper runtime stats; tries multiple endpoint/scope variants in order.
# Response data is under .results.data[] (FortiOS 7.x); falls back to .results[] for older firmware.
# $1 = output file path, $2 = base URL (no /select suffix), $3 = VDOM name (optional)
_shp_mon_get() {
	local _out="${1}" _base="${2}" _vdom="${3:-}"
	local _chk='(.results.data // .results // [] | length) > 0'
	fg_api_get "${_base}/select${_vdom:+?vdom=${_vdom}}" > "${_out}" 2>/dev/null
	"${JQ}" -e "${_chk}" "${_out}" >/dev/null 2>&1 && return
	[[ -n "${_vdom}" ]] && {
		fg_api_get "${_base}/select?scope=vdom&vdom=${_vdom}" > "${_out}" 2>/dev/null
		"${JQ}" -e "${_chk}" "${_out}" >/dev/null 2>&1 && return
	}
	fg_api_get "${_base}${_vdom:+?vdom=${_vdom}}" > "${_out}" 2>/dev/null
	"${JQ}" -e "${_chk}" "${_out}" >/dev/null 2>&1 && return
	[[ -n "${_vdom}" ]] && \
		fg_api_get "${_base}?scope=vdom&vdom=${_vdom}" > "${_out}" 2>/dev/null
}

# Always needed: HA CMDB (fg_ha_mode for System+HA checks) and global thresholds
_pf_get "${FG_API}/cmdb/system/ha"       ha_cmdb.json
_pf_get "${FG_API}/cmdb/system/global"   cmdb_global.json

[[ ( -n "${enable_res}" || -n "${enable_all}" ) && -z "${disable_res}" && -z "${_snmp_avail}" ]] && {
	_pf_get "${FG_API}/monitor/system/resource/usage?interval=1min&time_period=60" res_usage.json
	_pf_get "${FG_API}/monitor/system/resource/usage"                              res_usage_plain.json
}
[[ ( -n "${enable_ha}"      || -n "${enable_all}" ) && -z "${disable_ha}"      ]] && {
	_pf_get "${FG_API}/monitor/system/ha-statistics"                                    ha_stats.json
	[[ -z "${disable_hasync}" ]] && \
		_pf_get "${FG_API}/monitor/system/ha-checksums"                                 ha_checksums.json
}
[[ ( -n "${enable_ni}" || -n "${enable_nis}" || -n "${enable_all}" ) && -z "${disable_ni}" ]] && \
	_pf_get "${FG_API}/monitor/system/interface?include_aggregate=true&scope=global"    ni.json
[[ ( -n "${enable_vpn}"     || -n "${enable_all}" ) && -z "${disable_vpn}"     ]] && \
	_pf_get "${FG_API}/monitor/vpn/ipsec?scope=global&start=0&count=1000"               vpn.json
[[ ( -n "${enable_ssl}"     || -n "${enable_all}" ) && -z "${disable_ssl}"     ]] && \
	_pf_get "${FG_API}/monitor/vpn/ssl?scope=global"                                    ssl.json
[[ ( -n "${enable_sd}"      || -n "${enable_all}" ) && -z "${disable_sd}"      ]] && {
	_pf_get "${FG_API}/monitor/system/storage"                                          storage.json
	_pf_get "${FG_API}/monitor/log/current-disk-usage"                                  logdisk.json
}
[[ ( -n "${enable_lic}"     || -n "${enable_all}" ) && -z "${disable_lic}"     ]] && \
	_pf_get "${FG_API}/monitor/license/status"                                          license.json
[[ ( -n "${enable_cloud}"   || -n "${enable_all}" ) && -z "${disable_cloud}"   ]] && {
	_pf_get "${FG_API}/monitor/license/status"                                          cloud_lic.json
	_pf_get "${FG_API}/monitor/log/forticloud"                                          cloud_log.json
}
[[ ( -n "${enable_cert}"    || -n "${enable_all}" ) && -z "${disable_cert}"    ]] && \
	_pf_get "${FG_API}/monitor/system/available-certificates"                           certs.json
[[ ( -n "${enable_alerts}"  || -n "${enable_all}" ) && -z "${disable_alerts}"  ]] && {
	_al_url="${FG_API}/log/disk/event/list?rows=${alert_rows}&start=0&logtype=system"
	[[ -n "${alerts_vdom}" ]] && _al_url+="&vdom=${alerts_vdom}"
	_pf_get "${_al_url}" alerts.json
}
[[ ( -n "${enable_firmware}" || -n "${enable_all}" ) && -z "${disable_firmware}" ]] && {
	_pf_get "${FG_API}/monitor/system/firmware"                                         firmware.json
	# Component firmware: fetch AP/SW/FEX data when not already fetched by their own checks
	[[ -z "${disable_ap}" ]] && \
		_pf_get "${FG_API}/monitor/wifi/firmware"                                       wifi_firmware.json
	[[ -z "${disable_ap}" && -z "${enable_ap}" && -z "${enable_all}" ]] && \
		_pf_get "${FG_API}/monitor/wifi/managed_ap"                                     managed_ap.json
	[[ -z "${disable_sw}" && -z "${enable_sw}" && -z "${enable_all}" ]] && \
		_pf_get "${FG_API}/monitor/switch-controller/managed-switch"                    managed_sw.json
	[[ -z "${disable_fex}" && -z "${enable_fex}" && -z "${enable_all}" ]] && \
		_pf_get "${FG_API}/monitor/extension-controller/fortiextender"                  fex.json
}
[[ ( -n "${enable_sensors}" || -n "${enable_all}" ) && -z "${disable_sensors}" ]] && \
	_pf_get "${FG_API}/monitor/system/sensor-info"                                      sensors.json
[[ ( -n "${enable_fwstats}" || -n "${enable_all}" ) && -z "${disable_fwstats}" ]] && {
	_pf_get "${FG_API}/monitor/firewall/policy/select"                                  fwpolicy4.json
	_pf_get "${FG_API}/monitor/firewall/policy6/select"                                 fwpolicy6.json
}
[[ ( -n "${enable_shaper}" || -n "${enable_all}" ) && -z "${disable_shaper}" ]] && {
	if [[ -n "${shaper_vdom}" ]]; then
		IFS=',' read -ra _shp_pf_vdoms <<< "${shaper_vdom}"
		for _shp_pf_v in "${_shp_pf_vdoms[@]}"; do
			_shp_pf_v="${_shp_pf_v// /}"
			_pf_get "${FG_API}/cmdb/firewall.shaper/traffic-shaper?vdom=${_shp_pf_v}" "shaper_cmdb_${_shp_pf_v}.json"
			if [[ -n "${no_prefetch}" ]]; then
				_shp_mon_get "${_pf}/shaper_mon_${_shp_pf_v}.json" \
					"${FG_API}/monitor/firewall/shaper" "${_shp_pf_v}"
			else
				_shp_mon_get "${_pf}/shaper_mon_${_shp_pf_v}.json" \
					"${FG_API}/monitor/firewall/shaper" "${_shp_pf_v}" &
			fi
		done
	else
		# Auto mode: prefetch VDOM list; per-VDOM CMDB+monitor queries done at check time
		_pf_get "${FG_API}/cmdb/system/vdom?start=0&count=100"                          vdom_list.json
	fi
}
[[ ( -n "${enable_lb}" || -n "${enable_all}" ) && -z "${disable_lb}" ]] && {
	if [[ -n "${lb_vdom}" ]]; then
		IFS=',' read -ra _lb_pf_vdoms <<< "${lb_vdom}"
		for _lb_pf_v in "${_lb_pf_vdoms[@]}"; do
			_lb_pf_v="${_lb_pf_v// /}"
			_pf_get "${FG_API}/monitor/firewall/load-balance?count=500&vdom=${_lb_pf_v}" "lb_mon_${_lb_pf_v}.json"
		done
	else
		_pf_get "${FG_API}/monitor/firewall/load-balance?count=500" lb_mon_root.json
	fi
}
[[ ( -n "${enable_ntp}"   || -n "${enable_all}" ) && -z "${disable_ntp}"   ]] && \
	_pf_get "${FG_API}/monitor/system/ntp/status"                                       ntp_status.json
[[ ( -n "${enable_sdwan}" || -n "${enable_all}" ) && -z "${disable_sdwan}" ]] && {
	if [[ -n "${sdwan_vdom}" ]]; then
		_pf_get "${FG_API}/monitor/virtual-wan/health-check?scope=vdom&vdom=${sdwan_vdom}"  sdwan_hc.json
		_pf_get "${FG_API}/cmdb/system/sdwan?vdom=${sdwan_vdom}"                            sdwan_config.json
	else
		_pf_get "${FG_API}/monitor/virtual-wan/health-check"                                sdwan_hc.json
		_pf_get "${FG_API}/cmdb/system/sdwan"                                               sdwan_config.json
	fi
}
[[ ( -n "${enable_vdom}"  || -n "${enable_all}" ) && -z "${disable_vdom}"  ]] && {
	_pf_get "${FG_API}/cmdb/system/vdom?start=0&count=100"                              vdom_list.json
	_pf_get "${FG_API}/monitor/license/status"                                          vdom_lic_info.json
}
[[ ( -n "${enable_ftk}"   || -n "${enable_all}" ) && -z "${disable_ftk}"   ]] && \
	_pf_get "${FG_API}/monitor/user/fortitoken"                                         fortitoken.json
[[ ( -n "${enable_ap}"    || -n "${enable_all}" ) && -z "${disable_ap}"    ]] && \
	_pf_get "${FG_API}/monitor/wifi/managed_ap"                                         managed_ap.json
[[ ( -n "${enable_sw}"    || -n "${enable_all}" ) && -z "${disable_sw}"    ]] && \
	_pf_get "${FG_API}/monitor/switch-controller/managed-switch"                        managed_sw.json
[[ ( -n "${enable_fex}"   || -n "${enable_all}" ) && -z "${disable_fex}"   ]] && \
	_pf_get "${FG_API}/monitor/extension-controller/fortiextender"                      fex.json
[[ ( -n "${enable_dhcp}"  || -n "${enable_all}" ) && -z "${disable_dhcp}"  ]] && {
	_pf_get "${FG_API}/cmdb/system.dhcp/server"                                         dhcp_config.json
	_pf_get "${FG_API}/monitor/system/dhcp"                                             dhcp_leases.json
}
[[ ( -n "${enable_ipam}"  || -n "${enable_all}" ) && -z "${disable_ipam}"  ]] && {
	_pf_get "${FG_API}/monitor/system/ipam/status"                                      ipam_status.json
	_pf_get "${FG_API}/cmdb/system/ipam"                                                ipam_config.json
}
[[ ( -n "${enable_utm}"       || -n "${enable_all}" ) && -z "${disable_utm}"       ]] && \
	_pf_get "${FG_API}/monitor/ips/anomaly"                                             dos_rules.json
[[ -n "${enable_secrating}" && -z "${disable_secrating}" ]] && {
	_pf_get "${FG_API}/monitor/system/security-rating/summary"                          secrating_summary.json
	_pf_get "${FG_API}/monitor/system/security-rating/result"                           secrating_result.json
}
[[ -n "${enable_logwatch}" && -z "${disable_logwatch}" ]] && {
	if [[ -z "${logwatch_type}" ]]; then
		if [[ "${logwatch_device}" == "memory" ]]; then
			IFS=',' read -ra _lw_pf_types <<< "app-ctrl,ips,virus,webfilter,anomaly,dns,voip,dlp"
		else
			IFS=',' read -ra _lw_pf_types <<< "event,traffic,app-ctrl,ips,virus,webfilter,anomaly,dns,voip,dlp"
		fi
	else
		IFS=',' read -ra _lw_pf_types <<< "${logwatch_type}"
	fi
	for _lw_pf_t in "${_lw_pf_types[@]}"; do
		_lw_pf_t="${_lw_pf_t// /}"
		[[ -z "${_lw_pf_t}" ]] && continue
		_lw_pf_url="${FG_API}/log/${logwatch_device}/${_lw_pf_t}/list?rows=${logwatch_rows}&start=0"
		if [[ -n "${logwatch_subtype}" && ("${_lw_pf_t}" == "event" || "${_lw_pf_t}" == "traffic") ]]; then
			_lw_pf_url+="&logtype=${logwatch_subtype}"
		fi
		_pf_get "${_lw_pf_url}" "logwatch_${_lw_pf_t}.json"
	done
	unset _lw_pf_types _lw_pf_t _lw_pf_url
}

[[ -z "${no_prefetch}" ]] && wait  # collect parallel prefetch jobs

# Derive fg_ha_mode from prefetched result (needed by System Info and HA checks)
_ha_cmdb_buf=$(cat "${_pf}/ha_cmdb.json" 2>/dev/null)
fg_ha_mode=$(echo "${_ha_cmdb_buf}" | "${JQ}" --unbuffered -r \
	'.results.mode // "standalone"' 2>/dev/null)
[[ -z "${fg_ha_mode}" || "${fg_ha_mode}" == "null" ]] && fg_ha_mode="standalone"
[[ -z "${fg_ha_role}" || "${fg_ha_role}" == "null" ]] && fg_ha_role="${fg_ha_mode}"

# SNMP-only: derive HA mode from SNMP since CMDB API is not available
if [[ -n "${_snmp_only}" && -n "${_snmp_avail}" && \
      ( -n "${enable_ha}" || -n "${enable_all}" ) && -z "${disable_ha}" ]]; then
	_snmp_ha_raw=$(_snmp_get "${OID_HA_MODE}")
	case "${_snmp_ha_raw}" in
		2) fg_ha_mode="active-active"  ;;
		3) fg_ha_mode="active-passive" ;;
	esac
fi

# Optional: validate hostname matches expected
if [[ -n "${hostname_filter}" && "${fg_hostname}" != "${hostname_filter}" ]]; then
	echo "${status_unkn} - Connected hostname '${fg_hostname}' does not match expected '${hostname_filter}'"
	exit 4
fi

# Output hostname prefixes — all empty by default; set with --append-fw-name
_fwn=""   # per-item slash prefix:  "" | "hostname/"
_fwh=""   # standalone prefix:      "" | "hostname: "
_fws=": " # module separator:       ": " | " hostname: "
[[ -n "${append_fw_name}" ]] && {
	_fwn="${fg_hostname}/"
	_fwh="${fg_hostname}: "
	_fws="${_fws}"
}

# ---------------------------------------------------------------------------
# System Info Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sys}" || -n "${enable_all}" ) && -z "${disable_sys}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="System Info:\n---------------------------------------\n"
	fi

	_build=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r '.build // ""' 2>/dev/null)
	_build_s=""
	[[ -n "${_build}" && "${_build}" != "null" ]] && _build_s=" build ${_build}"

	_reboot=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r \
		'.results.utc_last_reboot // 0' 2>/dev/null)
	_uptime_s=""
	if [[ "${_reboot}" -gt 0 ]] 2>/dev/null; then
		_now=$(date +%s)
		_diff=$(( _now - _reboot ))
		_days=$(( _diff / 86400 ))
		_hours=$(( (_diff % 86400) / 3600 ))
		_mins=$(( (_diff % 3600) / 60 ))
		_uptime_s=" | Uptime: ${_days}d ${_hours}h ${_mins}m"
	fi

	fg_output+="${status_ok} - ${_fwh}${fg_model} | FortiOS: ${fg_version}${_build_s} | Role: ${fg_ha_role}${_uptime_s}\n"
	fg_perf+=" ${fg_hostname}_online=1"

	if [[ -n "${verbose}" ]]; then
		fg_output+="${status_ok} - ${_fwh}Serial: ${fg_serial} | HA mode: ${fg_ha_mode}\n"

		# DNS servers from CMDB
		_dns_buf=$(fg_api_get "${FG_API}/cmdb/system/dns")
		_dns_servers=$(echo "${_dns_buf}" | "${JQ}" --unbuffered -r '
			[.results.primary, .results.secondary] |
			map(select(. != null and . != "0.0.0.0" and . != "")) | join(" / ")' 2>/dev/null)
		[[ -n "${_dns_servers}" && "${_dns_servers}" != "null" ]] && \
			fg_output+="${status_ok} - ${_fwh}DNS servers: ${_dns_servers}\n"

		# NTP servers from CMDB (ha_cmdb_buf already fetched; fetch ntp separately)
		_ntp_buf=$(fg_api_get "${FG_API}/cmdb/system/ntp")
		_ntp_sync=$(echo "${_ntp_buf}" | "${JQ}" --unbuffered -r '.results.ntpsync // ""' 2>/dev/null)
		if [[ "${_ntp_sync}" == "enable" ]]; then
			_ntp_servers=$(echo "${_ntp_buf}" | "${JQ}" --unbuffered -r \
				'[.results.ntpserver[] | .server] | join(", ")' 2>/dev/null)
			[[ -n "${_ntp_servers}" ]] && \
				fg_output+="${status_ok} - ${_fwh}NTP servers: ${_ntp_servers}\n"
		fi

		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Uptime Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_uptime}" || -n "${enable_all}" ) && -z "${disable_uptime}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Uptime:\n---------------------------------------\n"
	fi

	_up_diff=0
	_up_src=""

	# SNMP path: try fgSysUpTime (Observium MIB .4.1.20.0, Counter64, centiseconds) first,
	# fall back to MIB-II sysUpTime (.1.3.6.1.2.1.1.3.0, TimeTicks, hundredths); both units
	# are hundredths of seconds so the /100 conversion is identical.
	if [[ -n "${_snmp_avail}" ]]; then
		_up_raw=$(_snmp_get "${OID_FG_UPTIME}")
		if [[ ! "${_up_raw}" =~ ^[0-9]+$ || "${_up_raw}" -eq 0 ]]; then
			_up_raw=$(_snmp_get "${OID_UPTIME}")
		fi
		if [[ "${_up_raw}" =~ ^[0-9]+$ && "${_up_raw}" -gt 0 ]]; then
			_up_diff=$(( _up_raw / 100 ))
			_up_src="SNMP"
		fi
	fi

	# REST API fallback: up_time (seconds, FortiOS 7.x) or utc_last_reboot (epoch, FortiOS 6.x)
	if [[ "${_up_diff}" -eq 0 ]]; then
		_up_raw_api=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r \
			'.results.up_time // 0' 2>/dev/null)
		if [[ "${_up_raw_api}" =~ ^[0-9]+$ && "${_up_raw_api}" -gt 0 ]] 2>/dev/null; then
			_up_diff="${_up_raw_api}"
			_up_src="API"
		else
			_up_reboot=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r \
				'.results.utc_last_reboot // 0' 2>/dev/null)
			if [[ "${_up_reboot}" =~ ^[0-9]+$ && "${_up_reboot}" -gt 0 ]] 2>/dev/null; then
				_up_diff=$(( $(date +%s) - _up_reboot ))
				_up_src="API"
			fi
		fi
	fi

	if [[ "${_up_diff}" -gt 0 ]]; then
		_up_days=$(( _up_diff / 86400 ))
		_up_hours=$(( (_up_diff % 86400) / 3600 ))
		_up_mins=$(( (_up_diff % 3600) / 60 ))
		_up_diff_min=$(( _up_diff / 60 ))

		_up_state="${status_ok}"
		if [[ "${crit_uptime}" -gt 0 ]] 2>/dev/null && \
		   (( _up_diff_min < crit_uptime )) 2>/dev/null; then
			_up_state="${status_crit}"
			fg_problem_output+="${status_crit} - Uptime${_fws}${_up_days}d ${_up_hours}h ${_up_mins}m - below critical threshold ${crit_uptime}m (recent reboot?)\n"
		elif [[ "${warn_uptime}" -gt 0 ]] 2>/dev/null && \
		     (( _up_diff_min < warn_uptime )) 2>/dev/null; then
			_up_state="${status_warn}"
			fg_problem_output+="${status_warn} - Uptime${_fws}${_up_days}d ${_up_hours}h ${_up_mins}m - below warning threshold ${warn_uptime}m (recent reboot?)\n"
		fi

		fg_output+="${_up_state} - Uptime${_fws}${_up_days}d ${_up_hours}h ${_up_mins}m\n"
		fg_perf+=" uptime_seconds=${_up_diff}"
	else
		if [[ -n "${_snmp_only}" ]]; then
			fg_output+="${status_ok} - Uptime${_fws}not available (SNMP not responding)\n"
		elif [[ -n "${_snmp_avail}" ]]; then
			fg_output+="${status_ok} - Uptime${_fws}not available (SNMP OID returned no data - check FortiGate SNMP config)\n"
		else
			fg_output+="${status_ok} - Uptime${_fws}not available via REST API (FortiOS 7.4+ requires --snmp-community / --snmp-user)\n"
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Resource Usage Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_res}" || -n "${enable_all}" ) && -z "${disable_res}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Resource Usage:\n---------------------------------------\n"
	fi

	_cpu=0 ; _mem=0 ; _mem_total_kb=0 ; _disk_mb=0 ; _disk_cap_mb=0 ; _disk_pct=0
	_sessions=0 ; _sessions6=0 ; _setup_rate=0 ; _npu_sessions=0

	# --- SNMP path (real-time OIDs, most accurate) ---------------------------
	if [[ -n "${_snmp_avail}" ]]; then
		_snmp_val() { local v; v=$(_snmp_get "$1"); [[ "${v}" =~ ^[0-9]+$ ]] && echo "${v}" || echo "0"; }
		_cpu=$(_snmp_val "${OID_CPU}")
		_mem=$(_snmp_val "${OID_MEM}")
		_mem_total_kb=$(_snmp_val "${OID_MEMCAP}")
		_disk_mb=$(_snmp_val "${OID_DISK}")
		_disk_cap_mb=$(_snmp_val "${OID_DISK_CAP}")
		_sessions=$(_snmp_val "${OID_SES}")
		_sessions6=$(_snmp_val "${OID_SES6}")
		_setup_rate=$(_snmp_val "${OID_SESRATE}")
		_npu_sessions=$(_snmp_val "${OID_NPU_SES}")
		# Compute disk% from fgSysDiskUsage / fgSysDiskCapacity
		if [[ "${_disk_cap_mb}" =~ ^[0-9]+$ && "${_disk_cap_mb}" -gt 0 ]]; then
			_disk_pct=$(( _disk_mb * 100 / _disk_cap_mb ))
		fi
		# Uptime: try fgSysUpTime (.4.1.20.0, Counter64) first, fall back to MIB-II sysUpTime
		_snmp_uptime_raw=$(_snmp_get "${OID_FG_UPTIME}")
		if [[ ! "${_snmp_uptime_raw}" =~ ^[0-9]+$ || "${_snmp_uptime_raw}" -eq 0 ]]; then
			_snmp_uptime_raw=$(_snmp_get "${OID_UPTIME}")
		fi
		if [[ "${_snmp_uptime_raw}" =~ ^[0-9]+$ && "${_snmp_uptime_raw}" -gt 0 ]]; then
			_snmp_up_sec=$(( _snmp_uptime_raw / 100 ))
			_snmp_up_days=$(( _snmp_up_sec / 86400 ))
			_snmp_up_hrs=$(( (_snmp_up_sec % 86400) / 3600 ))
			_snmp_up_min=$(( (_snmp_up_sec % 3600) / 60 ))
			[[ -n "${verbose}" ]] && \
				fg_output+="${status_ok} - ${_fwh}Uptime: ${_snmp_up_days}d ${_snmp_up_hrs}h ${_snmp_up_min}m\n"
		fi
		_res_src="SNMP"
	else
		# --- REST API path ---------------------------------------------------
		# Response structure: results.<field> is an array where [0].current is
		# the instantaneous value and [0].historical["1-min"].values contains
		# 3-second samples of 1-minute averages (newest first).
		# We average the 5 most-recent 1-min samples -> ~5-minute rolling average.
		_res_buffer=$(cat "${_pf}/res_usage.json" 2>/dev/null)
		if [[ -z "${_res_buffer}" || ! "${_res_buffer}" =~ '"results"' ]]; then
			_res_buffer=$(cat "${_pf}/res_usage_plain.json" 2>/dev/null)
		fi

		if [[ -n "${_res_buffer}" && "${_res_buffer}" =~ '"results"' ]]; then
			# Returns 5-min average from historical["1-min"] samples, falls back to .current
			_res_val() {
				local field="$1"
				echo "${_res_buffer}" | "${JQ}" --unbuffered -r \
					--arg f "${field}" '
					.results[$f] as $arr |
					if ($arr == null or ($arr | length) == 0) then 0
					else
						$arr[0] as $r |
						(($r.historical["1-min"].values // [])[0:5]
							| map(.[1]) | if length > 0 then (add / length) else null end)
						// $r.current
						// 0
					end | floor' 2>/dev/null
			}
			_cpu=$(_res_val cpu)
			_mem=$(_res_val mem)
			_disk_pct=$(_res_val disk)
			_setup_rate=$(_res_val setuprate)
			_sessions=$(_res_val session)
			_npu_sessions=$(_res_val session6)
			unset -f _res_val
		fi
		_res_src="REST"
	fi

	if [[ -n "${_res_buffer}" && "${_res_buffer}" =~ '"results"' ]] || [[ "${_res_src}" == "SNMP" ]]; then

		# Apply appliance-configured thresholds from CMDB when user hasn't overridden them
		_cmdb_global=$(cat "${_pf}/cmdb_global.json" 2>/dev/null)
		if [[ -n "${_cmdb_global}" && "${_cmdb_global}" =~ '"results"' ]]; then
			_appl_cpu_thr=$(echo "${_cmdb_global}" | "${JQ}" --unbuffered -r \
				'.results."cpu-use-threshold" // ""' 2>/dev/null)
			_appl_mem_warn=$(echo "${_cmdb_global}" | "${JQ}" --unbuffered -r \
				'.results."memory-use-threshold-green" // ""' 2>/dev/null)
			_appl_mem_crit=$(echo "${_cmdb_global}" | "${JQ}" --unbuffered -r \
				'.results."memory-use-threshold-red" // ""' 2>/dev/null)
			[[ -z "${_user_set_warn_cpu}" && "${_appl_cpu_thr}" =~ ^[0-9]+$ ]] && \
				warn_cpu="${_appl_cpu_thr}"
			[[ -z "${_user_set_crit_cpu}" && "${_appl_cpu_thr}" =~ ^[0-9]+$ ]] && \
				crit_cpu=$(( _appl_cpu_thr + 10 < 100 ? _appl_cpu_thr + 10 : 100 ))
		fi

		# CPU threshold check
		_cpu_state="${status_ok}"
		if (( _cpu >= crit_cpu )) 2>/dev/null; then
			_cpu_state="${status_crit}"
			fg_problem_output+="${status_crit} - ${_fwh}CPU CRITICAL: ${_cpu}% (threshold: ${crit_cpu}%)\n"
		elif (( _cpu >= warn_cpu )) 2>/dev/null; then
			_cpu_state="${status_warn}"
			fg_problem_output+="${status_warn} - ${_fwh}CPU WARNING: ${_cpu}% (threshold: ${warn_cpu}%)\n"
		fi
		fg_output+="${_cpu_state} - ${_fwh}CPU: ${_cpu}% (warn: ${warn_cpu}%, crit: ${crit_cpu}%)\n"

		# Memory threshold check
		_mem_state="${status_ok}"
		if (( _mem >= crit_mem )) 2>/dev/null; then
			_mem_state="${status_crit}"
			fg_problem_output+="${status_crit} - ${_fwh}Memory CRITICAL: ${_mem}% (threshold: ${crit_mem}%)\n"
		elif (( _mem >= warn_mem )) 2>/dev/null; then
			_mem_state="${status_warn}"
			fg_problem_output+="${status_warn} - ${_fwh}Memory WARNING: ${_mem}% (threshold: ${warn_mem}%)\n"
		fi

		_sess_detail=""
		[[ "${_sessions6}" != "0" && "${_sessions6}" != "null" ]] && \
			_sess_detail+=" | IPv6 sessions: ${_sessions6}"
		[[ "${_npu_sessions}" != "0" && "${_npu_sessions}" != "null" ]] && \
			_sess_detail+=" | NPU sessions: ${_npu_sessions}"
		[[ "${_setup_rate}" != "0" && "${_setup_rate}" != "null" ]] && \
			_sess_detail+=" | Session rate: ${_setup_rate}/s"
		_mem_detail=""
		if [[ "${_mem_total_kb}" =~ ^[0-9]+$ && "${_mem_total_kb}" -gt 0 ]]; then
			_mem_total_mb=$(( _mem_total_kb / 1024 ))
			_mem_detail=" (${_mem_total_mb} MB total)"
		fi
		# Session count threshold check
		_sess_state="${status_ok}"
		if (( crit_sessions >= 0 && _sessions >= crit_sessions )) 2>/dev/null; then
			_sess_state="${status_crit}"
			fg_problem_output+="${status_crit} - ${_fwh}Sessions CRITICAL: ${_sessions} (threshold: ${crit_sessions})\n"
		elif (( warn_sessions >= 0 && _sessions >= warn_sessions )) 2>/dev/null; then
			_sess_state="${status_warn}"
			fg_problem_output+="${status_warn} - ${_fwh}Sessions WARNING: ${_sessions} (threshold: ${warn_sessions})\n"
		fi
		fg_output+="${_mem_state} - ${_fwh}Memory: ${_mem}%${_mem_detail} (warn: ${warn_mem}%, crit: ${crit_mem}%) | Sessions: ${_sessions}${_sess_detail}\n"

		# Disk threshold check (only when disk is present)
		if [[ "${_disk_cap_mb}" =~ ^[0-9]+$ && "${_disk_cap_mb}" -gt 0 ]]; then
			_disk_state="${status_ok}"
			if (( _disk_pct >= crit_disk )) 2>/dev/null; then
				_disk_state="${status_crit}"
				fg_problem_output+="${status_crit} - ${_fwh}Disk CRITICAL: ${_disk_pct}% (threshold: ${crit_disk}%)\n"
			elif (( _disk_pct >= warn_disk )) 2>/dev/null; then
				_disk_state="${status_warn}"
				fg_problem_output+="${status_warn} - ${_fwh}Disk WARNING: ${_disk_pct}% (threshold: ${warn_disk}%)\n"
			fi
			[[ -n "${verbose}" ]] && \
				fg_output+="${_disk_state} - ${_fwh}Disk: ${_disk_pct}% (${_disk_mb}/${_disk_cap_mb} MB) (warn: ${warn_disk}%, crit: ${crit_disk}%)\n"
		fi

		# Detailed session stats from firewall session endpoint
		_sess_buf=$(fg_api_get "${FG_API}/monitor/firewall/session/full-stat")
		if [[ -n "${_sess_buf}" && "${_sess_buf}" =~ '"results"' ]]; then
			_sess_max=$(echo "${_sess_buf}" | "${JQ}" --unbuffered -r \
				'.results.session_limit // .results.max_session // ""' 2>/dev/null)
			_sess_total=$(echo "${_sess_buf}" | "${JQ}" --unbuffered -r \
				'.results.total // ""' 2>/dev/null)
			_sess_clash=$(echo "${_sess_buf}" | "${JQ}" --unbuffered -r \
				'.results.clash // ""' 2>/dev/null)
			_sess_tcp=$(echo "${_sess_buf}"  | "${JQ}" --unbuffered -r '.results.tcp   // ""' 2>/dev/null)
			_sess_udp=$(echo "${_sess_buf}"  | "${JQ}" --unbuffered -r '.results.udp   // ""' 2>/dev/null)
			_sess_icmp=$(echo "${_sess_buf}" | "${JQ}" --unbuffered -r '.results.icmp  // ""' 2>/dev/null)
			_sess_tcp6=$(echo "${_sess_buf}" | "${JQ}" --unbuffered -r '.results.tcp6  // ""' 2>/dev/null)
			_sess_other=$(echo "${_sess_buf}"| "${JQ}" --unbuffered -r '.results.others // ""' 2>/dev/null)

			# Session limit usage %
			_sess_pct=0
			if [[ "${_sess_max}" =~ ^[0-9]+$ && "${_sess_max}" -gt 0 ]]; then
				_sess_cur="${_sess_total}"
				[[ ! "${_sess_cur}" =~ ^[0-9]+$ ]] && _sess_cur="${_sessions}"
				[[ "${_sess_cur}" =~ ^[0-9]+$ ]] && \
					_sess_pct=$(( _sess_cur * 100 / _sess_max ))
				if (( _sess_pct >= crit_sessions_pct )) 2>/dev/null; then
					_sess_state="${status_crit}"
					fg_problem_output+="${status_crit} - ${_fwh}Sessions CRITICAL: ${_sess_cur}/${_sess_max} (${_sess_pct}%, threshold: ${crit_sessions_pct}%)\n"
				elif (( _sess_pct >= warn_sessions_pct )) 2>/dev/null; then
					_sess_state="${status_warn}"
					fg_problem_output+="${status_warn} - ${_fwh}Sessions WARNING: ${_sess_cur}/${_sess_max} (${_sess_pct}%, threshold: ${warn_sessions_pct}%)\n"
				fi
			fi

			if [[ -n "${verbose}" ]]; then
				_sdet=""
				[[ -n "${_sess_total}" && "${_sess_total}" != "null" ]] && _sdet+=" | Total: ${_sess_total}"
				if [[ "${_sess_max}" =~ ^[0-9]+$ && "${_sess_max}" -gt 0 ]]; then
					_sdet+=" | Limit: ${_sess_max} (${_sess_pct}%)"
				elif [[ -n "${_sess_max}" && "${_sess_max}" != "null" ]]; then
					_sdet+=" | Limit: ${_sess_max}"
				fi
				[[ -n "${_sess_clash}" && "${_sess_clash}" != "0" && "${_sess_clash}" != "null" ]] && \
					_sdet+=" | Clashes: ${_sess_clash}"
				[[ -n "${_sdet}" ]] && \
					fg_output+="${_sess_state} - ${_fwh}Session detail${_sdet}\n"
				_sproto=""
				[[ -n "${_sess_tcp}"  && "${_sess_tcp}"  != "null" ]] && _sproto+=" | TCP: ${_sess_tcp}"
				[[ -n "${_sess_udp}"  && "${_sess_udp}"  != "null" ]] && _sproto+=" | UDP: ${_sess_udp}"
				[[ -n "${_sess_icmp}" && "${_sess_icmp}" != "null" ]] && _sproto+=" | ICMP: ${_sess_icmp}"
				[[ -n "${_sess_tcp6}" && "${_sess_tcp6}" != "null" && "${_sess_tcp6}" != "0" ]] && \
					_sproto+=" | TCP6: ${_sess_tcp6}"
				[[ -n "${_sess_other}" && "${_sess_other}" != "null" && "${_sess_other}" != "0" ]] && \
					_sproto+=" | Other: ${_sess_other}"
				[[ -n "${_sproto}" ]] && \
					fg_output+="${status_ok} - ${_fwh}Sessions by protocol${_sproto}\n"
			fi
			[[ -n "${_sess_max}" && "${_sess_max}" != "null" ]] && \
				fg_perf+=" session_limit=${_sess_max}"
			[[ "${_sess_pct}" =~ ^[0-9]+$ && "${_sess_max}" =~ ^[0-9]+$ && "${_sess_max}" -gt 0 ]] && \
				fg_perf+=" session_usage_pct=${_sess_pct};${warn_sessions_pct};${crit_sessions_pct};0;100"
			[[ -n "${_sess_tcp}"  && "${_sess_tcp}"  =~ ^[0-9]+$ ]] && fg_perf+=" sessions_tcp=${_sess_tcp}"
			[[ -n "${_sess_udp}"  && "${_sess_udp}"  =~ ^[0-9]+$ ]] && fg_perf+=" sessions_udp=${_sess_udp}"
			[[ -n "${_sess_icmp}" && "${_sess_icmp}" =~ ^[0-9]+$ ]] && fg_perf+=" sessions_icmp=${_sess_icmp}"
			[[ -n "${_sess_tcp6}" && "${_sess_tcp6}" =~ ^[0-9]+$ && "${_sess_tcp6}" != "0" ]] && \
				fg_perf+=" sessions_tcp6=${_sess_tcp6}"
		fi

		fg_perf+=" cpu_pct=${_cpu};${warn_cpu};${crit_cpu};0;100"
		fg_perf+=" mem_pct=${_mem};${warn_mem};${crit_mem};0;100"
		[[ "${_mem_total_kb}" =~ ^[0-9]+$ && "${_mem_total_kb}" -gt 0 ]] && \
			fg_perf+=" mem_total_kb=${_mem_total_kb}"
		fg_perf+=" sessions=${_sessions};${warn_sessions};${crit_sessions}"
		[[ "${_sessions6}" != "0" && "${_sessions6}" != "null" ]] && \
			fg_perf+=" sessions6=${_sessions6}"
		[[ "${_npu_sessions}" != "0" && "${_npu_sessions}" != "null" ]] && \
			fg_perf+=" npu_sessions=${_npu_sessions}"
		[[ "${_setup_rate}" != "0" && "${_setup_rate}" != "null" ]] && \
			fg_perf+=" session_setup_rate=${_setup_rate}"
		if [[ "${_disk_cap_mb}" =~ ^[0-9]+$ && "${_disk_cap_mb}" -gt 0 ]]; then
			fg_perf+=" disk_pct=${_disk_pct};${warn_disk};${crit_disk};0;100"
			[[ "${_disk_mb}" =~ ^[0-9]+$ && "${_disk_mb}" -gt 0 ]] && \
				fg_perf+=" disk_mb=${_disk_mb};0;${_disk_cap_mb}"
		fi

	else
		if [[ -n "${_snmp_only}" ]]; then
			fg_output+="${status_ok} - Resource${_fws}not available (SNMP not responding)\n"
		else
			fg_output+="${status_unkn} - ${_fwh}Failed to retrieve resource usage\n"
			fg_problem_output+="${status_unkn} - ${_fwh}Failed to retrieve resource usage\n"
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# HA Cluster Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ha}" || -n "${enable_all}" ) && -z "${disable_ha}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="HA Cluster:\n---------------------------------------\n"
	fi

	if [[ "${fg_ha_mode}" == "standalone" || "${fg_ha_mode}" == "null" || -z "${fg_ha_mode}" ]]; then
		fg_output+="${status_ok} - ${_fwh}HA mode: standalone\n"
		fg_perf+=" ha_members=1"
	else
		_ha_buffer=$(cat "${_pf}/ha_stats.json" 2>/dev/null)

		if [[ -n "${_ha_buffer}" && "${_ha_buffer}" =~ '"results"' ]]; then
			_ha_total=$(echo "${_ha_buffer}" | "${JQ}" --unbuffered '.results | length' 2>/dev/null)
			_ha_group=$(echo "${_sys_buffer}" | "${JQ}" --unbuffered -r \
				'.results.ha_info.group_name // ""' 2>/dev/null)

			_ha_group_s=""
			[[ -n "${_ha_group}" && "${_ha_group}" != "null" ]] && _ha_group_s=" | Group: ${_ha_group}"

			fg_output+="${status_ok} - ${_fwh}HA ${fg_ha_mode} - ${_ha_total} member(s)${_ha_group_s}\n"

			# HA sync state check via ha-checksums
			if [[ -z "${disable_hasync}" ]]; then
				_ha_cs_buf=$(cat "${_pf}/ha_checksums.json" 2>/dev/null)
				if [[ -n "${_ha_cs_buf}" && "${_ha_cs_buf}" =~ '"results"' ]]; then
					_ha_cs_uniq=$(echo "${_ha_cs_buf}" | "${JQ}" --unbuffered -r \
						'[.results[] | .all // ""] | map(select(length > 0)) | unique | length' 2>/dev/null)
					if [[ "${_ha_cs_uniq}" == "1" ]]; then
						fg_output+="${status_ok} - HA Sync${_fws}synchronized\n"
					elif [[ "${_ha_cs_uniq}" =~ ^[0-9]+$ && "${_ha_cs_uniq}" -gt 1 ]]; then
						_ha_oos=$(echo "${_ha_cs_buf}" | "${JQ}" --unbuffered -r '
							(.results[] | select(.is_manage_master == 1) | .all // "") as $mcs |
							[.results[] | select(.is_manage_master != 1) |
								select((.all // "") != $mcs) | .hostname] | join(", ")' 2>/dev/null)
						fg_output+="${status_crit} - HA Sync${_fws}OUT OF SYNC (${_ha_oos:-unknown member(s)})\n"
						fg_problem_output+="${status_crit} - HA Sync${_fws}OUT OF SYNC (${_ha_oos:-unknown member(s)})\n"
						if [[ -n "${verbose}" ]]; then
							while IFS=$'\t' read -r _cs_host _cs_all _cs_glob _cs_root; do
								fg_output+="${status_ok} - HA Sync ${_fwn}${_cs_host}: all=${_cs_all} | global=${_cs_glob} | root=${_cs_root}\n"
							done < <(echo "${_ha_cs_buf}" | "${JQ}" --unbuffered -r '
								.results[] | [.hostname, (.all // "?"), (.global // "?"), (.root // "?")] | join("\t")' 2>/dev/null)
						fi
					else
						[[ -n "${verbose}" ]] && \
							fg_output+="${status_ok} - HA Sync${_fws}no checksum data available\n"
					fi
				else
					[[ -n "${verbose}" ]] && \
						fg_output+="${status_ok} - HA Sync${_fws}checksums endpoint not available\n"
				fi
			fi

			declare -a _ha_names _ha_roles _ha_cpus _ha_mems _ha_nets _ha_tbytes
			while IFS=$'\t' read -r _hm_host _hm_role _hm_cpu _hm_mem _hm_net _hm_tb; do
				_ha_names+=("${_hm_host}")
				_ha_roles+=("${_hm_role}")
				_ha_cpus+=("${_hm_cpu}")
				_ha_mems+=("${_hm_mem}")
				_ha_nets+=("${_hm_net}")
				_ha_tbytes+=("${_hm_tb}")
			done < <(echo "${_ha_buffer}" | "${JQ}" --unbuffered -r '
				.results[] | [
					(.hostname // "unknown"),
					(.role // "unknown"),
					(.cpu_usage // 0 | tostring),
					(.mem_usage // 0 | tostring),
					(.net_usage // 0 | tostring),
					(.tbyte // 0 | tostring)
				] | join("\t")' 2>/dev/null)

			for count in "${!_ha_names[@]}"; do
				_ha_lbl="${_ha_names[count]//-/_}"
				fg_perf+=" ha_${_ha_lbl}_cpu=${_ha_cpus[count]};${warn_cpu};${crit_cpu};0;100"
				fg_perf+=" ha_${_ha_lbl}_mem=${_ha_mems[count]};${warn_mem};${crit_mem};0;100"
				fg_perf+=" ha_${_ha_lbl}_net=${_ha_nets[count]};0;100"
				fg_perf+=" ha_${_ha_lbl}_tbytes=${_ha_tbytes[count]}c"
				if [[ -n "${verbose}" ]]; then
					_ha_net_s=""
					[[ "${_ha_nets[count]}" != "0" ]] && _ha_net_s=" | Net: ${_ha_nets[count]}%"
					_ha_tb_h=$(echo "${_ha_tbytes[count]}" | "${AWK}" '{
						if($1>=1099511627776) printf "%.1f TB",$1/1099511627776
						else if($1>=1073741824) printf "%.1f GB",$1/1073741824
						else if($1>=1048576) printf "%.1f MB",$1/1048576
						else printf "%d B",$1}')
					fg_output+="${status_ok} - HA member: ${_ha_names[count]} | Role: ${_ha_roles[count]} | CPU: ${_ha_cpus[count]}% | Mem: ${_ha_mems[count]}%${_ha_net_s} | Traffic: ${_ha_tb_h}\n"
				fi
			done
			unset _ha_names _ha_roles _ha_cpus _ha_mems _ha_nets _ha_tbytes

			fg_perf+=" ha_members=${_ha_total:-0}"
		else
			fg_output+="${status_ok} - ${_fwh}HA mode: ${fg_ha_mode} (statistics not available)\n"
			fg_perf+=" ha_members=0"
			# HA sync via SNMP (fallback when REST API stats unavailable)
			if [[ -z "${disable_hasync}" && -n "${_snmp_avail}" && -n "${SNMPWALK}" ]]; then
				mapfile -t _ha_snmp_sync  < <(_snmp_walk "${OID_HA_SYNC}"      | tr -d ' ')
				mapfile -t _ha_snmp_hosts < <(_snmp_walk "${OID_HA_PEER_HOST}" | tr -d ' "')
				if [[ "${#_ha_snmp_sync[@]}" -gt 0 ]]; then
					_ha_snmp_ok=1
					_ha_snmp_oos=""
					for _sn_idx in "${!_ha_snmp_sync[@]}"; do
						if [[ "${_ha_snmp_sync[_sn_idx]}" == "0" ]]; then
							_ha_snmp_ok=0
							_ha_snmp_host="${_ha_snmp_hosts[_sn_idx]:-unknown}"
							_ha_snmp_oos+="${_ha_snmp_oos:+, }${_ha_snmp_host}"
						fi
					done
					if [[ "${_ha_snmp_ok}" -eq 1 ]]; then
						fg_output+="${status_ok} - HA Sync${_fws}synchronized (SNMP)\n"
					else
						fg_output+="${status_crit} - HA Sync${_fws}OUT OF SYNC (${_ha_snmp_oos:-unknown member(s)}) (SNMP)\n"
						fg_problem_output+="${status_crit} - HA Sync${_fws}OUT OF SYNC (${_ha_snmp_oos:-unknown member(s)}) (SNMP)\n"
					fi
					if [[ -n "${verbose}" ]]; then
						for _sn_idx in "${!_ha_snmp_sync[@]}"; do
							_sn_label="in sync"
							[[ "${_ha_snmp_sync[_sn_idx]}" != "1" ]] && _sn_label="OUT OF SYNC"
							fg_output+="${status_ok} - HA Sync ${_fwn}${_ha_snmp_hosts[_sn_idx]:-unknown}: ${_sn_label}\n"
						done
					fi
				elif [[ -n "${verbose}" ]]; then
					fg_output+="${status_ok} - HA Sync${_fws}no SNMP sync data available\n"
				fi
			fi
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Network Interface Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ni}" || -n "${enable_nis}" || -n "${enable_all}" ) && -z "${disable_ni}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Network Interfaces:\n---------------------------------------\n"
	fi

	_ni_buffer=$(cat "${_pf}/ni.json" 2>/dev/null)

	# -eNIS requires --ifup
	if [[ -n "${enable_nis}" && -z "${enable_ni}" && -z "${ni_ifup}" ]]; then
		fg_output+="${status_unkn} - Interfaces${_fws}-eNIS requires --ifup <interface>\n"
		fg_problem_output+="${status_unkn} - Interfaces${_fws}-eNIS requires --ifup <interface>\n"
	elif [[ -n "${_ni_buffer}" && "${_ni_buffer}" =~ '"results"' ]]; then
		# Build lookup maps
		declare -A _ni_bl_map _ni_expect_up _ni_expect_down _ni_nis_found
		if [[ -n "${ni_blacklist}" ]]; then
			IFS=',' read -ra _ni_bl_arr <<< "${ni_blacklist}"
			for _ni_bl_e in "${_ni_bl_arr[@]}"; do _ni_bl_map["${_ni_bl_e}"]=1; done
		fi
		if [[ -n "${ni_ifup}" ]]; then
			IFS=',' read -ra _ni_up_arr <<< "${ni_ifup}"
			for _ni_up_e in "${_ni_up_arr[@]}"; do _ni_expect_up["${_ni_up_e}"]=1; done
		fi
		if [[ -n "${ni_ifdown}" ]]; then
			IFS=',' read -ra _ni_down_arr <<< "${ni_ifdown}"
			for _ni_down_e in "${_ni_down_arr[@]}"; do _ni_expect_down["${_ni_down_e}"]=1; done
		fi

		declare -a _ni_names _ni_links _ni_statuses _ni_speeds _ni_ips _ni_aliases \
		           _ni_txerr _ni_rxerr _ni_txdrops _ni_rxdrops _ni_txbytes _ni_rxbytes
		while IFS=$'\t' read -r _n_name _n_link _n_status _n_speed _n_ip _n_alias \
		                            _n_txerr _n_rxerr _n_txdrops _n_rxdrops _n_txbytes _n_rxbytes; do
			_ni_names+=("${_n_name}")
			_ni_links+=("${_n_link}")
			_ni_statuses+=("${_n_status}")
			_ni_speeds+=("${_n_speed}")
			_ni_ips+=("${_n_ip}")
			_ni_aliases+=("${_n_alias}")
			_ni_txerr+=("${_n_txerr}")
			_ni_rxerr+=("${_n_rxerr}")
			_ni_txdrops+=("${_n_txdrops}")
			_ni_rxdrops+=("${_n_rxdrops}")
			_ni_txbytes+=("${_n_txbytes}")
			_ni_rxbytes+=("${_n_rxbytes}")
		done < <(echo "${_ni_buffer}" | "${JQ}" --unbuffered -r '
			.results | to_entries[] | .value |
			select(.is_admin_interface != true) |
			[
				(.name // "unknown"),
				(if .link then "up" else "down" end),
				(.status // "up"),
				((.speed // 0) | tostring),
				(.ip // ""),
				(.alias // ""),
				((.tx_errors   // 0) | tostring),
				((.rx_errors   // 0) | tostring),
				((.tx_discards // 0) | tostring),
				((.rx_discards // 0) | tostring),
				((.tx_bytes    // 0) | tostring),
				((.rx_bytes    // 0) | tostring)
			] | join("\t")' 2>/dev/null)

		_ni_total=${#_ni_names[@]}
		_ni_up=0
		_ni_down=0
		_ni_checked=0

		for count in "${!_ni_names[@]}"; do
			_nin="${_ni_names[count]}"
			[[ -n "${_ni_bl_map[${_nin}]}" ]] && continue
			# In single-interface mode, skip everything not in --ifup
			if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
				[[ -z "${_ni_expect_up[${_nin}]}" ]] && continue
				_ni_nis_found["${_nin}"]=1
			fi

			_ni_is_admin_down=0
			[[ "${_ni_statuses[count]}" == "admin_down" ]] && _ni_is_admin_down=1

			_ni_detail=""
			[[ "${_ni_speeds[count]}" != "0" ]] && _ni_detail+=" | ${_ni_speeds[count]} Mbps"
			[[ -n "${_ni_aliases[count]}" ]] && _ni_detail+=" | ${_ni_aliases[count]}"
			[[ -n "${_ni_ips[count]}" ]] && _ni_detail+=" | ${_ni_ips[count]}"

			# Error counter check
			_ni_total_err=$(( _ni_txerr[count] + _ni_rxerr[count] ))
			_ni_err_state="${status_ok}"
			if [[ "${warn_ni_errors}" -ge 0 ]] 2>/dev/null && \
			   [[ "${crit_ni_errors}" -ge 0 ]] 2>/dev/null && \
			   (( _ni_total_err >= crit_ni_errors )) 2>/dev/null; then
				_ni_err_state="${status_crit}"
				fg_problem_output+="${status_crit} - Interface ${_fwn}${_nin}: ${_ni_total_err} errors (tx:${_ni_txerr[count]} rx:${_ni_rxerr[count]})\n"
			elif [[ "${warn_ni_errors}" -ge 0 ]] 2>/dev/null && \
			     (( _ni_total_err >= warn_ni_errors )) 2>/dev/null; then
				_ni_err_state="${status_warn}"
				fg_problem_output+="${status_warn} - Interface ${_fwn}${_nin}: ${_ni_total_err} errors (tx:${_ni_txerr[count]} rx:${_ni_rxerr[count]})\n"
			fi
			if [[ "${_ni_err_state}" != "${status_ok}" ]]; then
				fg_output+="${_ni_err_state} - Interface ${_fwn}${_nin}: ${_ni_total_err} errors (tx:${_ni_txerr[count]} rx:${_ni_rxerr[count]})\n"
			fi

			# Drop counter check
			_ni_txd="${_ni_txdrops[count]:-0}"; [[ ! "${_ni_txd}" =~ ^[0-9]+$ ]] && _ni_txd=0
			_ni_rxd="${_ni_rxdrops[count]:-0}"; [[ ! "${_ni_rxd}" =~ ^[0-9]+$ ]] && _ni_rxd=0
			_ni_total_drop=$(( _ni_txd + _ni_rxd ))
			if [[ "${warn_ni_drops}" -ge 0 ]] 2>/dev/null && \
			   [[ "${crit_ni_drops}" -ge 0 ]] 2>/dev/null && \
			   (( _ni_total_drop >= crit_ni_drops )) 2>/dev/null; then
				fg_output+="${status_crit} - Interface ${_fwn}${_nin}: ${_ni_total_drop} drops (tx:${_ni_txd} rx:${_ni_rxd})\n"
				fg_problem_output+="${status_crit} - Interface ${_fwn}${_nin}: ${_ni_total_drop} drops (tx:${_ni_txd} rx:${_ni_rxd})\n"
			elif [[ "${warn_ni_drops}" -ge 0 ]] 2>/dev/null && \
			     (( _ni_total_drop >= warn_ni_drops )) 2>/dev/null; then
				fg_output+="${status_warn} - Interface ${_fwn}${_nin}: ${_ni_total_drop} drops (tx:${_ni_txd} rx:${_ni_rxd})\n"
				fg_problem_output+="${status_warn} - Interface ${_fwn}${_nin}: ${_ni_total_drop} drops (tx:${_ni_txd} rx:${_ni_rxd})\n"
			fi

			# Perfdata per interface (link, bytes, errors, drops)
			_ni_lbl="${_nin//-/_}"
			_ni_link_val=0; [[ "${_ni_links[count]}" == "up" ]] && _ni_link_val=1
			fg_perf+=" ni_${_ni_lbl}_link=${_ni_link_val}"
			[[ "${_ni_rxbytes[count]}" =~ ^[0-9]+$ ]] && fg_perf+=" ni_${_ni_lbl}_rx_bytes=${_ni_rxbytes[count]}"
			[[ "${_ni_txbytes[count]}" =~ ^[0-9]+$ ]] && fg_perf+=" ni_${_ni_lbl}_tx_bytes=${_ni_txbytes[count]}"
			fg_perf+=" ni_${_ni_lbl}_rx_errors=${_ni_rxerr[count]:-0}"
			fg_perf+=" ni_${_ni_lbl}_tx_errors=${_ni_txerr[count]:-0}"
			fg_perf+=" ni_${_ni_lbl}_rx_drops=${_ni_rxd}"
			fg_perf+=" ni_${_ni_lbl}_tx_drops=${_ni_txd}"
			[[ "${_ni_total_err}" -gt 0 || "${warn_ni_errors}" -ge 0 ]] 2>/dev/null && \
				fg_perf+=" ni_${_ni_lbl}_errors=${_ni_total_err};${warn_ni_errors};${crit_ni_errors}"
			[[ "${_ni_total_drop}" -gt 0 || "${warn_ni_drops}" -ge 0 ]] 2>/dev/null && \
				fg_perf+=" ni_${_ni_lbl}_drops=${_ni_total_drop};${warn_ni_drops};${crit_ni_drops}"

			if [[ -n "${_ni_expect_up[${_nin}]}" ]]; then
				# Explicitly required UP
				(( _ni_checked++ ))
				if [[ "${_ni_links[count]}" == "up" ]]; then
					(( _ni_up++ ))
					if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
						fg_output+="${status_ok} - Interface ${_fwn}${_nin}: up${_ni_detail}\n"
					else
						[[ -n "${verbose}" ]] && \
							fg_output+="${status_ok} - Interface ${_fwn}${_nin}: link UP${_ni_detail}\n"
					fi
				else
					(( _ni_down++ ))
					_admin_s=""
					[[ "${_ni_is_admin_down}" -eq 1 ]] && _admin_s=" (admin-down)"
					if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
						fg_output+="${status_crit} - Interface ${_fwn}${_nin}: down${_admin_s}${_ni_detail}\n"
					else
						fg_output+="${status_crit} - Interface ${_fwn}${_nin}: link DOWN${_admin_s}${_ni_detail}\n"
					fi
					fg_problem_output+="${status_crit} - Interface ${_fwn}${_nin}: down${_admin_s}\n"
				fi
			elif [[ -n "${_ni_expect_down[${_nin}]}" ]]; then
				# Expected to be DOWN - flag if it comes up unexpectedly
				(( _ni_checked++ ))
				if [[ "${_ni_links[count]}" == "up" ]]; then
					fg_output+="${status_warn} - Interface ${_fwn}${_nin}: link UP (expected DOWN)${_ni_detail}\n"
					fg_problem_output+="${status_warn} - Interface ${_fwn}${_nin}: link UP but expected DOWN\n"
				else
					[[ -n "${verbose}" ]] && \
						fg_output+="${status_ok} - Interface ${_fwn}${_nin}: link DOWN (as expected)${_ni_detail}\n"
				fi
			else
				# Interface is not in --ifup or --ifdown (or no lists defined at all)
				# -> current state is assumed correct, always [OK]
				if [[ "${_ni_links[count]}" == "up" ]]; then
					(( _ni_up++ ))
				else
					(( _ni_down++ ))
				fi
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - Interface ${_fwn}${_nin}: link ${_ni_links[count]}${_ni_detail}\n"
			fi
		done

		if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
			# Check for --ifup interfaces not found in API data
			IFS=',' read -ra _nis_req <<< "${ni_ifup}"
			for _nis_r in "${_nis_req[@]}"; do
				if [[ -z "${_ni_nis_found[${_nis_r}]}" ]]; then
					fg_output+="${status_unkn} - Interface ${_fwn}${_nis_r}: not found\n"
					fg_problem_output+="${status_unkn} - Interface ${_fwn}${_nis_r}: not found\n"
				fi
			done
		elif [[ -z "${verbose}" ]]; then
			if [[ -n "${ni_ifup}" || -n "${ni_ifdown}" ]]; then
				fg_output+="${status_ok} - Interfaces${_fws}${_ni_checked} checked (${_ni_up} expected-up OK) | ${_ni_total} total, ${_ni_up} up, ${_ni_down} down\n"
			else
				fg_output+="${status_ok} - Interfaces${_fws}${_ni_total} total, ${_ni_up} up, ${_ni_down} down\n"
			fi
		fi

		if [[ -z "${enable_nis}" || -n "${enable_ni}" ]]; then
			fg_perf+=" ni_total=${_ni_total} ni_up=${_ni_up} ni_down=${_ni_down} ni_checked=${_ni_checked}"
		fi

		unset _ni_names _ni_links _ni_statuses _ni_speeds _ni_ips _ni_aliases \
		      _ni_txerr _ni_rxerr _ni_txdrops _ni_rxdrops _ni_txbytes _ni_rxbytes \
		      _ni_bl_map _ni_expect_up _ni_expect_down _ni_nis_found
	elif [[ -n "${_snmp_only}" && -n "${SNMPWALK}" ]]; then
		# SNMP interface check - IF-MIB ifTable
		declare -A _ni_bl_map _ni_expect_up _ni_expect_down _ni_nis_found
		[[ -n "${ni_blacklist}" ]] && { IFS=',' read -ra _a <<< "${ni_blacklist}"; for _e in "${_a[@]}"; do _ni_bl_map["${_e}"]=1; done; }
		[[ -n "${ni_ifup}" ]]      && { IFS=',' read -ra _a <<< "${ni_ifup}";      for _e in "${_a[@]}"; do _ni_expect_up["${_e}"]=1; done; }
		[[ -n "${ni_ifdown}" ]]    && { IFS=',' read -ra _a <<< "${ni_ifdown}";    for _e in "${_a[@]}"; do _ni_expect_down["${_e}"]=1; done; }
		mapfile -t _ni_names  < <(_snmp_walk "${OID_IF_NAME}"     | tr -d ' "')
		mapfile -t _ni_admin  < <(_snmp_walk "${OID_IF_ADMIN}"    | tr -d ' ')
		mapfile -t _ni_oper   < <(_snmp_walk "${OID_IF_OPER}"     | tr -d ' ')
		mapfile -t _ni_speeds < <(_snmp_walk "${OID_IF_HIGHSPEED}"| tr -d ' ')
		[[ -n "${verbose}" ]] && mapfile -t _ni_aliases < <(_snmp_walk "${OID_IF_ALIAS}" | tr -d '"')
		mapfile -t _ni_in_err  < <(_snmp_walk "${OID_IF_IN_ERR}"   | tr -d ' ')
		mapfile -t _ni_out_err < <(_snmp_walk "${OID_IF_OUT_ERR}"  | tr -d ' ')
		mapfile -t _ni_in_disc < <(_snmp_walk "${OID_IF_IN_DISC}"  | tr -d ' ')
		mapfile -t _ni_out_disc< <(_snmp_walk "${OID_IF_OUT_DISC}" | tr -d ' ')
		# Traffic counters: 64-bit HC by default, 32-bit with --use-32bit-counters
		if [[ -z "${snmp_32bit_counters}" ]]; then
			mapfile -t _ni_in_bytes  < <(_snmp_walk "${OID_IF_HC_IN}"     | tr -d ' ')
			mapfile -t _ni_out_bytes < <(_snmp_walk "${OID_IF_HC_OUT}"    | tr -d ' ')
		else
			mapfile -t _ni_in_bytes  < <(_snmp_walk "${OID_IF_IN_OCTETS}" | tr -d ' ')
			mapfile -t _ni_out_bytes < <(_snmp_walk "${OID_IF_OUT_OCTETS}"| tr -d ' ')
		fi
		_ni_total=0 ; _ni_up=0 ; _ni_down=0 ; _ni_checked=0
		for (( _nii=0; _nii<${#_ni_names[@]}; _nii++ )); do
			_iname="${_ni_names[_nii]}"
			[[ -z "${_iname}" ]] && continue
			[[ -n "${_ni_bl_map[${_iname}]}" ]] && continue
			# In single-interface mode, skip everything not in --ifup
			if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
				[[ -z "${_ni_expect_up[${_iname}]}" ]] && continue
				_ni_nis_found["${_iname}"]=1
			fi
			(( _ni_total++ ))
			_iadmin="${_ni_admin[_nii]:-2}" ; _ioper="${_ni_oper[_nii]:-2}"
			_ispeed="${_ni_speeds[_nii]:-0}" ; _speed_s=""
			[[ "${_ispeed}" =~ ^[0-9]+$ && "${_ispeed}" -gt 0 ]] 2>/dev/null && _speed_s=" | ${_ispeed} Mbps"
			_alias_s=""
			if [[ -n "${verbose}" && -n "${_ni_aliases[_nii]}" && "${_ni_aliases[_nii]}" != " " ]]; then
				_alias_s=" (${_ni_aliases[_nii]})"
			fi
			if [[ "${_iadmin}" == "2" ]]; then
				[[ -n "${verbose}" ]] && fg_output+="${status_ok} - Interface ${_iname}: admin-down\n"
				continue
			fi
			(( _ni_checked++ ))
			# Traffic + error + drop perfdata per interface
			_ni_lbl="${_iname//-/_}"
			_ni_link_val=0; [[ "${_ioper}" == "1" ]] && _ni_link_val=1
			_ni_rxb="${_ni_in_bytes[_nii]:-0}"   ; [[ ! "${_ni_rxb}"   =~ ^[0-9]+$ ]] && _ni_rxb=0
			_ni_txb="${_ni_out_bytes[_nii]:-0}"  ; [[ ! "${_ni_txb}"   =~ ^[0-9]+$ ]] && _ni_txb=0
			_ni_ierr="${_ni_in_err[_nii]:-0}"    ; [[ ! "${_ni_ierr}"  =~ ^[0-9]+$ ]] && _ni_ierr=0
			_ni_oerr="${_ni_out_err[_nii]:-0}"   ; [[ ! "${_ni_oerr}"  =~ ^[0-9]+$ ]] && _ni_oerr=0
			_ni_idisc="${_ni_in_disc[_nii]:-0}"  ; [[ ! "${_ni_idisc}" =~ ^[0-9]+$ ]] && _ni_idisc=0
			_ni_odisc="${_ni_out_disc[_nii]:-0}" ; [[ ! "${_ni_odisc}" =~ ^[0-9]+$ ]] && _ni_odisc=0
			_ni_terr=$(( _ni_ierr + _ni_oerr ))
			_ni_tdisc=$(( _ni_idisc + _ni_odisc ))
			fg_perf+=" ni_${_ni_lbl}_link=${_ni_link_val}"
			fg_perf+=" ni_${_ni_lbl}_rx_bytes=${_ni_rxb} ni_${_ni_lbl}_tx_bytes=${_ni_txb}"
			fg_perf+=" ni_${_ni_lbl}_rx_errors=${_ni_ierr} ni_${_ni_lbl}_tx_errors=${_ni_oerr}"
			fg_perf+=" ni_${_ni_lbl}_rx_drops=${_ni_idisc} ni_${_ni_lbl}_tx_drops=${_ni_odisc}"
			[[ "${_ni_terr}" -gt 0 || "${warn_ni_errors}" -ge 0 ]] 2>/dev/null && \
				fg_perf+=" ni_${_ni_lbl}_errors=${_ni_terr};${warn_ni_errors};${crit_ni_errors}"
			[[ "${_ni_tdisc}" -gt 0 || "${warn_ni_drops}" -ge 0 ]] 2>/dev/null && \
				fg_perf+=" ni_${_ni_lbl}_drops=${_ni_tdisc};${warn_ni_drops};${crit_ni_drops}"
			# Error threshold alerting
			if [[ "${warn_ni_errors}" -ge 0 ]] 2>/dev/null && \
			   [[ "${crit_ni_errors}" -ge 0 ]] 2>/dev/null && \
			   (( _ni_terr >= crit_ni_errors )) 2>/dev/null; then
				fg_output+="${status_crit} - Interface ${_fwn}${_iname}: ${_ni_terr} errors (in:${_ni_ierr} out:${_ni_oerr}) (SNMP)\n"
				fg_problem_output+="${status_crit} - Interface ${_fwn}${_iname}: ${_ni_terr} errors (in:${_ni_ierr} out:${_ni_oerr}) (SNMP)\n"
			elif [[ "${warn_ni_errors}" -ge 0 ]] 2>/dev/null && \
			     (( _ni_terr >= warn_ni_errors )) 2>/dev/null; then
				fg_output+="${status_warn} - Interface ${_fwn}${_iname}: ${_ni_terr} errors (in:${_ni_ierr} out:${_ni_oerr}) (SNMP)\n"
				fg_problem_output+="${status_warn} - Interface ${_fwn}${_iname}: ${_ni_terr} errors (in:${_ni_ierr} out:${_ni_oerr}) (SNMP)\n"
			fi
			# Drop threshold alerting
			if [[ "${warn_ni_drops}" -ge 0 ]] 2>/dev/null && \
			   [[ "${crit_ni_drops}" -ge 0 ]] 2>/dev/null && \
			   (( _ni_tdisc >= crit_ni_drops )) 2>/dev/null; then
				fg_output+="${status_crit} - Interface ${_fwn}${_iname}: ${_ni_tdisc} drops (in:${_ni_idisc} out:${_ni_odisc}) (SNMP)\n"
				fg_problem_output+="${status_crit} - Interface ${_fwn}${_iname}: ${_ni_tdisc} drops (in:${_ni_idisc} out:${_ni_odisc}) (SNMP)\n"
			elif [[ "${warn_ni_drops}" -ge 0 ]] 2>/dev/null && \
			     (( _ni_tdisc >= warn_ni_drops )) 2>/dev/null; then
				fg_output+="${status_warn} - Interface ${_fwn}${_iname}: ${_ni_tdisc} drops (in:${_ni_idisc} out:${_ni_odisc}) (SNMP)\n"
				fg_problem_output+="${status_warn} - Interface ${_fwn}${_iname}: ${_ni_tdisc} drops (in:${_ni_idisc} out:${_ni_odisc}) (SNMP)\n"
			fi
			if [[ -n "${_ni_expect_up[${_iname}]}" ]]; then
				(( _ni_checked++ ))
				if [[ "${_ioper}" == "1" ]]; then
					(( _ni_up++ ))
					if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
						fg_output+="${status_ok} - Interface ${_fwn}${_iname}: up${_speed_s}\n"
					else
						[[ -n "${verbose}" ]] && fg_output+="${status_ok} - Interface ${_iname}${_alias_s}: up${_speed_s}\n"
					fi
				else
					(( _ni_down++ ))
					if [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
						fg_output+="${status_crit} - Interface ${_fwn}${_iname}: down${_speed_s}\n"
					else
						fg_output+="${status_crit} - Interface ${_fwn}${_iname}: down (expected up)${_speed_s}\n"
					fi
					fg_problem_output+="${status_crit} - Interface ${_fwn}${_iname}: down\n"
				fi
			elif [[ -n "${_ni_expect_down[${_iname}]}" ]]; then
				(( _ni_checked++ ))
				if [[ "${_ioper}" == "1" ]]; then
					(( _ni_up++ ))
					fg_output+="${status_warn} - Interface ${_iname}${_alias_s}: up (expected down)${_speed_s}\n"
					fg_problem_output+="${status_warn} - Interface ${_iname}: up but expected down\n"
				else
					(( _ni_down++ ))
					[[ -n "${verbose}" ]] && fg_output+="${status_ok} - Interface ${_iname}${_alias_s}: down (as expected)${_speed_s}\n"
				fi
			else
				if [[ "${_ioper}" == "1" ]]; then
					(( _ni_up++ ))
					[[ -n "${verbose}" ]] && fg_output+="${status_ok} - Interface ${_iname}${_alias_s}: up${_speed_s}\n"
				else
					(( _ni_down++ ))
					[[ -n "${verbose}" ]] && fg_output+="${status_warn} - Interface ${_iname}${_alias_s}: down${_speed_s}\n"
				fi
			fi
		done
		if [[ ${#_ni_names[@]} -eq 0 ]]; then
			fg_output+="${status_ok} - Interfaces${_fws}no data (check SNMP permissions)\n"
		elif [[ -n "${enable_nis}" && -z "${enable_ni}" ]]; then
			# Check for --ifup interfaces not found via SNMP
			IFS=',' read -ra _nis_req <<< "${ni_ifup}"
			for _nis_r in "${_nis_req[@]}"; do
				if [[ -z "${_ni_nis_found[${_nis_r}]}" ]]; then
					fg_output+="${status_unkn} - Interface ${_fwn}${_nis_r}: not found (SNMP)\n"
					fg_problem_output+="${status_unkn} - Interface ${_fwn}${_nis_r}: not found (SNMP)\n"
				fi
			done
		else
			if [[ -n "${ni_ifup}" || -n "${ni_ifdown}" ]]; then
				fg_output+="${status_ok} - Interfaces${_fws}${_ni_checked} checked (${_ni_up} expected-up OK) | ${_ni_total} total, ${_ni_up} up, ${_ni_down} down (SNMP)\n"
			else
				fg_output+="${status_ok} - Interfaces${_fws}${_ni_total} total, ${_ni_up} up, ${_ni_down} down (SNMP)\n"
			fi
			fg_perf+=" ni_total=${_ni_total} ni_up=${_ni_up} ni_down=${_ni_down} ni_checked=${_ni_checked}"
		fi
		unset _ni_names _ni_admin _ni_oper _ni_speeds _ni_aliases \
		      _ni_in_bytes _ni_out_bytes _ni_in_err _ni_out_err _ni_in_disc _ni_out_disc \
		      _ni_bl_map _ni_expect_up _ni_expect_down _ni_nis_found
	elif [[ -n "${_snmp_only}" ]]; then
		fg_output+="${status_ok} - Interfaces${_fws}not available (install snmpwalk for SNMP interface check)\n"
	else
		fg_output+="${status_unkn} - ${_fwh}Failed to retrieve interface status\n"
		fg_problem_output+="${status_unkn} - ${_fwh}Failed to retrieve interface status\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# IPsec VPN Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_vpn}" || -n "${enable_all}" ) && -z "${disable_vpn}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="IPsec VPN Tunnels:\n---------------------------------------\n"
	fi

	_vpn_buffer=$(cat "${_pf}/vpn.json" 2>/dev/null)

	if [[ -n "${_vpn_buffer}" && "${_vpn_buffer}" =~ '"results"' ]]; then
		_vpn_total=$(echo "${_vpn_buffer}" | "${JQ}" --unbuffered '.results | length' 2>/dev/null)

		if [[ "${_vpn_total:-0}" -eq 0 ]]; then
			fg_output+="${status_ok} - VPN${_fws}no IPsec tunnels configured\n"
		else
			declare -A _vpn_bl_map
			if [[ -n "${vpn_blacklist}" ]]; then
				IFS=',' read -ra _vpn_bl_arr <<< "${vpn_blacklist}"
				for _vpn_bl_e in "${_vpn_bl_arr[@]}"; do _vpn_bl_map["${_vpn_bl_e}"]=1; done
			fi

			declare -a _vpn_names _vpn_statuses _vpn_rgwys _vpn_in _vpn_out
			while IFS=$'\t' read -r _vn_name _vn_status _vn_rgwy _vn_in _vn_out; do
				_vpn_names+=("${_vn_name}")
				_vpn_statuses+=("${_vn_status}")
				_vpn_rgwys+=("${_vn_rgwy}")
				_vpn_in+=("${_vn_in}")
				_vpn_out+=("${_vn_out}")
			done < <(echo "${_vpn_buffer}" | "${JQ}" --unbuffered -r '
				.results[] | [
					(.name // "unknown"),
					((.proxyid // []) | if length > 0 then
						if any(.[]; .status == "up") then "up" else "down" end
					else "unknown" end),
					(.rgwy // ""),
					(.incoming_bytes // 0 | tostring),
					(.outgoing_bytes // 0 | tostring)
				] | join("\t")' 2>/dev/null)

			_vpn_up=0
			_vpn_down=0
			declare -a _vpn_dn_lines _vpn_dn_perfs

			for count in "${!_vpn_names[@]}"; do
				_vn="${_vpn_names[count]}"
				[[ -n "${_vpn_bl_map[${_vn}]}" ]] && continue

				_vpn_detail=""
				[[ -n "${_vpn_rgwys[count]}" && "${_vpn_rgwys[count]}" != "0.0.0.0" ]] && \
					_vpn_detail+=" | remote: ${_vpn_rgwys[count]}"

				_vn_in_h=$(echo "${_vpn_in[count]}" | "${AWK}" '{
					if ($1 >= 1073741824) printf "%.1f GB", $1/1073741824
					else if ($1 >= 1048576) printf "%.1f MB", $1/1048576
					else if ($1 >= 1024) printf "%.1f KB", $1/1024
					else printf "%d B", $1}')
				_vn_out_h=$(echo "${_vpn_out[count]}" | "${AWK}" '{
					if ($1 >= 1073741824) printf "%.1f GB", $1/1073741824
					else if ($1 >= 1048576) printf "%.1f MB", $1/1048576
					else if ($1 >= 1024) printf "%.1f KB", $1/1024
					else printf "%d B", $1}')
				_vpn_detail+=" | in: ${_vn_in_h} out: ${_vn_out_h}"

				if [[ "${_vpn_statuses[count]}" == "up" ]]; then
					(( _vpn_up++ ))
					[[ -n "${verbose}" ]] && \
						fg_output+="${status_ok} - VPN ${_fwn}${_vn}: UP${_vpn_detail}\n"
				else
					(( _vpn_down++ ))
					_vpn_dn_lines+=("VPN ${_fwn}${_vn}: ${_vpn_statuses[count]}${_vpn_detail}")
				fi

				fg_perf+=" vpn_${_vn}_in=${_vpn_in[count]}B vpn_${_vn}_out=${_vpn_out[count]}B"
			done

			# Determine severity based on down count vs thresholds
			_vpn_sev="${status_ok}"
			if (( crit_vpn_down >= 0 && _vpn_down >= crit_vpn_down )) 2>/dev/null && [[ "${_vpn_down}" -gt 0 ]]; then
				_vpn_sev="${status_crit}"
			elif (( warn_vpn_down >= 0 && _vpn_down >= warn_vpn_down )) 2>/dev/null && [[ "${_vpn_down}" -gt 0 ]]; then
				_vpn_sev="${status_warn}"
			fi
			for _vdn_line in "${_vpn_dn_lines[@]}"; do
				fg_output+="${_vpn_sev} - ${_vdn_line}\n"
				[[ "${_vpn_sev}" != "${status_ok}" ]] && \
					fg_problem_output+="${_vpn_sev} - ${_vdn_line%% |*}\n"
			done
			unset _vpn_dn_lines

			if [[ "${_vpn_down}" -eq 0 && -z "${verbose}" ]]; then
				fg_output+="${status_ok} - VPN${_fws}${_vpn_up}/${_vpn_total} tunnel(s) UP\n"
			fi

			fg_perf+=" vpn_total=${_vpn_total} vpn_up=${_vpn_up} vpn_down=${_vpn_down}"

			unset _vpn_names _vpn_statuses _vpn_rgwys _vpn_in _vpn_out _vpn_bl_map
		fi
	elif [[ -n "${_snmp_only}" && -n "${SNMPWALK}" ]]; then
		# SNMP VPN check - FortiGate fgVpnTunTable
		declare -A _vpn_bl_map
		[[ -n "${vpn_blacklist}" ]] && { IFS=',' read -ra _a <<< "${vpn_blacklist}"; for _e in "${_a[@]}"; do _vpn_bl_map["${_e}"]=1; done; }
		mapfile -t _vpn_names   < <(_snmp_walk "${OID_VPN_NAME}"   | tr -d ' "')
		mapfile -t _vpn_sts     < <(_snmp_walk "${OID_VPN_STATUS}" | tr -d ' ')
		mapfile -t _vpn_in_oct  < <(_snmp_walk "${OID_VPN_IN}"     | tr -d ' ')
		mapfile -t _vpn_out_oct < <(_snmp_walk "${OID_VPN_OUT}"    | tr -d ' ')
		_vpn_total=0 ; _vpn_up=0 ; _vpn_down=0
		declare -a _vpn_dn_lines
		for (( _vi=0; _vi<${#_vpn_names[@]}; _vi++ )); do
			_vname="${_vpn_names[_vi]}"
			[[ -z "${_vname}" ]] && continue
			[[ -n "${_vpn_bl_map[${_vname}]}" ]] && continue
			(( _vpn_total++ ))
			_vst="${_vpn_sts[_vi]:-1}"
			_vin="${_vpn_in_oct[_vi]:-0}" ; _vout="${_vpn_out_oct[_vi]:-0}"
			_vbytes_s=""
			if [[ -n "${verbose}" && "${_vin}" =~ ^[0-9]+$ ]]; then
				_vin_mb=$(( _vin  / 1048576 )) ; _vout_mb=$(( _vout / 1048576 ))
				_vbytes_s=" | In: ${_vin_mb} MB, Out: ${_vout_mb} MB"
			fi
			if [[ "${_vst}" == "2" ]]; then
				(( _vpn_up++ ))
				[[ -n "${verbose}" ]] && fg_output+="${status_ok} - VPN Tunnel ${_vname}: up${_vbytes_s}\n"
			else
				(( _vpn_down++ ))
				_vpn_dn_lines+=("VPN Tunnel ${_vname}: down")
			fi
		done
		# Apply threshold: determine severity of down tunnels
		_vpn_sev="${status_ok}"
		if (( crit_vpn_down >= 0 && _vpn_down >= crit_vpn_down )) 2>/dev/null && [[ "${_vpn_down}" -gt 0 ]]; then
			_vpn_sev="${status_crit}"
		elif (( warn_vpn_down >= 0 && _vpn_down >= warn_vpn_down )) 2>/dev/null && [[ "${_vpn_down}" -gt 0 ]]; then
			_vpn_sev="${status_warn}"
		fi
		for _vdn_line in "${_vpn_dn_lines[@]}"; do
			fg_output+="${_vpn_sev} - ${_vdn_line}\n"
			[[ "${_vpn_sev}" != "${status_ok}" ]] && fg_problem_output+="${_vpn_sev} - ${_vdn_line}\n"
		done
		unset _vpn_dn_lines
		if [[ ${_vpn_total} -eq 0 ]]; then
			fg_output+="${status_ok} - VPN${_fws}no tunnels found via SNMP\n"
		else
			fg_output+="${status_ok} - VPN${_fws}${_vpn_up}/${_vpn_total} tunnel(s) up (SNMP)\n"
			fg_perf+=" vpn_total=${_vpn_total} vpn_up=${_vpn_up} vpn_down=${_vpn_down}"
		fi
		unset _vpn_names _vpn_sts _vpn_in_oct _vpn_out_oct _vpn_bl_map
	else
		fg_output+="${status_ok} - VPN${_fws}no IPsec data (endpoint not available or no tunnels)\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# SSL-VPN Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ssl}" || -n "${enable_all}" ) && -z "${disable_ssl}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="SSL-VPN:\n---------------------------------------\n"
	fi

	_ssl_buffer=$(cat "${_pf}/ssl.json" 2>/dev/null)

	if [[ -n "${_ssl_buffer}" && "${_ssl_buffer}" =~ '"results"' ]]; then
		# FortiOS 7.4+: results is an array of active sessions (no .statistics wrapper)
		# Older FortiOS:  results is an object with .statistics.{users,tunnels,web_sessions}
		_ssl_users=$(echo "${_ssl_buffer}" | "${JQ}" --unbuffered -r '
			if (.results | type) == "array"
			then [.results[].user] | unique | length
			else .results.statistics.users // 0 end' 2>/dev/null)
		_ssl_tunnels=$(echo "${_ssl_buffer}" | "${JQ}" --unbuffered -r '
			if (.results | type) == "array"
			then [.results[] | select(.type == "tunnel")] | length
			else .results.statistics.tunnels // 0 end' 2>/dev/null)
		_ssl_web=$(echo "${_ssl_buffer}" | "${JQ}" --unbuffered -r '
			if (.results | type) == "array"
			then [.results[] | select(.type == "web")] | length
			else .results.statistics.web_sessions // 0 end' 2>/dev/null)
		_ssl_users="${_ssl_users:-0}" ; _ssl_tunnels="${_ssl_tunnels:-0}" ; _ssl_web="${_ssl_web:-0}"

		fg_output+="${status_ok} - SSL-VPN${_fws}${_ssl_users} user(s) | ${_ssl_tunnels} tunnel(s) | ${_ssl_web} web session(s)\n"
		fg_perf+=" sslvpn_users=${_ssl_users} sslvpn_tunnels=${_ssl_tunnels} sslvpn_web_sessions=${_ssl_web}"
	else
		fg_output+="${status_ok} - SSL-VPN${_fws}not configured or endpoint not available\n"
		fg_perf+=" sslvpn_users=0 sslvpn_tunnels=0"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# NTP Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ntp}" || -n "${enable_all}" ) && -z "${disable_ntp}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="NTP:\n---------------------------------------\n"
	fi

	_ntp_buf=$(cat "${_pf}/ntp_status.json" 2>/dev/null)

	if [[ -n "${_ntp_buf}" && "${_ntp_buf}" =~ '"results"' ]]; then
		_ntp_total=0 ; _ntp_reachable=0 ; _ntp_unreachable=0 ; _ntp_max_offset_ms=0 ; _ntp_best_server=""
		while IFS=$'\t' read -r _ns _nr _noff _nstrat; do
			(( _ntp_total++ ))
			if [[ "${_nr}" == "true" ]]; then
				(( _ntp_reachable++ ))
				_noff_ms=$(echo "${_noff}" | "${AWK}" '{printf "%d", $1*1000}')
				[[ "${_noff_ms}" -lt 0 ]] 2>/dev/null && _noff_ms=$(( -_noff_ms ))
				if [[ -z "${_ntp_best_server}" || "${_noff_ms}" -lt "${_ntp_max_offset_ms}" ]]; then
					_ntp_best_server="${_ns}" ; _ntp_best_offset_ms="${_noff_ms}" ; _ntp_best_strat="${_nstrat}"
				fi
				[[ "${_noff_ms}" -gt "${_ntp_max_offset_ms}" ]] && _ntp_max_offset_ms="${_noff_ms}"
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - NTP ${_fwn}${_ns}: reachable | stratum: ${_nstrat} | offset: ${_noff_ms}ms\n"
			else
				(( _ntp_unreachable++ ))
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_crit} - NTP ${_fwn}${_ns}: unreachable\n"
				fg_problem_output+="${status_crit} - NTP ${_fwn}${_ns}: unreachable\n"
			fi
		done < <(echo "${_ntp_buf}" | "${JQ}" --unbuffered -r \
			'.results[] | [(.server // .ip), (.reachable | tostring), ((.offset // 0) | tostring), ((.stratum // 0) | tostring)] | join("\t")' 2>/dev/null)

		# Determine summary severity: unreachable peers -> CRIT, then offset thresholds
		if [[ "${_ntp_total}" -eq 0 || "${_ntp_reachable}" -eq 0 ]]; then
			fg_output+="${status_crit} - NTP${_fws}no NTP servers reachable (${_ntp_total} configured)\n"
			fg_problem_output+="${status_crit} - NTP${_fws}no NTP servers reachable\n"
		else
			_ntp_sum_sev="${status_ok}"
			[[ "${_ntp_unreachable}" -gt 0 ]] && _ntp_sum_sev="${status_crit}"
			if (( _ntp_max_offset_ms >= crit_ntp_offset )) 2>/dev/null; then
				_ntp_sum_sev="${status_crit}"
				fg_problem_output+="${status_crit} - NTP${_fws}max offset ${_ntp_max_offset_ms}ms (crit: ${crit_ntp_offset}ms)\n"
			elif (( _ntp_max_offset_ms >= warn_ntp_offset )) 2>/dev/null; then
				[[ "${_ntp_sum_sev}" != "${status_crit}" ]] && _ntp_sum_sev="${status_warn}"
				fg_problem_output+="${status_warn} - NTP${_fws}max offset ${_ntp_max_offset_ms}ms (warn: ${warn_ntp_offset}ms)\n"
			fi
			fg_output+="${_ntp_sum_sev} - NTP${_fws}${_ntp_reachable}/${_ntp_total} reachable"
			[[ "${_ntp_unreachable}" -gt 0 ]] && fg_output+=", ${_ntp_unreachable} UNREACHABLE"
			fg_output+=" | offset: ${_ntp_max_offset_ms}ms (warn: ${warn_ntp_offset}ms, crit: ${crit_ntp_offset}ms)"
			[[ -n "${_ntp_best_server}" ]] && fg_output+=" | best: ${_ntp_best_server} (stratum ${_ntp_best_strat:-?}, ${_ntp_best_offset_ms:-?}ms)"
			fg_output+="\n"
		fi
		fg_perf+=" ntp_reachable=${_ntp_reachable} ntp_unreachable=${_ntp_unreachable} ntp_total=${_ntp_total} ntp_max_offset_ms=${_ntp_max_offset_ms};${warn_ntp_offset};${crit_ntp_offset}"
	else
		fg_output+="${status_ok} - NTP${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# SD-WAN Health Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sdwan}" || -n "${enable_all}" ) && -z "${disable_sdwan}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="SD-WAN:\n---------------------------------------\n"
	fi

	_sdwan_buf=$(cat "${_pf}/sdwan_hc.json"     2>/dev/null)
	_sdwan_cfg=$(cat "${_pf}/sdwan_config.json" 2>/dev/null)

	# Auto-detect: if root vdom shows SD-WAN disabled and no --sdwan-vdom was given,
	# scan non-root vdoms for the one that has SD-WAN enabled
	if [[ -z "${sdwan_vdom}" ]]; then
		_sdwan_probes_pre=$(echo "${_sdwan_buf}" | "${JQ}" --unbuffered -r '.results | length' 2>/dev/null)
		_sdwan_status_pre=$(echo "${_sdwan_cfg}" | "${JQ}" --unbuffered -r '.results.status // "unknown"' 2>/dev/null)
		if [[ ("${_sdwan_probes_pre}" == "0" || ! "${_sdwan_probes_pre}" =~ ^[0-9]+$) && "${_sdwan_status_pre}" == "disable" ]]; then
			while IFS= read -r _vd_name; do
				[[ -z "${_vd_name}" || "${_vd_name}" == "root" ]] && continue
				_vd_sdwan_cfg=$(fg_api_get "${FG_API}/cmdb/system/sdwan?vdom=${_vd_name}" 2>/dev/null)
				if [[ "$(echo "${_vd_sdwan_cfg}" | "${JQ}" --unbuffered -r '.results.status // "disable"' 2>/dev/null)" == "enable" ]]; then
					_sdwan_buf=$(fg_api_get "${FG_API}/monitor/virtual-wan/health-check?scope=vdom&vdom=${_vd_name}" 2>/dev/null)
					_sdwan_cfg="${_vd_sdwan_cfg}"
					sdwan_vdom="${_vd_name}"
					break
				fi
			done < <("${JQ}" --unbuffered -r '.results[].name // empty' "${_pf}/vdom_list.json" 2>/dev/null)
		fi
	fi

	if [[ -n "${_sdwan_buf}" && "${_sdwan_buf}" =~ '"results"' ]]; then
		_sdwan_probes=$(echo "${_sdwan_buf}" | "${JQ}" --unbuffered -r '.results | length' 2>/dev/null)
		if [[ "${_sdwan_probes}" -eq 0 ]] 2>/dev/null; then
			_sdwan_cmdb_status=$(echo "${_sdwan_cfg}" | "${JQ}" --unbuffered -r '.results.status // "unknown"' 2>/dev/null)
			if [[ "${_sdwan_cmdb_status}" == "disable" ]]; then
				fg_output+="${status_ok} - SD-WAN${_fws}disabled\n"
			else
				fg_output+="${status_ok} - SD-WAN${_fws}enabled, no health-check probes configured\n"
			fi
		else
			_sdwan_dead=0 ; _sdwan_alive=0 ; _sdwan_total=0
			while IFS=$'\t' read -r _sw_probe _sw_iface _sw_status _sw_lat _sw_loss _sw_jitter; do
				(( _sdwan_total++ ))
				_sw_lat_ms=$(echo "${_sw_lat}" | "${AWK}" '{printf "%d", $1}')
				_sw_loss_pct=$(echo "${_sw_loss}" | "${AWK}" '{printf "%d", $1}')
				if [[ "${_sw_status}" == "alive" || "${_sw_status}" == "up" ]]; then
					(( _sdwan_alive++ ))
					_sw_state="${status_ok}"
					if (( _sw_loss_pct >= crit_sdwan_loss )) 2>/dev/null; then
						_sw_state="${status_crit}"
						fg_problem_output+="${status_crit} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: loss ${_sw_loss_pct}% >= ${crit_sdwan_loss}%\n"
					elif (( _sw_loss_pct >= warn_sdwan_loss )) 2>/dev/null; then
						_sw_state="${status_warn}"
						fg_problem_output+="${status_warn} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: loss ${_sw_loss_pct}% >= ${warn_sdwan_loss}%\n"
					elif (( crit_sdwan_latency >= 0 && _sw_lat_ms >= crit_sdwan_latency )) 2>/dev/null; then
						_sw_state="${status_crit}"
						fg_problem_output+="${status_crit} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: latency ${_sw_lat_ms}ms >= ${crit_sdwan_latency}ms\n"
					elif (( warn_sdwan_latency >= 0 && _sw_lat_ms >= warn_sdwan_latency )) 2>/dev/null; then
						_sw_state="${status_warn}"
						fg_problem_output+="${status_warn} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: latency ${_sw_lat_ms}ms >= ${warn_sdwan_latency}ms\n"
					fi
					[[ -n "${verbose}" ]] && \
						fg_output+="${_sw_state} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: ${_sw_status} | latency: ${_sw_lat_ms}ms | loss: ${_sw_loss_pct}%\n"
				else
					(( _sdwan_dead++ ))
					fg_output+="${status_crit} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: ${_sw_status}\n"
					fg_problem_output+="${status_crit} - SD-WAN ${_fwn}${_sw_probe}/${_sw_iface}: dead\n"
				fi
				_sw_lbl="${_sw_probe//[^a-zA-Z0-9_]/_}_${_sw_iface//[^a-zA-Z0-9_]/_}"
				fg_perf+=" sdwan_${_sw_lbl}_latency=${_sw_lat_ms};${warn_sdwan_latency};${crit_sdwan_latency} sdwan_${_sw_lbl}_loss=${_sw_loss_pct};${warn_sdwan_loss};${crit_sdwan_loss}"
			done < <(echo "${_sdwan_buf}" | "${JQ}" --unbuffered -r '
				.results | to_entries[] | .key as $probe | .value |
				if has("members") then
					.members[] |
					[$probe, .interface, (.status // "unknown"),
					 ((.latency // 0) | tostring), ((.packet_loss // 0) | tostring),
					 ((.jitter // 0) | tostring)]
				else
					to_entries[] |
					[$probe, .key, (.value.status // "unknown"),
					 ((.value.latency // 0) | tostring), ((.value.packet_loss // 0) | tostring),
					 ((.value.jitter // 0) | tostring)]
				end | join("\t")' 2>/dev/null)

			if [[ "${_sdwan_dead}" -eq 0 ]]; then
				fg_output+="${status_ok} - SD-WAN${_fws}${_sdwan_alive}/${_sdwan_total} members alive\n"
			fi
			fg_perf+=" sdwan_alive=${_sdwan_alive} sdwan_dead=${_sdwan_dead} sdwan_total=${_sdwan_total}"
		fi
	else
		fg_output+="${status_ok} - SD-WAN${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# FortiAP Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ap}" || -n "${enable_all}" ) && -z "${disable_ap}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="FortiAP:\n---------------------------------------\n"
	fi

	_ap_buf=$(cat "${_pf}/managed_ap.json" 2>/dev/null)

	if [[ -n "${_ap_buf}" && "${_ap_buf}" =~ '"results"' ]]; then
		_ap_total=0 ; _ap_up=0 ; _ap_down=0 ; _ap_clients_total=0
		declare -a _ap_dn_lines

		# Pass 1: per-AP summary
		while IFS=$'\t' read -r _ap_name _ap_serial _ap_status _ap_clients _ap_fw \
		                         _ap_mesh _ap_temp _ap_failure _ap_join; do
			(( _ap_total++ ))
			_ap_lbl="${_ap_name//[^a-zA-Z0-9]/_}"
			[[ "${_ap_clients}" =~ ^[0-9]+$ ]] && (( _ap_clients_total += _ap_clients ))
			if [[ "${_ap_status}" == "connected" ]]; then
				(( _ap_up++ ))
				if [[ -n "${verbose}" ]]; then
					_ap_extra=""
					[[ "${_ap_mesh}" =~ ^[0-9]+$ && "${_ap_mesh}" -gt 0 ]] && _ap_extra+=" | mesh-hop: ${_ap_mesh}"
					[[ -n "${_ap_temp}" && "${_ap_temp}" =~ ^[0-9]+$ ]]    && _ap_extra+=" | temp: ${_ap_temp}°C"
					[[ -n "${_ap_failure}" && "${_ap_failure}" != "N/A" ]] && _ap_extra+=" | last-fail: ${_ap_failure}"
					fg_output+="${status_ok} - AP ${_fwn}${_ap_name}: connected | ${_ap_serial} | fw: ${_ap_fw} | clients: ${_ap_clients}${_ap_extra}\n"
				fi
				[[ "${_ap_clients}" =~ ^[0-9]+$ ]] && fg_perf+=" ap_${_ap_lbl}_clients=${_ap_clients}"
			else
				(( _ap_down++ ))
				_ap_dn_lines+=("AP ${_fwn}${_ap_name} (${_ap_serial}): ${_ap_status}")
			fi
		done < <(echo "${_ap_buf}" | "${JQ}" --unbuffered -r '.results[] |
			[(.name // .wtp_id), (.serial // "unknown"), (.status // "unknown"),
			 ((.clients // 0) | tostring), (.os_version // ""),
			 ((.mesh_hop_count // 0) | tostring),
			 (((.sensors_temperatures // [])[0] // "") | tostring),
			 (.last_failure // "N/A"), (.join_time // "")] | join("\t")' 2>/dev/null)

		# Pass 2: per-radio detail (verbose output + perfdata)
		while IFS=$'\t' read -r _rap_name _r_id _r_type _r_clients _r_chan _r_txpwr \
		                         _r_util _r_bw_rx _r_bw_tx _r_bytes_rx _r_bytes_tx \
		                         _r_retries _r_noise; do
			_rap_lbl="${_rap_name//[^a-zA-Z0-9]/_}"
			_r_lbl="${_rap_lbl}_radio${_r_id}"
			_r_type_s="${_r_type#802.11}"
			if [[ -n "${verbose}" ]]; then
				_r_bw_rx_kbs=$(( _r_bw_rx / 1024 ))
				_r_bw_tx_kbs=$(( _r_bw_tx / 1024 ))
				fg_output+="${status_ok} - AP ${_fwn}${_rap_name} radio${_r_id} (${_r_type_s}):"
				fg_output+=" ch${_r_chan} | txpwr: ${_r_txpwr}dBm | clients: ${_r_clients}"
				fg_output+=" | util: ${_r_util}% | retries: ${_r_retries}%"
				fg_output+=" | bw: ${_r_bw_rx_kbs}/${_r_bw_tx_kbs} KB/s | noise: ${_r_noise}dBm\n"
			fi
			[[ "${_r_clients}"  =~ ^[0-9]+$ ]] && fg_perf+=" ap_${_r_lbl}_clients=${_r_clients}"
			[[ "${_r_util}"     =~ ^[0-9]+$ ]] && fg_perf+=" ap_${_r_lbl}_chan_util=${_r_util}"
			[[ "${_r_retries}"  =~ ^[0-9]+$ ]] && fg_perf+=" ap_${_r_lbl}_retries=${_r_retries}"
			[[ "${_r_bytes_rx}" =~ ^[0-9]+$ ]] && fg_perf+=" ap_${_r_lbl}_bytes_rx=${_r_bytes_rx}c"
			[[ "${_r_bytes_tx}" =~ ^[0-9]+$ ]] && fg_perf+=" ap_${_r_lbl}_bytes_tx=${_r_bytes_tx}c"
		done < <(echo "${_ap_buf}" | "${JQ}" --unbuffered -r '.results[] | . as $ap |
			.radio[]? |
			select(.radio_type != null and .radio_type != "unknown" and .radio_id != null) |
			[($ap.name // $ap.wtp_id), (.radio_id | tostring), (.radio_type // "unknown"),
			 ((.client_count // 0) | tostring), ((.oper_chan // 0) | tostring),
			 ((.oper_txpower // 0) | tostring), ((.channel_utilization_percent // 0) | tostring),
			 ((.bandwidth_rx // 0) | tostring), ((.bandwidth_tx // 0) | tostring),
			 ((.bytes_rx // 0) | tostring), ((.bytes_tx // 0) | tostring),
			 ((.tx_retries_percent // 0) | tostring), ((.noise_floor // 0) | tostring)] | join("\t")' 2>/dev/null)

		# Down AP severity
		_ap_sev="${status_ok}"
		if (( crit_ap_down >= 0 && _ap_down >= crit_ap_down )) 2>/dev/null && [[ "${_ap_down}" -gt 0 ]]; then
			_ap_sev="${status_crit}"
		elif (( warn_ap_down >= 0 && _ap_down >= warn_ap_down )) 2>/dev/null && [[ "${_ap_down}" -gt 0 ]]; then
			_ap_sev="${status_warn}"
		fi
		for _ap_line in "${_ap_dn_lines[@]}"; do
			fg_output+="${_ap_sev} - ${_ap_line}\n"
			[[ "${_ap_sev}" != "${status_ok}" ]] && fg_problem_output+="${_ap_sev} - ${_ap_line}\n"
		done
		unset _ap_dn_lines

		# Total client count threshold
		_ap_cl_sev="${status_ok}"
		if (( crit_ap_clients >= 0 && _ap_clients_total >= crit_ap_clients )) 2>/dev/null; then
			_ap_cl_sev="${status_crit}"
			fg_problem_output+="${status_crit} - FortiAP${_fws}${_ap_clients_total} total clients (crit: ${crit_ap_clients})\n"
		elif (( warn_ap_clients >= 0 && _ap_clients_total >= warn_ap_clients )) 2>/dev/null; then
			_ap_cl_sev="${status_warn}"
			fg_problem_output+="${status_warn} - FortiAP${_fws}${_ap_clients_total} total clients (warn: ${warn_ap_clients})\n"
		fi

		if [[ "${_ap_total}" -eq 0 ]]; then
			fg_output+="${status_ok} - FortiAP${_fws}no managed APs\n"
		else
			fg_output+="${_ap_cl_sev} - FortiAP${_fws}${_ap_up}/${_ap_total} AP(s) connected | clients: ${_ap_clients_total}\n"
			fg_perf+=" ap_total=${_ap_total} ap_up=${_ap_up} ap_down=${_ap_down}"
			fg_perf+=" ap_clients_total=${_ap_clients_total};${warn_ap_clients};${crit_ap_clients}"
		fi
	else
		fg_output+="${status_ok} - FortiAP${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# FortiSwitch Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sw}" || -n "${enable_all}" ) && -z "${disable_sw}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="FortiSwitch:\n---------------------------------------\n"
	fi

	_sw_buf=$(cat "${_pf}/managed_sw.json" 2>/dev/null)

	if [[ -n "${_sw_buf}" && "${_sw_buf}" =~ '"results"' ]]; then
		_sw_total=0 ; _sw_up=0 ; _sw_down=0
		declare -a _sw_dn_lines
		while IFS=$'\t' read -r _sw_name _sw_serial _sw_status _sw_fw; do
			(( _sw_total++ ))
			if [[ "${_sw_status}" == "connected" || "${_sw_status}" == "authorized" ]]; then
				(( _sw_up++ ))
				if [[ -n "${verbose}" ]]; then
					_sw_fw_s="" ; [[ -n "${_sw_fw}" && "${_sw_fw}" != "null" && "${_sw_fw}" != "" ]] && _sw_fw_s=" | fw: ${_sw_fw}"
					fg_output+="${status_ok} - Switch ${_fwn}${_sw_name}: ${_sw_status}${_sw_fw_s}\n"
				fi
			else
				(( _sw_down++ ))
				_sw_dn_lines+=("Switch ${_fwn}${_sw_name} (${_sw_serial}): ${_sw_status}")
			fi
		done < <(echo "${_sw_buf}" | "${JQ}" --unbuffered -r \
			'.results[] | [(.name // .switch_id), (.serial // "unknown"), (.status // "unknown"),
			 (.os_version // .firmware_version // .version // "")] | join("\t")' 2>/dev/null)

		_sw_sev="${status_ok}"
		if (( crit_sw_down >= 0 && _sw_down >= crit_sw_down )) 2>/dev/null && [[ "${_sw_down}" -gt 0 ]]; then
			_sw_sev="${status_crit}"
		elif (( warn_sw_down >= 0 && _sw_down >= warn_sw_down )) 2>/dev/null && [[ "${_sw_down}" -gt 0 ]]; then
			_sw_sev="${status_warn}"
		fi
		for _sw_line in "${_sw_dn_lines[@]}"; do
			fg_output+="${_sw_sev} - ${_sw_line}\n"
			[[ "${_sw_sev}" != "${status_ok}" ]] && fg_problem_output+="${_sw_sev} - ${_sw_line}\n"
		done
		unset _sw_dn_lines

		if [[ "${_sw_total}" -eq 0 ]]; then
			fg_output+="${status_ok} - FortiSwitch${_fws}no managed switches\n"
		else
			fg_output+="${status_ok} - FortiSwitch${_fws}${_sw_up}/${_sw_total} switch(es) connected\n"
			fg_perf+=" sw_total=${_sw_total} sw_up=${_sw_up} sw_down=${_sw_down}"
		fi
	elif [[ -n "${_sw_buf}" ]]; then
		fg_output+="${status_ok} - FortiSwitch${_fws}no managed switches\n"
	else
		fg_output+="${status_ok} - FortiSwitch${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# FortiExtender Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_fex}" || -n "${enable_all}" ) && -z "${disable_fex}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="FortiExtender:\n---------------------------------------\n"
	fi

	_fex_buf=$(cat "${_pf}/fex.json" 2>/dev/null)

	if [[ -n "${_fex_buf}" && "${_fex_buf}" =~ '"results"' ]]; then
		_fex_total=0 ; _fex_up=0 ; _fex_down=0
		declare -a _fex_dn_lines
		while IFS=$'\t' read -r _fex_name _fex_serial _fex_status; do
			(( _fex_total++ ))
			if [[ "${_fex_status}" == "connected" || "${_fex_status}" == "authorized" ]]; then
				(( _fex_up++ ))
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - FEX ${_fwn}${_fex_name}: ${_fex_status}\n"
			else
				(( _fex_down++ ))
				_fex_dn_lines+=("FEX ${_fwn}${_fex_name} (${_fex_serial}): ${_fex_status}")
			fi
		done < <(echo "${_fex_buf}" | "${JQ}" --unbuffered -r \
			'.results[] | [(.name // .id), (.serial // "unknown"), (.status // "unknown")] | join("\t")' 2>/dev/null)

		_fex_sev="${status_ok}"
		if [[ "${_fex_down}" -gt 0 ]]; then
			_fex_sev="${status_crit}"
		fi
		for _fex_line in "${_fex_dn_lines[@]}"; do
			fg_output+="${_fex_sev} - ${_fex_line}\n"
			fg_problem_output+="${_fex_sev} - ${_fex_line}\n"
		done
		unset _fex_dn_lines

		if [[ "${_fex_total}" -eq 0 ]]; then
			fg_output+="${status_ok} - FortiExtender${_fws}no managed extenders\n"
		else
			fg_output+="${status_ok} - FortiExtender${_fws}${_fex_up}/${_fex_total} extender(s) connected\n"
			fg_perf+=" fex_total=${_fex_total} fex_up=${_fex_up} fex_down=${_fex_down}"
		fi
	elif [[ -n "${_fex_buf}" ]]; then
		fg_output+="${status_ok} - FortiExtender${_fws}no managed extenders\n"
	else
		fg_output+="${status_ok} - FortiExtender${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# DHCP Server Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_dhcp}" || -n "${enable_all}" ) && -z "${disable_dhcp}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="DHCP:\n---------------------------------------\n"
	fi

	_dhcp_cmdb_buf=$(cat "${_pf}/dhcp_config.json"  2>/dev/null)
	_dhcp_leases_buf=$(cat "${_pf}/dhcp_leases.json" 2>/dev/null)

	if [[ -n "${_dhcp_cmdb_buf}" && "${_dhcp_cmdb_buf}" =~ '"results"' ]]; then
		# Build exclusion map from --exclude-dhcp
		declare -A _dhcp_excl_map
		if [[ -n "${dhcp_exclude}" ]]; then
			IFS=',' read -ra _dhcp_excl_arr <<< "${dhcp_exclude}"
			for _de in "${_dhcp_excl_arr[@]}"; do
				_de="${_de// /}"  # trim spaces
				[[ -n "${_de}" ]] && _dhcp_excl_map["${_de}"]=1
			done
		fi

		# Build lease count map: server_id -> count
		declare -A _dhcp_lmap
		while IFS=$'\t' read -r _dl_id _dl_cnt; do
			_dhcp_lmap["${_dl_id}"]="${_dl_cnt}"
		done < <(echo "${_dhcp_leases_buf}" | "${JQ}" --unbuffered -r '
			.results // [] | group_by(.server_mkey) | .[] |
			[(.[0].server_mkey | tostring), (length | tostring)] | join("\t")' 2>/dev/null)

		_dhcp_servers=0 ; _dhcp_total_leases=0 ; _dhcp_total_pool=0
		_dhcp_warn_count=0 ; _dhcp_crit_count=0
		declare -a _dhcp_prob_lines

		# Parse threshold mode: trailing % → percentage; plain number → free leases remaining
		_dhcp_warn_pct="" ; _dhcp_warn_abs=""
		_dhcp_crit_pct="" ; _dhcp_crit_abs=""
		if [[ "${warn_dhcp_usage}" == *% ]]; then
			_dhcp_warn_pct="${warn_dhcp_usage%\%}"
		else
			_dhcp_warn_abs="${warn_dhcp_usage}"
		fi
		if [[ "${crit_dhcp_usage}" == *% ]]; then
			_dhcp_crit_pct="${crit_dhcp_usage%\%}"
		else
			_dhcp_crit_abs="${crit_dhcp_usage}"
		fi
		# Display string for thresholds
		_dhcp_thr_warn="${warn_dhcp_usage}"; _dhcp_thr_crit="${crit_dhcp_usage}"
		[[ -n "${_dhcp_warn_abs}" ]] && _dhcp_thr_warn="${_dhcp_warn_abs} free"
		[[ -n "${_dhcp_crit_abs}" ]] && _dhcp_thr_crit="${_dhcp_crit_abs} free"

		while IFS=$'\t' read -r _sid _siface _sresv _sranges; do
			[[ -n "${_dhcp_excl_map[${_siface}]}" ]] && continue
			(( _dhcp_servers++ ))
			_sif_lbl="${_siface//[^a-zA-Z0-9]/_}"

			# Compute pool size via IP arithmetic on each range
			_pool_size=0
			IFS=';' read -ra _rng_list <<< "${_sranges}"
			for _rng in "${_rng_list[@]}"; do
				IFS=',' read -r _rstart _rend <<< "${_rng}"
				[[ -z "${_rstart}" || -z "${_rend}" ]] && continue
				IFS='.' read -ra _sa <<< "${_rstart}"
				IFS='.' read -ra _ea <<< "${_rend}"
				_si=$(( (_sa[0]<<24)+(_sa[1]<<16)+(_sa[2]<<8)+_sa[3] ))
				_ei=$(( (_ea[0]<<24)+(_ea[1]<<16)+(_ea[2]<<8)+_ea[3] ))
				(( _pool_size += _ei - _si + 1 ))
			done

			_leases="${_dhcp_lmap[${_sid}]:-0}"
			(( _dhcp_total_leases += _leases ))
			(( _dhcp_total_pool   += _pool_size ))

			_usage_pct=0
			[[ "${_pool_size}" -gt 0 ]] && _usage_pct=$(( _leases * 100 / _pool_size ))
			_free=$(( _pool_size - _leases ))

			_dhcp_state="${status_ok}"
			if { [[ -n "${_dhcp_crit_pct}" && "${_usage_pct}" -ge "${_dhcp_crit_pct}" ]] || \
			     [[ -n "${_dhcp_crit_abs}" && "${_free}"      -lt "${_dhcp_crit_abs}" ]]; }; then
				_dhcp_state="${status_crit}" ; (( _dhcp_crit_count++ ))
				_dhcp_prob_lines+=("${status_crit} - DHCP ${_fwn}${_siface}: ${_leases}/${_pool_size} leases (${_usage_pct}%, ${_free} free) (crit: ${_dhcp_thr_crit})")
			elif { [[ -n "${_dhcp_warn_pct}" && "${_usage_pct}" -ge "${_dhcp_warn_pct}" ]] || \
			       [[ -n "${_dhcp_warn_abs}" && "${_free}"      -lt "${_dhcp_warn_abs}" ]]; }; then
				_dhcp_state="${status_warn}" ; (( _dhcp_warn_count++ ))
				_dhcp_prob_lines+=("${status_warn} - DHCP ${_fwn}${_siface}: ${_leases}/${_pool_size} leases (${_usage_pct}%, ${_free} free) (warn: ${_dhcp_thr_warn})")
			fi

			if [[ -n "${verbose}" ]]; then
				_resv_s=""
				[[ "${_sresv}" =~ ^[0-9]+$ && "${_sresv}" -gt 0 ]] && _resv_s=" | reservations: ${_sresv}"
				_free_s=""; [[ -n "${_dhcp_warn_abs}" || -n "${_dhcp_crit_abs}" ]] && _free_s=", ${_free} free"
				fg_output+="${_dhcp_state} - DHCP ${_fwn}${_siface}: ${_leases}/${_pool_size} leases (${_usage_pct}%${_free_s}) (warn: ${_dhcp_thr_warn}, crit: ${_dhcp_thr_crit})${_resv_s}\n"
			fi

			fg_perf+=" dhcp_${_sif_lbl}_pool=${_pool_size}"
			if [[ -n "${_dhcp_warn_abs}" || -n "${_dhcp_crit_abs}" ]]; then
				# Absolute mode: thresholds apply to free count (inverted range: warn when free < N)
				fg_perf+=" dhcp_${_sif_lbl}_free=${_free};${_dhcp_warn_abs:-}:;${_dhcp_crit_abs:-}:;0;${_pool_size}"
				fg_perf+=" dhcp_${_sif_lbl}_leases=${_leases}"
				fg_perf+=" dhcp_${_sif_lbl}_pct=${_usage_pct}%"
			else
				fg_perf+=" dhcp_${_sif_lbl}_leases=${_leases}"
				fg_perf+=" dhcp_${_sif_lbl}_pct=${_usage_pct}%;${_dhcp_warn_pct:-};${_dhcp_crit_pct:-};0;100"
			fi
			[[ "${_sresv}" =~ ^[0-9]+$ && "${_sresv}" -gt 0 ]] && \
				fg_perf+=" dhcp_${_sif_lbl}_reservations=${_sresv}"

		done < <(echo "${_dhcp_cmdb_buf}" | "${JQ}" --unbuffered -r '
			.results[] | select(.status == "enable") |
			[(.id | tostring), .interface,
			 ((.["reserved-address"] // []) | length | tostring),
			 (.["ip-range"] // [] |
			  map([.["start-ip"], .["end-ip"]] | join(",")) | join(";"))
			] | join("\t")' 2>/dev/null)

		for _dp_line in "${_dhcp_prob_lines[@]}"; do
			fg_output+="${_dp_line}\n"
			fg_problem_output+="${_dp_line}\n"
		done
		unset _dhcp_prob_lines _dhcp_lmap _dhcp_excl_map

		_dhcp_sum_sev="${status_ok}"
		[[ "${_dhcp_warn_count}" -gt 0 ]] && _dhcp_sum_sev="${status_warn}"
		[[ "${_dhcp_crit_count}" -gt 0 ]] && _dhcp_sum_sev="${status_crit}"
		fg_output+="${_dhcp_sum_sev} - DHCP${_fws}${_dhcp_servers} pools | ${_dhcp_total_leases}/${_dhcp_total_pool} total leases\n"
		fg_perf+=" dhcp_total_leases=${_dhcp_total_leases} dhcp_total_pool=${_dhcp_total_pool}"
	else
		fg_output+="${status_ok} - DHCP${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# IPAM Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ipam}" || -n "${enable_all}" ) && -z "${disable_ipam}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="IPAM:\n---------------------------------------\n"
	fi

	_ipam_status_buf=$(cat "${_pf}/ipam_status.json" 2>/dev/null)
	_ipam_config_buf=$(cat "${_pf}/ipam_config.json" 2>/dev/null)

	if [[ -n "${_ipam_status_buf}" && "${_ipam_status_buf}" =~ '"status"' ]]; then
		_ipam_enabled=$(echo "${_ipam_status_buf}" | "${JQ}" --unbuffered -r '.results.status // "disabled"' 2>/dev/null)
		_ipam_type=$(echo "${_ipam_status_buf}"    | "${JQ}" --unbuffered -r '.results.server_type // ""'   2>/dev/null)
		_ipam_avail=$(echo "${_ipam_status_buf}"   | "${JQ}" --unbuffered -r '.results.available_subnet_size // 0' 2>/dev/null)
		_ipam_alloc=$(echo "${_ipam_status_buf}"   | "${JQ}" --unbuffered -r '.results.allocated_subnet_size // 0' 2>/dev/null)

		_ipam_pools=0 ; _ipam_rules=0
		declare -a _ipam_pool_subnets
		if [[ -n "${_ipam_config_buf}" && "${_ipam_config_buf}" =~ '"results"' ]]; then
			_ipam_pools=$(echo "${_ipam_config_buf}" | "${JQ}" --unbuffered -r '(.results.pools // []) | length' 2>/dev/null)
			_ipam_rules=$(echo "${_ipam_config_buf}" | "${JQ}" --unbuffered -r '(.results.rules // []) | length' 2>/dev/null)
			while IFS= read -r _ps; do
				[[ -n "${_ps}" ]] && _ipam_pool_subnets+=("${_ps}")
			done < <(echo "${_ipam_config_buf}" | "${JQ}" --unbuffered -r '(.results.pools // [])[] | .subnet // empty' 2>/dev/null)
		fi

		# Compute total and usage %
		_ipam_total=0 ; _ipam_usage_pct=0
		if [[ "${_ipam_alloc}" =~ ^[0-9]+$ && "${_ipam_avail}" =~ ^[0-9]+$ ]]; then
			_ipam_total=$(( _ipam_alloc + _ipam_avail ))
			[[ "${_ipam_total}" -gt 0 ]] && _ipam_usage_pct=$(( _ipam_alloc * 100 / _ipam_total ))
		fi

		if [[ "${_ipam_enabled}" == "enabled" || "${_ipam_enabled}" == "enable" ]]; then
			_ipam_state="${status_ok}"
			_ipam_detail=""
			[[ -n "${_ipam_type}" ]] && _ipam_detail+=" | type: ${_ipam_type}"
			[[ "${_ipam_pools}" =~ ^[0-9]+$ && "${_ipam_pools}" -gt 0 ]] && _ipam_detail+=" | pools: ${_ipam_pools}"
			[[ "${_ipam_rules}" =~ ^[0-9]+$ && "${_ipam_rules}" -gt 0 ]] && _ipam_detail+=" | rules: ${_ipam_rules}"
			if [[ "${_ipam_total}" -gt 0 ]]; then
				_ipam_detail+=" | allocated: ${_ipam_alloc}/${_ipam_total} (${_ipam_usage_pct}%) | available: ${_ipam_avail}"
				if (( _ipam_usage_pct >= crit_ipam_usage )) 2>/dev/null; then
					_ipam_state="${status_crit}"
					fg_problem_output+="${status_crit} - IPAM${_fws}usage ${_ipam_usage_pct}% CRITICAL (threshold: ${crit_ipam_usage}%)${_ipam_detail}\n"
				elif (( _ipam_usage_pct >= warn_ipam_usage )) 2>/dev/null; then
					_ipam_state="${status_warn}"
					fg_problem_output+="${status_warn} - IPAM${_fws}usage ${_ipam_usage_pct}% WARNING (threshold: ${warn_ipam_usage}%)${_ipam_detail}\n"
				fi
			elif [[ "${_ipam_avail}" =~ ^[0-9]+$ ]]; then
				_ipam_detail+=" | available subnets: ${_ipam_avail}"
			fi
			fg_output+="${_ipam_state} - IPAM${_fws}enabled${_ipam_detail}\n"
			if [[ -n "${verbose}" && "${#_ipam_pool_subnets[@]}" -gt 0 ]]; then
				for _ps in "${_ipam_pool_subnets[@]}"; do
					fg_output+="${_ipam_state} - IPAM${_fws}pool ${_ps}\n"
				done
			fi
			[[ "${_ipam_pools}"     =~ ^[0-9]+$ ]] && fg_perf+=" ipam_pools=${_ipam_pools}"
			[[ "${_ipam_alloc}"     =~ ^[0-9]+$ ]] && fg_perf+=" ipam_allocated_subnets=${_ipam_alloc}"
			[[ "${_ipam_avail}"     =~ ^[0-9]+$ ]] && fg_perf+=" ipam_available_subnets=${_ipam_avail}"
			[[ "${_ipam_total}"     -gt 0        ]] && fg_perf+=" ipam_total_subnets=${_ipam_total}"
			[[ "${_ipam_usage_pct}" =~ ^[0-9]+$  ]] && fg_perf+=" ipam_usage_pct=${_ipam_usage_pct};${warn_ipam_usage};${crit_ipam_usage};0;100"
		else
			[[ -n "${verbose}" ]] && fg_output+="${status_ok} - IPAM${_fws}disabled\n"
		fi
		unset _ipam_pool_subnets
	else
		fg_output+="${status_ok} - IPAM${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# UTM / Security Services Check (IPS, AV, AppCtrl, DoS)
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_utm}" || -n "${enable_all}" ) && -z "${disable_utm}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="UTM / Security Services:\n---------------------------------------\n"
	fi

	_utm_lic_buf=$(cat "${_pf}/license.json"  2>/dev/null)
	_utm_dos_buf=$(cat "${_pf}/dos_rules.json" 2>/dev/null)
	_utm_now=$(date +%s)

	if [[ -n "${_utm_lic_buf}" && "${_utm_lic_buf}" =~ '"results"' ]]; then
		declare -a _utm_prob_lines

		# --- Downloaded FDS services: have version + last_update, check age ---
		for _utm_svc in ips antivirus appctrl web_filtering botnet_domain geoip_db malicious_urls; do
			case "${_utm_svc}" in
				ips)            _utm_label="IPS" ;;
				antivirus)      _utm_label="AV" ;;
				appctrl)        _utm_label="AppCtrl" ;;
				web_filtering)  _utm_label="WebFilter" ;;
				botnet_domain)  _utm_label="Botnet DB" ;;
				geoip_db)       _utm_label="GeoIP" ;;
				malicious_urls) _utm_label="Malicious URLs" ;;
			esac

			_utm_status=$(echo "${_utm_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_utm_svc}" '.results[$svc].status // "unknown"' 2>/dev/null)
			[[ "${_utm_status}" == "unknown" ]] && continue
			_utm_version=$(echo "${_utm_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_utm_svc}" '.results[$svc].version // ""' 2>/dev/null)
			_utm_last_upd=$(echo "${_utm_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_utm_svc}" '.results[$svc].last_update // 0' 2>/dev/null)
			_utm_eng_ver=$(echo "${_utm_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_utm_svc}" '.results[$svc].engine.version // ""' 2>/dev/null)

			# Signature/DB age
			_utm_age_s="" ; _utm_age_days=-1
			if [[ "${_utm_last_upd}" =~ ^[0-9]+$ && "${_utm_last_upd}" -gt 978307200 ]]; then
				_utm_age_days=$(( (_utm_now - _utm_last_upd) / 86400 ))
				if [[ "${_utm_age_days}" -lt 1 ]]; then
					_utm_age_s=" | updated: today"
				else
					_utm_age_s=" | updated: ${_utm_age_days}d ago"
				fi
			else
				# No valid last_update (with or without a DB) - treat as infinitely stale
				_utm_age_days=99999
				if [[ -n "${_utm_version}" && "${_utm_version}" != "0.00000" ]]; then
					_utm_age_s=" | updated: never (has db)"
				else
					_utm_age_s=" | updated: never"
				fi
			fi

			_utm_eng_s=""
			[[ -n "${_utm_eng_ver}" ]] && _utm_eng_s=" | engine: ${_utm_eng_ver}"

			_utm_svc_state="${status_ok}"
			# Status-based alert (no_license/expired)
			case "${_utm_status}" in
				no_license|expired)
					if [[ -z "${ignore_utm_status}" ]]; then
						_utm_svc_state="${status_warn}"
						_utm_prob_lines+=("${status_warn} - UTM${_fws}${_utm_label} ${_utm_status} (db: ${_utm_version})")
					fi
					;;
			esac
			# Age-based alert: applies to ALL services with a known update date
			if [[ "${_utm_age_days}" -ge 0 ]]; then
				if (( _utm_age_days >= crit_utm_update )) 2>/dev/null; then
					_utm_svc_state="${status_crit}"
					_utm_prob_lines+=("${status_crit} - UTM${_fws}${_utm_label} db ${_utm_age_days}d old (crit: ${crit_utm_update}d)")
				elif (( _utm_age_days >= warn_utm_update )) 2>/dev/null; then
					[[ "${_utm_svc_state}" != "${status_crit}" ]] && _utm_svc_state="${status_warn}"
					_utm_prob_lines+=("${status_warn} - UTM${_fws}${_utm_label} db ${_utm_age_days}d old (warn: ${warn_utm_update}d)")
				fi
			fi

			[[ -n "${verbose}" ]] && \
				fg_output+="${_utm_svc_state} - UTM${_fws}${_utm_label} db: ${_utm_version} | status: ${_utm_status}${_utm_age_s}${_utm_eng_s}\n"

			_utm_lbl="${_utm_svc//[-.]/_}"
			[[ -n "${_utm_version}" ]] && fg_perf+=" utm_${_utm_lbl}_db_ver=$(echo "${_utm_version}" | tr -d '.')"
			[[ "${_utm_age_days}" -ge 0 ]] && \
				fg_perf+=" utm_${_utm_lbl}_update_age=${_utm_age_days};${warn_utm_update};${crit_utm_update}"
		done

		# --- Live FortiGuard services: status + running flag only ---
		for _utm_svc in antispam outbreak_prevention; do
			case "${_utm_svc}" in
				antispam)            _utm_label="AntiSpam" ;;
				outbreak_prevention) _utm_label="OBP" ;;
			esac

			_utm_status=$(echo "${_utm_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_utm_svc}" '.results[$svc].status // "unknown"' 2>/dev/null)
			[[ "${_utm_status}" == "unknown" ]] && continue
			_utm_running=$(echo "${_utm_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_utm_svc}" '.results[$svc].running // ""' 2>/dev/null)

			_utm_run_s=""
			[[ "${_utm_running}" == "true" ]]  && _utm_run_s=" | running: yes"
			[[ "${_utm_running}" == "false" ]] && _utm_run_s=" | running: no"

			_utm_svc_state="${status_ok}"
			if [[ "${_utm_status}" == "no_license" || "${_utm_status}" == "expired" ]]; then
				if [[ -z "${ignore_utm_status}" ]]; then
					_utm_svc_state="${status_warn}"
					_utm_prob_lines+=("${status_warn} - UTM${_fws}${_utm_label} ${_utm_status}")
				fi
			fi

			[[ -n "${verbose}" ]] && \
				fg_output+="${_utm_svc_state} - UTM${_fws}${_utm_label} | status: ${_utm_status}${_utm_run_s}\n"
		done

		# --- DoS protection rules ---
		if [[ -n "${_utm_dos_buf}" && "${_utm_dos_buf}" =~ '"results"' ]]; then
			_dos_total=$(echo "${_utm_dos_buf}" | "${JQ}" --unbuffered -r \
				'.results | length' 2>/dev/null)
			_dos_blocking=$(echo "${_utm_dos_buf}" | "${JQ}" --unbuffered -r \
				'[.results[] | select(.action > 0)] | length' 2>/dev/null)
			_dos_log_only=$(echo "${_utm_dos_buf}" | "${JQ}" --unbuffered -r \
				'[.results[] | select(.action == 1)] | length' 2>/dev/null)
			_dos_inactive=$(echo "${_utm_dos_buf}" | "${JQ}" --unbuffered -r \
				'[.results[] | select(.action == 0)] | length' 2>/dev/null)
			[[ ! "${_dos_total}"    =~ ^[0-9]+$ ]] && _dos_total=0
			[[ ! "${_dos_blocking}" =~ ^[0-9]+$ ]] && _dos_blocking=0
			[[ ! "${_dos_log_only}" =~ ^[0-9]+$ ]] && _dos_log_only=0
			[[ ! "${_dos_inactive}" =~ ^[0-9]+$ ]] && _dos_inactive=0

			_dos_detail=""
			[[ "${_dos_blocking}" -gt 0 ]] && _dos_detail+=" | blocking: ${_dos_blocking}"
			[[ "${_dos_log_only}"  -gt 0 ]] && _dos_detail+=" | log-only: ${_dos_log_only}"
			[[ "${_dos_inactive}"  -gt 0 ]] && _dos_detail+=" | inactive: ${_dos_inactive}"
			fg_output+="${status_ok} - UTM${_fws}DoS ${_dos_total} rules${_dos_detail}\n"
			fg_perf+=" dos_rules_total=${_dos_total} dos_rules_blocking=${_dos_blocking}"
		fi

		for _up_line in "${_utm_prob_lines[@]}"; do
			[[ "${_up_line}" != *"${status_ok}"* ]] && fg_problem_output+="${_up_line}\n"
		done
		unset _utm_prob_lines
	else
		fg_output+="${status_ok} - UTM${_fws}not available in SNMP-only mode\n"
	fi

	# IPS + AV detection statistics — SNMP only (no REST equivalent in FortiOS)
	# Helper: sum array of numeric SNMP walk values
	_snmp_sum_arr() { printf '%s\n' "$@" | "${AWK}" '{s+=$1} END{print s+0}'; }

	# --- IPS statistics ---
	_ips_detections=0 ; _ips_crit_sv=0 ; _ips_high_sv=0 ; _ips_med_sv=0
	_ips_low_sv=0     ; _ips_info_sv=0 ; _ips_drops=0    ; _ips_data=0
	if [[ -n "${_snmp_avail}" && -n "${SNMPWALK}" ]]; then
		mapfile -t _ips_det_a  < <(_snmp_walk "${OID_IPS_DETECT}" | tr -d ' ')
		if [[ "${#_ips_det_a[@]}" -gt 0 ]]; then
			mapfile -t _ips_crt_a  < <(_snmp_walk "${OID_IPS_CRIT_S}" | tr -d ' ')
			mapfile -t _ips_hig_a  < <(_snmp_walk "${OID_IPS_HIGH_S}" | tr -d ' ')
			mapfile -t _ips_med_a  < <(_snmp_walk "${OID_IPS_MED_S}"  | tr -d ' ')
			mapfile -t _ips_low_a  < <(_snmp_walk "${OID_IPS_LOW_S}"  | tr -d ' ')
			mapfile -t _ips_inf_a  < <(_snmp_walk "${OID_IPS_INFO_S}" | tr -d ' ')
			mapfile -t _ips_drp_a  < <(_snmp_walk "${OID_IPS_DROPS}"  | tr -d ' ')
			_ips_detections=$(_snmp_sum_arr "${_ips_det_a[@]}")
			_ips_crit_sv=$(_snmp_sum_arr "${_ips_crt_a[@]}")
			_ips_high_sv=$(_snmp_sum_arr "${_ips_hig_a[@]}")
			_ips_med_sv=$(_snmp_sum_arr "${_ips_med_a[@]}")
			_ips_low_sv=$(_snmp_sum_arr "${_ips_low_a[@]}")
			_ips_info_sv=$(_snmp_sum_arr "${_ips_inf_a[@]}")
			_ips_drops=$(_snmp_sum_arr "${_ips_drp_a[@]}")
			_ips_data=1
		fi
	fi

	if [[ "${_ips_data}" -eq 1 ]]; then
		_ips_high_total=$(( _ips_crit_sv + _ips_high_sv ))
		_ips_state="${status_ok}"
		_ips_thr_s=""
		if (( crit_ips >= 0 && _ips_detections > crit_ips )) 2>/dev/null; then
			_ips_state="${status_crit}"
			_ips_thr_s=" (crit: >${crit_ips})"
			fg_problem_output+="${status_crit} - UTM${_fws}IPS ${_ips_detections} detections (crit: >${crit_ips})\n"
		elif (( warn_ips >= 0 && _ips_detections > warn_ips )) 2>/dev/null; then
			_ips_state="${status_warn}"
			_ips_thr_s=" (warn: >${warn_ips})"
			fg_problem_output+="${status_warn} - UTM${_fws}IPS ${_ips_detections} detections (warn: >${warn_ips})\n"
		fi
		if (( crit_ips_high >= 0 && _ips_high_total > crit_ips_high )) 2>/dev/null; then
			[[ "${_ips_state}" != "${status_crit}" ]] && _ips_state="${status_crit}"
			fg_problem_output+="${status_crit} - UTM${_fws}IPS ${_ips_high_total} crit+high detections (crit: >${crit_ips_high})\n"
		elif (( warn_ips_high >= 0 && _ips_high_total > warn_ips_high )) 2>/dev/null; then
			[[ "${_ips_state}" != "${status_crit}" ]] && _ips_state="${status_warn}"
			fg_problem_output+="${status_warn} - UTM${_fws}IPS ${_ips_high_total} crit+high detections (warn: >${warn_ips_high})\n"
		fi
		_ips_sev_s=""
		if [[ -n "${verbose}" ]]; then
			_ips_sev_s=" | crit: ${_ips_crit_sv} | high: ${_ips_high_sv} | med: ${_ips_med_sv} | low: ${_ips_low_sv} | info: ${_ips_info_sv}"
		elif (( _ips_crit_sv + _ips_high_sv > 0 )) 2>/dev/null; then
			_ips_sev_s=" | crit+high: ${_ips_high_total}"
		fi
		_ips_drop_s=""
		(( _ips_drops > 0 )) 2>/dev/null && _ips_drop_s=" | drops: ${_ips_drops}"
		fg_output+="${_ips_state} - UTM${_fws}IPS ${_ips_detections} detections${_ips_thr_s}${_ips_sev_s}${_ips_drop_s}\n"
		fg_perf+=" ips_detections=${_ips_detections};${warn_ips};${crit_ips}"
		fg_perf+=" ips_crit=${_ips_crit_sv} ips_high=${_ips_high_sv} ips_med=${_ips_med_sv}"
		fg_perf+=" ips_low=${_ips_low_sv} ips_drops=${_ips_drops}"
	fi

	# --- AV statistics ---
	_av_detected=0 ; _av_blocked=0 ; _av_oversized=0 ; _av_crptd=0 ; _av_data=0
	if [[ -n "${_snmp_avail}" && -n "${SNMPWALK}" ]]; then
		mapfile -t _av_det_a < <(_snmp_walk "${OID_AV_DETECTED}"  | tr -d ' ')
		if [[ "${#_av_det_a[@]}" -gt 0 ]]; then
			mapfile -t _av_blk_a < <(_snmp_walk "${OID_AV_BLOCKED}"   | tr -d ' ')
			mapfile -t _av_ovs_a < <(_snmp_walk "${OID_AV_OVERSIZED}" | tr -d ' ')
			mapfile -t _av_cpt_a < <(_snmp_walk "${OID_AV_CRPTD}"     | tr -d ' ')
			_av_detected=$(_snmp_sum_arr "${_av_det_a[@]}")
			_av_blocked=$(_snmp_sum_arr "${_av_blk_a[@]}")
			_av_oversized=$(_snmp_sum_arr "${_av_ovs_a[@]}")
			_av_crptd=$(_snmp_sum_arr "${_av_cpt_a[@]}")
			_av_data=1
		fi
	fi

	if [[ "${_av_data}" -eq 1 ]]; then
		_av_state="${status_ok}"
		_av_thr_s=""
		if (( crit_av >= 0 && _av_detected > crit_av )) 2>/dev/null; then
			_av_state="${status_crit}"
			_av_thr_s=" (crit: >${crit_av})"
			fg_problem_output+="${status_crit} - UTM${_fws}AV ${_av_detected} detections (crit: >${crit_av})\n"
		elif (( warn_av >= 0 && _av_detected > warn_av )) 2>/dev/null; then
			_av_state="${status_warn}"
			_av_thr_s=" (warn: >${warn_av})"
			fg_problem_output+="${status_warn} - UTM${_fws}AV ${_av_detected} detections (warn: >${warn_av})\n"
		fi
		_av_det_s=""
		_av_ovs_s=""
		_av_cpt_s=""
		if [[ -n "${verbose}" ]]; then
			_av_det_s=" | blocked: ${_av_blocked}"
			(( _av_oversized > 0 )) 2>/dev/null && _av_ovs_s=" | oversized: ${_av_oversized}"
			(( _av_crptd > 0 ))     2>/dev/null && _av_cpt_s=" | pass-encrypted: ${_av_crptd}"
		elif (( _av_blocked > 0 )) 2>/dev/null; then
			_av_det_s=" | blocked: ${_av_blocked}"
		fi
		fg_output+="${_av_state} - UTM${_fws}AV ${_av_detected} detected${_av_thr_s}${_av_det_s}${_av_ovs_s}${_av_cpt_s}\n"
		fg_perf+=" av_detected=${_av_detected};${warn_av};${crit_av}"
		fg_perf+=" av_blocked=${_av_blocked} av_oversized=${_av_oversized} av_pass_crptd=${_av_crptd}"
	fi

	unset -f _snmp_sum_arr

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# VDOM Resource Usage Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_vdom}" || -n "${enable_all}" ) && -z "${disable_vdom}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="VDOM Resources:\n---------------------------------------\n"
	fi

	_vdom_list_buf=$(cat "${_pf}/vdom_list.json" 2>/dev/null)

	if [[ -n "${_vdom_list_buf}" && "${_vdom_list_buf}" =~ '"results"' ]]; then
		_vdom_count=0
		_vdom_prob=0

		while IFS= read -r _vd_name; do
			[[ -z "${_vd_name}" ]] && continue
			_vd_res_buf=$(fg_api_get "${FG_API}/monitor/system/vdom-resource?vdom=${_vd_name}" 2>/dev/null)
			[[ -z "${_vd_res_buf}" || ! "${_vd_res_buf}" =~ '"results"' ]] && continue

			_vd_cpu=$(echo "${_vd_res_buf}"    | "${JQ}" --unbuffered -r '.results.cpu // 0' 2>/dev/null)
			_vd_mem=$(echo "${_vd_res_buf}"    | "${JQ}" --unbuffered -r '.results.memory // 0' 2>/dev/null)
			_vd_sess=$(echo "${_vd_res_buf}"   | "${JQ}" --unbuffered -r '.results.session.current_usage // 0' 2>/dev/null)
			_vd_ipsec1=$(echo "${_vd_res_buf}" | "${JQ}" --unbuffered -r '.results["ipsec-phase1"].current_usage // 0' 2>/dev/null)
			_vd_ipsec2=$(echo "${_vd_res_buf}" | "${JQ}" --unbuffered -r '.results["ipsec-phase2"].current_usage // 0' 2>/dev/null)

			(( _vdom_count++ ))
			_vd_lbl="${_vd_name//[^a-zA-Z0-9_]/_}"
			_vd_state="${status_ok}"
			_vd_issues=""

			if [[ "${_vd_cpu}" =~ ^[0-9]+$ ]]; then
				if (( _vd_cpu >= crit_vdom_cpu )) 2>/dev/null; then
					_vd_state="${status_crit}"
					_vd_issues+=" cpu:${_vd_cpu}%>=${crit_vdom_cpu}%"
					fg_problem_output+="${status_crit} - VDOM ${_fwn}${_vd_name}: cpu ${_vd_cpu}% >= ${crit_vdom_cpu}%\n"
					(( _vdom_prob++ ))
				elif (( _vd_cpu >= warn_vdom_cpu )) 2>/dev/null; then
					[[ "${_vd_state}" != "${status_crit}" ]] && _vd_state="${status_warn}"
					_vd_issues+=" cpu:${_vd_cpu}%>=${warn_vdom_cpu}%"
					fg_problem_output+="${status_warn} - VDOM ${_fwn}${_vd_name}: cpu ${_vd_cpu}% >= ${warn_vdom_cpu}%\n"
					(( _vdom_prob++ ))
				fi
			fi

			if [[ "${_vd_mem}" =~ ^[0-9]+$ ]]; then
				if (( _vd_mem >= crit_vdom_mem )) 2>/dev/null; then
					_vd_state="${status_crit}"
					_vd_issues+=" mem:${_vd_mem}%>=${crit_vdom_mem}%"
					fg_problem_output+="${status_crit} - VDOM ${_fwn}${_vd_name}: mem ${_vd_mem}% >= ${crit_vdom_mem}%\n"
					(( _vdom_prob++ ))
				elif (( _vd_mem >= warn_vdom_mem )) 2>/dev/null; then
					[[ "${_vd_state}" != "${status_crit}" ]] && _vd_state="${status_warn}"
					_vd_issues+=" mem:${_vd_mem}%>=${warn_vdom_mem}%"
					fg_problem_output+="${status_warn} - VDOM ${_fwn}${_vd_name}: mem ${_vd_mem}% >= ${warn_vdom_mem}%\n"
					(( _vdom_prob++ ))
				fi
			fi

			if [[ "${_vd_sess}" =~ ^[0-9]+$ ]]; then
				if (( crit_vdom_sessions >= 0 && _vd_sess >= crit_vdom_sessions )) 2>/dev/null; then
					_vd_state="${status_crit}"
					_vd_issues+=" sessions:${_vd_sess}>=${crit_vdom_sessions}"
					fg_problem_output+="${status_crit} - VDOM ${_fwn}${_vd_name}: sessions ${_vd_sess} >= ${crit_vdom_sessions}\n"
					(( _vdom_prob++ ))
				elif (( warn_vdom_sessions >= 0 && _vd_sess >= warn_vdom_sessions )) 2>/dev/null; then
					[[ "${_vd_state}" != "${status_crit}" ]] && _vd_state="${status_warn}"
					_vd_issues+=" sessions:${_vd_sess}>=${warn_vdom_sessions}"
					fg_problem_output+="${status_warn} - VDOM ${_fwn}${_vd_name}: sessions ${_vd_sess} >= ${warn_vdom_sessions}\n"
					(( _vdom_prob++ ))
				fi
			fi

			_vd_detail="cpu: ${_vd_cpu}% | mem: ${_vd_mem}%"
			[[ "${_vd_sess}" =~ ^[0-9]+$ ]] && _vd_detail+=" | sessions: ${_vd_sess}"
			[[ "${_vd_ipsec1}" =~ ^[0-9]+$ && "${_vd_ipsec1}" -gt 0 ]] && \
				_vd_detail+=" | ipsec-ph1: ${_vd_ipsec1} ph2: ${_vd_ipsec2}"

			[[ -n "${verbose}" || "${_vd_state}" != "${status_ok}" ]] && \
				fg_output+="${_vd_state} - VDOM ${_fwn}${_vd_name}: ${_vd_detail}${_vd_issues:+ (${_vd_issues# })}\n"

			fg_perf+=" vdom_${_vd_lbl}_cpu=${_vd_cpu};${warn_vdom_cpu};${crit_vdom_cpu};0;100"
			fg_perf+=" vdom_${_vd_lbl}_mem=${_vd_mem};${warn_vdom_mem};${crit_vdom_mem};0;100"
			[[ "${_vd_sess}" =~ ^[0-9]+$ ]] && fg_perf+=" vdom_${_vd_lbl}_sessions=${_vd_sess}"

		done < <("${JQ}" --unbuffered -r '.results[].name // empty' "${_pf}/vdom_list.json" 2>/dev/null)

		# VDOM license usage summary
		_vdom_lic_buf=$(cat "${_pf}/vdom_lic_info.json" 2>/dev/null)
		[[ -z "${_vdom_lic_buf}" ]] && _vdom_lic_buf=$(cat "${_pf}/license.json" 2>/dev/null)
		_vdom_lic_used=$("${JQ}" --unbuffered -r '.results.vdom.used // -1' <<< "${_vdom_lic_buf}" 2>/dev/null)
		_vdom_lic_max=$("${JQ}"  --unbuffered -r '.results.vdom.max  // -1' <<< "${_vdom_lic_buf}" 2>/dev/null)

		_vdom_lic_s=""
		_vdom_lic_state="${status_ok}"
		if [[ "${_vdom_lic_max}" =~ ^[0-9]+$ && "${_vdom_lic_max}" -gt 0 ]]; then
			_vdom_lic_pct=$(( _vdom_lic_used * 100 / _vdom_lic_max ))
			_vdom_lic_s=" (license: ${_vdom_lic_used}/${_vdom_lic_max} vdoms, ${_vdom_lic_pct}%)"
			fg_perf+=" vdom_used=${_vdom_lic_used};$(( _vdom_lic_max * warn_vdom_license / 100 ));$(( _vdom_lic_max * crit_vdom_license / 100 ));0;${_vdom_lic_max}"
			fg_perf+=" vdom_max=${_vdom_lic_max}"
			if (( _vdom_lic_pct >= crit_vdom_license )) 2>/dev/null; then
				_vdom_lic_state="${status_crit}"
				fg_problem_output+="${status_crit} - VDOM${_fws}license usage ${_vdom_lic_used}/${_vdom_lic_max} (${_vdom_lic_pct}% >= ${crit_vdom_license}%)\n"
				(( _vdom_prob++ ))
			elif (( _vdom_lic_pct >= warn_vdom_license )) 2>/dev/null; then
				_vdom_lic_state="${status_warn}"
				fg_problem_output+="${status_warn} - VDOM${_fws}license usage ${_vdom_lic_used}/${_vdom_lic_max} (${_vdom_lic_pct}% >= ${warn_vdom_license}%)\n"
				(( _vdom_prob++ ))
			fi
		fi

		if [[ "${_vdom_count}" -eq 0 ]]; then
			fg_output+="${status_ok} - VDOM${_fws}no vdom data available\n"
		elif [[ "${_vdom_prob}" -eq 0 ]]; then
			fg_output+="${status_ok} - VDOM${_fws}${_vdom_count} vdom(s) within thresholds${_vdom_lic_s}\n"
		else
			_vdom_sum_state="${status_warn}"
			[[ "${_vdom_lic_state}" == "${status_crit}" ]] && _vdom_sum_state="${status_crit}"
			fg_output+="${_vdom_sum_state} - VDOM${_fws}${_vdom_count} vdom(s)${_vdom_lic_s}\n"
		fi
		fg_perf+=" vdom_count=${_vdom_count}"
	else
		fg_output+="${status_ok} - VDOM${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# FortiToken Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_ftk}" || -n "${enable_all}" ) && -z "${disable_ftk}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="FortiToken:\n---------------------------------------\n"
	fi

	_ftk_buf=$(cat "${_pf}/fortitoken.json" 2>/dev/null)

	if [[ -n "${_ftk_buf}" && "${_ftk_buf}" =~ '"results"' ]]; then
		_ftk_total=0
		_ftk_activated=0
		_ftk_available=0
		_ftk_unactivated=0
		_ftk_mobile=0
		_ftk_hardware=0

		while IFS=$'\t' read -r _ft_type _ft_status; do
			(( _ftk_total++ ))
			case "${_ft_type}" in
				mobile)   (( _ftk_mobile++ )) ;;
				hardware) (( _ftk_hardware++ )) ;;
			esac
			case "${_ft_status}" in
				activated)   (( _ftk_activated++ )) ;;
				available)   (( _ftk_available++ )) ;;
				*)           (( _ftk_unactivated++ )) ;;
			esac
		done < <("${JQ}" --unbuffered -r '
			.results | to_entries[] | .value |
			[(.type // "unknown"), (.status.name // "unknown")] | join("\t")' \
			"${_pf}/fortitoken.json" 2>/dev/null)

		_ftk_type_s=""
		[[ "${_ftk_mobile}"   -gt 0 ]] && _ftk_type_s+=" mobile: ${_ftk_mobile}"
		[[ "${_ftk_hardware}" -gt 0 ]] && _ftk_type_s+=" hardware: ${_ftk_hardware}"

		_ftk_detail="total: ${_ftk_total} | activated: ${_ftk_activated} | available: ${_ftk_available}"
		[[ "${_ftk_unactivated}" -gt 0 ]] && _ftk_detail+=" | other: ${_ftk_unactivated}"
		[[ -n "${_ftk_type_s}" ]] && _ftk_detail+=" |${_ftk_type_s}"

		_ftk_state="${status_ok}"
		if [[ "${_ftk_total}" -gt 0 && "${_ftk_activated}" -eq 0 ]]; then
			_ftk_state="${status_warn}"
			fg_problem_output+="${status_warn} - FortiToken${_fws}no activated tokens (${_ftk_total} total)\n"
		fi
		if (( crit_ftk_available >= 0 && _ftk_available <= crit_ftk_available )) 2>/dev/null; then
			_ftk_state="${status_crit}"
			fg_problem_output+="${status_crit} - FortiToken${_fws}only ${_ftk_available} token(s) available (crit: <= ${crit_ftk_available})\n"
		elif (( warn_ftk_available >= 0 && _ftk_available <= warn_ftk_available )) 2>/dev/null; then
			[[ "${_ftk_state}" != "${status_crit}" ]] && _ftk_state="${status_warn}"
			fg_problem_output+="${status_warn} - FortiToken${_fws}only ${_ftk_available} token(s) available (warn: <= ${warn_ftk_available})\n"
		fi

		fg_output+="${_ftk_state} - FortiToken${_fws}${_ftk_detail}\n"
		fg_perf+=" ftk_total=${_ftk_total} ftk_activated=${_ftk_activated} ftk_available=${_ftk_available};${warn_ftk_available};${crit_ftk_available}"

		if [[ -n "${verbose}" && "${_ftk_total}" -gt 0 ]]; then
			while IFS='|' read -r _ft_serial _ft_type _ft_user _ft_status _ft_trial; do
				_ft_trial_s="" ; [[ "${_ft_trial}" == "true" ]] && _ft_trial_s=" (trial)"
				_ft_user_s="" ; [[ -n "${_ft_user}" && "${_ft_user}" != "-" ]] && _ft_user_s=" | user: ${_ft_user}"
				fg_output+="${status_ok} - FortiToken ${_fwn}${_ft_serial}: ${_ft_type}${_ft_trial_s} | status: ${_ft_status}${_ft_user_s}\n"
			done < <("${JQ}" --unbuffered -r '
				.results | to_entries[] | .value |
				[.serial_number, (.type // "unknown"), (.user // "-"),
				 (.status.name // "unknown"), (.is_trial // false | tostring)] | join("|")' \
				"${_pf}/fortitoken.json" 2>/dev/null)
		fi
	else
		fg_output+="${status_ok} - FortiToken${_fws}not available in SNMP-only mode\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Storage / Disk Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sd}" || -n "${enable_all}" ) && -z "${disable_sd}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Storage:\n---------------------------------------\n"
	fi

	_sd_buffer=$(cat "${_pf}/storage.json"  2>/dev/null)
	_logdisk_buf=$(cat "${_pf}/logdisk.json" 2>/dev/null)
	_logdisk_avail=0
	[[ -n "${_logdisk_buf}" && "${_logdisk_buf}" =~ '"results"' ]] && _logdisk_avail=1

	if [[ -n "${_sd_buffer}" && "${_sd_buffer}" =~ '"results"' ]]; then
		_sd_total=$(echo "${_sd_buffer}" | "${JQ}" --unbuffered '.results | length' 2>/dev/null)

		if [[ "${_sd_total:-0}" -gt 0 ]]; then
			declare -a _sd_names _sd_sizes _sd_usages _sd_pcts
			while IFS=$'\t' read -r _s_name _s_size _s_usage _s_pct; do
				_sd_names+=("${_s_name}")
				_sd_sizes+=("${_s_size}")
				_sd_usages+=("${_s_usage}")
				_sd_pcts+=("${_s_pct}")
			done < <(echo "${_sd_buffer}" | "${JQ}" --unbuffered -r '
				.results[] | [
					(.name // .partition // "disk"),
					((.size // 0) | tostring),
					((.usage // 0) | tostring),
					(if (.size // 0) > 0 then ((.usage // 0) * 100 / .size | floor)
					 else 0 end | tostring)
				] | join("\t")' 2>/dev/null)

			_sd_warn=0
			_sd_crit=0

			for count in "${!_sd_names[@]}"; do
				_sdn="${_sd_names[count]}"
				_sdp="${_sd_pcts[count]}"

				_sd_size_h=$(echo "${_sd_sizes[count]}" | "${AWK}" '{
					if ($1 >= 1073741824) printf "%.1f GB", $1/1073741824
					else if ($1 >= 1048576) printf "%.1f MB", $1/1048576
					else if ($1 >= 1024) printf "%.1f KB", $1/1024
					else printf "%d B", $1}')
				_sd_used_h=$(echo "${_sd_usages[count]}" | "${AWK}" '{
					if ($1 >= 1073741824) printf "%.1f GB", $1/1073741824
					else if ($1 >= 1048576) printf "%.1f MB", $1/1048576
					else if ($1 >= 1024) printf "%.1f KB", $1/1024
					else printf "%d B", $1}')
				_sd_detail="${_sd_used_h} / ${_sd_size_h} (${_sdp}%)"

				_sd_label="${_sdn//\//_}"
				_sd_label="${_sd_label//-/_}"
				fg_perf+=" storage_${_sd_label}_pct=${_sdp};${warn_disk};${crit_disk};0;100"
				fg_perf+=" storage_${_sd_label}_used=${_sd_usages[count]}B"
				fg_perf+=" storage_${_sd_label}_size=${_sd_sizes[count]}B"

				if (( _sdp >= crit_disk )) 2>/dev/null; then
					fg_output+="${status_crit} - Storage ${_fwn}${_sdn}: ${_sd_detail} (threshold: ${crit_disk}%)\n"
					fg_problem_output+="${status_crit} - Storage ${_fwn}${_sdn}: ${_sdp}% used\n"
					(( _sd_crit++ ))
				elif (( _sdp >= warn_disk )) 2>/dev/null; then
					fg_output+="${status_warn} - Storage ${_fwn}${_sdn}: ${_sd_detail} (threshold: ${warn_disk}%)\n"
					fg_problem_output+="${status_warn} - Storage ${_fwn}${_sdn}: ${_sdp}% used\n"
					(( _sd_warn++ ))
				elif [[ -n "${verbose}" ]]; then
					fg_output+="${status_ok} - Storage ${_fwn}${_sdn}: ${_sd_detail}\n"
				fi
			done

			if [[ "${_sd_crit}" -eq 0 && "${_sd_warn}" -eq 0 && -z "${verbose}" ]]; then
				fg_output+="${status_ok} - Storage${_fws}${_sd_total} partition(s) within thresholds\n"
			fi

			unset _sd_names _sd_sizes _sd_usages _sd_pcts
		else
			fg_output+="${status_ok} - Storage${_fws}no storage data available\n"
		fi
	else
		# API wins: only use SNMP if REST log disk also has no data
		if [[ -n "${_snmp_avail}" && "${_logdisk_avail}" -eq 0 ]]; then
			_snmp_disk_mb=$(_snmp_val "${OID_DISK}")
			_snmp_disk_cap=$(_snmp_val "${OID_DISK_CAP}")
			if [[ "${_snmp_disk_cap}" =~ ^[0-9]+$ && "${_snmp_disk_cap}" -gt 0 ]]; then
				_snmp_disk_pct=$(( _snmp_disk_mb * 100 / _snmp_disk_cap ))
				_snmp_disk_mb_h=$(echo "${_snmp_disk_mb}" | "${AWK}" '{
					if ($1>=1024) printf "%.1f GB",$1/1024; else printf "%d MB",$1}')
				_snmp_disk_cap_h=$(echo "${_snmp_disk_cap}" | "${AWK}" '{
					if ($1>=1024) printf "%.1f GB",$1/1024; else printf "%d MB",$1}')
				fg_perf+=" disk_pct=${_snmp_disk_pct};${warn_disk};${crit_disk};0;100"
				fg_perf+=" disk_mb=${_snmp_disk_mb};0;${_snmp_disk_cap}"
				if (( _snmp_disk_pct >= crit_disk )) 2>/dev/null; then
					fg_output+="${status_crit} - Storage${_fws}${_snmp_disk_mb_h} / ${_snmp_disk_cap_h} (${_snmp_disk_pct}%, threshold: ${crit_disk}%)\n"
					fg_problem_output+="${status_crit} - Storage${_fws}disk ${_snmp_disk_pct}% used\n"
				elif (( _snmp_disk_pct >= warn_disk )) 2>/dev/null; then
					fg_output+="${status_warn} - Storage${_fws}${_snmp_disk_mb_h} / ${_snmp_disk_cap_h} (${_snmp_disk_pct}%, threshold: ${warn_disk}%)\n"
					fg_problem_output+="${status_warn} - Storage${_fws}disk ${_snmp_disk_pct}% used\n"
				else
					fg_output+="${status_ok} - Storage${_fws}${_snmp_disk_mb_h} / ${_snmp_disk_cap_h} (${_snmp_disk_pct}%) (SNMP)\n"
				fi
			else
				fg_output+="${status_ok} - Storage${_fws}no disk data via SNMP\n"
			fi
		elif [[ "${_logdisk_avail}" -eq 0 ]]; then
			fg_output+="${status_ok} - Storage${_fws}endpoint not available\n"
		fi
	fi

	# Log disk usage from monitor endpoint (already loaded above)
	if [[ "${_logdisk_avail}" -eq 1 ]]; then
		_ld_used=$(echo "${_logdisk_buf}" | "${JQ}" --unbuffered -r '.results.used_bytes // 0' 2>/dev/null)
		_ld_total=$(echo "${_logdisk_buf}" | "${JQ}" --unbuffered -r '.results.total_bytes // 0' 2>/dev/null)
		if [[ "${_ld_total}" -gt 0 ]] 2>/dev/null; then
			_ld_pct=$(echo "${_ld_used} ${_ld_total}" | "${AWK}" '{printf "%d", $1*100/$2}')
			_ld_used_h=$(echo "${_ld_used}" | "${AWK}" '{
				if ($1>=1073741824) printf "%.1f GB",$1/1073741824
				else if ($1>=1048576) printf "%.1f MB",$1/1048576
				else if ($1>=1024) printf "%.1f KB",$1/1024
				else printf "%d B",$1}')
			_ld_total_h=$(echo "${_ld_total}" | "${AWK}" '{
				if ($1>=1073741824) printf "%.1f GB",$1/1073741824
				else if ($1>=1048576) printf "%.1f MB",$1/1048576
				else if ($1>=1024) printf "%.1f KB",$1/1024
				else printf "%d B",$1}')
			fg_perf+=" log_disk_pct=${_ld_pct};${warn_disk};${crit_disk};0;100"
			fg_perf+=" log_disk_used=${_ld_used}B"
			if (( _ld_pct >= crit_disk )) 2>/dev/null; then
				fg_output+="${status_crit} - Storage ${_fwn}log: ${_ld_used_h} / ${_ld_total_h} (${_ld_pct}%, threshold: ${crit_disk}%)\n"
				fg_problem_output+="${status_crit} - Storage ${_fwn}log: ${_ld_pct}% used\n"
			elif (( _ld_pct >= warn_disk )) 2>/dev/null; then
				fg_output+="${status_warn} - Storage ${_fwn}log: ${_ld_used_h} / ${_ld_total_h} (${_ld_pct}%, threshold: ${warn_disk}%)\n"
				fg_problem_output+="${status_warn} - Storage ${_fwn}log: ${_ld_pct}% used\n"
			elif [[ -n "${verbose}" ]]; then
				fg_output+="${status_ok} - Storage ${_fwn}log: ${_ld_used_h} / ${_ld_total_h} (${_ld_pct}%)\n"
			fi
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# License Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_lic}" || -n "${enable_all}" ) && -z "${disable_lic}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="License:\n---------------------------------------\n"
	fi

	_lic_buffer=$(cat "${_pf}/license.json" 2>/dev/null)

	if [[ -n "${_lic_buffer}" && "${_lic_buffer}" =~ '"results"' ]]; then
		_lic_now=$(date +%s)
		_lic_warn_sec=$(( warn_lic * 86400 ))
		_lic_crit_sec=$(( crit_lic * 86400 ))
		_lic_warn=0
		_lic_crit=0

		# Generic iteration over all license result keys - works regardless of
		# FortiOS naming (appctrl vs app_ctrl, webfilter vs web_filtering, etc.)
		# Keys skipped: vdom (count-based), vm (null on physical), version
		_lic_skip_keys="vdom vm version fortigate"

		declare -a _lk_names _lk_statuses _lk_expires _lk_last_updates _lk_update_statuses
		while IFS=$'\t' read -r _lk_name _lk_status _lk_exp _lk_lupd _lk_updstat; do
			_lk_names+=("${_lk_name}")
			_lk_statuses+=("${_lk_status}")
			_lk_expires+=("${_lk_exp}")
			_lk_last_updates+=("${_lk_lupd}")
			_lk_update_statuses+=("${_lk_updstat}")
		done < <(echo "${_lic_buffer}" | "${JQ}" --unbuffered -r \
			--argjson skip '["vdom","vm","version","fortigate"]' '
			.results | to_entries[] |
			select(.value | type == "object") |
			select(.key as $k | $skip | index($k) | not) |
			[
				.key,
				(.value.status // .value.support.status // ""),
				(.value.expires // .value.support.expires // .value.expiry_date // ""),
				((.value.last_update // 0) | tostring),
				(.value.last_update_result_status // "")
			] | @tsv' 2>/dev/null)

		# Build license blacklist map
		declare -A _lic_bl_map
		if [[ -n "${lic_ignore}" ]]; then
			IFS=',' read -ra _lic_bl_arr <<< "${lic_ignore}"
			for _lic_bl_e in "${_lic_bl_arr[@]}"; do _lic_bl_map["${_lic_bl_e}"]=1; done
		fi
		# When --ignore-all-licenses: downgrade alert states to OK in output, skip problem_output
		_lef_c="${lic_ignore_all:+${status_ok}}" ; _lef_c="${_lef_c:-${status_crit}}"
		_lef_w="${lic_ignore_all:+${status_ok}}" ; _lef_w="${_lef_w:-${status_warn}}"

		for count in "${!_lk_names[@]}"; do
			_feat="${_lk_names[count]}"
			_feat_status="${_lk_statuses[count]}"
			_feat_expires="${_lk_expires[count]}"

			[[ -z "${_feat_status}" || "${_feat_status}" == "null" ]] && continue
			[[ -n "${_lic_bl_map[${_feat}]}" ]] && continue

			if [[ "${_feat_status}" == "no-license" ]]; then
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - License ${_fwn}${_feat}: not licensed\n"
				continue
			fi

			if [[ -n "${_feat_expires}" && "${_feat_expires}" != "null" ]]; then
				_feat_exp_epoch=$(date -d "${_feat_expires}" +%s 2>/dev/null || echo "0")
				if [[ "${_feat_exp_epoch:-0}" -gt 0 ]]; then
					_feat_diff=$(( _feat_exp_epoch - _lic_now ))
					_feat_days=$(( _feat_diff / 86400 ))
					if [[ "${_feat_diff}" -lt 0 ]]; then
						fg_output+="${_lef_c} - License ${_fwn}${_feat}: EXPIRED (${_feat_expires})\n"
						[[ -z "${lic_ignore_all}" ]] && {
							fg_problem_output+="${status_crit} - License ${_fwn}${_feat}: EXPIRED\n"
							(( _lic_crit++ ))
						}
					elif [[ "${_feat_diff}" -lt "${_lic_crit_sec}" ]]; then
						fg_output+="${_lef_c} - License ${_fwn}${_feat}: expires in ${_feat_days}d (${_feat_expires})\n"
						[[ -z "${lic_ignore_all}" ]] && {
							fg_problem_output+="${status_crit} - License ${_fwn}${_feat}: expires in ${_feat_days}d\n"
							(( _lic_crit++ ))
						}
					elif [[ "${_feat_diff}" -lt "${_lic_warn_sec}" ]]; then
						fg_output+="${_lef_w} - License ${_fwn}${_feat}: expires in ${_feat_days}d (${_feat_expires})\n"
						[[ -z "${lic_ignore_all}" ]] && {
							fg_problem_output+="${status_warn} - License ${_fwn}${_feat}: expires in ${_feat_days}d\n"
							(( _lic_warn++ ))
						}
					else
						fg_output+="${status_ok} - License ${_fwn}${_feat}: valid (${_feat_expires}, ${_feat_days}d left)\n"
					fi
					_feat_label="${_feat//-/_}"
					fg_perf+=" lic_${_feat_label}_days=${_feat_days};${warn_lic};${crit_lic};0"
				fi
			elif [[ "${_feat_status}" == "expired" ]]; then
				fg_output+="${_lef_c} - License ${_fwn}${_feat}: EXPIRED\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_crit} - License ${_fwn}${_feat}: EXPIRED\n"
					(( _lic_crit++ ))
				}
			elif [[ "${_feat_status}" == "licensed" || "${_feat_status}" == "registered" ]]; then
				fg_output+="${status_ok} - License ${_fwn}${_feat}: ${_feat_status}\n"
			fi

			# For licensed/free_license DB features: check last_update age
			_feat_lupd="${_lk_last_updates[count]}"
			if [[ "${_feat_status}" == "licensed" || "${_feat_status}" == "free_license" ]] && \
			   [[ "${_feat_lupd}" =~ ^[0-9]+$ && "${_feat_lupd}" -gt 0 ]] 2>/dev/null; then
				_lupd_age_sec=$(( _lic_now - _feat_lupd ))
				_lupd_age_days=$(( _lupd_age_sec / 86400 ))
				_db_warn_sec=$(( warn_db_age * 86400 ))
				_db_crit_sec=$(( crit_db_age * 86400 ))
				_lupd_date=$(date -d "@${_feat_lupd}" "+%Y-%m-%d" 2>/dev/null)
				if [[ "${_lupd_age_sec}" -gt "${_db_crit_sec}" ]]; then
					fg_output+="${_lef_c} - License ${_fwn}${_feat}: DB not updated for ${_lupd_age_days}d (last: ${_lupd_date})\n"
					[[ -z "${lic_ignore_all}" ]] && {
						fg_problem_output+="${status_crit} - License ${_fwn}${_feat}: DB stale (${_lupd_age_days}d)\n"
						(( _lic_crit++ ))
					}
				elif [[ "${_lupd_age_sec}" -gt "${_db_warn_sec}" ]]; then
					fg_output+="${_lef_w} - License ${_fwn}${_feat}: DB not updated for ${_lupd_age_days}d (last: ${_lupd_date})\n"
					[[ -z "${lic_ignore_all}" ]] && {
						fg_problem_output+="${status_warn} - License ${_fwn}${_feat}: DB stale (${_lupd_age_days}d)\n"
						(( _lic_warn++ ))
					}
				elif [[ -n "${verbose}" ]]; then
					fg_output+="${status_ok} - License ${_fwn}${_feat}: DB updated ${_lupd_age_days}d ago (${_lupd_date})\n"
				fi
				_feat_label="${_feat//-/_}"
				fg_perf+=" lic_${_feat_label}_db_age=${_lupd_age_days};${warn_db_age};${crit_db_age};0"
			fi
		done

		unset _lk_names _lk_statuses _lk_expires _lk_last_updates _lk_update_statuses _lic_bl_map

		if [[ "${_lic_crit}" -eq 0 && "${_lic_warn}" -eq 0 ]]; then
			fg_output+="${status_ok} - License${_fws}all checked licenses valid\n"
		fi
	elif [[ -n "${_snmp_only}" && -n "${_snmp_avail}" && -n "${SNMPWALK}" ]]; then
		_lic_now=$(date +%s)
		_lic_warn_sec=$(( warn_lic * 86400 ))
		_lic_crit_sec=$(( crit_lic * 86400 ))
		_lic_warn=0
		_lic_crit=0

		declare -A _lic_bl_map
		if [[ -n "${lic_ignore}" ]]; then
			IFS=',' read -ra _lic_bl_arr <<< "${lic_ignore}"
			for _lic_bl_e in "${_lic_bl_arr[@]}"; do _lic_bl_map["${_lic_bl_e}"]=1; done
		fi
		_lef_c="${lic_ignore_all:+${status_ok}}" ; _lef_c="${_lef_c:-${status_crit}}"
		_lef_w="${lic_ignore_all:+${status_ok}}" ; _lef_w="${_lef_w:-${status_warn}}"

		# Support contracts (fgLicContractTable)
		mapfile -t _lsnmp_names   < <(_snmp_walk "${OID_LIC_CONTRACT_DESC}"   | tr -d '"')
		mapfile -t _lsnmp_expires < <(_snmp_walk "${OID_LIC_CONTRACT_EXPIRY}" | tr -d '"')
		for _si in "${!_lsnmp_names[@]}"; do
			_snmp_lname="${_lsnmp_names[_si]}"
			_snmp_lexp_raw="${_lsnmp_expires[_si]:-}"
			[[ -z "${_snmp_lname}" || -z "${_snmp_lexp_raw}" || "${_snmp_lexp_raw}" == "0" ]] && continue
			[[ -n "${_lic_bl_map[${_snmp_lname}]}" ]] && continue
			if [[ "${_snmp_lexp_raw}" =~ ^[0-9]+$ ]]; then
				_snmp_lexp_epoch="${_snmp_lexp_raw}"
			else
				_snmp_lexp_epoch=$(date -d "${_snmp_lexp_raw}" +%s 2>/dev/null || echo "0")
			fi
			[[ "${_snmp_lexp_epoch:-0}" -le 0 ]] && continue
			_snmp_ldiff=$(( _snmp_lexp_epoch - _lic_now ))
			_snmp_ldays=$(( _snmp_ldiff / 86400 ))
			_snmp_ldate=$(date -d "@${_snmp_lexp_epoch}" "+%Y-%m-%d" 2>/dev/null)
			if [[ "${_snmp_ldiff}" -lt 0 ]]; then
				fg_output+="${_lef_c} - License ${_fwn}${_snmp_lname}: EXPIRED (${_snmp_ldate})\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_crit} - License ${_fwn}${_snmp_lname}: EXPIRED\n"
					(( _lic_crit++ ))
				}
			elif [[ "${_snmp_ldiff}" -lt "${_lic_crit_sec}" ]]; then
				fg_output+="${_lef_c} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d (${_snmp_ldate})\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_crit} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d\n"
					(( _lic_crit++ ))
				}
			elif [[ "${_snmp_ldiff}" -lt "${_lic_warn_sec}" ]]; then
				fg_output+="${_lef_w} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d (${_snmp_ldate})\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_warn} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d\n"
					(( _lic_warn++ ))
				}
			else
				fg_output+="${status_ok} - License ${_fwn}${_snmp_lname}: valid (${_snmp_ldate}, ${_snmp_ldays}d left)\n"
			fi
			_snmp_lbl="${_snmp_lname//-/_}"
			fg_perf+=" lic_${_snmp_lbl}_days=${_snmp_ldays};${warn_lic};${crit_lic};0"
		done

		# FortiGuard service versions (fgLicVersionTable) — includes last_update for DB age
		mapfile -t _lsnmp_names   < <(_snmp_walk "${OID_LIC_VER_DESC}"    | tr -d '"')
		mapfile -t _lsnmp_expires < <(_snmp_walk "${OID_LIC_VER_EXPIRY}"  | tr -d '"')
		mapfile -t _lsnmp_updts   < <(_snmp_walk "${OID_LIC_VER_UPDTIME}" | tr -d '"')
		for _si in "${!_lsnmp_names[@]}"; do
			_snmp_lname="${_lsnmp_names[_si]}"
			_snmp_lexp_raw="${_lsnmp_expires[_si]:-}"
			[[ -z "${_snmp_lname}" || -z "${_snmp_lexp_raw}" || "${_snmp_lexp_raw}" == "0" ]] && continue
			[[ -n "${_lic_bl_map[${_snmp_lname}]}" ]] && continue
			if [[ "${_snmp_lexp_raw}" =~ ^[0-9]+$ ]]; then
				_snmp_lexp_epoch="${_snmp_lexp_raw}"
			else
				_snmp_lexp_epoch=$(date -d "${_snmp_lexp_raw}" +%s 2>/dev/null || echo "0")
			fi
			[[ "${_snmp_lexp_epoch:-0}" -le 0 ]] && continue
			_snmp_ldiff=$(( _snmp_lexp_epoch - _lic_now ))
			_snmp_ldays=$(( _snmp_ldiff / 86400 ))
			_snmp_ldate=$(date -d "@${_snmp_lexp_epoch}" "+%Y-%m-%d" 2>/dev/null)
			if [[ "${_snmp_ldiff}" -lt 0 ]]; then
				fg_output+="${_lef_c} - License ${_fwn}${_snmp_lname}: EXPIRED (${_snmp_ldate})\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_crit} - License ${_fwn}${_snmp_lname}: EXPIRED\n"
					(( _lic_crit++ ))
				}
			elif [[ "${_snmp_ldiff}" -lt "${_lic_crit_sec}" ]]; then
				fg_output+="${_lef_c} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d (${_snmp_ldate})\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_crit} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d\n"
					(( _lic_crit++ ))
				}
			elif [[ "${_snmp_ldiff}" -lt "${_lic_warn_sec}" ]]; then
				fg_output+="${_lef_w} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d (${_snmp_ldate})\n"
				[[ -z "${lic_ignore_all}" ]] && {
					fg_problem_output+="${status_warn} - License ${_fwn}${_snmp_lname}: expires in ${_snmp_ldays}d\n"
					(( _lic_warn++ ))
				}
			else
				fg_output+="${status_ok} - License ${_fwn}${_snmp_lname}: valid (${_snmp_ldate}, ${_snmp_ldays}d left)\n"
			fi
			_snmp_lbl="${_snmp_lname//-/_}"
			fg_perf+=" lic_${_snmp_lbl}_days=${_snmp_ldays};${warn_lic};${crit_lic};0"
			# DB age check
			_snmp_lupd="${_lsnmp_updts[_si]:-0}"
			if [[ "${_snmp_lupd}" =~ ^[0-9]+$ && "${_snmp_lupd}" -gt 0 ]] 2>/dev/null; then
				_snmp_lupd_age=$(( _lic_now - _snmp_lupd ))
				_snmp_lupd_days=$(( _snmp_lupd_age / 86400 ))
				_db_warn_sec=$(( warn_db_age * 86400 ))
				_db_crit_sec=$(( crit_db_age * 86400 ))
				_snmp_lupd_date=$(date -d "@${_snmp_lupd}" "+%Y-%m-%d" 2>/dev/null)
				if [[ "${_snmp_lupd_age}" -gt "${_db_crit_sec}" ]]; then
					fg_output+="${_lef_c} - License ${_fwn}${_snmp_lname}: DB not updated for ${_snmp_lupd_days}d (last: ${_snmp_lupd_date})\n"
					[[ -z "${lic_ignore_all}" ]] && {
						fg_problem_output+="${status_crit} - License ${_fwn}${_snmp_lname}: DB stale (${_snmp_lupd_days}d)\n"
						(( _lic_crit++ ))
					}
				elif [[ "${_snmp_lupd_age}" -gt "${_db_warn_sec}" ]]; then
					fg_output+="${_lef_w} - License ${_fwn}${_snmp_lname}: DB not updated for ${_snmp_lupd_days}d (last: ${_snmp_lupd_date})\n"
					[[ -z "${lic_ignore_all}" ]] && {
						fg_problem_output+="${status_warn} - License ${_fwn}${_snmp_lname}: DB stale (${_snmp_lupd_days}d)\n"
						(( _lic_warn++ ))
					}
				elif [[ -n "${verbose}" ]]; then
					fg_output+="${status_ok} - License ${_fwn}${_snmp_lname}: DB updated ${_snmp_lupd_days}d ago (${_snmp_lupd_date})\n"
				fi
				_snmp_lbl2="${_snmp_lname//-/_}"
				fg_perf+=" lic_${_snmp_lbl2}_db_age=${_snmp_lupd_days};${warn_db_age};${crit_db_age};0"
			fi
		done

		unset _lic_bl_map _lsnmp_names _lsnmp_expires _lsnmp_updts

		if [[ "${_lic_crit}" -eq 0 && "${_lic_warn}" -eq 0 ]]; then
			fg_output+="${status_ok} - License${_fws}all checked licenses valid (SNMP)\n"
		fi
	elif [[ -n "${_snmp_only}" ]]; then
		fg_output+="${status_ok} - License${_fws}not available in SNMP-only mode\n"
	else
		fg_output+="${status_unkn} - ${_fwh}Failed to retrieve license status\n"
		fg_problem_output+="${status_unkn} - ${_fwh}Failed to retrieve license status\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# FortiCloud Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_cloud}" || -n "${enable_all}" ) && -z "${disable_cloud}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="FortiCloud:\n---------------------------------------\n"
	fi

	_cloud_lic_buf=$(cat "${_pf}/cloud_lic.json" 2>/dev/null)
	_cloud_log_buf=$(cat "${_pf}/cloud_log.json" 2>/dev/null)

	if [[ -n "${_cloud_lic_buf}" && "${_cloud_lic_buf}" =~ '"results"' ]]; then
		# Connection status
		_fc_status=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud.status // ""' 2>/dev/null)
		_fc_account=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud.account // ""' 2>/dev/null)
		_fc_domain=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud.domain // ""' 2>/dev/null)

		_fc_state="${status_ok}"
		if [[ "${_fc_status}" != "cloud_logged_in" && -n "${_fc_status}" ]]; then
			_fc_state="${status_warn}"
			fg_problem_output+="${status_warn} - FortiCloud${_fws}not logged in (status: ${_fc_status})\n"
		fi
		# Domain check
		if [[ -n "${cloud_domain_expected}" && -n "${_fc_domain}" && "${_fc_domain}" != "null" ]]; then
			if [[ "${_fc_domain^^}" != "${cloud_domain_expected^^}" ]]; then
				_fc_state="${status_warn}"
				fg_problem_output+="${status_warn} - FortiCloud${_fws}domain mismatch: got '${_fc_domain}', expected '${cloud_domain_expected}'\n"
			fi
		fi
		_fc_acct_s="" ; [[ -n "${_fc_account}" && "${_fc_account}" != "null" ]] && _fc_acct_s=" | account: ${_fc_account}"
		_fc_dom_s=""  ; [[ -n "${_fc_domain}"  && "${_fc_domain}"  != "null" ]] && _fc_dom_s=" | domain: ${_fc_domain}"
		fg_output+="${_fc_state} - FortiCloud${_fws}${_fc_status:-unknown}${_fc_acct_s}${_fc_dom_s}\n"

		# Log storage usage
		_fcl_used=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_logging.used_bytes // ""' 2>/dev/null)
		_fcl_max=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_logging.max_bytes // ""' 2>/dev/null)
		_fcl_ret=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_logging.log_retention_days // ""' 2>/dev/null)
		_fcl_lstatus=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_logging.status // ""' 2>/dev/null)

		_fcl_pct=0
		if [[ "${_fcl_used}" =~ ^[0-9]+$ && "${_fcl_max}" =~ ^[0-9]+$ && "${_fcl_max}" -gt 0 ]]; then
			_fcl_pct=$(( _fcl_used * 100 / _fcl_max ))
			_fcl_used_gb=$(echo "scale=1; ${_fcl_used}/1073741824" | bc 2>/dev/null)
			_fcl_max_tb=$(echo "scale=1; ${_fcl_max}/1099511627776" | bc 2>/dev/null)
			_fcl_ret_s="" ; [[ -n "${_fcl_ret}" && "${_fcl_ret}" != "null" ]] && _fcl_ret_s=" | retention: ${_fcl_ret}d"
			_fcl_state="${status_ok}"
			if (( _fcl_pct >= crit_cloud_log_usage )) 2>/dev/null; then
				_fcl_state="${status_crit}"
				fg_problem_output+="${status_crit} - FortiCloud${_fws}log storage ${_fcl_pct}% CRITICAL (threshold: ${crit_cloud_log_usage}%)\n"
			elif (( _fcl_pct >= warn_cloud_log_usage )) 2>/dev/null; then
				_fcl_state="${status_warn}"
				fg_problem_output+="${status_warn} - FortiCloud${_fws}log storage ${_fcl_pct}% WARNING (threshold: ${warn_cloud_log_usage}%)\n"
			fi
			fg_output+="${_fcl_state} - FortiCloud${_fws}log storage ${_fcl_used_gb}GB / ${_fcl_max_tb}TB (${_fcl_pct}%) | license: ${_fcl_lstatus}${_fcl_ret_s}\n"
			fg_perf+=" forticloud_log_used_bytes=${_fcl_used}"
			fg_perf+=" forticloud_log_max_bytes=${_fcl_max}"
			fg_perf+=" forticloud_log_pct=${_fcl_pct};${warn_cloud_log_usage};${crit_cloud_log_usage};0;100"
		fi

		# Sandbox stats
		_fcs_status=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_sandbox.status // ""' 2>/dev/null)
		_fcs_daily=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_sandbox.files_uploaded_daily // ""' 2>/dev/null)
		_fcs_max=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
			'.results.forticloud_sandbox.max_files_daily // ""' 2>/dev/null)
		if [[ -n "${_fcs_status}" && "${_fcs_status}" != "null" && "${_fcs_status}" != "no_license" ]]; then
			_fcs_pct=0 ; _fcs_state="${status_ok}"
			if [[ "${_fcs_daily}" =~ ^[0-9]+$ && "${_fcs_max}" =~ ^[0-9]+$ && "${_fcs_max}" -gt 0 ]]; then
				_fcs_pct=$(( _fcs_daily * 100 / _fcs_max ))
				if (( _fcs_pct >= crit_cloud_sandbox )) 2>/dev/null; then
					_fcs_state="${status_crit}"
					fg_problem_output+="${status_crit} - FortiCloud${_fws}sandbox daily quota ${_fcs_pct}% CRITICAL (${_fcs_daily}/${_fcs_max}, threshold: ${crit_cloud_sandbox}%)\n"
				elif (( _fcs_pct >= warn_cloud_sandbox )) 2>/dev/null; then
					_fcs_state="${status_warn}"
					fg_problem_output+="${status_warn} - FortiCloud${_fws}sandbox daily quota ${_fcs_pct}% WARNING (${_fcs_daily}/${_fcs_max}, threshold: ${warn_cloud_sandbox}%)\n"
				fi
			fi
			_fcs_quota_s=""
			[[ "${_fcs_daily}" =~ ^[0-9]+$ && "${_fcs_max}" =~ ^[0-9]+$ ]] && \
				_fcs_quota_s=" | files today: ${_fcs_daily}/${_fcs_max} (${_fcs_pct}%)"
			fg_output+="${_fcs_state} - FortiCloud${_fws}sandbox ${_fcs_status}${_fcs_quota_s}\n"
			[[ "${_fcs_daily}" =~ ^[0-9]+$ ]] && \
				fg_perf+=" forticloud_sandbox_daily=${_fcs_daily};${warn_cloud_sandbox};${crit_cloud_sandbox}"
			[[ "${_fcs_pct}" =~ ^[0-9]+$ && "${_fcs_max}" -gt 0 ]] && \
				fg_perf+=" forticloud_sandbox_pct=${_fcs_pct};${warn_cloud_sandbox};${crit_cloud_sandbox};0;100"
		fi

		# Other cloud service statuses (verbose: show all; non-verbose: only problems)
		for _cs in fortianalyzer_cloud fortimanager_cloud fortisandbox_cloud fortiems_cloud; do
			_cs_status=$(echo "${_cloud_lic_buf}" | "${JQ}" --unbuffered -r \
				--arg svc "${_cs}" '.results[$svc].status // ""' 2>/dev/null)
			[[ -z "${_cs_status}" || "${_cs_status}" == "null" ]] && continue
			_cs_label="${_cs//_/ }"
			if [[ "${_cs_status}" == "no_license" ]]; then
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - FortiCloud${_fws}${_cs_label}: not licensed\n"
			elif [[ "${_cs_status}" == "licensed" || "${_cs_status}" == "free_license" ]]; then
				fg_output+="${status_ok} - FortiCloud${_fws}${_cs_label}: ${_cs_status}\n"
			else
				fg_output+="${status_warn} - FortiCloud${_fws}${_cs_label}: ${_cs_status}\n"
			fi
		done

		# Staging disk from monitor/log/forticloud
		if [[ -n "${_cloud_log_buf}" && "${_cloud_log_buf}" =~ '"results"' ]]; then
			_fcld_quota=$(echo "${_cloud_log_buf}" | "${JQ}" --unbuffered -r \
				'.results.disk.quota // ""' 2>/dev/null)
			_fcld_used=$(echo "${_cloud_log_buf}" | "${JQ}" --unbuffered -r \
				'.results.disk.used // ""' 2>/dev/null)
			if [[ "${_fcld_quota}" =~ ^[0-9]+$ && "${_fcld_quota}" -gt 0 && "${_fcld_used}" =~ ^[0-9]+$ ]]; then
				_fcld_pct=$(( _fcld_used * 100 / _fcld_quota ))
				_fcld_used_kb=$(( _fcld_used / 1024 ))
				_fcld_quota_mb=$(( _fcld_quota / 1048576 ))
				_fcld_state="${status_ok}"
				if (( _fcld_pct >= crit_cloud_staging )) 2>/dev/null; then
					_fcld_state="${status_crit}"
					fg_problem_output+="${status_crit} - FortiCloud${_fws}staging disk ${_fcld_pct}% CRITICAL (threshold: ${crit_cloud_staging}%)\n"
				elif (( _fcld_pct >= warn_cloud_staging )) 2>/dev/null; then
					_fcld_state="${status_warn}"
					fg_problem_output+="${status_warn} - FortiCloud${_fws}staging disk ${_fcld_pct}% WARNING (threshold: ${warn_cloud_staging}%)\n"
				fi
				fg_output+="${_fcld_state} - FortiCloud${_fws}staging disk ${_fcld_used_kb}KB / ${_fcld_quota_mb}MB (${_fcld_pct}%)\n"
				fg_perf+=" forticloud_staging_used_bytes=${_fcld_used}"
				fg_perf+=" forticloud_staging_pct=${_fcld_pct};${warn_cloud_staging};${crit_cloud_staging};0;100"
			fi
		fi
	else
		fg_output+="${status_unkn} - FortiCloud${_fws}failed to retrieve license status\n"
		fg_problem_output+="${status_unkn} - FortiCloud${_fws}failed to retrieve license status\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Certificate Expiry Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_cert}" || -n "${enable_all}" ) && -z "${disable_cert}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Certificates:\n---------------------------------------\n"
	fi

	# Use monitor endpoint - richer than CMDB: has valid_to epoch, cert_protocol, exists flag
	_cert_buffer=$(cat "${_pf}/certs.json" 2>/dev/null)

	if [[ -n "${_cert_buffer}" && "${_cert_buffer}" =~ '"results"' ]]; then
		declare -A _cert_bl_map
		if [[ -n "${cert_blacklist}" ]]; then
			IFS=',' read -ra _cert_bl_arr <<< "${cert_blacklist}"
			for _cert_bl_e in "${_cert_bl_arr[@]}"; do _cert_bl_map["${_cert_bl_e}"]=1; done
		fi

		_cert_now=$(date +%s)
		_cert_warn_sec=$(( warn_cert * 86400 ))
		_cert_crit_sec=$(( crit_cert * 86400 ))
		_cert_warn=0
		_cert_crit=0
		_cert_ok=0

		# Only certs that actually exist on the device; skip factory in non-verbose
		declare -a _cert_names _cert_epochs _cert_expraw _cert_sources _cert_protocols _cert_statuses _cert_subjects
		while IFS=$'\t' read -r _cn_name _cn_epoch _cn_expraw _cn_source _cn_proto _cn_status _cn_subj; do
			_cert_names+=("${_cn_name}")
			_cert_epochs+=("${_cn_epoch}")
			_cert_expraw+=("${_cn_expraw}")
			_cert_sources+=("${_cn_source}")
			_cert_protocols+=("${_cn_proto}")
			_cert_statuses+=("${_cn_status}")
			_cert_subjects+=("${_cn_subj}")
		done < <(echo "${_cert_buffer}" | "${JQ}" --unbuffered -r '
			.results[] |
			select(.exists == true) |
			[
				(.name // "unknown"),
				(.valid_to // 0 | tostring),
				(.valid_to_raw // ""),
				(.source // ""),
				(if .cert_protocol != null and .cert_protocol != "none" then .cert_protocol else "" end),
				(.status // ""),
				(.subject_raw // "")
			] | join("\t")' 2>/dev/null)

		_cert_total=${#_cert_names[@]}

		for count in "${!_cert_names[@]}"; do
			_cn="${_cert_names[count]}"
			[[ -n "${_cert_bl_map[${_cn}]}" ]] && continue
			[[ "${_cert_sources[count]}" == "factory" && -z "${verbose}" ]] && continue

			_cn_proto_s=""
			[[ -n "${_cert_protocols[count]}" ]] && _cn_proto_s=" [${_cert_protocols[count]}]"

			_cn_subj_s=""
			[[ -n "${_cert_subjects[count]}" ]] && _cn_subj_s=" | ${_cert_subjects[count]}"

			_cn_exp_epoch="${_cert_epochs[count]}"

			# No expiry timestamp
			if [[ "${_cn_exp_epoch}" == "0" || -z "${_cn_exp_epoch}" ]]; then
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - Cert ${_fwn}${_cn}${_cn_proto_s}: present (no expiry)\n"
				(( _cert_ok++ ))
				continue
			fi

			# Use pre-formatted raw date from API when available, else format epoch
			if [[ -n "${_cert_expraw[count]}" && "${_cert_expraw[count]}" != "null" ]]; then
				_cn_exp_date="${_cert_expraw[count]%% *}"
			else
				_cn_exp_date=$(date -d "@${_cn_exp_epoch}" "+%Y-%m-%d" 2>/dev/null)
			fi

			_cn_diff=$(( _cn_exp_epoch - _cert_now ))
			_cn_days=$(( _cn_diff / 86400 ))

			if [[ "${_cn_diff}" -lt 0 ]]; then
				fg_output+="${status_crit} - Cert ${_fwn}${_cn}${_cn_proto_s}: EXPIRED (${_cn_exp_date})${_cn_subj_s}\n"
				fg_problem_output+="${status_crit} - Cert ${_fwn}${_cn}: EXPIRED\n"
				(( _cert_crit++ ))
			elif [[ "${_cn_diff}" -lt "${_cert_crit_sec}" ]]; then
				fg_output+="${status_crit} - Cert ${_fwn}${_cn}${_cn_proto_s}: expires in ${_cn_days}d (${_cn_exp_date})${_cn_subj_s}\n"
				fg_problem_output+="${status_crit} - Cert ${_fwn}${_cn}: expires in ${_cn_days}d\n"
				(( _cert_crit++ ))
			elif [[ "${_cn_diff}" -lt "${_cert_warn_sec}" ]]; then
				fg_output+="${status_warn} - Cert ${_fwn}${_cn}${_cn_proto_s}: expires in ${_cn_days}d (${_cn_exp_date})${_cn_subj_s}\n"
				fg_problem_output+="${status_warn} - Cert ${_fwn}${_cn}: expires in ${_cn_days}d\n"
				(( _cert_warn++ ))
			else
				(( _cert_ok++ ))
				fg_output+="${status_ok} - Cert ${_fwn}${_cn}${_cn_proto_s}: valid until ${_cn_exp_date} (${_cn_days}d)${_cn_subj_s}\n"
			fi
		done

		if [[ "${_cert_crit}" -eq 0 && "${_cert_warn}" -eq 0 && -z "${verbose}" ]]; then
			fg_output+="${status_ok} - Certs${_fws}${_cert_ok} certificate(s) OK\n"
		fi

		fg_perf+=" certs_total=${_cert_total} certs_ok=${_cert_ok} certs_warn=${_cert_warn} certs_crit=${_cert_crit}"

		unset _cert_names _cert_epochs _cert_expraw _cert_sources _cert_protocols _cert_statuses _cert_subjects _cert_bl_map
	else
		fg_output+="${status_ok} - Certs${_fws}endpoint not available\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# System Alerts Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_alerts}" || -n "${enable_all}" ) && -z "${disable_alerts}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="System Alerts:\n---------------------------------------\n"
	fi

	_al_buffer=$(cat "${_pf}/alerts.json" 2>/dev/null)

	_al_http=$(echo "${_al_buffer}" | "${JQ}" --unbuffered -r '.http_status // ""' 2>/dev/null)

	if [[ -n "${_al_buffer}" && "${_al_buffer}" =~ '"results"' && "${_al_http}" != "404" ]]; then
		_al_crit=0
		_al_warn=0
		_al_info=0

		declare -a _al_levels _al_msgs _al_times
		while IFS=$'\t' read -r _al_level _al_msg _al_time; do
			_al_levels+=("${_al_level}")
			_al_msgs+=("${_al_msg}")
			_al_times+=("${_al_time}")
		done < <(echo "${_al_buffer}" | "${JQ}" --unbuffered -r '
			.results[] |
			select(.level == "emergency" or .level == "alert" or .level == "critical" or .level == "error") |
			[
				(.level // "unknown"),
				(.msg // .message // ""),
				(.date // "")
			] | join("\t")' 2>/dev/null)

		for count in "${!_al_levels[@]}"; do
			case "${_al_levels[count]}" in
			emergency|alert|critical)
				(( _al_crit++ ))
				fg_output+="${status_crit} - Alert ${_fwn}[${_al_levels[count]}]: ${_al_msgs[count]}\n"
				fg_problem_output+="${status_crit} - Alert ${_fwn}[${_al_levels[count]}]: ${_al_msgs[count]}\n"
				;;
			error)
				(( _al_warn++ ))
				fg_output+="${status_warn} - Alert ${_fwn}[error]: ${_al_msgs[count]}\n"
				fg_problem_output+="${status_warn} - Alert ${_fwn}[error]: ${_al_msgs[count]}\n"
				;;
			esac
		done

		if [[ "${_al_crit}" -eq 0 && "${_al_warn}" -eq 0 ]]; then
			fg_output+="${status_ok} - Alerts${_fws}no critical/error events in last ${alert_rows} entries\n"
		fi

		fg_perf+=" alerts_crit=${_al_crit} alerts_warn=${_al_warn}"

		unset _al_levels _al_msgs _al_times
	elif [[ "${_al_http}" == "404" ]]; then
		_al_vdom_hint="" ; [[ -n "${alerts_vdom}" ]] && _al_vdom_hint=" (vdom: ${alerts_vdom})"
		[[ -n "${verbose}" ]] && \
			fg_output+="${status_ok} - Alerts${_fws}event log not on disk${_al_vdom_hint} - event logging to disk may not be configured (check log.disk/filter)\n"
		fg_perf+=" alerts_crit=0 alerts_warn=0"
	else
		[[ -n "${verbose}" ]] && \
			fg_output+="${status_ok} - Alerts${_fws}disk log not available or no events\n"
		fg_perf+=" alerts_crit=0 alerts_warn=0"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Firmware Version Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_firmware}" || -n "${enable_all}" ) && -z "${disable_firmware}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Firmware:\n---------------------------------------\n"
	fi

	_fw_buffer=$(cat "${_pf}/firmware.json" 2>/dev/null)

	# Blacklist JSON array (used for FG, AP, SW, FEX firmware checks)
	_fw_bl_json="[]"
	if [[ -n "${firmware_blacklist}" ]]; then
		_fw_bl_json=$(printf '%s' "${firmware_blacklist}" | "${JQ}" -Rc \
			'split(",") | map(ltrimstr(" ") | rtrimstr(" ")) | map(select(length > 0))' 2>/dev/null)
		[[ -z "${_fw_bl_json}" ]] && _fw_bl_json="[]"
	fi

	if [[ -n "${_fw_buffer}" && "${_fw_buffer}" =~ '"results"' ]]; then
		_fw_installed=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current.version // "unknown"' 2>/dev/null)
		_fw_build=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current.build // ""' 2>/dev/null)
		_fw_type=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current."release-type" // ""' 2>/dev/null)
		_fw_maturity=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current.maturity // ""' 2>/dev/null)
		_fw_cur_major=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current.major // 0' 2>/dev/null)
		_fw_cur_minor=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current.minor // 0' 2>/dev/null)
		_fw_cur_patch=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			'.results.current.patch // 0' 2>/dev/null)

		_fw_build_s="" ; [[ -n "${_fw_build}"    && "${_fw_build}"    != "null" ]] && _fw_build_s=" build ${_fw_build}"
		_fw_type_s=""  ; [[ -n "${_fw_type}"     && "${_fw_type}"     != "null" && "${_fw_type}" != "" ]] && _fw_type_s=" (${_fw_type})"
		_fw_mat_s=""   ; [[ -n "${_fw_maturity}" && "${_fw_maturity}" != "null" && "${_fw_maturity}" != "" ]] && _fw_mat_s="/${_fw_maturity}"

		# Maturity filter for available versions: "M" = Mature, "F" = Feature/Fresh
		_fw_mat_filter='true'
		[[ -n "${firmware_mature_only}" ]] && _fw_mat_filter='(.maturity == "M")'

		# Latest GA patch update (same major.minor, higher patch)
		_fw_new_patch=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			--argjson maj "${_fw_cur_major}" --argjson min "${_fw_cur_minor}" --argjson pat "${_fw_cur_patch}" \
			--argjson bl "${_fw_bl_json}" '
			[(.results.available // [])[] |
				select(."release-type" == "GA" and .major == $maj and .minor == $min and .patch > $pat) |
				select('"${_fw_mat_filter}"') |
				select(.version as $v | $bl | all(. as $b | ($v | index($b)) == null))] |
			sort_by(.patch) | last | .version // ""' 2>/dev/null)

		# Latest GA minor update (same major, higher minor)
		_fw_new_minor=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			--argjson maj "${_fw_cur_major}" --argjson min "${_fw_cur_minor}" \
			--argjson bl "${_fw_bl_json}" '
			[(.results.available // [])[] |
				select(."release-type" == "GA" and .major == $maj and .minor > $min) |
				select('"${_fw_mat_filter}"') |
				select(.version as $v | $bl | all(. as $b | ($v | index($b)) == null))] |
			sort_by([.minor,.patch]) | last | .version // ""' 2>/dev/null)

		# Latest GA major update (higher major)
		_fw_new_major=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
			--argjson maj "${_fw_cur_major}" \
			--argjson bl "${_fw_bl_json}" '
			[(.results.available // [])[] |
				select(."release-type" == "GA" and .major > $maj) |
				select('"${_fw_mat_filter}"') |
				select(.version as $v | $bl | all(. as $b | ($v | index($b)) == null))] |
			sort_by([.major,.minor,.patch]) | last | .version // ""' 2>/dev/null)

		_fw_state="${status_ok}"
		fg_output+="${_fw_state} - Firmware${_fws}current: ${_fw_installed}${_fw_build_s}${_fw_type_s}${_fw_mat_s}\n"

		# Patch update
		if [[ -n "${_fw_new_patch}" && "${_fw_new_patch}" != "null" ]]; then
			if [[ -z "${no_firmware_updates_warn}" && -z "${no_firmware_minor_warn}" ]]; then
				_fw_state="${status_warn}"
				fg_output+="${status_warn} - Firmware${_fws}patch update available: ${_fw_new_patch}\n"
				fg_problem_output+="${status_warn} - Firmware${_fws}patch update available (installed: ${_fw_installed}, available: ${_fw_new_patch})\n"
			else
				fg_output+="${status_ok} - Firmware${_fws}patch update available: ${_fw_new_patch}\n"
			fi
		fi

		# Minor update
		if [[ -n "${_fw_new_minor}" && "${_fw_new_minor}" != "null" ]]; then
			if [[ -z "${no_firmware_updates_warn}" && -z "${no_firmware_minor_warn}" ]]; then
				_fw_state="${status_warn}"
				fg_output+="${status_warn} - Firmware${_fws}minor update available: ${_fw_new_minor}\n"
				fg_problem_output+="${status_warn} - Firmware${_fws}minor update available (installed: ${_fw_installed}, available: ${_fw_new_minor})\n"
			else
				fg_output+="${status_ok} - Firmware${_fws}minor update available: ${_fw_new_minor}\n"
			fi
		fi

		# Major update
		if [[ -n "${_fw_new_major}" && "${_fw_new_major}" != "null" ]]; then
			if [[ -z "${no_firmware_updates_warn}" && -z "${no_firmware_major_warn}" ]]; then
				_fw_state="${status_warn}"
				fg_output+="${status_warn} - Firmware${_fws}major update available: ${_fw_new_major}\n"
				fg_problem_output+="${status_warn} - Firmware${_fws}major update available (installed: ${_fw_installed}, available: ${_fw_new_major})\n"
			else
				fg_output+="${status_ok} - Firmware${_fws}major update available: ${_fw_new_major}\n"
			fi
		fi

		if [[ -n "${verbose}" ]]; then
			_fw_show_all_arg=false
			[[ -n "${firmware_show_all}" ]] && _fw_show_all_arg=true
			_fw_avail_all=$(echo "${_fw_buffer}" | "${JQ}" --unbuffered -r \
				--argjson cmaj "${_fw_cur_major}" --argjson cmin "${_fw_cur_minor}" --argjson cpat "${_fw_cur_patch}" \
				--argjson show_all "${_fw_show_all_arg}" '
				[(.results.available // [])[] |
					select(
						$show_all or
						(.major > $cmaj or
						 (.major == $cmaj and .minor > $cmin) or
						 (.major == $cmaj and .minor == $cmin and .patch > $cpat))
					) |
					(.version // "") +
					(if (."release-type" // "") != "" then " (" + ."release-type" + "/" + (.maturity // "") + ")" else "" end)
				] | sort | .[]' 2>/dev/null)
			if [[ -n "${_fw_avail_all}" ]]; then
				while IFS= read -r _fv; do
					fg_output+="${status_ok} - Firmware${_fws}available: ${_fv}\n"
				done <<< "${_fw_avail_all}"
			fi
		fi
	elif [[ -n "${_snmp_only}" && -n "${fg_version}" && "${fg_version}" != "unknown" ]]; then
		fg_output+="${status_ok} - Firmware${_fws}current: ${fg_version} (SNMP, update check not available)\n"
	else
		fg_output+="${status_ok} - Firmware${_fws}endpoint not available\n"
	fi

	# ---------------------------------------------------------------------------
	# FortiAP firmware: per-AP current version + per-model update check
	# ---------------------------------------------------------------------------
	_ap_mgd_buf=$(cat "${_pf}/managed_ap.json" 2>/dev/null)
	_ap_wf_buf=$(cat  "${_pf}/wifi_firmware.json" 2>/dev/null)

	if [[ -n "${_ap_mgd_buf}" && "${_ap_mgd_buf}" =~ '"results"' ]]; then
		# Load per-model update data from wifi_firmware.json into associative arrays
		declare -A _apfw_latest_v _apfw_avail_v _apfw_err_v
		if [[ -n "${_ap_wf_buf}" && "${_ap_wf_buf}" =~ '"models"' ]]; then
			while IFS=$'\t' read -r _wfm _wflv _wfav _wfer; do
				_apfw_latest_v["${_wfm}"]="${_wflv}"
				_apfw_avail_v["${_wfm}"]="${_wfav}"
				_apfw_err_v["${_wfm}"]="${_wfer}"
			done < <(echo "${_ap_wf_buf}" | "${JQ}" --unbuffered -r '
				.results.models | to_entries[] |
				[.key,
				 (.value.latest_version // ""),
				 ((.value.available // false) | tostring),
				 (.value.error // "")] | join("\t")' 2>/dev/null)
		fi

		# Per-AP firmware lines
		while IFS=$'\t' read -r _apfw_name _apfw_os; do
			[[ -z "${_apfw_os}" ]] && continue

			# Parse os_version: "MODEL-vX.Y.Z-buildNNNN" → model, version, build
			_apfw_model="${_apfw_os%%-v*}"
			_apfw_raw="${_apfw_os#*-v}"
			[[ "${_apfw_raw}" == "${_apfw_os}" ]] && { _apfw_model="" ; _apfw_raw="${_apfw_os#v}" ; }
			_apfw_cver="${_apfw_raw%-build*}"
			_apfw_cbld="${_apfw_raw##*-build}"
			[[ "${_apfw_cbld}" == "${_apfw_raw}" ]] && _apfw_cbld=""
			_apfw_cur_s="v${_apfw_cver}"
			[[ -n "${_apfw_cbld}" ]] && _apfw_cur_s+=" build ${_apfw_cbld}"

			fg_output+="${status_ok} - Firmware AP ${_apfw_name}: current: ${_apfw_cur_s}\n"

			# Cross-reference with wifi_firmware data for this model
			_apfw_lv="${_apfw_latest_v["${_apfw_model}"]:-}"
			_apfw_av="${_apfw_avail_v["${_apfw_model}"]:-}"
			_apfw_er="${_apfw_err_v["${_apfw_model}"]:-}"

			if [[ "${_apfw_av}" == "true" && -n "${_apfw_lv}" && "${_apfw_lv}" != "null" ]]; then
				# Parse latest version (handles "MODEL-vX.Y.Z-buildN" or "X.Y.Z-buildN")
				_apfw_lraw="${_apfw_lv#*-v}"
				[[ "${_apfw_lraw}" == "${_apfw_lv}" ]] && _apfw_lraw="${_apfw_lv#v}"
				_apfw_lver="${_apfw_lraw%-build*}"
				_apfw_lbld="${_apfw_lraw##*-build}"
				[[ "${_apfw_lbld}" == "${_apfw_lraw}" ]] && _apfw_lbld=""
				_apfw_lat_s="v${_apfw_lver}"
				[[ -n "${_apfw_lbld}" ]] && _apfw_lat_s+=" (build ${_apfw_lbld})"

				# Determine update type by comparing version numbers
				IFS='.' read -r _acv_maj _acv_min _acv_pat <<< "${_apfw_cver}"
				IFS='.' read -r _alv_maj _alv_min _alv_pat <<< "${_apfw_lver}"
				_apfw_uptype="update"
				if [[ "${_alv_maj}" =~ ^[0-9]+$ && "${_acv_maj}" =~ ^[0-9]+$ ]]; then
					if   (( _alv_maj >  _acv_maj )) 2>/dev/null; then _apfw_uptype="major update"
					elif (( _alv_maj == _acv_maj && _alv_min > _acv_min )) 2>/dev/null; then _apfw_uptype="minor update"
					elif (( _alv_maj == _acv_maj && _alv_min == _acv_min && _alv_pat > _acv_pat )) 2>/dev/null; then _apfw_uptype="patch update"
					fi
				fi

				# Blacklist check (substring match against raw latest version string)
				_apfw_bl=0
				if [[ -n "${firmware_blacklist}" ]]; then
					IFS=',' read -ra _apfw_bl_arr <<< "${firmware_blacklist}"
					for _apfw_bl_v in "${_apfw_bl_arr[@]}"; do
						_apfw_bl_v="${_apfw_bl_v# }" ; _apfw_bl_v="${_apfw_bl_v% }"
						[[ -n "${_apfw_bl_v}" && "${_apfw_lv}" == *"${_apfw_bl_v}"* ]] && _apfw_bl=1 && break
					done
					unset _apfw_bl_arr
				fi

				if [[ "${_apfw_bl}" -eq 1 ]]; then
					[[ -n "${verbose}" ]] && \
						fg_output+="${status_ok} - Firmware AP ${_apfw_name}: ${_apfw_uptype} ${_apfw_lat_s} blacklisted\n"
				elif [[ -z "${no_firmware_updates_warn}" ]]; then
					fg_output+="${status_warn} - Firmware AP ${_apfw_name}: ${_apfw_uptype} available: ${_apfw_lat_s}\n"
					fg_problem_output+="${status_warn} - Firmware AP ${_apfw_name}: ${_apfw_uptype} available (current: v${_apfw_cver}, latest: ${_apfw_lat_s})\n"
				else
					fg_output+="${status_ok} - Firmware AP ${_apfw_name}: ${_apfw_uptype} available: ${_apfw_lat_s}\n"
				fi
			elif [[ -n "${_apfw_er}" ]]; then
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - Firmware AP ${_apfw_name}: update check unavailable (FortiGuard timeout)\n"
			elif [[ -n "${verbose}" && -n "${_apfw_av}" ]]; then
				fg_output+="${status_ok} - Firmware AP ${_apfw_name}: up-to-date\n"
			fi
		done < <(echo "${_ap_mgd_buf}" | "${JQ}" --unbuffered -r \
			'.results[] | [(.name // .wtp_id), (.os_version // "")] | join("\t")' 2>/dev/null)

		unset _apfw_latest_v _apfw_avail_v _apfw_err_v
	fi

	# ---------------------------------------------------------------------------
	# FortiSwitch firmware (current version from managed-switch; no update API)
	# ---------------------------------------------------------------------------
	if [[ -n "${verbose}" ]]; then
		_sw_fw_buf=$(cat "${_pf}/managed_sw.json" 2>/dev/null)
		if [[ -n "${_sw_fw_buf}" && "${_sw_fw_buf}" =~ '"results"' ]]; then
			while IFS=$'\t' read -r _swfw_name _swfw_serial _swfw_ver; do
				_swfw_ver_s="unknown"
				[[ -n "${_swfw_ver}" && "${_swfw_ver}" != "null" && "${_swfw_ver}" != "" ]] && \
					_swfw_ver_s="${_swfw_ver}"
				fg_output+="${status_ok} - Firmware SW ${_swfw_name}: current: ${_swfw_ver_s} | serial: ${_swfw_serial}\n"
			done < <(echo "${_sw_fw_buf}" | "${JQ}" --unbuffered -r '
				.results[] |
				[(.name // .switch_id), (.serial // "unknown"),
				 (.os_version // .firmware_version // .version // "")] | join("\t")' 2>/dev/null)
		fi
	fi

	# ---------------------------------------------------------------------------
	# FortiExtender firmware (current version from fortiextender; no update API)
	# ---------------------------------------------------------------------------
	if [[ -n "${verbose}" ]]; then
		_fex_fw_buf=$(cat "${_pf}/fex.json" 2>/dev/null)
		if [[ -n "${_fex_fw_buf}" && "${_fex_fw_buf}" =~ '"results"' ]]; then
			while IFS=$'\t' read -r _fexfw_name _fexfw_serial _fexfw_ver; do
				_fexfw_ver_s="unknown"
				[[ -n "${_fexfw_ver}" && "${_fexfw_ver}" != "null" && "${_fexfw_ver}" != "" ]] && \
					_fexfw_ver_s="${_fexfw_ver}"
				fg_output+="${status_ok} - Firmware FEX ${_fexfw_name}: current: ${_fexfw_ver_s} | serial: ${_fexfw_serial}\n"
			done < <(echo "${_fex_fw_buf}" | "${JQ}" --unbuffered -r '
				.results[] |
				[(.name // .id), (.serial // "unknown"),
				 (.os_version // .firmware_version // .version // "")] | join("\t")' 2>/dev/null)
		fi
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Hardware Sensor Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_sensors}" || -n "${enable_all}" ) && -z "${disable_sensors}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Hardware Sensors:\n---------------------------------------\n"
	fi

	_sen_buffer=$(cat "${_pf}/sensors.json" 2>/dev/null)

	if [[ -n "${_sen_buffer}" && "${_sen_buffer}" =~ '"results"' ]]; then
		_sen_crit=0
		_sen_warn=0
		_sen_ok=0

		declare -a _sen_names _sen_vals _sen_types _sen_lnc _sen_lc _sen_unc _sen_uc
		while IFS=$'\t' read -r _sn_name _sn_val _sn_type _sn_lnc _sn_lc _sn_unc _sn_uc; do
			_sen_names+=("${_sn_name}")
			_sen_vals+=("${_sn_val}")
			_sen_types+=("${_sn_type}")
			_sen_lnc+=("${_sn_lnc}")
			_sen_lc+=("${_sn_lc}")
			_sen_unc+=("${_sn_unc}")
			_sen_uc+=("${_sn_uc}")
		done < <(echo "${_sen_buffer}" | "${JQ}" --unbuffered -r '
			.results[] |
			select(.value != null and .value != 0) |
			[
				(.name // "unknown"),
				((.value // 0) | tostring),
				(.type // ""),
				((.thresholds.lower_non_critical // "") | tostring),
				((.thresholds.lower_critical // "") | tostring),
				((.thresholds.upper_non_critical // "") | tostring),
				((.thresholds.upper_critical // "") | tostring)
			] | join("\t")' 2>/dev/null)

		for count in "${!_sen_names[@]}"; do
			_sn="${_sen_names[count]}"
			_sv="${_sen_vals[count]}"
			_st="${_sen_types[count]}"
			_lnc="${_sen_lnc[count]}"
			_lc="${_sen_lc[count]}"
			_unc="${_sen_unc[count]}"
			_uc="${_sen_uc[count]}"

			_sen_unit=""
			case "${_st}" in
				temperature) _sen_unit="°C" ;;
				fan)         _sen_unit=" RPM" ;;
				voltage)     _sen_unit="V" ;;
			esac

			_sen_lbl="${_sn//[ \/]/_}"
			_sen_pw="${_unc}" ; [[ "${_sen_pw}" == "null" ]] && _sen_pw=""
			_sen_pc="${_uc}"  ; [[ "${_sen_pc}" == "null" ]] && _sen_pc=""
			fg_perf+=" sensor_${_sen_lbl}=${_sv};${_sen_pw};${_sen_pc}"

			_sen_state="${status_ok}"
			if [[ -n "${_lc}" && "${_lc}" != "null" ]] && \
			   "${AWK}" "BEGIN{exit !(${_sv}+0 < ${_lc}+0)}" 2>/dev/null; then
				_sen_state="${status_crit}"
				fg_output+="${status_crit} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} below lower CRITICAL threshold ${_lc}\n"
				fg_problem_output+="${status_crit} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} (lower_crit: ${_lc})\n"
				(( _sen_crit++ ))
			elif [[ -n "${_uc}" && "${_uc}" != "null" ]] && \
			     "${AWK}" "BEGIN{exit !(${_sv}+0 > ${_uc}+0)}" 2>/dev/null; then
				_sen_state="${status_crit}"
				fg_output+="${status_crit} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} above upper CRITICAL threshold ${_uc}\n"
				fg_problem_output+="${status_crit} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} (upper_crit: ${_uc})\n"
				(( _sen_crit++ ))
			elif [[ -n "${_lnc}" && "${_lnc}" != "null" ]] && \
			     "${AWK}" "BEGIN{exit !(${_sv}+0 < ${_lnc}+0)}" 2>/dev/null; then
				_sen_state="${status_warn}"
				fg_output+="${status_warn} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} below lower WARNING threshold ${_lnc}\n"
				fg_problem_output+="${status_warn} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} (lower_warn: ${_lnc})\n"
				(( _sen_warn++ ))
			elif [[ -n "${_unc}" && "${_unc}" != "null" ]] && \
			     "${AWK}" "BEGIN{exit !(${_sv}+0 > ${_unc}+0)}" 2>/dev/null; then
				_sen_state="${status_warn}"
				fg_output+="${status_warn} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} above upper WARNING threshold ${_unc}\n"
				fg_problem_output+="${status_warn} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit} (upper_warn: ${_unc})\n"
				(( _sen_warn++ ))
			else
				(( _sen_ok++ ))
				[[ -n "${verbose}" ]] && \
					fg_output+="${status_ok} - Sensor ${_fwn}${_sn}: ${_sv}${_sen_unit}\n"
			fi
		done

		if [[ "${_sen_crit}" -eq 0 && "${_sen_warn}" -eq 0 && -z "${verbose}" ]]; then
			fg_output+="${status_ok} - Sensors${_fws}${_sen_ok} sensor(s) within thresholds\n"
		fi

		fg_perf+=" sensors_ok=${_sen_ok} sensors_warn=${_sen_warn} sensors_crit=${_sen_crit}"
		unset _sen_names _sen_vals _sen_types _sen_lnc _sen_lc _sen_unc _sen_uc
	else
		fg_output+="${status_ok} - Sensors${_fws}endpoint not available\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Firewall Policy Statistics Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_fwstats}" || -n "${enable_all}" ) && -z "${disable_fwstats}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Firewall Policy Stats:\n---------------------------------------\n"
	fi

	_fws4_buffer=$(cat "${_pf}/fwpolicy4.json" 2>/dev/null)
	_fws6_buffer=$(cat "${_pf}/fwpolicy6.json" 2>/dev/null)

	_fws_total_bytes=0
	_fws_sw_bytes=0
	_fws_asic_bytes=0
	_fws_nturbo_bytes=0
	_fws_sessions=0
	_fws_hits=0
	_fws_policies=0
	_fws_any=0

	_fws_never_hit=0
	declare -a _fws_never_hit_names

	for _fws_buf in "${_fws4_buffer}" "${_fws6_buffer}"; do
		[[ -z "${_fws_buf}" || ! "${_fws_buf}" =~ '"results"' ]] && continue
		_fws_any=1
		while IFS=$'\t' read -r _fb _sw _as _nt _se _hi _pid _pname; do
			_fws_total_bytes=$(( _fws_total_bytes + _fb ))
			_fws_sw_bytes=$(( _fws_sw_bytes + _sw ))
			_fws_asic_bytes=$(( _fws_asic_bytes + _as ))
			_fws_nturbo_bytes=$(( _fws_nturbo_bytes + _nt ))
			_fws_sessions=$(( _fws_sessions + _se ))
			_fws_hits=$(( _fws_hits + _hi ))
			(( _fws_policies++ ))
			if [[ -n "${check_policy_cleanup}" && "${_hi}" == "0" ]]; then
				(( _fws_never_hit++ ))
				_fws_never_hit_names+=("${_pid}${_pname:+:${_pname}}")
			fi
		done < <(echo "${_fws_buf}" | "${JQ}" --unbuffered -r '
			.results[] | [
				((.bytes // 0) | tostring),
				((.software_bytes // 0) | tostring),
				((.asic_bytes // 0) | tostring),
				((.nturbo_bytes // 0) | tostring),
				((.active_sessions // 0) | tostring),
				((.hit_count // 0) | tostring),
				((.policyid // "") | tostring),
				(.name // "")
			] | join("\t")' 2>/dev/null)
	done

	if [[ "${_fws_any}" -eq 1 ]]; then
		_fws_bytes_h=$(echo "${_fws_total_bytes}" | "${AWK}" '{
			if($1>=1099511627776) printf "%.1f TB",$1/1099511627776
			else if($1>=1073741824) printf "%.1f GB",$1/1073741824
			else if($1>=1048576) printf "%.1f MB",$1/1048576
			else if($1>=1024) printf "%.1f KB",$1/1024
			else printf "%d B",$1}')

		fg_output+="${status_ok} - FW Stats${_fws}${_fws_sessions} active sessions | ${_fws_policies} policies | total: ${_fws_bytes_h}\n"

		if [[ -n "${verbose}" ]]; then
			_fws_fmt() { echo "${1}" | "${AWK}" '{if($1>=1073741824) printf "%.1f GB",$1/1073741824; else if($1>=1048576) printf "%.1f MB",$1/1048576; else printf "%d B",$1}'; }
			fg_output+="${status_ok} - FW Stats${_fws}ASIC: $(_fws_fmt "${_fws_asic_bytes}") | SW: $(_fws_fmt "${_fws_sw_bytes}") | NTurbo: $(_fws_fmt "${_fws_nturbo_bytes}") | hits: ${_fws_hits}\n"
			unset -f _fws_fmt
		fi

		# Policy cleanup: warn on never-hit policies
		if [[ -n "${check_policy_cleanup}" && "${_fws_never_hit}" -gt 0 ]]; then
			fg_output+="${status_warn} - FW Stats${_fws}${_fws_never_hit}/${_fws_policies} policies never hit (hit_count=0)\n"
			fg_problem_output+="${status_warn} - FW Stats${_fws}${_fws_never_hit}/${_fws_policies} policies never hit (hit_count=0)\n"
			if [[ -n "${verbose}" ]]; then
				_fws_nl_s=$(IFS=','; echo "${_fws_never_hit_names[*]}")
				fg_output+="${status_warn} - FW Stats${_fws}Never-hit policy IDs: ${_fws_nl_s}\n"
			fi
		fi
		unset _fws_never_hit_names

		fg_perf+=" fw_active_sessions=${_fws_sessions}"
		fg_perf+=" fw_total_bytes=${_fws_total_bytes}c"
		fg_perf+=" fw_asic_bytes=${_fws_asic_bytes}c"
		fg_perf+=" fw_sw_bytes=${_fws_sw_bytes}c"
		fg_perf+=" fw_nturbo_bytes=${_fws_nturbo_bytes}c"
		fg_perf+=" fw_hit_count=${_fws_hits}c"
		[[ -n "${check_policy_cleanup}" ]] && fg_perf+=" fw_never_hit_policies=${_fws_never_hit}"
	else
		fg_output+="${status_ok} - FW Stats${_fws}endpoint not available\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Traffic Shaper Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_shaper}" || -n "${enable_all}" ) && -z "${disable_shaper}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Traffic Shapers:\n---------------------------------------\n"
	fi

	# Build (cmdb_file, mon_file, vdom_prefix) triples to process
	declare -a _shp_files_cmdb _shp_files_mon _shp_vpfx
	if [[ -n "${shaper_vdom}" ]]; then
		# Explicit VDOM list — use pre-fetched per-VDOM files
		IFS=',' read -ra _shp_vdom_list <<< "${shaper_vdom}"
		for _sv in "${_shp_vdom_list[@]}"; do
			_sv="${_sv// /}"
			_shp_files_cmdb+=("${_pf}/shaper_cmdb_${_sv}.json")
			_shp_files_mon+=("${_pf}/shaper_mon_${_sv}.json")
			_shp_vpfx+=("${_sv}/")
		done
	else
		# Auto mode: query every VDOM from the pre-fetched VDOM list
		mapfile -t _shp_auto_vdoms < <("${JQ}" -r '.results[].name // empty' \
			"${_pf}/vdom_list.json" 2>/dev/null)
		if [[ "${#_shp_auto_vdoms[@]}" -gt 0 ]]; then
			for _sv in "${_shp_auto_vdoms[@]}"; do
				[[ -z "${_sv}" ]] && continue
				fg_api_get "${FG_API}/cmdb/firewall.shaper/traffic-shaper?vdom=${_sv}" \
					> "${_pf}/shaper_cmdb_${_sv}.json" 2>/dev/null
				_shp_mon_get "${_pf}/shaper_mon_${_sv}.json" \
					"${FG_API}/monitor/firewall/shaper" "${_sv}"
				_shp_files_cmdb+=("${_pf}/shaper_cmdb_${_sv}.json")
				_shp_files_mon+=("${_pf}/shaper_mon_${_sv}.json")
				_shp_vpfx+=("${_sv}/")
			done
		else
			# Non-VDOM device: query root without scope
			fg_api_get "${FG_API}/cmdb/firewall.shaper/traffic-shaper" \
				> "${_pf}/shaper_cmdb_root.json" 2>/dev/null
			_shp_mon_get "${_pf}/shaper_mon_root.json" \
				"${FG_API}/monitor/firewall/shaper"
			_shp_files_cmdb+=("${_pf}/shaper_cmdb_root.json")
			_shp_files_mon+=("${_pf}/shaper_mon_root.json")
			_shp_vpfx+=("")
		fi
	fi

	_shp_count=0
	_shp_total_drop_pkts=0
	_shp_any_warn=0
	_shp_any_crit=0
	_shp_any_data=0

	for _shp_fi in "${!_shp_files_cmdb[@]}"; do
		_shp_buf_cmdb=$(cat "${_shp_files_cmdb[_shp_fi]}" 2>/dev/null)
		[[ -z "${_shp_buf_cmdb}" || ! "${_shp_buf_cmdb}" =~ '"results"' ]] && continue
		_shp_any_data=1
		_shp_vp="${_shp_vpfx[_shp_fi]}"

		# Load optional runtime stats from monitor endpoint into associative arrays keyed by shaper name.
		# FortiOS 7.x: data under .results.data[]; fields in bytes/sec for bandwidth values.
		declare -A _shp_mdrop_pkts=() _shp_mdrop_bytes=() _shp_mbw_used=()
		_shp_buf_mon=$(cat "${_shp_files_mon[_shp_fi]}" 2>/dev/null)
		if [[ -n "${_shp_buf_mon}" && "${_shp_buf_mon}" =~ '"results"' ]]; then
			while IFS=$'\t' read -r _mn _mdrops _mdb _mcbw; do
				[[ -z "${_mn}" ]] && continue
				_shp_mdrop_pkts["${_mn}"]="${_mdrops:-0}"
				_shp_mdrop_bytes["${_mn}"]="${_mdb:-0}"
				# current_bandwidth is bytes/sec → convert to kbps
				_shp_mbw_used["${_mn}"]=$(( ${_mcbw:-0} * 8 / 1000 ))
			done < <(echo "${_shp_buf_mon}" | "${JQ}" --unbuffered -r '
				(.results.data // .results)[]? | [
					(.name // ""),
					((.drops // .dropped_pkts // 0) | tostring),
					((.dropped_bytes // 0) | tostring),
					((.current_bandwidth // .bandwidth_used // 0) | tostring)
				] | join("\t")' 2>/dev/null)
		fi

		# Process configured shapers from CMDB; CMDB uses hyphenated field names
		while IFS=$'\t' read -r _sname _sgbw _smbw _sbwunit _sprio; do
			[[ -z "${_sname}" ]] && continue
			(( _shp_count++ ))

			# Runtime stats from monitor overlay (0 when endpoint returns no data)
			_sdrop_pkts="${_shp_mdrop_pkts[${_sname}]:-0}"
			_sdrop_bytes="${_shp_mdrop_bytes[${_sname}]:-0}"
			_sbw_used="${_shp_mbw_used[${_sname}]:-0}"   # already in kbps

			[[ ! "${_sdrop_pkts}"  =~ ^[0-9]+$ ]] && _sdrop_pkts=0
			[[ ! "${_sdrop_bytes}" =~ ^[0-9]+$ ]] && _sdrop_bytes=0
			[[ ! "${_sbw_used}"    =~ ^[0-9]+$ ]] && _sbw_used=0
			[[ ! "${_smbw}"        =~ ^[0-9]+$ ]] && _smbw=0
			_shp_total_drop_pkts=$(( _shp_total_drop_pkts + _sdrop_pkts ))

			_shp_state="${status_ok}"
			if [[ "${warn_shaper_drops}" -ge 0 ]] 2>/dev/null && \
			   [[ "${crit_shaper_drops}" -ge 0 ]] 2>/dev/null && \
			   (( _sdrop_pkts >= crit_shaper_drops )) 2>/dev/null; then
				_shp_state="${status_crit}"
				(( _shp_any_crit++ ))
				fg_problem_output+="${status_crit} - Shaper ${_fwn}${_shp_vp}${_sname}: ${_sdrop_pkts} pkts dropped\n"
			elif [[ "${warn_shaper_drops}" -ge 0 ]] 2>/dev/null && \
			     (( _sdrop_pkts >= warn_shaper_drops )) 2>/dev/null; then
				_shp_state="${status_warn}"
				(( _shp_any_warn++ ))
				fg_problem_output+="${status_warn} - Shaper ${_fwn}${_shp_vp}${_sname}: ${_sdrop_pkts} pkts dropped\n"
			fi

			if [[ -n "${verbose}" || "${_shp_state}" != "${status_ok}" ]]; then
				_shp_bw_s=" | max: ${_smbw} ${_sbwunit}"
				[[ "${_sbw_used}" -gt 0 ]] 2>/dev/null && \
					_shp_bw_s=" | bw: ${_sbw_used}/${_smbw} ${_sbwunit}"
				fg_output+="${_shp_state} - Shaper ${_fwn}${_shp_vp}${_sname}: dropped: ${_sdrop_pkts} pkts / ${_sdrop_bytes} bytes${_shp_bw_s}\n"
			fi

			_shp_lbl="${_shp_vp//\//_}${_sname// /_}"
			_shp_lbl="${_shp_lbl//-/_}"
			fg_perf+=" shaper_${_shp_lbl}_dropped_pkts=${_sdrop_pkts};${warn_shaper_drops};${crit_shaper_drops}"
			fg_perf+=" shaper_${_shp_lbl}_dropped_bytes=${_sdrop_bytes}"
			fg_perf+=" shaper_${_shp_lbl}_bw_used=${_sbw_used}"
			[[ "${_smbw}" -gt 0 ]] && fg_perf+=" shaper_${_shp_lbl}_max_bw=${_smbw}"
		done < <(echo "${_shp_buf_cmdb}" | "${JQ}" --unbuffered -r '
			.results[]? | [
				(.name // ""),
				((.["guaranteed-bandwidth"] // 0) | tostring),
				((.["maximum-bandwidth"]    // 0) | tostring),
				(.["bandwidth-unit"] // "kbps"),
				(.priority // "")
			] | join("\t")' 2>/dev/null)

		unset _shp_mdrop_pkts _shp_mdrop_bytes _shp_mbw_used
	done

	if [[ "${_shp_any_data}" -eq 1 ]]; then
		_shp_vdom_s=""
		if [[ -n "${shaper_vdom}" ]]; then
			_shp_vdom_s=" (${shaper_vdom})"
		elif [[ "${#_shp_auto_vdoms[@]}" -gt 0 ]]; then
			_shp_vdom_s=" ($(IFS=','; echo "${_shp_auto_vdoms[*]}"))"
		fi
		if [[ "${_shp_count}" -eq 0 ]]; then
			fg_output+="${status_ok} - Shapers${_fws}none configured${_shp_vdom_s}\n"
		elif [[ "${_shp_any_crit}" -gt 0 ]]; then
			fg_output+="${status_crit} - Shapers${_fws}${_shp_count} shaper(s)${_shp_vdom_s} | total dropped: ${_shp_total_drop_pkts} pkts | ${_shp_any_crit} above crit threshold\n"
		elif [[ "${_shp_any_warn}" -gt 0 ]]; then
			fg_output+="${status_warn} - Shapers${_fws}${_shp_count} shaper(s)${_shp_vdom_s} | total dropped: ${_shp_total_drop_pkts} pkts | ${_shp_any_warn} above warn threshold\n"
		else
			fg_output+="${status_ok} - Shapers${_fws}${_shp_count} shaper(s)${_shp_vdom_s} | total dropped: ${_shp_total_drop_pkts} pkts\n"
		fi
		fg_perf+=" shaper_total_dropped_pkts=${_shp_total_drop_pkts}"
	else
		fg_output+="${status_ok} - Shapers${_fws}endpoint not available\n"
	fi
	unset _shp_files_cmdb _shp_files_mon _shp_vpfx

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Load Balancer / Virtual Server Check
# ---------------------------------------------------------------------------
if [[ ( -n "${enable_lb}" || -n "${enable_all}" ) && -z "${disable_lb}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Load Balancer Virtual Servers:\n---------------------------------------\n"
	fi

	declare -a _lb_mon_files=() _lb_mon_vpfx=()
	if [[ -n "${lb_vdom}" ]]; then
		IFS=',' read -ra _lb_vdom_list <<< "${lb_vdom}"
		for _lv in "${_lb_vdom_list[@]}"; do
			_lv="${_lv// /}"
			_lb_mon_files+=("${_pf}/lb_mon_${_lv}.json")
			_lb_mon_vpfx+=("${_lv}/")
		done
	else
		_lb_mon_files+=("${_pf}/lb_mon_root.json")
		_lb_mon_vpfx+=("")
	fi

	declare -a _lb_vip_order=()
	declare -A _lb_vip_seen=() _lb_vip_extip=() _lb_vip_extport=() _lb_vip_vtype=() \
	            _lb_vip_rs_total=() _lb_vip_rs_up=() _lb_vip_rs_down=() \
	            _lb_vip_rs_disabled=() _lb_vip_rs_lines=() \
	            _lb_vip_sessions=() _lb_vip_bytes=() _lb_vip_events=()
	_lb_total_vips=0
	_lb_total_rs=0
	_lb_total_rs_up=0
	_lb_total_rs_down=0
	_lb_total_rs_disabled=0
	_lb_any_crit=0
	_lb_any_warn=0
	_lb_any_data=0

	declare -A _lb_bl_vip_map=() _lb_bl_rs_map=()
	if [[ -n "${lb_blacklist_vip:-}" ]]; then
		IFS=',' read -ra _lb_bl_vip_arr <<< "${lb_blacklist_vip}"
		for _e in "${_lb_bl_vip_arr[@]}"; do _lb_bl_vip_map["${_e// /}"]=1; done
	fi
	if [[ -n "${lb_blacklist_rs:-}" ]]; then
		IFS=',' read -ra _lb_bl_rs_arr <<< "${lb_blacklist_rs}"
		for _e in "${_lb_bl_rs_arr[@]}"; do _lb_bl_rs_map["${_e// /}"]=1; done
	fi

	for _lb_fi in "${!_lb_mon_files[@]}"; do
		_lb_buf=$(cat "${_lb_mon_files[_lb_fi]}" 2>/dev/null)
		[[ -z "${_lb_buf}" ]] && continue
		# Monitor format: results[] contain virtual_server_name
		"${JQ}" -e '[.results[]? | select(.virtual_server_name != null)] | length > 0' \
			<<< "${_lb_buf}" >/dev/null 2>&1 || continue
		_lb_any_data=1
		_lb_vp="${_lb_mon_vpfx[_lb_fi]}"

		while IFS=$'\t' read -r _vname _vip _vport _vtype _rsip _rsport _rshealth _rsmode _rssess _rsbytes _rsevents _rsrtt; do
			[[ -z "${_vname}" ]] && continue
			[[ -n "${_lb_bl_vip_map[${_vname}]:-}" ]] && continue
			_vk="${_lb_vp}${_vname}"

			if [[ -z "${_lb_vip_seen[${_vk}]:-}" ]]; then
				_lb_vip_seen["${_vk}"]=1
				_lb_vip_extip["${_vk}"]="${_vip}"
				_lb_vip_extport["${_vk}"]="${_vport}"
				_lb_vip_vtype["${_vk}"]="${_vtype}"
				_lb_vip_rs_total["${_vk}"]=0
				_lb_vip_rs_up["${_vk}"]=0
				_lb_vip_rs_down["${_vk}"]=0
				_lb_vip_rs_disabled["${_vk}"]=0
				_lb_vip_rs_lines["${_vk}"]=""
				_lb_vip_sessions["${_vk}"]=0
				_lb_vip_bytes["${_vk}"]=0
				_lb_vip_events["${_vk}"]=0
				_lb_vip_order+=("${_vk}")
				(( _lb_total_vips++ ))
			fi

			[[ -z "${_rsip}" ]] && continue
			[[ -n "${_lb_bl_rs_map[${_rsip}]:-}" || -n "${_lb_bl_rs_map[${_rsip}:${_rsport}]:-}" ]] && continue
			(( _lb_vip_rs_total["${_vk}"]++ ))
			(( _lb_total_rs++ ))

			if [[ "${_rsmode}" == "disabled" ]]; then
				(( _lb_vip_rs_disabled["${_vk}"]++ ))
				(( _lb_total_rs_disabled++ ))
				_rs_line_state="${status_warn}"
			elif [[ "${_rshealth}" == "down" ]]; then
				(( _lb_vip_rs_down["${_vk}"]++ ))
				(( _lb_total_rs_down++ ))
				_rs_line_state="${status_crit}"
			else
				(( _lb_vip_rs_up["${_vk}"]++ ))
				(( _lb_total_rs_up++ ))
				_rs_line_state="${status_ok}"
			fi

			[[ "${_rssess}"   =~ ^[0-9]+$ ]] && (( _lb_vip_sessions["${_vk}"] += _rssess ))
			[[ "${_rsbytes}"  =~ ^[0-9]+$ ]] && (( _lb_vip_bytes["${_vk}"]   += _rsbytes ))
			[[ "${_rsevents}" =~ ^[0-9]+$ ]] && (( _lb_vip_events["${_vk}"]  += _rsevents ))

			_rs_detail="${_rshealth}, ${_rsmode}"
			[[ "${_rssess}"   =~ ^[0-9]+$ && "${_rssess}"   -gt 0 ]] && _rs_detail+=", ${_rssess} sess"
			[[ "${_rsbytes}"  =~ ^[0-9]+$ && "${_rsbytes}"  -gt 0 ]] && \
				_rs_detail+=", $(echo "${_rsbytes}" | "${AWK}" '{if($1>=1073741824) printf "%.1f GB",$1/1073741824; else if($1>=1048576) printf "%.1f MB",$1/1048576; else if($1>=1024) printf "%.1f kB",$1/1024; else printf "%d B",$1}')"
			[[ "${_rsevents}" =~ ^[0-9]+$ && "${_rsevents}" -gt 0 ]] && _rs_detail+=", ${_rsevents} events"
			[[ -n "${_rsrtt}" ]] && _rs_detail+=", RTT: ${_rsrtt}s"

			_rs_lbl="${_vk//\//_}"; _rs_lbl="${_rs_lbl// /_}"; _rs_lbl="${_rs_lbl//-/_}"
			_rs_lbl+="_${_rsip//./_}_${_rsport}"
			fg_perf+=" lb_${_rs_lbl}_sessions=${_rssess:-0}"
			fg_perf+=" lb_${_rs_lbl}_bytes=${_rsbytes:-0}"
			fg_perf+=" lb_${_rs_lbl}_events=${_rsevents:-0}"

			_lb_vip_rs_lines["${_vk}"]+="${_rs_line_state} -   RS ${_fwn}${_vk}: ${_rsip}:${_rsport} (${_rs_detail})\n"
		done < <("${JQ}" --unbuffered -r '
			.results[]? | . as $v |
			if (($v.list // []) | length) > 0 then
				$v.list[] | [
					$v.virtual_server_name,
					($v.virtual_server_ip // ""),
					($v.virtual_server_port | tostring),
					($v.virtual_server_type // "ipv4"),
					(.real_server_ip // ""),
					(.real_server_port | tostring),
					(.status // ""),
					(.mode // ""),
					((.active_sessions  // 0) | tostring),
					((.bytes_processed  // 0) | tostring),
					((.monitor_events   // 0) | tostring),
					(.RTT // "")
				]
			else
				[$v.virtual_server_name, ($v.virtual_server_ip // ""),
				 ($v.virtual_server_port | tostring), ($v.virtual_server_type // "ipv4"),
				 "", "0", "", "", "0", "0", "0", ""]
			end | join("\t")' <<< "${_lb_buf}" 2>/dev/null)
	done

	# Output per-VIP summary + optional per-RS lines
	for _vk in "${_lb_vip_order[@]}"; do
		_v_up="${_lb_vip_rs_up[${_vk}]}"
		_v_down="${_lb_vip_rs_down[${_vk}]}"
		_v_disabled="${_lb_vip_rs_disabled[${_vk}]}"
		_v_total="${_lb_vip_rs_total[${_vk}]}"
		_v_extip="${_lb_vip_extip[${_vk}]}"
		_v_extport="${_lb_vip_extport[${_vk}]}"
		_v_vtype="${_lb_vip_vtype[${_vk}]}"

		_v_state="${status_ok}"
		_v_detail=""
		if [[ "${_v_total}" -gt 0 && "${_v_up}" -eq 0 && "${_v_down}" -gt 0 ]]; then
			_v_state="${status_crit}"
			_v_detail=" (all RS down)"
			(( _lb_any_crit++ ))
		elif [[ "${_v_down}" -gt 0 ]]; then
			_v_state="${status_warn}"
			_v_detail=" (${_v_down}/${_v_total} RS down)"
			(( _lb_any_warn++ ))
		elif [[ "${_v_disabled}" -gt 0 ]]; then
			_v_state="${status_warn}"
			_v_detail=" (${_v_disabled}/${_v_total} RS disabled)"
			(( _lb_any_warn++ ))
		fi

		_v_sess="${_lb_vip_sessions[${_vk}]:-0}"
		_v_bytes="${_lb_vip_bytes[${_vk}]:-0}"
		_v_events="${_lb_vip_events[${_vk}]:-0}"
		_v_stats=""
		[[ "${_v_sess}"   -gt 0 ]] && _v_stats+=" | ${_v_sess} sess"
		[[ "${_v_bytes}"  -gt 0 ]] && _v_stats+=" | $(echo "${_v_bytes}" | "${AWK}" '{if($1>=1073741824) printf "%.1f GB",$1/1073741824; else if($1>=1048576) printf "%.1f MB",$1/1048576; else if($1>=1024) printf "%.1f kB",$1/1024; else printf "%d B",$1}')"
		[[ "${_v_events}" -gt 0 ]] && _v_stats+=" | ${_v_events} events"

		if [[ -n "${verbose}" || "${_v_state}" != "${status_ok}" ]]; then
			fg_output+="${_v_state} - VirtualServer ${_fwn}${_vk} (${_v_extip}:${_v_extport}/${_v_vtype}): ${_v_up}/${_v_total} RS up${_v_detail}${_v_stats}\n"
			[[ -n "${verbose}" && -n "${_lb_vip_rs_lines[${_vk}]}" ]] && \
				fg_output+="${_lb_vip_rs_lines[${_vk}]}"
		fi

		[[ "${_v_state}" != "${status_ok}" ]] && \
			fg_problem_output+="${_v_state} - VirtualServer ${_fwn}${_vk} (${_v_extip}:${_v_extport}/${_v_vtype}): ${_v_up}/${_v_total} RS up${_v_detail}\n"

		_lb_lbl="${_vk//\//_}"; _lb_lbl="${_lb_lbl// /_}"; _lb_lbl="${_lb_lbl//-/_}"
		fg_perf+=" lb_${_lb_lbl}_rs_total=${_v_total} lb_${_lb_lbl}_rs_up=${_v_up}"
		[[ "${_v_down}"     -gt 0 ]] && fg_perf+=" lb_${_lb_lbl}_rs_down=${_v_down}"
		[[ "${_v_disabled}" -gt 0 ]] && fg_perf+=" lb_${_lb_lbl}_rs_disabled=${_v_disabled}"
		fg_perf+=" lb_${_lb_lbl}_sessions=${_v_sess}"
		fg_perf+=" lb_${_lb_lbl}_bytes=${_v_bytes}"
		fg_perf+=" lb_${_lb_lbl}_events=${_v_events}"
	done

	if [[ "${_lb_any_data}" -eq 1 ]]; then
		_lb_vdom_s=""
		[[ -n "${lb_vdom}" ]] && _lb_vdom_s=" (${lb_vdom})"
		if [[ "${_lb_total_vips}" -eq 0 ]]; then
			fg_output+="${status_ok} - Load Balancer${_fws}none configured${_lb_vdom_s}\n"
		elif [[ "${_lb_any_crit}" -gt 0 ]]; then
			fg_output+="${status_crit} - Load Balancer${_fws}${_lb_total_vips} VIP(s)${_lb_vdom_s} | RS: ${_lb_total_rs_up}/${_lb_total_rs} up | ${_lb_any_crit} VIP(s) with all RS down\n"
		elif [[ "${_lb_any_warn}" -gt 0 ]]; then
			_lb_warn_detail=""
			[[ "${_lb_total_rs_down}"     -gt 0 ]] && _lb_warn_detail+=" | ${_lb_total_rs_down} RS down"
			[[ "${_lb_total_rs_disabled}" -gt 0 ]] && _lb_warn_detail+=" | ${_lb_total_rs_disabled} RS disabled"
			fg_output+="${status_warn} - Load Balancer${_fws}${_lb_total_vips} VIP(s)${_lb_vdom_s} | RS: ${_lb_total_rs_up}/${_lb_total_rs} up${_lb_warn_detail}\n"
		else
			fg_output+="${status_ok} - Load Balancer${_fws}${_lb_total_vips} VIP(s)${_lb_vdom_s} | RS: ${_lb_total_rs_up}/${_lb_total_rs} up\n"
		fi
		fg_perf+=" lb_total_vips=${_lb_total_vips} lb_rs_total=${_lb_total_rs} lb_rs_up=${_lb_total_rs_up}"
		[[ "${_lb_total_rs_down}" -gt 0 ]] && fg_perf+=" lb_rs_down=${_lb_total_rs_down}"
	else
		fg_output+="${status_unknown} - Load Balancer${_fws}no data (endpoint: monitor/firewall/load-balance)\n"
	fi
	unset _lb_mon_files _lb_mon_vpfx _lb_vip_order _lb_vip_seen _lb_vip_extip _lb_vip_extport \
	      _lb_vip_vtype _lb_vip_rs_total _lb_vip_rs_up _lb_vip_rs_down \
	      _lb_vip_rs_disabled _lb_vip_rs_lines _lb_vip_sessions _lb_vip_bytes _lb_vip_events \
	      _lb_bl_vip_map _lb_bl_rs_map

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Security Rating Check
# ---------------------------------------------------------------------------
if [[ -n "${enable_secrating}" && -z "${disable_secrating}" ]]; then
	if [[ -n "${verbose}" ]]; then
		fg_output+="Security Rating:\n---------------------------------------\n"
	fi

	_sr_sum_buf=$(cat "${_pf}/secrating_summary.json" 2>/dev/null)
	_sr_res_buf=$(cat "${_pf}/secrating_result.json"  2>/dev/null)

	# Determine availability: 404 = Security Fabric not enabled; empty/other error = unknown
	_sr_http=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r '.http_status // ""' 2>/dev/null)
	_sr_status_api=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r '.status // ""' 2>/dev/null)
	_sr_results_type=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r 'if .results | type == "object" and (. | keys | length) > 0 then "object" elif .results | type == "array" then "array" else "none" end' 2>/dev/null)

	if [[ "${_sr_status_api}" == "success" && "${_sr_results_type}" == "object" ]]; then
		# Overall totals — try .results.total first, then .results directly
		_sr_score=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r \
			'.results.total.score // .results.score // ""' 2>/dev/null)
		_sr_grade=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r \
			'.results.total.score_letter // .results.score_letter // ""' 2>/dev/null)
		_sr_pass=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r \
			'.results.total.pass // .results.pass // 0' 2>/dev/null)
		_sr_warn=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r \
			'.results.total.warning // .results.warning // 0' 2>/dev/null)
		_sr_fail=$(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r \
			'.results.total.fail // .results.fail // 0' 2>/dev/null)

		_sr_state="${status_ok}"
		# Score threshold (lower is worse; alert when score < threshold)
		if [[ "${_sr_score}" =~ ^[0-9]+$ ]]; then
			if (( crit_secrating_score >= 0 && _sr_score < crit_secrating_score )) 2>/dev/null; then
				_sr_state="${status_crit}"
				fg_problem_output+="${status_crit} - Security Rating${_fws}score ${_sr_score} CRITICAL (threshold: <${crit_secrating_score})\n"
			elif (( warn_secrating_score >= 0 && _sr_score < warn_secrating_score )) 2>/dev/null; then
				_sr_state="${status_warn}"
				fg_problem_output+="${status_warn} - Security Rating${_fws}score ${_sr_score} WARNING (threshold: <${warn_secrating_score})\n"
			fi
		fi

		_sr_grade_s="" ; [[ -n "${_sr_grade}" && "${_sr_grade}" != "null" ]] && _sr_grade_s=" (${_sr_grade})"
		_sr_score_s="" ; [[ -n "${_sr_score}" && "${_sr_score}" != "null" ]] && _sr_score_s=" | score: ${_sr_score}${_sr_grade_s}"
		_sr_counts_s=" | pass: ${_sr_pass} | warn: ${_sr_warn} | fail: ${_sr_fail}"
		fg_output+="${_sr_state} - Security Rating${_fws% }${_sr_score_s}${_sr_counts_s}\n"

		# Failed checks — collect names and severities
		if [[ -n "${_sr_res_buf}" && "${_sr_res_buf}" =~ '"results"' ]]; then
			declare -a _sr_failed_high _sr_failed_med _sr_failed_low _sr_warned

			while IFS=$'\t' read -r _sr_name _sr_status _sr_sev _sr_cat; do
				case "${_sr_status}" in
					fail)
						case "${_sr_sev}" in
							critical|high) _sr_failed_high+=("${_sr_name} [${_sr_cat}]") ;;
							medium)        _sr_failed_med+=("${_sr_name} [${_sr_cat}]") ;;
							*)             _sr_failed_low+=("${_sr_name} [${_sr_cat}]") ;;
						esac
						;;
					warning) _sr_warned+=("${_sr_name} [${_sr_cat}]") ;;
				esac
			done < <(echo "${_sr_res_buf}" | "${JQ}" --unbuffered -r \
				'(.results // [])[] | select(.status == "fail" or .status == "warning") |
				[(.name // "unknown"), (.status // ""), (.severity // "low"), (.category // "")] | @tsv' \
				2>/dev/null)

			# High/critical failures always emit a CRIT problem line
			for _sr_item in "${_sr_failed_high[@]}"; do
				[[ "${_sr_state}" != "${status_crit}" ]] && _sr_state="${status_crit}"
				fg_problem_output+="${status_crit} - Security Rating${_fws}FAIL ${_sr_item}\n"
			done
			# Medium failures emit a WARN problem line (unless already crit)
			for _sr_item in "${_sr_failed_med[@]}"; do
				[[ "${_sr_state}" == "${status_ok}" ]] && _sr_state="${status_warn}"
				fg_problem_output+="${status_warn} - Security Rating${_fws}FAIL ${_sr_item}\n"
			done

			if [[ -n "${verbose}" ]]; then
				for _sr_item in "${_sr_failed_low[@]}"; do
					fg_output+="${status_warn} - Security Rating${_fws}FAIL ${_sr_item}\n"
				done
				for _sr_item in "${_sr_warned[@]}"; do
					fg_output+="${status_warn} - Security Rating${_fws}WARN ${_sr_item}\n"
				done

				# Per-category breakdown from summary
				while IFS=$'\t' read -r _sr_cat_name _sr_cp _sr_cw _sr_cf _sr_cs; do
					[[ "${_sr_cat_name}" == "total" || "${_sr_cat_name}" == "null" ]] && continue
					_sr_cs_s="" ; [[ "${_sr_cs}" =~ ^[0-9]+$ ]] && _sr_cs_s=" score: ${_sr_cs} |"
					fg_output+="${status_ok} - Security Rating${_fws}[${_sr_cat_name}]${_sr_cs_s} pass: ${_sr_cp} | warn: ${_sr_cw} | fail: ${_sr_cf}\n"
				done < <(echo "${_sr_sum_buf}" | "${JQ}" --unbuffered -r \
					'.results | to_entries[] | [.key, (.value.pass // 0), (.value.warning // 0), (.value.fail // 0), (.value.score // "")] | @tsv' \
					2>/dev/null)
			fi

			unset _sr_failed_high _sr_failed_med _sr_failed_low _sr_warned
		fi

		# Perfdata
		[[ "${_sr_score}" =~ ^[0-9]+$ ]] && \
			fg_perf+=" secrating_score=${_sr_score};${warn_secrating_score};${crit_secrating_score};0;100"
		[[ "${_sr_pass}"  =~ ^[0-9]+$ ]] && fg_perf+=" secrating_pass=${_sr_pass}"
		[[ "${_sr_warn}"  =~ ^[0-9]+$ ]] && fg_perf+=" secrating_warnings=${_sr_warn}"
		[[ "${_sr_fail}"  =~ ^[0-9]+$ ]] && fg_perf+=" secrating_fail=${_sr_fail}"
	elif [[ "${_sr_http}" == "404" || "${_sr_status_api}" == "error" ]]; then
		[[ -n "${verbose}" ]] && \
			fg_output+="${status_ok} - Security Rating${_fws}not available (Security Fabric not configured - enable under Security Fabric > Settings)\n"
	elif [[ "${_sr_results_type}" == "array" ]]; then
		[[ -n "${verbose}" ]] && \
			fg_output+="${status_ok} - Security Rating${_fws}no rating data yet (trigger a run under Security Fabric > Security Rating)\n"
	else
		[[ -n "${verbose}" ]] && \
			fg_output+="${status_ok} - Security Rating${_fws}no data returned\n"
	fi

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Logwatch Check
# ---------------------------------------------------------------------------
if [[ -n "${enable_logwatch}" && -z "${disable_logwatch}" ]]; then
	# Resolve log types: empty = all defaults for device, else split comma list
	if [[ -z "${logwatch_type}" ]]; then
		if [[ "${logwatch_device}" == "memory" ]]; then
			IFS=',' read -ra _lw_types <<< "app-ctrl,ips,virus,webfilter,anomaly,dns,voip,dlp"
		else
			IFS=',' read -ra _lw_types <<< "event,traffic,app-ctrl,ips,virus,webfilter,anomaly,dns,voip,dlp"
		fi
		_lw_type_display="all"
	else
		IFS=',' read -ra _lw_types <<< "${logwatch_type}"
		_lw_type_display="${logwatch_type}"
	fi

	if [[ -n "${verbose}" ]]; then
		_lw_hdr="Logwatch (${logwatch_device}/${_lw_type_display}"
		if [[ -n "${logwatch_subtype}" && "${#_lw_types[@]}" -eq 1 &&
		      ("${_lw_types[0]}" == "event" || "${_lw_types[0]}" == "traffic") ]]; then
			_lw_hdr+="/${logwatch_subtype}"
		fi
		_lw_hdr+=")"
		fg_output+="${_lw_hdr}:\n---------------------------------------\n"
	fi

	# Build jq select expression for eventid and/or action filters (once, shared)
	_lw_jq_sel="true"
	if [[ -n "${logwatch_eventids}" ]]; then
		_lw_eid_expr=""
		IFS=',' read -ra _lw_tmp <<< "${logwatch_eventids}"
		for _lw_v in "${_lw_tmp[@]}"; do
			_lw_v="${_lw_v// /}"
			if [[ "${_lw_v}" =~ ^[0-9]+$ ]]; then
				[[ -n "${_lw_eid_expr}" ]] && _lw_eid_expr+=" or "
				_lw_eid_expr+="(.eventid // 0) == ${_lw_v}"
			fi
		done
		[[ -n "${_lw_eid_expr}" ]] && _lw_jq_sel+=" and (${_lw_eid_expr})"
		unset _lw_tmp
	fi
	if [[ -n "${logwatch_actions}" ]]; then
		_lw_act_expr=""
		IFS=',' read -ra _lw_tmp <<< "${logwatch_actions}"
		for _lw_v in "${_lw_tmp[@]}"; do
			_lw_v="${_lw_v// /}"
			if [[ -n "${_lw_v}" ]]; then
				[[ -n "${_lw_act_expr}" ]] && _lw_act_expr+=" or "
				_lw_act_expr+="((.action // \"\") | ascii_downcase) == (\"${_lw_v}\" | ascii_downcase)"
			fi
		done
		[[ -n "${_lw_act_expr}" ]] && _lw_jq_sel+=" and (${_lw_act_expr})"
		unset _lw_tmp
	fi

	_lw_filter_mode=0
	[[ -n "${logwatch_eventids}" || -n "${logwatch_actions}" ]] && _lw_filter_mode=1

	_lw_crit_count=0; _lw_warn_count=0; _lw_match_count=0; _lw_total=0
	_lw_ok_types=0
	declare -a _lw_lines _lw_skip_types

	# Process each type's prefetch file and aggregate results
	for _lw_t in "${_lw_types[@]}"; do
		_lw_t="${_lw_t// /}"
		[[ -z "${_lw_t}" ]] && continue

		_lw_buf=$(cat "${_pf}/logwatch_${_lw_t}.json" 2>/dev/null)
		if [[ -z "${_lw_buf}" || ! "${_lw_buf}" =~ '"results"' ]]; then
			_lw_skip_types+=("${_lw_t}")
			continue
		fi

		(( _lw_ok_types++ ))
		_lw_t_cnt=$(echo "${_lw_buf}" | "${JQ}" --unbuffered -r '.results | length' 2>/dev/null)
		[[ ! "${_lw_t_cnt}" =~ ^[0-9]+$ ]] && _lw_t_cnt=0
		(( _lw_total += _lw_t_cnt ))

		# Use \t as field separator; msg is last so it absorbs any embedded \t
		while IFS=$'\t' read -r _lw_date _lw_level _lw_eid _lw_act \
		                           _lw_src _lw_srcport _lw_dst _lw_dstport _lw_polid _lw_msg; do
			(( _lw_match_count++ ))
			_lw_eid_s="" ; [[ "${_lw_eid}" != "0" && -n "${_lw_eid}" ]] && _lw_eid_s=" | eventid: ${_lw_eid}"
			_lw_act_s="" ; [[ -n "${_lw_act}" ]] && _lw_act_s=" | action: ${_lw_act}"
			_lw_conn_s=""
			_lw_src_s="${_lw_src}"
			[[ "${_lw_srcport}" != "0" && -n "${_lw_srcport}" ]] && _lw_src_s+=":${_lw_srcport}"
			_lw_dst_s="${_lw_dst}"
			[[ "${_lw_dstport}" != "0" && -n "${_lw_dstport}" ]] && _lw_dst_s+=":${_lw_dstport}"
			[[ -n "${_lw_src_s}" || -n "${_lw_dst_s}" ]] && _lw_conn_s=" | ${_lw_src_s} -> ${_lw_dst_s}"
			_lw_pol_s="" ; [[ "${_lw_polid}" != "0" && -n "${_lw_polid}" ]] && _lw_pol_s=" (policy: ${_lw_polid})"

			if [[ "${_lw_filter_mode}" -eq 0 ]]; then
				case "${_lw_level}" in
					emergency|alert|critical)
						(( _lw_crit_count++ ))
						_lw_lines+=("${status_crit} - Logwatch${_fws}[${_lw_t}][${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s} ${_lw_date}: ${_lw_msg}")
						fg_problem_output+="${status_crit} - Logwatch${_fws}[${_lw_t}][${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s} ${_lw_date}: ${_lw_msg}\n"
						;;
					error|warning)
						(( _lw_warn_count++ ))
						_lw_lines+=("${status_warn} - Logwatch${_fws}[${_lw_t}][${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s} ${_lw_date}: ${_lw_msg}")
						fg_problem_output+="${status_warn} - Logwatch${_fws}[${_lw_t}][${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s} ${_lw_date}: ${_lw_msg}\n"
						;;
				esac
			else
				# Filter mode: collect all matches; thresholds applied after loop
				_lw_lines+=("[${_lw_t}][${_lw_level}]${_lw_eid_s}${_lw_act_s}${_lw_conn_s}${_lw_pol_s} ${_lw_date}: ${_lw_msg}")
			fi
		done < <(echo "${_lw_buf}" | "${JQ}" --unbuffered -r \
			".results[] | select(${_lw_jq_sel}) |
			[(.date // \"\"), (.level // \"unknown\"),
			 (.eventid // 0 | tostring),
			 (.action // \"\"),
			 (.srcip // \"\"),
			 ((.srcport // 0) | tostring),
			 (.dstip // \"\"),
			 ((.dstport // 0) | tostring),
			 ((.policyid // 0) | tostring),
			 (.msg // .message // \"\")] | join(\"\t\")" 2>/dev/null)
	done

	if [[ "${_lw_ok_types}" -gt 0 ]]; then
		# Filter mode: apply count thresholds after collecting all matches
		if [[ "${_lw_filter_mode}" -eq 1 ]]; then
			_lw_fs="${status_ok}"
			if (( crit_logwatch >= 0 && _lw_match_count >= crit_logwatch )) 2>/dev/null; then
				_lw_fs="${status_crit}" ; _lw_crit_count="${_lw_match_count}"
			elif (( _lw_match_count >= warn_logwatch )) 2>/dev/null; then
				_lw_fs="${status_warn}" ; _lw_warn_count="${_lw_match_count}"
			fi
			if [[ "${_lw_fs}" != "${status_ok}" ]]; then
				for _lw_l in "${_lw_lines[@]}"; do
					fg_problem_output+="${_lw_fs} - Logwatch${_fws}${_lw_l}\n"
					[[ -n "${verbose}" ]] && fg_output+="${_lw_fs} - Logwatch${_fws}${_lw_l}\n"
				done
			elif [[ -n "${verbose}" ]]; then
				for _lw_l in "${_lw_lines[@]}"; do
					fg_output+="${status_ok} - Logwatch${_fws}${_lw_l}\n"
				done
			fi
		else
			[[ -n "${verbose}" ]] && for _lw_l in "${_lw_lines[@]}"; do fg_output+="${_lw_l}\n"; done
		fi

		if [[ "${_lw_crit_count}" -gt 0 || "${_lw_warn_count}" -gt 0 ]]; then
			_lw_st="${status_crit}"
			[[ "${_lw_crit_count}" -eq 0 ]] && _lw_st="${status_warn}"
			fg_output+="${_lw_st} - Logwatch${_fws}${_lw_match_count} match(es) in last ${_lw_total} entries (crit: ${_lw_crit_count}, warn: ${_lw_warn_count})\n"
		else
			fg_output+="${status_ok} - Logwatch${_fws}no matches in last ${_lw_total} entries\n"
		fi
		[[ -n "${verbose}" && "${#_lw_skip_types[@]}" -gt 0 ]] && \
			fg_output+="${status_ok} - Logwatch${_fws}skipped (not available): ${_lw_skip_types[*]}\n"

		fg_perf+=" logwatch_hits=${_lw_match_count} logwatch_crit=${_lw_crit_count} logwatch_warn=${_lw_warn_count}"
	else
		fg_output+="${status_ok} - Logwatch${_fws}log endpoint not available (${logwatch_device}/${_lw_type_display})\n"
		fg_perf+=" logwatch_hits=0 logwatch_crit=0 logwatch_warn=0"
	fi

	unset _lw_types _lw_lines _lw_skip_types

	if [[ -n "${verbose}" ]]; then
		fg_output+="---------------------------------------\n\n"
	fi
fi

# ---------------------------------------------------------------------------
# Determine exit state from output content and print result
# ---------------------------------------------------------------------------
if [[ ${fg_output} =~ "[UNKNOWN]" ]]; then
	state=3
	if [[ -z "${silent}" ]]; then
		fg_problems="One or more Problems detected:\n---------------------------------------------------------------------\n"
		fg_problem_output+="---------------------------------------------------------------------\n\nAll Services:\n---------------------------------------------------------------------\n"
	fi
elif [[ ${fg_output} =~ "[CRITICAL]" ]]; then
	state=2
	if [[ -z "${silent}" ]]; then
		fg_problems="One or more Problems detected:\n---------------------------------------------------------------------\n"
		fg_problem_output+="---------------------------------------------------------------------\n\nAll Services:\n---------------------------------------------------------------------\n"
	fi
elif [[ ${fg_output} =~ "[WARNING]" ]]; then
	state=1
	if [[ -z "${silent}" ]]; then
		fg_problems="One or more Problems detected:\n---------------------------------------------------------------------\n"
		fg_problem_output+="---------------------------------------------------------------------\n\nAll Services:\n---------------------------------------------------------------------\n"
	fi
else
	state=0
	fg_problems="All Services OK"
fi

# Replace | in human-readable text with , to avoid Nagios treating it as a perfdata separator
_pp="${fg_problem_output//|/,}"
_po="${fg_output//|/,}"
_perf_sep="${no_perfdata:+}" ; [[ -z "${no_perfdata}" ]] && _perf_sep="|${fg_perf}"

if [[ -z "${silent}" && -n "${fg_problem_output}" ]]; then
	echo -e "${fg_problems}${_pp}${_po}${_perf_sep}"
elif [[ -n "${silent}" && -n "${fg_problem_output}" ]]; then
	echo -e "${_pp}${_perf_sep}"
elif [[ -n "${silent}" && -z "${fg_problem_output}" ]]; then
	echo -e "${status_ok} - All Services are fine${_perf_sep}"
elif [[ -z "${silent}" && -z "${fg_problem_output}" ]]; then
	echo -e "${_po}${_perf_sep}"
else
	echo -e "${_po}${_perf_sep}"
fi
exitstate=${state}
rm -rf "${_pf}" 2>/dev/null
exit ${exitstate}
