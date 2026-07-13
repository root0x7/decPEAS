#!/usr/bin/env bash
#
# decPEAS - Detection PEAS (Professional Edition)
# Linux persistence-mechanism detection for Blue Teams.
#
# Read-only auditor: it never modifies, deletes, or "fixes" anything.
# It only inspects the system and reports findings.
#
# Version : 2.0
# License : MIT
#
# Usage:
#   ./decpeas.sh [options]
#
# Options:
#   -o, --output FILE     Write a plain-text report copy to FILE
#   -j, --json FILE       Write findings as JSON to FILE
#   -b, --baseline FILE   Compare against a baseline; write/refresh with --write-baseline
#       --write-baseline FILE
#                         Generate a baseline snapshot and exit
#   -q, --quiet           Only print SUSPICIOUS/CRITICAL to the console
#       --no-color        Disable ANSI colours
#       --min-severity L  info|warning|suspicious|critical (default: info)
#   -h, --help            Show this help
#
# Exit codes:
#   0  no suspicious/critical findings
#   1  at least one SUSPICIOUS or CRITICAL finding
#   2  usage / runtime error

set -uo pipefail

################################################################################
# Globals & configuration
################################################################################

VERSION="2.0"
SELF_NAME="$(basename "$0")"

OUTPUT_FILE=""
JSON_FILE=""
BASELINE_FILE=""
WRITE_BASELINE_FILE=""
QUIET=0
USE_COLOR="auto"
MIN_SEVERITY="info"

# Severity ranks (numeric, for filtering/exit logic)
declare -A SEV_RANK=( [info]=0 [warning]=1 [suspicious]=2 [critical]=3 )

# Counters (kept correct by writing findings to a temp file, not by ++ in subshells)
FINDINGS_FILE="$(mktemp -t decpeas.findings.XXXXXX)"
CURRENT_SECTION="init"

# Directories to prune from full-filesystem scans (virtual / network / noisy)
PRUNE_DIRS=(/proc /sys /run /dev/pts /var/lib/docker/overlay2 /snap)

cleanup() { rm -f "$FINDINGS_FILE" 2>/dev/null; }
trap cleanup EXIT

################################################################################
# Colour handling (TTY-aware, honours NO_COLOR and --no-color)
################################################################################

setup_colors() {
    local enable=0
    case "$USE_COLOR" in
        always) enable=1 ;;
        never)  enable=0 ;;
        auto)   [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && enable=1 ;;
    esac
    if [ "$enable" -eq 1 ]; then
        RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
        BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; MAGENTA=$'\033[0;35m'
        NC=$'\033[0m'; BOLD=$'\033[1m'
    else
        RED=""; YELLOW=""; GREEN=""; BLUE=""; CYAN=""; MAGENTA=""; NC=""; BOLD=""
    fi
}

################################################################################
# IOC signatures
#  - Word boundaries where a bare word would over-match (e.g. "nc" inside "sync").
#  - This is a *heuristic first pass*, not proof; obfuscation can evade it.
################################################################################

# Reverse-shell / download / execution indicators for scripts & configs.
IOC_RE='(^|[^[:alnum:]_])(curl|wget|ncat|socat|nc|/dev/tcp/|/dev/udp/|bash[[:space:]]+-i|sh[[:space:]]+-i|mkfifo|python[0-9]?[[:space:]].*(socket|pty)|perl[[:space:]].*socket|ruby[[:space:]].*socket|php[[:space:]]+-r|base64[[:space:]]+(-d|--decode|-di)|openssl[[:space:]]+s_client|msfvenom|meterpreter|xterm[[:space:]]+-display)([^[:alnum:]_]|$)'

# Ports commonly used by implants / handlers.
SUSPECT_PORTS_RE=':(4444|4445|1337|31337|8888|9001|9002|12345|54321|6666|6667)$'

################################################################################
# Finding / reporting helpers
#   Findings are appended to a real file, so counts survive subshells created by
#   pipes and process substitutions (this was the main bug in v1).
################################################################################

# add_finding <severity> <message>
add_finding() {
    local sev="$1"; shift
    local msg="$*"
    # Tab-separated: severity <TAB> section <TAB> message
    printf '%s\t%s\t%s\n' "$sev" "$CURRENT_SECTION" "$msg" >> "$FINDINGS_FILE"

    # Console output honours --quiet and --min-severity
    local rank="${SEV_RANK[$sev]}"
    local min="${SEV_RANK[$MIN_SEVERITY]}"
    [ "$rank" -lt "$min" ] && return 0
    if [ "$QUIET" -eq 1 ] && [ "$rank" -lt "${SEV_RANK[suspicious]}" ]; then
        return 0
    fi

    case "$sev" in
        critical)   printf '%s[CRITICAL]%s %s\n'   "$RED$BOLD" "$NC" "$msg" ;;
        suspicious) printf '%s[SUSPICIOUS]%s %s\n' "$RED"      "$NC" "$msg" ;;
        warning)    printf '%s[WARNING]%s %s\n'    "$YELLOW"   "$NC" "$msg" ;;
        info)       printf '%s[INFO]%s %s\n'       "$GREEN"    "$NC" "$msg" ;;
    esac
}

crit()  { add_finding critical   "$*"; }
susp()  { add_finding suspicious "$*"; }
warn()  { add_finding warning    "$*"; }
info()  { add_finding info       "$*"; }
note()  { printf '%s  %s%s\n' "$CYAN" "$*" "$NC"; }   # non-finding context line

print_section() {
    CURRENT_SECTION="$1"
    printf '\n%s%s== %s ==%s\n' "$BOLD" "$BLUE" "$1" "$NC"
}

have() { command -v "$1" >/dev/null 2>&1; }

# Grep helper that reports the actual matching lines (indented) for evidence.
match_ioc() { grep -aIniE "$IOC_RE" "$1" 2>/dev/null; }

################################################################################
# Detection modules
################################################################################

check_cron_jobs() {
    print_section "Cron persistence"

    if [ -f /etc/crontab ]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            if grep -qaiE "$IOC_RE" <<<"$line"; then
                susp "/etc/crontab: $line"
            fi
        done < /etc/crontab
    fi

    # System-wide cron directories
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$dir" ] || continue
        while IFS= read -r file; do
            if match_ioc "$file" >/dev/null; then
                susp "$dir: IOC in $file"
                match_ioc "$file" | sed 's/^/    /'
            fi
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null)
    done

    # Per-user crontabs
    while IFS= read -r user; do
        local out
        out="$(crontab -l -u "$user" 2>/dev/null)" || continue
        [ -z "$out" ] && continue
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            if grep -qaiE "$IOC_RE" <<<"$line"; then
                susp "user crontab ($user): $line"
            fi
        done <<<"$out"
    done < <(cut -f1 -d: /etc/passwd 2>/dev/null)

    # Raw spool files (catch tampering that crontab -l might hide)
    for spool in /var/spool/cron /var/spool/cron/crontabs; do
        [ -d "$spool" ] || continue
        while IFS= read -r f; do
            match_ioc "$f" >/dev/null && susp "cron spool: IOC in $f"
        done < <(find "$spool" -type f 2>/dev/null)
    done
}

check_at_jobs() {
    print_section "at / batch jobs"
    if have atq; then
        local q; q="$(atq 2>/dev/null)"
        [ -n "$q" ] && warn "Pending 'at' jobs present:" && printf '%s\n' "$q" | sed 's/^/    /'
    fi
    for d in /var/spool/cron/atjobs /var/spool/at; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            match_ioc "$f" >/dev/null && susp "at job IOC: $f"
        done < <(find "$d" -type f 2>/dev/null)
    done
}

check_systemd() {
    print_section "systemd services & timers"
    have systemctl || { note "systemctl not available"; return; }

    # Enabled services whose unit file contains IOCs or lives in an odd path
    while IFS= read -r unit; do
        local path
        path="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)"
        [ -f "$path" ] || continue
        if match_ioc "$path" >/dev/null; then
            susp "service $unit ($path)"
            grep -aiE 'Exec(Start|StartPre|StartPost|Stop)=' "$path" 2>/dev/null | sed 's/^/    /'
        fi
        case "$path" in
            /tmp/*|/dev/shm/*|/var/tmp/*|/home/*)
                susp "service $unit in unusual location: $path" ;;
        esac
    done < <(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}')

    # Timers are a very common (and often overlooked) persistence vector
    while IFS= read -r timer; do
        local path
        path="$(systemctl show -p FragmentPath --value "$timer" 2>/dev/null)"
        [ -f "$path" ] || continue
        case "$path" in
            /tmp/*|/dev/shm/*|/var/tmp/*|/home/*)
                susp "timer $timer in unusual location: $path" ;;
            *)
                warn "enabled timer: $timer -> $path" ;;
        esac
    done < <(systemctl list-unit-files --type=timer --state=enabled --no-legend 2>/dev/null | awk '{print $1}')

    # User-level units under home dirs
    while IFS= read -r uhome; do
        local udir="$uhome/.config/systemd/user"
        [ -d "$udir" ] || continue
        while IFS= read -r sf; do
            warn "user systemd unit: $sf"
            match_ioc "$sf" >/dev/null && susp "IOC in user unit: $sf"
        done < <(find "$udir" -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null)
    done < <(get_home_dirs)
}

check_init_scripts() {
    print_section "init scripts, rc.local, profile.d"

    for f in /etc/rc.local /etc/rc.d/rc.local; do
        [ -f "$f" ] || continue
        if match_ioc "$f" >/dev/null; then
            susp "$f contains IOCs"
            match_ioc "$f" | sed 's/^/    /'
        else
            info "$f present"
        fi
    done

    [ -d /etc/init.d ] && while IFS= read -r s; do
        match_ioc "$s" >/dev/null && susp "init.d IOC: $s"
    done < <(find /etc/init.d -type f 2>/dev/null)

    # profile.d / update-motd.d run on login/shell start -> good hiding spots
    for d in /etc/profile.d /etc/update-motd.d; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            match_ioc "$f" >/dev/null && susp "$d IOC: $f"
        done < <(find "$d" -type f 2>/dev/null)
    done

    [ -f /etc/environment ] && match_ioc /etc/environment >/dev/null \
        && susp "/etc/environment contains IOCs"
}

check_shell_configs() {
    print_section "Shell configuration files"
    local files=(.bashrc .bash_profile .bash_login .profile .zshrc .zshenv
                 .zprofile .config/fish/config.fish .bash_logout)

    while IFS= read -r uhome; do
        for rc in "${files[@]}"; do
            local p="$uhome/$rc"
            [ -f "$p" ] || continue
            if match_ioc "$p" >/dev/null; then
                susp "$p contains IOCs"
                match_ioc "$p" | sed 's/^/    /'
            fi
        done
    done < <(get_home_dirs)

    for cfg in /etc/bash.bashrc /etc/profile /etc/zsh/zshrc /etc/zsh/zshenv; do
        [ -f "$cfg" ] || continue
        match_ioc "$cfg" >/dev/null && susp "global shell config IOC: $cfg"
    done
}

check_ssh() {
    print_section "SSH persistence"

    while IFS= read -r uhome; do
        local user; user="$(basename "$uhome")"
        for ak in "$uhome/.ssh/authorized_keys" "$uhome/.ssh/authorized_keys2"; do
            [ -f "$ak" ] || continue
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${line// }" ]] && continue
                if grep -q 'command=' <<<"$line"; then
                    if grep -qiE 'bash|/bin/sh|curl|wget|nc |ncat|python|perl|ruby' <<<"$line"; then
                        susp "$user: forced-command key looks like a shell: ${line:0:80}..."
                    else
                        warn "$user: authorized_keys forced command present"
                    fi
                fi
                grep -q 'from=' <<<"$line" || warn "$user: key with no 'from=' source restriction"
            done < "$ak"
        done
        # ProxyCommand in user ssh config can be abused
        [ -f "$uhome/.ssh/config" ] && grep -qiE 'ProxyCommand|LocalCommand' "$uhome/.ssh/config" 2>/dev/null \
            && warn "$user: ~/.ssh/config uses ProxyCommand/LocalCommand"
    done < <(get_home_dirs)

    if [ -f /etc/ssh/sshd_config ]; then
        grep -qiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' /etc/ssh/sshd_config \
            && susp "sshd: PermitEmptyPasswords yes"
        grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config \
            && warn "sshd: PermitRootLogin yes"
        grep -qiE '^[[:space:]]*AuthorizedKeysFile' /etc/ssh/sshd_config \
            && info "sshd: custom AuthorizedKeysFile set" \
            && grep -iE '^[[:space:]]*AuthorizedKeysFile' /etc/ssh/sshd_config | sed 's/^/    /'
        grep -qiE '^[[:space:]]*ForceCommand' /etc/ssh/sshd_config \
            && warn "sshd: global ForceCommand set"
    fi
}

check_accounts() {
    print_section "Account & privilege backdoors"

    # Non-root accounts with UID 0
    while IFS=: read -r name _ uid _; do
        if [ "$uid" = "0" ] && [ "$name" != "root" ]; then
            crit "UID 0 account other than root: $name"
        fi
    done < /etc/passwd

    # Accounts with a login shell but empty password field in /etc/shadow
    if [ -r /etc/shadow ]; then
        while IFS=: read -r name pass _; do
            [ -z "$pass" ] && crit "account with empty password hash: $name"
        done < /etc/shadow
    else
        note "/etc/shadow not readable (run as root for password checks)"
    fi

    # sudoers NOPASSWD / broad grants
    for f in /etc/sudoers $(find /etc/sudoers.d -type f 2>/dev/null); do
        [ -r "$f" ] || continue
        grep -qE '^[^#].*NOPASSWD' "$f" 2>/dev/null && warn "sudoers NOPASSWD rule in $f"
        grep -qE '^[^#].*ALL[[:space:]]*=[[:space:]]*\(ALL.*\)[[:space:]]*ALL' "$f" 2>/dev/null \
            && info "broad ALL grant in $f"
    done
}

check_suid_sgid() {
    print_section "SUID/SGID binaries"

    local known='^/usr/bin/(sudo|su|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|ping|pkexec|fusermount3?|crontab|at|wall|write|expiry|chage|ssh-agent)$|^/bin/(su|mount|umount|ping)$|^/usr/lib/'

    # SUID/SGID in writable / temp locations -> almost always bad
    while IFS= read -r f; do
        susp "SUID/SGID in temp/home: $f ($(stat -c '%a %U:%G' "$f" 2>/dev/null))"
    done < <(find /tmp /dev/shm /var/tmp $(get_home_dirs) -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

    # Recently created SUID binaries outside the known-good set
    while IFS= read -r f; do
        [[ "$f" =~ $known ]] && continue
        warn "recent SUID/SGID (<=30d): $f ($(stat -c '%a %U:%G' "$f" 2>/dev/null))"
    done < <(fs_find / -type f \( -perm -4000 -o -perm -2000 \) -mtime -30 2>/dev/null)
}

check_ld_preload() {
    print_section "LD_PRELOAD / library hijacking"

    if [ -f /etc/ld.so.preload ]; then
        crit "/etc/ld.so.preload exists"
        sed 's/^/    /' /etc/ld.so.preload
    fi
    [ -n "${LD_PRELOAD:-}" ]  && warn "LD_PRELOAD set in environment: $LD_PRELOAD"
    [ -n "${LD_LIBRARY_PATH:-}" ] && info "LD_LIBRARY_PATH set: $LD_LIBRARY_PATH"

    # ld.so.conf entries pointing at writable dirs
    if [ -f /etc/ld.so.conf ] || [ -d /etc/ld.so.conf.d ]; then
        while IFS= read -r libdir; do
            case "$libdir" in
                /tmp/*|/dev/shm/*|/var/tmp/*|/home/*)
                    susp "ld.so.conf includes writable path: $libdir" ;;
            esac
        done < <(cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -vE '^\s*#|^\s*include')
    fi

    while IFS= read -r lib; do
        susp "shared object in temp dir: $lib"
    done < <(find /tmp /dev/shm /var/tmp -name '*.so*' -type f 2>/dev/null)
}

check_kernel_modules() {
    print_section "Kernel modules"
    # NOTE: v1 compared `lsmod | wc -l` (has header, excludes built-ins) to
    # /sys/module (includes built-ins) and always false-alarmed. That heuristic
    # is unreliable, so we instead flag concrete oddities.

    if [ -f /etc/modules ] || [ -d /etc/modules-load.d ]; then
        while IFS= read -r m; do
            [[ "$m" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${m// }" ]] && continue
            info "auto-loaded module configured: $m"
        done < <(cat /etc/modules /etc/modules-load.d/*.conf 2>/dev/null)
    fi

    # Loaded modules whose backing file lives outside standard paths
    if have modinfo; then
        while IFS= read -r mod; do
            local fn; fn="$(modinfo -n "$mod" 2>/dev/null)"
            [ -z "$fn" ] && continue
            case "$fn" in
                /lib/modules/*|/usr/lib/modules/*|"(builtin)") ;;
                *) susp "module $mod loaded from non-standard path: $fn" ;;
            esac
        done < <(lsmod | awk 'NR>1{print $1}')
    fi
}

check_containers() {
    print_section "Container persistence"
    if have docker; then
        while IFS= read -r c; do
            [ -z "$c" ] && continue
            if docker inspect "$c" 2>/dev/null | grep -q '"NetworkMode": "host"'; then
                warn "docker container in host network mode: $c"
            fi
            if docker inspect "$c" 2>/dev/null | grep -q '"Privileged": true'; then
                susp "privileged docker container: $c"
            fi
            docker inspect "$c" 2>/dev/null | grep -q '"RestartPolicy".*"always"' \
                && info "container with restart=always: $c"
        done < <(docker ps -aq 2>/dev/null | xargs -r docker inspect --format '{{.Name}}' 2>/dev/null | sed 's#^/##')
    fi

    if [ -f /.dockerenv ] || grep -qa 'docker\|containerd\|kubepods' /proc/1/cgroup 2>/dev/null; then
        note "This host appears to be inside a container"
        # Host filesystem / docker socket mounted inside = escape risk
        mount 2>/dev/null | grep -qE 'docker.sock' && susp "docker socket mounted inside container"
    fi
}

check_webshells() {
    print_section "Web shells"
    local dirs=(/var/www /usr/share/nginx /srv/www /usr/local/apache2/htdocs /opt/lampp/htdocs)
    local shell_re='(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\(.*\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode[[:space:]]*\(.*(eval|gzinflate|str_rot13)|preg_replace[[:space:]]*\(.*/e|\$\{[[:space:]]*\$_(GET|POST)'

    for d in "${dirs[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r f; do
            grep -qaiE "$shell_re" "$f" 2>/dev/null && susp "possible web shell: $f"
        done < <(find "$d" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.asp' \
                    -o -name '*.aspx' -o -name '*.jsp' -o -name '*.jspx' \) 2>/dev/null)
    done
}

check_network() {
    print_section "Network persistence"

    # Listening sockets (prefer ss; fall back to netstat)
    local listen=""
    if have ss;      then listen="$(ss -tulnpH 2>/dev/null)"
    elif have netstat; then listen="$(netstat -tulnp 2>/dev/null | tail -n +3)"; fi

    if [ -n "$listen" ]; then
        while IFS= read -r line; do
            local addr port
            addr="$(awk '{print $5}' <<<"$line")"
            [ -z "$addr" ] && addr="$(grep -oE '[0-9.]+:[0-9]+|\[[^]]*\]:[0-9]+' <<<"$line" | head -1)"
            port="${addr##*:}"
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            if [[ "$addr" =~ $SUSPECT_PORTS_RE ]]; then
                susp "listening on suspicious port: $line"
            elif [ "$port" -gt 49152 ]; then
                warn "listening on high/ephemeral port: $line"
            fi
        done <<<"$listen"
    else
        note "no ss/netstat available for socket enumeration"
    fi

    # NAT redirect/forward rules
    if have nft; then
        nft list ruleset 2>/dev/null | grep -qiE 'dnat|redirect' && warn "nftables NAT redirect/DNAT rules present"
    elif have iptables; then
        iptables -t nat -S 2>/dev/null | grep -qiE 'DNAT|REDIRECT' && warn "iptables NAT DNAT/REDIRECT rules present"
    fi
}

check_processes() {
    print_section "Suspicious processes"
    # NOTE: v1's ps-vs-/proc "hidden process" count is racy and off-by-one; dropped.

    local pat='(^|/)(ncat|socat|meterpreter|beacon|stager|xmrig|kdevtmpfsi|kinsing)([[:space:]]|$)'
    while IFS= read -r line; do
        grep -qaiE "$pat" <<<"$line" && susp "process name of interest: $line"
    done < <(ps -eo pid,user,comm,args 2>/dev/null | tail -n +2)

    # Executables running from writable/temp directories
    while IFS= read -r pid; do
        local exe; exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)" || continue
        case "$exe" in
            /tmp/*|/dev/shm/*|/var/tmp/*|*" (deleted)")
                susp "PID $pid runs from temp/deleted path: $exe" ;;
        esac
    done < <(ls /proc 2>/dev/null | grep -E '^[0-9]+$')
}

check_pam() {
    print_section "PAM modules & configuration"
    local pam_dirs=(/lib/security /lib64/security /usr/lib/security
                    /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security
                    /usr/lib64/security)

    for d in "${pam_dirs[@]}"; do
        [ -d "$d" ] || continue
        while IFS= read -r m; do
            warn "recently modified PAM module (<=30d): $m"
        done < <(find "$d" -name '*.so' -mtime -30 2>/dev/null)
    done

    if [ -d /etc/pam.d ]; then
        while IFS= read -r c; do
            warn "recently modified PAM config (<=30d): $c"
        done < <(find /etc/pam.d -type f -mtime -30 2>/dev/null)
        # pam_exec lines can silently run attacker commands on auth
        while IFS= read -r hit; do
            susp "pam_exec directive found: $hit"
        done < <(grep -rlniE 'pam_exec\.so' /etc/pam.d 2>/dev/null)
    fi
}

check_unusual_files() {
    print_section "Unusual files & locations"

    while IFS= read -r f; do
        susp "regular file under /dev: $f"
    done < <(find /dev -type f 2>/dev/null)

    while IFS= read -r f; do
        warn "large file in /tmp: $f ($(du -h "$f" 2>/dev/null | cut -f1))"
    done < <(find /tmp -type f -size +50M 2>/dev/null)

    # Immutable files outside expected areas can indicate anti-tamper implants
    if have lsattr; then
        while IFS= read -r f; do
            lsattr "$f" 2>/dev/null | grep -q '^....i' && susp "immutable file: $f"
        done < <(find /tmp /var/tmp /dev/shm /home -maxdepth 3 -type f 2>/dev/null | head -200)
    fi
}

################################################################################
# Helpers used by modules
################################################################################

# Emit /root plus every real home directory from /etc/passwd (dedup, existing).
get_home_dirs() {
    { echo /root
      awk -F: '($3>=1000 || $1=="root"){print $6}' /etc/passwd 2>/dev/null
      ls -d /home/* 2>/dev/null
    } | sort -u | while IFS= read -r d; do [ -d "$d" ] && echo "$d"; done
}

# find wrapper that stays on one filesystem and prunes virtual/noisy dirs.
fs_find() {
    local start="$1"; shift
    local prune=()
    local first=1
    for p in "${PRUNE_DIRS[@]}"; do
        if [ "$first" -eq 1 ]; then prune+=( -path "$p"); first=0
        else prune+=( -o -path "$p"); fi
    done
    find "$start" -xdev \( "${prune[@]}" \) -prune -o "$@" -print 2>/dev/null
}

################################################################################
# Reporting: summary, JSON, baseline
################################################################################

count_sev() { awk -F'\t' -v s="$1" '$1==s{n++} END{print n+0}' "$FINDINGS_FILE" 2>/dev/null; }

print_summary() {
    print_section "Summary"
    local c s w i
    c="$(count_sev critical)"; s="$(count_sev suspicious)"
    w="$(count_sev warning)";  i="$(count_sev info)"

    printf '%s%sCRITICAL   : %s%s\n' "$RED"    "$BOLD" "$c" "$NC"
    printf '%s%sSUSPICIOUS : %s%s\n' "$RED"    "$BOLD" "$s" "$NC"
    printf '%s%sWARNING    : %s%s\n' "$YELLOW" "$BOLD" "$w" "$NC"
    printf '%s%sINFO       : %s%s\n' "$GREEN"  "$BOLD" "$i" "$NC"

    if [ "$((c + s))" -gt 0 ]; then
        printf '\n%s%s[!] Potential persistence detected — investigate the items above.%s\n' "$RED" "$BOLD" "$NC"
    elif [ "$w" -gt 5 ]; then
        printf '\n%s[!] Several noteworthy configurations — manual review advised.%s\n' "$YELLOW" "$NC"
    else
        printf '\n%s[ok] No suspicious or critical findings in basic checks.%s\n' "$GREEN" "$NC"
    fi

    printf '\n%sNext steps:%s auditd/syslog review, compare against a known-good baseline, and\n' "$CYAN" "$NC"
    printf 'corroborate with rkhunter / chkrootkit / AIDE. This tool is a first pass, not proof.\n'
}

write_json() {
    local f="$1"
    {
        printf '{\n'
        printf '  "tool": "decPEAS", "version": "%s",\n' "$VERSION"
        printf '  "generated": "%s",\n' "$(date -Is 2>/dev/null || date)"
        printf '  "host": "%s",\n' "$(hostname 2>/dev/null)"
        printf '  "counts": {"critical": %s, "suspicious": %s, "warning": %s, "info": %s},\n' \
            "$(count_sev critical)" "$(count_sev suspicious)" "$(count_sev warning)" "$(count_sev info)"
        printf '  "findings": [\n'
        local first=1
        while IFS=$'\t' read -r sev section msg; do
            # Minimal JSON string escaping
            local em="${msg//\\/\\\\}"; em="${em//\"/\\\"}"; em="${em//$'\t'/ }"
            [ "$first" -eq 0 ] && printf ',\n'
            printf '    {"severity": "%s", "section": "%s", "message": "%s"}' "$sev" "$section" "$em"
            first=0
        done < "$FINDINGS_FILE"
        printf '\n  ]\n}\n'
    } > "$f"
    note "JSON report written to $f"
}

do_baseline_compare() {
    local base="$1"
    [ -f "$base" ] || { warn "baseline file not found: $base"; return; }
    print_section "Baseline comparison"
    # Compare on section+message (severity may vary)
    local cur; cur="$(cut -f2- "$FINDINGS_FILE" | sort -u)"
    local new
    new="$(comm -23 <(echo "$cur") <(sort -u "$base"))"
    if [ -n "$new" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && susp "NEW since baseline: $line"
        done <<<"$new"
    else
        info "No new findings versus baseline."
    fi
}

write_baseline() {
    local f="$1"
    cut -f2- "$FINDINGS_FILE" | sort -u > "$f"
    note "Baseline snapshot written to $f ($(wc -l <"$f") entries)"
}

################################################################################
# CLI
################################################################################

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -o|--output)        OUTPUT_FILE="$2"; shift 2 ;;
            -j|--json)          JSON_FILE="$2"; shift 2 ;;
            -b|--baseline)      BASELINE_FILE="$2"; shift 2 ;;
            --write-baseline)   WRITE_BASELINE_FILE="$2"; shift 2 ;;
            -q|--quiet)         QUIET=1; shift ;;
            --no-color)         USE_COLOR="never"; shift ;;
            --color)            USE_COLOR="always"; shift ;;
            --min-severity)     MIN_SEVERITY="$2"; shift 2 ;;
            -h|--help)          usage; exit 0 ;;
            *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
        esac
    done
    [[ -n "${SEV_RANK[$MIN_SEVERITY]:-}" ]] || { echo "Invalid --min-severity: $MIN_SEVERITY" >&2; exit 2; }
}

banner() {
    printf '%s' "$CYAN"
    cat <<'EOF'
     _           ____  _____    _    ____
  __| | ___  ___|  _ \| ____|  / \  / ___|
 / _` |/ _ \/ __| |_) |  _|   / _ \ \___ \
| (_| |  __/ (__|  __/| |___ / ___ \ ___) |
 \__,_|\___|\___|_|   |_____/_/   \_\____/
     Persistence Detection Tool — Blue Team Edition
EOF
    printf '%s v%s  (read-only auditor)\n' "$NC" "$VERSION"
    [ "$EUID" -ne 0 ] && warn "Not running as root — user files, /etc/shadow and some units may be skipped."
}

run_all() {
    check_cron_jobs
    check_at_jobs
    check_systemd
    check_init_scripts
    check_shell_configs
    check_ssh
    check_accounts
    check_suid_sgid
    check_ld_preload
    check_kernel_modules
    check_containers
    check_webshells
    check_network
    check_processes
    check_pam
    check_unusual_files
}

main() {
    parse_args "$@"
    setup_colors

    # Route console output to tee if an output file was requested (strip colours there).
    if [ -n "$OUTPUT_FILE" ]; then
        exec > >(tee >(sed -r 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"))
    fi

    banner
    run_all

    if [ -n "$WRITE_BASELINE_FILE" ]; then
        write_baseline "$WRITE_BASELINE_FILE"
    fi
    [ -n "$BASELINE_FILE" ] && do_baseline_compare "$BASELINE_FILE"

    print_summary
    [ -n "$JSON_FILE" ] && write_json "$JSON_FILE"

    local total_bad=$(( $(count_sev critical) + $(count_sev suspicious) ))
    [ "$total_bad" -gt 0 ] && exit 1 || exit 0
}

main "$@"
