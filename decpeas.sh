#!/bin/bash


# decPEAS - Detection PEAS 
# Linux Persistence Mechanism Detection Tool for Blue Team 
# Version: 1.0

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${CYAN}"
cat << "EOF"
     _           ____  _____    _    ____  
  __| | ___  ___|  _ \| ____|  / \  / ___| 
 / _` |/ _ \/ __| |_) |  _|   / _ \ \___ \ 
| (_| |  __/ (__|  __/| |___ / ___ \ ___) |
 \__,_|\___|\___|_|   |_____/_/   \_\____/ 
                                            
    Persistence Detection Tool v1.0
    Blue Team Edition - by Defender
EOF
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] Some checks require root privileges${NC}"
fi

SUSPICIOUS_COUNT=0
WARNING_COUNT=0

print_section() {
    echo -e "\n${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║${NC} ${CYAN}$1${NC}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════╗${NC}\n"
}

print_suspicious() {
    echo -e "${RED}[SUSPICIOUS]${NC} $1"
    ((SUSPICIOUS_COUNT++))
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNING_COUNT++))
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

check_cron_jobs() {
    print_section "CRON JOBS PERSISTENCE"
    
    echo -e "${CYAN}System Crontabs:${NC}"
    if [ -f /etc/crontab ]; then
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^#.*$ ]] && [[ ! -z "$line" ]]; then
                if echo "$line" | grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec'; then
                    print_suspicious "/etc/crontab: $line"
                else
                    print_info "/etc/crontab: $line"
                fi
            fi
        done < /etc/crontab
    fi
    
    echo -e "\n${CYAN}User Crontabs:${NC}"
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -l -u "$user" 2>/dev/null | while IFS= read -r line; do
            if [[ ! "$line" =~ ^#.*$ ]] && [[ ! -z "$line" ]]; then
                if echo "$line" | grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec'; then
                    print_suspicious "User $user: $line"
                else
                    print_info "User $user: $line"
                fi
            fi
        done
    done
    
    for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$dir" ]; then
            echo -e "\n${CYAN}$dir:${NC}"
            find "$dir" -type f 2>/dev/null | while read -r file; do
                if grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec' "$file" 2>/dev/null; then
                    print_suspicious "$file - suspicious commands found"
                else
                    print_info "$file"
                fi
            done
        fi
    done
}

check_systemd_services() {
    print_section "SYSTEMD SERVICES PERSISTENCE"
    
    echo -e "${CYAN}Suspicious systemd services:${NC}"
    
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep '.service' | awk '{print $1}' | while read -r service; do
        service_file=$(systemctl show -p FragmentPath "$service" 2>/dev/null | cut -d= -f2)
        
        if [ -f "$service_file" ]; then
            if grep -qiE 'curl|wget|nc |bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|/tmp/|/dev/shm/' "$service_file" 2>/dev/null; then
                print_suspicious "$service ($service_file)"
                grep -iE 'ExecStart|ExecStartPre|ExecStartPost' "$service_file" 2>/dev/null | sed 's/^/  /'
            fi
            
            if [[ "$service_file" =~ ^/tmp/|^/dev/shm/|^/home/.*/.config/systemd ]]; then
                print_warning "$service - unusual location: $service_file"
            fi
        fi
    done
    
    echo -e "\n${CYAN}User systemd services:${NC}"
    for user_home in /home/*; do
        user=$(basename "$user_home")
        user_service_dir="$user_home/.config/systemd/user"
        if [ -d "$user_service_dir" ]; then
            find "$user_service_dir" -name "*.service" 2>/dev/null | while read -r service_file; do
                print_warning "User $user service: $service_file"
                grep -iE 'ExecStart|ExecStartPre|ExecStartPost' "$service_file" 2>/dev/null | sed 's/^/  /'
            done
        fi
    done
}

check_init_scripts() {
    print_section "INIT SCRIPTS & RC.LOCAL PERSISTENCE"
    
    if [ -f /etc/rc.local ]; then
        echo -e "${CYAN}/etc/rc.local:${NC}"
        if grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec' /etc/rc.local; then
            print_suspicious "/etc/rc.local - suspicious commands found"
            cat /etc/rc.local | sed 's/^/  /'
        else
            print_info "/etc/rc.local exists"
        fi
    fi
    
    echo -e "\n${CYAN}/etc/init.d scripts:${NC}"
    if [ -d /etc/init.d ]; then
        find /etc/init.d -type f 2>/dev/null | while read -r script; do
            if grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec' "$script"; then
                print_suspicious "$script - suspicious commands"
            fi
        done
    fi
}

check_shell_configs() {
    print_section "SHELL CONFIGURATION FILES PERSISTENCE"
    
    shell_files=(".bashrc" ".bash_profile" ".profile" ".zshrc" ".zshenv" ".config/fish/config.fish")
    
    for user_home in /root /home/*; do
        user=$(basename "$user_home")
        
        for shell_file in "${shell_files[@]}"; do
            full_path="$user_home/$shell_file"
            
            if [ -f "$full_path" ]; then
                if grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64.*-d|eval|exec|export.*http_proxy|export.*https_proxy' "$full_path"; then
                    print_suspicious "$full_path - suspicious commands"
                    grep -niE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec|export.*proxy' "$full_path" | sed 's/^/  /'
                fi
            fi
        done
    done
    
    echo -e "\n${CYAN}Global shell configs:${NC}"
    global_configs=("/etc/bash.bashrc" "/etc/profile" "/etc/zsh/zshrc")
    
    for config in "${global_configs[@]}"; do
        if [ -f "$config" ]; then
            if grep -qiE 'curl|wget|nc|bash -i|/dev/tcp|python.*socket|perl.*socket|ruby.*socket|base64|eval|exec' "$config"; then
                print_suspicious "$config - suspicious commands"
            fi
        fi
    done
}

check_ssh_persistence() {
    print_section "SSH PERSISTENCE MECHANISMS"
    
    echo -e "${CYAN}Authorized Keys:${NC}"
    for user_home in /root /home/*; do
        user=$(basename "$user_home")
        auth_keys="$user_home/.ssh/authorized_keys"
        
        if [ -f "$auth_keys" ]; then
            echo -e "\n${YELLOW}User: $user${NC}"
            
            while IFS= read -r line; do
                if [[ ! "$line" =~ ^#.*$ ]] && [[ ! -z "$line" ]]; then
                    if echo "$line" | grep -q "command="; then
                        if echo "$line" | grep -qiE 'bash|sh|curl|wget|nc|python|perl|ruby'; then
                            print_suspicious "Restricted command: $line"
                        else
                            print_warning "Command restriction: $line"
                        fi
                    else
                        print_info "$line"
                    fi
                    
                    if ! echo "$line" | grep -q "from="; then
                        print_warning "No 'from' restriction on key (allows from any IP)"
                    fi
                fi
            done < "$auth_keys"
        fi
    done
    
    echo -e "\n${CYAN}SSH Configuration:${NC}"
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -qiE '^PermitRootLogin.*yes' /etc/ssh/sshd_config; then
            print_warning "Root login permitted"
        fi
        
        if grep -qiE '^PermitEmptyPasswords.*yes' /etc/ssh/sshd_config; then
            print_suspicious "Empty passwords permitted!"
        fi
        
        if grep -qiE '^AuthorizedKeysFile' /etc/ssh/sshd_config; then
            print_info "Custom authorized keys location:"
            grep -iE '^AuthorizedKeysFile' /etc/ssh/sshd_config | sed 's/^/  /'
        fi
    fi
}

check_suid_sgid() {
    print_section "SUSPICIOUS SUID/SGID FILES"
    
    echo -e "${CYAN}New SUID/SGID files (last 30 days):${NC}"
    find / -type f \( -perm -4000 -o -perm -2000 \) -mtime -30 2>/dev/null | while read -r file; do
        if ! echo "$file" | grep -qE '^/usr/bin/(sudo|su|passwd|mount|umount|ping|pkexec)|^/bin/(su|mount|umount|ping)'; then
            print_warning "$file ($(stat -c '%a %U:%G' "$file" 2>/dev/null))"
        fi
    done
    
    echo -e "\n${CYAN}SUID/SGID in unusual locations:${NC}"
    find /tmp /dev/shm /var/tmp /home -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r file; do
        print_suspicious "$file ($(stat -c '%a %U:%G' "$file" 2>/dev/null))"
    done
}

check_ld_preload() {
    print_section "LD_PRELOAD & SHARED LIBRARY HIJACKING"
    
    if [ -f /etc/ld.so.preload ]; then
        print_suspicious "/etc/ld.so.preload exists!"
        cat /etc/ld.so.preload | sed 's/^/  /'
    fi
    
    echo -e "\n${CYAN}Environment LD_PRELOAD:${NC}"
    env | grep -i LD_PRELOAD && print_warning "LD_PRELOAD environment variable found"
    
    echo -e "\n${CYAN}Suspicious shared library locations:${NC}"
    find /tmp /dev/shm /var/tmp -name "*.so" 2>/dev/null | while read -r lib; do
        print_suspicious "$lib"
    done
}

check_kernel_modules() {
    print_section "KERNEL MODULES (ROOTKITS)"
    
    echo -e "${CYAN}Loaded kernel modules:${NC}"
    
    lsmod_count=$(lsmod | wc -l)
    proc_count=$(find /sys/module -mindepth 1 -maxdepth 1 -type d | wc -l)
    
    if [ "$lsmod_count" -ne "$proc_count" ]; then
        print_suspicious "Hidden kernel modules might exist! lsmod: $lsmod_count, /sys/module: $proc_count"
    fi
    
    echo -e "\n${CYAN}Recently loaded modules:${NC}"
    dmesg | grep -i "module" | tail -10 | sed 's/^/  /'
    
    lsmod | tail -n +2 | awk '{print $1}' | while read -r module; do
        if echo "$module" | grep -qiE 'rootkit|backdoor|hide|suspicious'; then
            print_suspicious "Module: $module"
        fi
    done
}

check_containers() {
    print_section "CONTAINER PERSISTENCE"
    
    if command -v docker &> /dev/null; then
        echo -e "${CYAN}Docker Containers:${NC}"
        docker ps -a 2>/dev/null | tail -n +2 | while read -r line; do
            container_name=$(echo "$line" | awk '{print $NF}')
            container_image=$(echo "$line" | awk '{print $2}')
            
            if echo "$container_image" | grep -qiE 'latest|unknown|scratch'; then
                print_warning "Container: $container_name, Image: $container_image"
            fi
        done
        
        echo -e "\n${CYAN}Containers using host network:${NC}"
        docker ps -a --format '{{.Names}}' 2>/dev/null | while read -r container; do
            if docker inspect "$container" 2>/dev/null | grep -q '"NetworkMode": "host"'; then
                print_warning "$container - running in host network mode"
            fi
        done
    fi
    
    echo -e "\n${CYAN}Container escape indicators:${NC}"
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        print_info "Running inside a container"
        
        if mount | grep -qE '/proc|/sys|/dev' | grep -v 'type tmpfs'; then
            print_suspicious "Suspicious mounts found"
            mount | grep -E '/proc|/sys|/dev' | sed 's/^/  /'
        fi
    fi
}

check_webshells() {
    print_section "WEB SHELLS & BACKDOORS"
    
    web_dirs=("/var/www" "/usr/share/nginx" "/usr/local/apache" "/opt/lampp/htdocs")
    
    echo -e "${CYAN}Searching for web shells:${NC}"
    
    for web_dir in "${web_dirs[@]}"; do
        if [ -d "$web_dir" ]; then
            echo -e "\n${YELLOW}Checking: $web_dir${NC}"
            
            find "$web_dir" -type f \( -name "*.php" -o -name "*.asp" -o -name "*.aspx" -o -name "*.jsp" \) 2>/dev/null | while read -r file; do
                if grep -qiE 'eval.*\$_(GET|POST|REQUEST)|system.*\$_(GET|POST|REQUEST)|exec.*\$_(GET|POST|REQUEST)|shell_exec|passthru|base64_decode.*eval|assert.*\$_(GET|POST)|preg_replace.*\/e' "$file"; then
                    print_suspicious "Possible web shell: $file"
                fi
            done
            
            find "$web_dir" -type f -mtime -7 2>/dev/null | while read -r file; do
                if file "$file" | grep -qiE 'php|html|script'; then
                    print_info "Modified in last 7 days: $file"
                fi
            done
        fi
    done
}

check_network_persistence() {
    print_section "NETWORK-BASED PERSISTENCE"
    
    echo -e "${CYAN}Active network connections:${NC}"
    netstat -antp 2>/dev/null | grep ESTABLISHED | while read -r line; do
        if echo "$line" | grep -qE ':4444|:31337|:1337|:8080|:8888|:9999'; then
            print_warning "$line"
        fi
    done
    
    echo -e "\n${CYAN}Listening ports:${NC}"
    ss -tlnp 2>/dev/null | tail -n +2 | while read -r line; do
        port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
        
        if [ "$port" -gt 49152 ] || [ "$port" -eq 4444 ] || [ "$port" -eq 31337 ]; then
            print_warning "$line"
        fi
    done
    
    echo -e "\n${CYAN}Port forwarding rules:${NC}"
    if command -v iptables &> /dev/null; then
        iptables -t nat -L -n 2>/dev/null | grep -E 'REDIRECT|DNAT' && print_warning "Port forwarding rules found"
    fi
}

check_processes() {
    print_section "SUSPICIOUS PROCESSES"
    
    echo -e "${CYAN}Suspicious process names:${NC}"
    ps aux | grep -iE 'nc|ncat|socat|meterpreter|metasploit|empire|covenant|beacon|stager' | grep -v grep | while read -r line; do
        print_suspicious "$line"
    done
    
    echo -e "\n${CYAN}Processes running from temporary directories:${NC}"
    ps aux | grep -E '/tmp/|/dev/shm/|/var/tmp/' | grep -v grep | while read -r line; do
        print_warning "$line"
    done
    
    echo -e "\n${CYAN}Checking for hidden processes:${NC}"
    ps_count=$(ps aux | wc -l)
    proc_count=$(ls -1 /proc | grep -E '^[0-9]+$' | wc -l)
    
    if [ "$ps_count" -lt "$proc_count" ]; then
        print_suspicious "Hidden processes might exist! ps: $ps_count, /proc: $proc_count"
    fi
}

check_pam_backdoors() {
    print_section "PAM BACKDOORS"
    
    echo -e "${CYAN}PAM configuration:${NC}"
    
    if [ -d /lib/security ] || [ -d /lib64/security ]; then
        for pam_dir in /lib/security /lib64/security; do
            if [ -d "$pam_dir" ]; then
                find "$pam_dir" -name "*.so" -mtime -30 2>/dev/null | while read -r pam_module; do
                    print_warning "Recently changed PAM module: $pam_module"
                done
            fi
        done
    fi
    
    if [ -d /etc/pam.d ]; then
        find /etc/pam.d -type f -mtime -30 2>/dev/null | while read -r pam_conf; do
            print_warning "Recently changed PAM config: $pam_conf"
        done
    fi
}

check_unusual_files() {
    print_section "UNUSUAL FILES & LOCATIONS"
    
    echo -e "${CYAN}Regular files in /dev:${NC}"
    find /dev -type f 2>/dev/null | while read -r file; do
        print_suspicious "$file"
    done
    
    echo -e "\n${CYAN}Large files in /tmp (10MB+):${NC}"
    find /tmp -type f -size +10M 2>/dev/null | while read -r file; do
        print_warning "$file ($(du -h "$file" | cut -f1))"
    done
    
    echo -e "\n${CYAN}Hidden files in unusual locations:${NC}"
    find /usr /opt /var -name ".*" -type f 2>/dev/null | grep -vE '\.so|\.conf|\.cache' | head -20 | while read -r file; do
        print_info "$file"
    done
}

print_summary() {
    print_section "DETECTION SUMMARY"
    
    echo -e "${RED}${BOLD}Total SUSPICIOUS findings: $SUSPICIOUS_COUNT${NC}"
    echo -e "${YELLOW}${BOLD}Total WARNING findings: $WARNING_COUNT${NC}"
    
    if [ $SUSPICIOUS_COUNT -gt 0 ]; then
        echo -e "\n${RED}${BOLD}[!] Persistence mechanisms found on the system!${NC}"
        echo -e "${RED}Further investigation is recommended.${NC}"
    elif [ $WARNING_COUNT -gt 5 ]; then
        echo -e "\n${YELLOW}[!] Multiple suspicious configurations detected.${NC}"
        echo -e "${YELLOW}Manual inspection is recommended.${NC}"
    else
        echo -e "\n${GREEN}[✓] No serious issues found in basic checks.${NC}"
    fi
    
    echo -e "\n${CYAN}Recommendations:${NC}"
    echo -e "1. Inspect discovered SUSPICIOUS items in detail"
    echo -e "2. Analyze log files (auditd, syslog)"
    echo -e "3. Compare against system backups"
    echo -e "4. Monitor network traffic"
    echo -e "5. Perform additional scans with tools like rkhunter, chkrootkit"
}

main() {
    check_cron_jobs
    check_systemd_services
    check_init_scripts
    check_shell_configs
    check_ssh_persistence
    check_suid_sgid
    check_ld_preload
    check_kernel_modules
    check_containers
    check_webshells
    check_network_persistence
    check_processes
    check_pam_backdoors
    check_unusual_files
    print_summary
}

main
