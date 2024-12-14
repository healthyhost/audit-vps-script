#!/bin/bash

# audit.sh
#
# This script performs security checks on an Ubuntu/Debian VPS, ensuring it follows
# good security practices. It checks for:
#   * UFW firewall configuration
#   * SSH hardening
#   * Non-root user setup
#   * Automatic updates
#   * Fail2ban configuration
#
# Usage:    
#   Local reporting only:
#     sudo ./audit.sh
#   
#   Report to remote service:
#     sudo ./audit.sh <session-id>
#
# Note: Certain commands require sudo privileges.
# When no session id is provided, results are only printed to terminal.
# When session id is set, results are sent to API_ENDPOINT and also printed to terminal.
# Each check's status (running/pass/fail/error) is reported progressively in both modes.

set -u

VERSION="0.1.0"
API_ENDPOINT="http://127.0.0.1:8080/audit-step"
AUDIT_ID=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 10 | head -n 1)
SESSION="${1:-}" # Get first parameter or empty string if not provided

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

check_os() {
    local os=""
    if [ -f /etc/lsb-release ]; then
        os="ubuntu"
    elif [ -f /etc/debian_version ]; then
        os="debian"
    fi

    if [ -z "$os" ]; then
        echo -e "${RED}This script only supports Ubuntu/Debian systems. Exiting.${NC}"
        echo "Please ensure you're running this script on a supported operating system."
        exit 1
    fi

    echo -e "${GREEN}Detected supported OS: ${os}${NC}\n"
}

check_dependencies() {
    echo -e "${CYAN}Checking required dependencies...${NC}"
    
    local required_commands=("curl" "jq" "systemctl" "apt-get")
    local missing_commands=()

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_commands+=("$cmd")
        fi
    done

    if [ ${#missing_commands[@]} -ne 0 ]; then
        echo -e "${RED}The following required commands are missing:${NC}"
        for cmd in "${missing_commands[@]}"; do
            echo "  - $cmd"
        done
        echo
        echo -e "${YELLOW}Please install these commands before running this script.{NC}"
        exit 1
    fi

    echo -e "${GREEN}All required dependencies are installed${NC}\n"
    return 0
}

send_to_api() {
    # Only proceed if SESSION is set
    if [ -n "${SESSION:-}" ]; then
        local category="$1"
        local status="$2"
        local message="$3"
        local check="${4:-}"
        
        local data
        if [ -n "$check" ]; then
            data=$(jq -n \
                --arg session "$SESSION" \
                --arg category "$category" \
                --arg status "$status" \
                --arg msg "$message" \
                --arg check "$check" \
                --arg id "$AUDIT_ID" \
                --arg version "$VERSION" \
                '{session_id: $session, id: $id, category: $category, status: $status, message: $msg, check: $check, version: $version}')
        else
            data=$(jq -n \
                --arg session "$SESSION" \
                --arg category "$category" \
                --arg status "$status" \
                --arg msg "$message" \
                --arg id "$AUDIT_ID" \
                --arg version "$VERSION" \
                '{session_id: $session, id: $id, category: $category, status: $status, message: $msg, version: $version}')
        fi

        local response
        response=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$data" "$API_ENDPOINT")

        local http_code
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" != "200" ]; then
            echo "$response" | sed '$d'
            echo -e "${RED}Failed to send status to API (HTTP $http_code)${NC}"
            return 1
        fi
    fi
    return 0
}

print_status() {
    local category="$1"
    local status="$2"
    local message="$3"
    local check="${4:-}"
    
    local indent=""
    local status_color=""
    
    if [ -n "$check" ]; then
        indent="  ├─ "
        category="$check"  # Use check as the category for checks
    fi

    case "$status" in
        "running")
            status_color="$CYAN"
            ;;
        "pass")
            status_color="$GREEN"
            ;;
        "fail")
            status_color="$RED"
            ;;
        "error")
            status_color="$RED"
            ;;
        "skip")
            status_color="$YELLOW"
            ;;
        *)
            status_color="$YELLOW"
            ;;
    esac

    echo -e "${indent}${status_color}[${status^^}]${NC} ${category}: ${message}"
}

send_status() {
    local category="$1"
    local status="$2"
    local message="$3"
    local check="${4:-}"

    print_status "$category" "$status" "$message" "$check"
    send_to_api "$category" "$status" "$message" "$check"
}

check_ufw() {
    local category="ufw_security"
    local failed=false
    
    send_status "$category" "running" "Starting UFW security check"

    # Check if UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        send_status "$category" "fail" "UFW is not installed" "installation"
        failed=true
    else
        send_status "$category" "pass" "UFW is installed" "installation"
    fi
    
    # Check if UFW is active
    if ! $failed; then
        if ! sudo ufw status | grep -q "Status: active"; then
            send_status "$category" "fail" "UFW is installed but not active" "active_status"
            failed=true
        else
            send_status "$category" "pass" "UFW is active" "active_status"
        fi
    else
        send_status "$category" "skip" "Skipping check" "active_status"
    fi
    
    # Check default policies
    if ! $failed; then
        local default_incoming
        if ! default_incoming=$(sudo ufw status verbose | grep "Default:" | grep "incoming" | awk '{print $2}'); then
            send_status "$category" "error" "Failed to retrieve UFW default policy" "default_policy"
            failed=true
        elif [ "$default_incoming" != "deny" ]; then
            send_status "$category" "fail" "Default incoming policy is not set to deny" "default_policy"
            failed=true
        else
            send_status "$category" "pass" "Default incoming policy is properly set to deny" "default_policy"
        fi
    else
        send_status "$category" "skip" "Skipping check" "default_policy"
    fi
    
    # Final status
    if $failed; then
        send_status "$category" "fail" "Some UFW security checks failed"
        return 1
    else
        send_status "$category" "pass" "All UFW security checks passed"
        return 0
    fi
}

check_ssh() {
    local category="ssh_security"
    local final_status="pass"
    local ssh_enabled=false
    local config_file="/etc/ssh/sshd_config"
    
    send_status "$category" "running" "Starting SSH security check"

    # Check if SSH is enabled
    if systemctl is-active --quiet sshd; then
        send_status "$category" "pass" "SSH service is enabled" "service_status"
        ssh_enabled=true
    else
        send_status "$category" "pass" "SSH service is disabled - no further checks needed" "service_status"
        send_status "$category" "skip" "SSH disabled - skipping check" "key_auth"
        send_status "$category" "skip" "SSH disabled - skipping check" "config_PermitRootLogin"
        send_status "$category" "skip" "SSH disabled - skipping check" "config_ChallengeResponseAuthentication"
        send_status "$category" "skip" "SSH disabled - skipping check" "config_PasswordAuthentication"
        send_status "$category" "skip" "SSH disabled - skipping check" "config_UsePAM"
        send_status "$category" "skip" "SSH disabled - skipping check" "port"
        send_status "$category" "pass" "All SSH security checks passed"
        return 0
    fi
    
    # Only continue if SSH is enabled
    if $ssh_enabled; then
        # Check if key-based auth is setup (look for authorized_keys)
        if ! find /home -type f -name "authorized_keys" 2>/dev/null | grep -q .; then
            send_status "$category" "fail" "No authorized_keys found in any home directory" "key_auth"
            final_status="fail"
        else
            send_status "$category" "pass" "Key-based authentication is set up" "key_auth"
        fi
        
        # Check SSH config settings
        local config_checks=(
            "PermitRootLogin no"
            "ChallengeResponseAuthentication no"
            "PasswordAuthentication no"
            "UsePAM no"
        )
        
        for check in "${config_checks[@]}"; do
            local key="${check% *}" # Get the key part (before the space)
            local expected="${check#* }" # Get the value part (after the space)
            local actual
            
            # Get actual value, removing any leading whitespace and ignoring comments
            actual=$(sudo grep "^[[:space:]]*${key}[[:space:]]" "$config_file" | awk '{print $2}' | tail -n1)
            
            if [ -z "$actual" ]; then
                send_status "$category" "fail" "${key} is not set in sshd_config" "config_${key}"
                final_status="fail"
            elif [ "$actual" != "$expected" ]; then
                send_status "$category" "fail" "${key} is set to '$actual' (should be '$expected')" "config_${key}"
                final_status="fail"
            else
                send_status "$category" "pass" "${key} is correctly set to '$expected'" "config_${key}"
            fi
        done
        
        # Check SSH port
        local ssh_port
        ssh_port=$(sudo grep "^[[:space:]]*Port[[:space:]]" "$config_file" | awk '{print $2}')
        
        if [ -z "$ssh_port" ]; then
            send_status "$category" "fail" "SSH port is not explicitly set (defaults to 22)" "port"
            final_status="fail"
        elif [ "$ssh_port" = "22" ]; then
            send_status "$category" "fail" "SSH is using the standard port (22)" "port"
            final_status="fail"
        else
            send_status "$category" "pass" "SSH is using non-standard port ${ssh_port}" "port"
        fi
    fi
    
    # Final status
    if [ "$final_status" = "fail" ]; then
        send_status "$category" "fail" "Some SSH security checks failed"
        return 1
    else
        send_status "$category" "pass" "All SSH security checks passed"
        return 0
    fi
}

check_non_root_user() {
    local category="non_root_user"
    local final_status="pass"
    local sudo_users
    local admin_users
    local privileged_users
    
    send_status "$category" "running" "Checking for properly configured non-root user"

    # Look for users with sudo privileges (in sudo or admin group)
    sudo_users=$(grep -Po '^sudo:.*:\K.*$' /etc/group | tr ',' '\n' | grep -v root)
    admin_users=$(grep -Po '^admin:.*:\K.*$' /etc/group | tr ',' '\n' | grep -v root)
    
    if [ -z "$sudo_users" ] && [ -z "$admin_users" ]; then
        send_status "$category" "fail" "No non-root users found with sudo privileges" "sudo_access"
        final_status="fail"
    else
        # Combine and deduplicate users
        privileged_users=$(echo -e "${sudo_users}\n${admin_users}" | sort -u | grep -v '^$')
        
        # Check if any of these users have a valid shell
        local valid_user_found=false
        local user_shell
        
        while IFS= read -r user; do
            user_shell=$(getent passwd "$user" | cut -d: -f7)
            if [[ "$user_shell" != "/usr/sbin/nologin" && "$user_shell" != "/bin/false" ]]; then
                valid_user_found=true
                send_status "$category" "pass" "Found valid sudo user: $user" "sudo_access"
                break
            fi
        done <<< "$privileged_users"
        
        if ! $valid_user_found; then
            send_status "$category" "fail" "No sudo users found with valid login shell" "sudo_access"
            final_status="fail"
        fi
    fi
    
    # Final status
    if [ "$final_status" = "fail" ]; then
        send_status "$category" "fail" "Non-root user check failed"
        return 1
    else
        send_status "$category" "pass" "Valid non-root sudo user exists"
        return 0
    fi
}

check_unattended_upgrades() {
   local category="unattended_upgrades"
   local final_status="pass"
   local auto_upgrades_file="/etc/apt/apt.conf.d/20auto-upgrades"
   local update_enabled
   local upgrade_enabled
   
   send_status "$category" "running" "Checking automatic upgrades configuration"

   # Check if package is installed
   if ! dpkg -l | grep -q "unattended-upgrades"; then
       send_status "$category" "fail" "unattended-upgrades package is not installed" "installation"
       final_status="fail"
       return 1
   fi
   send_status "$category" "pass" "unattended-upgrades package is installed" "installation"

   # Check if service is running
   if ! systemctl is-active --quiet unattended-upgrades.service; then
       send_status "$category" "fail" "unattended-upgrades service is not running" "service_status"
       final_status="fail"
   else
       send_status "$category" "pass" "unattended-upgrades service is running" "service_status"
   fi

   # Check if automatic updates are enabled in /etc/apt/apt.conf.d/20auto-upgrades
   if [ ! -f "$auto_upgrades_file" ]; then
       send_status "$category" "fail" "Auto-upgrades configuration file not found" "config_file"
       send_status "$category" "skip" "Config file not present - skipping check" "auto_update"
       send_status "$category" "skip" "Config file not present - skipping check" "auto_update"
       final_status="fail"
   else
       send_status "$category" "pass" "Auto-upgrades configuration file exists" "config_file"

       update_enabled=$(grep "APT::Periodic::Update-Package-Lists" "$auto_upgrades_file" | grep -o '[0-9]\+' || echo "0")
       upgrade_enabled=$(grep "APT::Periodic::Unattended-Upgrade" "$auto_upgrades_file" | grep -o '[0-9]\+' || echo "0")
       
       if [ "$update_enabled" = "0" ]; then
           send_status "$category" "fail" "Automatic package list updates are disabled" "auto_update"
           final_status="fail"
       else 
           send_status "$category" "pass" "Automatic updates are enabled" "auto_update"
       fi

       if [ "$upgrade_enabled" = "0" ]; then
           send_status "$category" "fail" "Automatic upgrades are disabled" "auto_upgrade"
           final_status="fail"
       else
           send_status "$category" "pass" "Automatic upgrades are enabled" "auto_upgrade"
       fi
   fi

   # Final status
   if [ "$final_status" = "fail" ]; then
       send_status "$category" "fail" "Automatic upgrades check failed"
       return 1
   else
       send_status "$category" "pass" "Automatic upgrades are properly configured"
       return 0
   fi
}

check_fail2ban() {
    local category="fail2ban"
    local failed=false
    local installation_failed=false
    local config_file_missing=false
    local ssh_enabled
    local ssh_mode
    
    send_status "$category" "running" "Checking fail2ban installation and configuration"

    # Check if package is installed - all other checks depend on this
    if ! dpkg -l | grep -q "fail2ban"; then
        send_status "$category" "fail" "fail2ban package is not installed" "installation"
        installation_failed=true
        failed=true
    else
        send_status "$category" "pass" "fail2ban package is installed" "installation"
    fi

    if ! $installation_failed; then
        # Check if service is enabled
        if ! systemctl is-enabled --quiet fail2ban.service; then
            send_status "$category" "fail" "fail2ban service is not enabled" "service_enabled"
            failed=true
        else
            send_status "$category" "pass" "fail2ban service is enabled" "service_enabled"
        fi

        # Check if service is running
        if ! systemctl is-active --quiet fail2ban.service; then
            send_status "$category" "fail" "fail2ban service is not running" "service_active"
            failed=true
        else
            send_status "$category" "pass" "fail2ban service is running" "service_active"
        fi

        # Check if jail.local exists - jail config depends on this
        if [ ! -f "/etc/fail2ban/jail.local" ]; then
            send_status "$category" "fail" "jail.local configuration file not found" "config_file"
            config_file_missing=true
            failed=true
        else
            send_status "$category" "pass" "jail.local configuration file exists" "config_file"
        fi

        # Check SSH jail configuration only if jail.local exists
       if ! $config_file_missing; then
           # Check if SSH jail is enabled
           ssh_enabled=$(grep -A10 "^\[sshd\]" /etc/fail2ban/jail.local | grep "enabled" | awk '{print $NF}' | tr -d '[:space:]')
           if [ "$ssh_enabled" != "true" ]; then
               send_status "$category" "fail" "SSH jail is not enabled" "ssh_jail_enabled"
               failed=true
           else
               send_status "$category" "pass" "SSH jail is enabled" "ssh_jail_enabled"
           fi

           # Check if mode is aggressive
           ssh_mode=$(grep -A10 "^\[sshd\]" /etc/fail2ban/jail.local | grep "^mode[[:space:]]*=[[:space:]]*aggressive" >/dev/null && echo "aggressive" || echo "")      
           if [ "$ssh_mode" != "aggressive" ]; then
               send_status "$category" "fail" "SSH jail is not in aggressive mode" "ssh_jail_mode"
               failed=true
           else
               send_status "$category" "pass" "SSH jail is in aggressive mode" "ssh_jail_mode"
           fi
       else
           send_status "$category" "skip" "jail.local missing - skipping jail configuration check" "ssh_jail_enabled"
           send_status "$category" "skip" "jail.local missing - skipping jail configuration check" "ssh_jail_mode"
       fi
    else
        # Skip all remaining checks if installation failed
        send_status "$category" "skip" "fail2ban not installed - skipping check" "service_enabled"
        send_status "$category" "skip" "fail2ban not installed - skipping check" "service_active"
        send_status "$category" "skip" "fail2ban not installed - skipping check" "config_file"
        send_status "$category" "skip" "fail2ban not installed - skipping check" "ssh_jail_enabled"
        send_status "$category" "skip" "fail2ban not installed - skipping check" "ssh_jail_mode"
    fi
    
    # Final status
    if $failed; then
        send_status "$category" "fail" "Fail2ban security checks failed"
        return 1
    else
        send_status "$category" "pass" "Fail2ban is properly configured"
        return 0
    fi
}

main() {
    check_os
    check_dependencies
  
    if [ -n "${SESSION:-}" ]; then
        echo -e "Session ID: ${SESSION:-}"
    else
        echo -e "${YELLOW}Running in local mode (no SESSION provided)${NC}"
    fi
    echo

    send_status "audit" "running" "Starting security audit v${VERSION}"

    check_ufw
    check_ssh
    check_non_root_user
    check_unattended_upgrades
    check_fail2ban

    send_status "audit" "pass" "Security audit complete"
}

main "$@"