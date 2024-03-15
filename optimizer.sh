#!/bin/bash


clear


# Green, Yellow & Red Messages.
green_msg() {
    tput setaf 2
    echo "  $1"
    tput sgr0
}

yellow_msg() {
    tput setaf 3
    echo "  $1"
    tput sgr0
}

red_msg() {
    tput setaf 1
    echo "  $1"
    tput sgr0
}

cyn_msg() {
    tput setaf 6
    echo "  $1"
    tput sgr0
}

# Paths
HOST_PATH="/etc/hosts"
DNS_PATH="/etc/resolv.conf"


# Intro
echo 
green_msg '================================================================='
cyn_msg   'This script will automatically Optimize your Linux Server.'
cyn_msg   'Tested on: Ubuntu 20+, Debian 11+'
cyn_msg   'Root access is required.'  
green_msg '================================================================='
echo 


# Root
check_if_running_as_root() {
    # If you want to run as another user, please modify $EUID to be owned by this user
    if [[ "$EUID" -ne '0' ]]; then
      echo 
      red_msg 'Error: You must run this script as root!'
      echo 
      sleep 0.5
      exit 1
    fi
}


# Check Root
check_if_running_as_root
sleep 0.5


# Install dependencies
install_dependencies_debian_based() {
  echo 
  yellow_msg 'Installing Dependencies...'
  echo 
  sleep 0.5
  
  apt update -q
  apt install -y wget curl sudo jq

  echo
  green_msg 'Dependencies Installed.'
  echo 
  sleep 0.5
}


# Fix Hosts file
fix_etc_hosts(){ 
  echo 
  yellow_msg "Fixing Hosts file."
  sleep 0.5

  cp $HOST_PATH /etc/hosts.bak
  yellow_msg "Default hosts file saved. Directory: /etc/hosts.bak"
  sleep 0.5

  if ! grep -q $(hostname) $HOST_PATH; then
    echo "127.0.1.1 $(hostname)" | sudo tee -a $HOST_PATH > /dev/null
    green_msg "Hosts Fixed."
    echo 
    sleep 0.5
  else
    green_msg "Hosts OK. No changes made."
    echo 
    sleep 0.5
  fi
}


# Fix DNS
fix_dns(){
    echo 
    yellow_msg "Fixing DNS Temporarily." 
    sleep 0.5

    cp $DNS_PATH /etc/resolv.conf.bak
    yellow_msg "Default resolv.conf file saved. Directory: /etc/resolv.conf.bak" 
    sleep 0.5

    sed -i '/nameserver/d' $DNS_PATH

    echo "nameserver 8.8.8.8" >> $DNS_PATH
    echo "nameserver 8.8.4.4" >> $DNS_PATH
 
    green_msg "DNS Fixed Temporarily."
    echo 
    sleep 0.5
}


# Timezone
set_timezone() {
    echo
    yellow_msg 'Setting TimeZone based on VPS IP address...'
    sleep 0.5

    get_location_info() {
        local ip_sources=("https://ipv4.icanhazip.com" "https://api.ipify.org" "https://ipv4.ident.me/")
        local location_info

        for source in "${ip_sources[@]}"; do
            local ip=$(curl -s "$source")
            if [ -n "$ip" ]; then
                location_info=$(curl -s "http://ip-api.com/json/$ip")
                if [ -n "$location_info" ]; then
                    echo "$location_info"
                    return 0
                fi
            fi
        done

        red_msg "Error: Failed to fetch location information from known sources. Setting timezone to UTC."
        sudo timedatectl set-timezone "UTC"
        return 1
    }

    # Fetch location information from three sources
    location_info_1=$(get_location_info)
    location_info_2=$(get_location_info)
    location_info_3=$(get_location_info)

    # Extract timezones from the location information
    timezones=($(echo "$location_info_1 $location_info_2 $location_info_3" | jq -r '.timezone'))

    # Check if at least two timezones are equal
    if [[ "${timezones[0]}" == "${timezones[1]}" || "${timezones[0]}" == "${timezones[2]}" || "${timezones[1]}" == "${timezones[2]}" ]]; then
        # Set the timezone based on the first matching pair
        timezone="${timezones[0]}"
        sudo timedatectl set-timezone "$timezone"
        green_msg "Timezone set to $timezone"
    else
        red_msg "Error: Failed to fetch consistent location information from known sources. Setting timezone to UTC."
        sudo timedatectl set-timezone "UTC"
    fi

    echo
    sleep 0.5
}


# OS Detection
if [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "Ubuntu" ]]; then
    OS="ubuntu"
    echo 
    sleep 0.5
    yellow_msg "OS: Ubuntu"
    echo 
    sleep 0.5
elif [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "Debian GNU/Linux" ]]; then
    OS="debian"
    echo 
    sleep 0.5
    yellow_msg "OS: Debian"
    echo 
    sleep 0.5
else
    echo 
    sleep 0.5
    red_msg "Unknown OS"
    OS="unknown"
    echo 
    sleep 2
fi


## Run

# Install dependencies
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    install_dependencies_debian_based
elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "almalinux" ]]; then
    exit
fi


# Fix Hosts file
fix_etc_hosts
sleep 0.5

# Fix DNS
fix_dns
sleep 0.5

# Timezone
set_timezone
sleep 0.5


# Run Script based on Distros
case $OS in
unknown)
    # Unknown
    exit 
    ;;
esac


# Declare Paths & Settings.
SYS_PATH="/etc/sysctl.conf"
PROF_PATH="/etc/profile"
SSH_PORT=""
SSH_PATH="/etc/ssh/sshd_config"
SWAP_PATH="/swapfile"
SWAP_SIZE=1G



# Net Interface
ext_interface () {
    for interface in /sys/class/net/*
    do
        [[ "${interface##*/}" != 'lo' ]] && \
            ping -c1 -W2 -I "${interface##*/}" 208.67.222.222 >/dev/null 2>&1 && \
                printf '%s' "${interface##*/}" && return 0
    done
}
INTERFACE=$(ext_interface)

# Root
check_if_running_as_root() {
    # If you want to run as another user, please modify $EUID to be owned by this user
    if [[ "$EUID" -ne '0' ]]; then
      echo 
      red_msg 'Error: You must run this script as root!'
      echo 
      sleep 0.5
      exit 1
    fi
}


# Check Root
check_if_running_as_root
sleep 0.5


# Ask Reboot
ask_reboot() {
    yellow_msg 'Reboot now? (Recommended) (y/n)'
    echo 
    while true; do
        read choice
        echo 
        if [[ "$choice" == 'y' || "$choice" == 'Y' ]]; then
            sleep 0.5
            reboot
            exit 0
        fi
        if [[ "$choice" == 'n' || "$choice" == 'N' ]]; then
            break
        fi
    done
}


# Update & Upgrade & Remove & Clean
complete_update() {
    echo 
    yellow_msg 'Updating the System. (This can take a while...)'
    echo 
    sleep 0.5

    sudo apt -q update
    sudo apt upgrade -y
    sudo apt autoremove -y
    sleep 0.5

    # Again :D
    sudo apt -y -q autoclean
    sudo apt -y clean
    sudo apt -q update
    sudo apt -y upgrade
    sudo apt -y autoremove --purge

    echo 
    green_msg 'System Updated & Cleaned Successfully.'
    echo 
    sleep 0.5
}


# Install XanMod Kernel
install_xanmod() {
    echo 
    yellow_msg 'Checking XanMod...'
    echo 
    sleep 0.5
    
    if uname -r | grep -q 'xanmod'; then
        green_msg 'XanMod is already installed.'
        echo 
        sleep 0.5
    else
        echo 
        yellow_msg 'XanMod not found. Installing XanMod Kernel...'
        echo 
        sleep 0.5

        # Update and Upgrade
        sudo apt update -q
        sudo apt upgrade -y
        sudo apt install wget curl gpg -y

        # Add the XanMod repository key
        wget -qO - https://gitlab.com/afrd.gpg | sudo gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
        # Add the XanMod repository
        echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | sudo tee /etc/apt/sources.list.d/xanmod-release.list

        # Check the CPU level
        cpu_level=$(awk -f - <<EOF
        BEGIN {
            while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1
            if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1
            if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2
            if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3
            if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4
            if (level > 0) { print level; exit level + 1 }
            exit 1
        }
EOF
        )

        # Install the appropriate XanMod kernel based on CPU level
        case $cpu_level in
            1)
                sudo apt update -qq && sudo apt install linux-xanmod-lts-x64v1 -y
                ;;
            2)
                sudo apt update -qq && sudo apt install linux-xanmod-lts-x64v2 -y
                ;;
            3)
                sudo apt update -qq && sudo apt install linux-xanmod-lts-x64v3 -y
                ;;
            4)
                sudo apt update -qq && sudo apt install linux-xanmod-lts-x64v4 -y
                ;;
            *)
                echo "Unsupported CPU level."
                exit 1
                ;;
        esac
    
        # Clean up
        sudo apt update -qq
        sudo apt autoremove -y
        echo 
        green_msg "XanMod Kernel Installed."
        echo 
        sleep 0.5
    fi
}

## Install useful packages
installations() {
    echo 
    yellow_msg 'Installing Useful Packages...'
    echo 
    sleep 0.5

    # Networking packages
    sudo apt -q -y install nftables speedtest-cli

    # System utilities
    sudo apt -q -y install curl wget 

    # Additional libraries and dependencies
    sudo apt -q -y install jq

    # Miscellaneous
    sudo apt -q -y install dialog htop

    echo 
    green_msg 'Useful Packages Installed Succesfully.'
    echo 
    sleep 0.5
}

# Enable packages at server boot
enable_packages() {
    sudo systemctl enable nftables
    echo 
    green_msg 'Packages Enabled Succesfully.'
    echo
    sleep 0.5
}


## Swap Maker
swap_maker() {
    echo 
    yellow_msg 'Making SWAP Space...'
    echo 
    sleep 0.5

    # Make Swap
    sudo fallocate -l $SWAP_SIZE $SWAP_PATH  # Allocate size
    sudo chmod 600 $SWAP_PATH                # Set proper permission
    sudo mkswap $SWAP_PATH                   # Setup swap         
    sudo swapon $SWAP_PATH                   # Enable swap
    echo "$SWAP_PATH   none    swap    sw    0   0" >> /etc/fstab # Add to fstab
    echo 
    green_msg 'SWAP Created Successfully.'
    echo
    sleep 0.5
}


## SYSCTL Optimization
sysctl_optimizations() {
    # Make a backup of the original sysctl.conf file
    cp $SYS_PATH /etc/sysctl.conf.bak

    echo 
    yellow_msg 'Default sysctl.conf file Saved. Directory: /etc/sysctl.conf.bak'
    echo 
    sleep 1

    echo 
    yellow_msg 'Optimizing the Network.'
    echo 
    sleep 0.5

    # Replace the new sysctl.conf file.
    wget "https://raw.githubusercontent.com/Onair-santa/Debian-Optimizer/main/files/sysctl.conf" -q -O $SYS_PATH
    sed -i '/net.ipv6.conf.eth0.disable_ipv6/d' $SYS_PATH
    echo "net.ipv6.conf."$INTERFACE".disable_ipv6 = 1" | tee -a $SYS_PATH

    sysctl -p
    echo 

    green_msg 'Network is Optimized.'
    echo 
    sleep 0.5
}


# Function to find the SSH port and set it in the SSH_PORT variable
find_ssh_port() {
    echo 
    yellow_msg "Finding SSH port..."
    # Check if the SSH configuration file exists
    if [ -e "$SSH_PATH" ]; then
        # Use grep to search for the 'Port' directive in the SSH configuration file
        SSH_PORT=$(grep -oP '^Port\s+\K\d+' "$SSH_PATH" 2>/dev/null)

        if [ -n "$SSH_PORT" ]; then
            echo 
            green_msg "SSH port found: $SSH_PORT"
            echo 
            sleep 0.5
        else
            echo 
            green_msg "SSH port is default 22."
            echo 
            SSH_PORT=22
            sleep 0.5
        fi
    else
        red_msg "SSH configuration file not found at $SSH_PATH"
    fi
}

# Remove old SSH config to prevent duplicates.
remove_old_ssh_conf() {
    # Make a backup of the original sshd_config file
    cp $SSH_PATH /etc/ssh/sshd_config.bak

    echo 
    yellow_msg 'Default SSH Config file Saved. Directory: /etc/ssh/sshd_config.bak'
    echo 
    sleep 1
    
    # Disable DNS lookups for connecting clients
    sed -i 's/#UseDNS yes/UseDNS no/' $SSH_PATH

    # Enable compression for SSH connections
    sed -i 's/#Compression no/Compression yes/' $SSH_PATH

    # Remove less efficient encryption ciphers
    sed -i 's/Ciphers .*/Ciphers aes256-ctr,chacha20-poly1305@openssh.com/' $SSH_PATH

    # Remove these lines
    sed -i '/MaxAuthTries/d' $SSH_PATH
    sed -i '/MaxSessions/d' $SSH_PATH
    sed -i '/TCPKeepAlive/d' $SSH_PATH
    sed -i '/ClientAliveInterval/d' $SSH_PATH
    sed -i '/ClientAliveCountMax/d' $SSH_PATH
    sed -i '/AllowAgentForwarding/d' $SSH_PATH
    sed -i '/AllowTcpForwarding/d' $SSH_PATH
    sed -i '/GatewayPorts/d' $SSH_PATH
    sed -i '/PermitTunnel/d' $SSH_PATH
    sed -i '/X11Forwarding/d' $SSH_PATH
    sed -i '/Port/d' $SSH_PATH
    sed -i '/PubkeyAuthentication/d' $SSH_PATH
    sed -i '/PasswordAuthentication/d' $SSH_PATH
}


## Update SSH config
update_sshd_conf() {
    echo 
    yellow_msg 'Optimizing SSH...'
    echo 
    sleep 0.5

    # Enable TCP keep-alive messages
    echo "TCPKeepAlive yes" | tee -a $SSH_PATH

    # Configure client keep-alive messages
    echo "ClientAliveInterval 3000" | tee -a $SSH_PATH
    echo "ClientAliveCountMax 100" | tee -a $SSH_PATH

    # Allow agent forwarding
    echo "AllowAgentForwarding yes" | tee -a $SSH_PATH

    # Allow TCP forwarding
    echo "AllowTcpForwarding yes" | tee -a $SSH_PATH

    # Enable gateway ports
    echo "GatewayPorts yes" | tee -a $SSH_PATH

    # Enable tunneling
    echo "PermitTunnel yes" | tee -a $SSH_PATH

    # Enable X11 graphical interface forwarding
    echo "X11Forwarding yes" | tee -a $SSH_PATH
    
    # My
    echo "Port 2222" | tee -a $SSH_PATH
    echo "PubkeyAuthentication yes" | tee -a $SSH_PATH
    echo "PasswordAuthentication no" | tee -a $SSH_PATH
    echo "UseDNS no"  | tee -a $SSH_PATH
    echo "Banner none"  | tee -a $SSH_PATH
    
    # Restart the SSH service to apply the changes
    service ssh restart

    echo 
    green_msg 'SSH is Optimized.'
    echo 
    sleep 0.5
}


# System Limits Optimizations
limits_optimizations() {
    echo
    yellow_msg 'Optimizing System Limits...'
    echo 
    sleep 0.5

    # Clear old ulimits
    sed -i '/ulimit -c/d' $PROF_PATH
    sed -i '/ulimit -d/d' $PROF_PATH
    sed -i '/ulimit -f/d' $PROF_PATH
    sed -i '/ulimit -i/d' $PROF_PATH
    sed -i '/ulimit -l/d' $PROF_PATH
    sed -i '/ulimit -m/d' $PROF_PATH
    sed -i '/ulimit -n/d' $PROF_PATH
    sed -i '/ulimit -q/d' $PROF_PATH
    sed -i '/ulimit -s/d' $PROF_PATH
    sed -i '/ulimit -t/d' $PROF_PATH
    sed -i '/ulimit -u/d' $PROF_PATH
    sed -i '/ulimit -v/d' $PROF_PATH
    sed -i '/ulimit -x/d' $PROF_PATH
    sed -i '/ulimit -s/d' $PROF_PATH


    # Add new ulimits
    # The maximum size of core files created.
    echo "ulimit -c unlimited" | tee -a $PROF_PATH

    # The maximum size of a process's data segment
    echo "ulimit -d unlimited" | tee -a $PROF_PATH

    # The maximum size of files created by the shell (default option)
    echo "ulimit -f unlimited" | tee -a $PROF_PATH

    # The maximum number of pending signals
    echo "ulimit -i unlimited" | tee -a $PROF_PATH

    # The maximum size that may be locked into memory
    echo "ulimit -l unlimited" | tee -a $PROF_PATH

    # The maximum memory size
    echo "ulimit -m unlimited" | tee -a $PROF_PATH

    # The maximum number of open file descriptors
    echo "ulimit -n 1048576" | tee -a $PROF_PATH

    # The maximum POSIX message queue size
    echo "ulimit -q unlimited" | tee -a $PROF_PATH

    # The maximum stack size
    echo "ulimit -s -H 65536" | tee -a $PROF_PATH
    echo "ulimit -s 32768" | tee -a $PROF_PATH

    # The maximum number of seconds to be used by each process.
    echo "ulimit -t unlimited" | tee -a $PROF_PATH

    # The maximum number of processes available to a single user
    echo "ulimit -u unlimited" | tee -a $PROF_PATH

    # The maximum amount of virtual memory available to the process
    echo "ulimit -v unlimited" | tee -a $PROF_PATH

    # The maximum number of file locks
    echo "ulimit -x unlimited" | tee -a $PROF_PATH


    echo 
    green_msg 'System Limits are Optimized.'
    echo 
    sleep 0.5
}

## NFT Optimizations
nft_optimizations() {
    echo
    yellow_msg 'Installing & Optimizing Nftables...'
    echo 
    sleep 0.5

    # Purge firewalld to install NFT.
    sudo apt -y purge firewalld

    # Install NFT if it isn't installed.
    sudo apt update -q
    sudo apt install -y nftables

    # Start and enable nftables
    sudo systemctl start nftables
    sudo systemctl enable nftables
    sleep 0.5

    # Open default ports.
    sudo nft add rule inet filter input iifname lo accept
    sudo nft add rule inet filter input ct state established,related accept
    sudo nft add rule inet filter input iifname $INTERFACE tcp dport "$SSH_PORT" accept
    sudo nft add rule inet filter input iifname $INTERFACE tcp dport 80 accept
    sudo nft add rule inet filter input iifname $INTERFACE tcp dport 443 accept
    sudo nft add chain inet filter input '{ policy drop; }'
    sleep 0.5
    echo '#!/usr/sbin/nft -f' > /etc/nftables.conf
    sleep 0.5
    echo 'flush ruleset' >> /etc/nftables.conf
    sleep 0.5
    sudo nft list ruleset | sudo tee -a /etc/nftables.conf
    sleep 0.5

    # Enable & Reload
    sudo systemctl restart nftables
    echo 
    green_msg 'NFT is Installed & Optimized. (Ports 2222, 80, 443 is opened)'
    echo 
    sleep 0.5
}

# Install Crowdsec
crowdsec_install() {
    echo
    yellow_msg 'Installing & Optimizing Crowdsec...'
    echo 
    sleep 0.5
    
    CS_PATH="/etc/crowdsec/config.yaml"
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash && sudo apt install crowdsec
    sleep 0.5
    sudo apt install crowdsec-firewall-bouncer-nftables
    wget "https://raw.githubusercontent.com/Onair-santa/Debian-Optimizer/main/files/config.yaml" -q -O $CS_PATH
    cscli collections install crowdsecurity/iptables
    # Reload
    sudo systemctl reload crowdsec
    echo 
    green_msg 'Crowdsec Installed & Optimized.'
    echo 
    sleep 0.5
}

# Install Fail2ban
f2b_install() {
    echo
    yellow_msg 'Installing Fail2ban...'
    echo
    sleep 0.5
    
    F2B_PATH="/etc/fail2ban/jail.local"
    wget https://github.com/fail2ban/fail2ban/releases/download/1.0.2/fail2ban_1.0.2-1.upstream1_all.deb
    sudo dpkg -i fail2ban_1.0.2-1.upstream1_all.deb
    sleep 1
    wget "https://raw.githubusercontent.com/Onair-santa/Debian-Optimizer/main/files/jail.local" -q -O $F2B_PATH
    sudo systemctl enable fail2ban
    fail2ban-client reload
    sleep 1
    fail2ban-client status
    echo 
    green_msg 'Fail2ban installed and work fine'
    echo 
    sleep 1
}


# Show the Menu
show_menu() {
    echo 
    yellow_msg 'Choose One Option: '
    echo 
    green_msg '1.  - Complete Update + Packages + SWAP + Optimize Net, SSH & Sys Limits + NFT + Fail2ban'
    green_msg '2.  - Complete Update + SWAP + Optimize Net, SSH & Sys Limits + NFT'
    green_msg '3.  - Complete Update + SWAP + Optimize Net, SSH & Sys Limits'
    echo 
    cyn_msg '4.  - Complete Update & Clean the OS'
    cyn_msg '5.  - Install Packages(htop, curl, nftables, speedtest)'
    cyn_msg '6.  - Make SWAP (1Gb)'
    cyn_msg '7.  - Optimize the Network, SSH & System Limits'
    echo 
    yellow_msg '8.  - Optimize the Network settings'
    yellow_msg '9.  - Optimize the SSH settings(port 2222, disable PassAuth, enable PubKey)'
    yellow_msg '10. - Optimize the System Limits'
    yellow_msg '11. - Install & Optimize NFT(open ports 2222 443 80)'
    yellow_msg '12. - Install Crowdsec'
    yellow_msg '13. - Install Fail2ban'
    echo 
    cyn_msg '14. - XanMod + SSH & Sys Limites + SWAP + NFT + Optimize Net + Fail2ban'
    cyn_msg '15. - Install XanMod Kernel'
    echo
    red_msg 'Q - Exit'
    echo 
}


# Choosing Program
main() {
    while true; do
        show_menu
        read -p 'Enter Your Choice: ' choice
        case $choice in
        1)
            complete_update
            sleep 0.5

            installations
            enable_packages
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

            find_ssh_port
            ext_interface
            nft_optimizations
            sleep 0.5

            f2b_install
            sleep 0.5
            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        2)
            complete_update
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

            find_ssh_port
            ext_interface
            nft_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        3)
            complete_update
            sleep 0.5

            swap_maker
            sleep 0.5

            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        4)
            complete_update
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
            
        5)
            complete_update
            sleep 0.5

            installations
            enable_packages
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        6)
            swap_maker
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        7)
            sysctl_optimizations
            sleep 0.5

            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            limits_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        8)
            sysctl_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ;;
        9)
            remove_old_ssh_conf
            sleep 0.5

            update_sshd_conf
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ;;
        10)
            limits_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        11)
            find_ssh_port
            ext_interface
            nft_optimizations
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='
            ;;
        12)
            crowdsec_install
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='
            ;;
        13)
            f2b_install
            sleep 0.5
            
            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='
            ;;
        14)
            apply_everything

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;

        15)
            complete_update
            sleep 0.5

            install_xanmod
            sleep 0.5

            echo 
            green_msg '========================='
            green_msg  'Done.'
            green_msg '========================='

            ask_reboot
            ;;
        q)
            exit 0
            ;;

        *)
            red_msg 'Wrong input!'
            ;;
        esac
    done
}


# Apply Everything
apply_everything() {

    complete_update
    sleep 0.5

    install_xanmod
    sleep 0.5 

    installations
    enable_packages
    sleep 0.5

    swap_maker
    sleep 0.5

    sysctl_optimizations
    sleep 0.5

    remove_old_ssh_conf
    sleep 0.5

    update_sshd_conf
    sleep 0.5

    limits_optimizations
    sleep 0.5
    
    find_ssh_port
    ext_interface
    nft_optimizations
    sleep 0.5

    f2b_install
    sleep 0.5
}


main
