# 📥 Debian Optimizer

## <a href="#"><img src="https://github.com/vpnhood/VpnHood/wiki/images/logo-linux.png" width="32" height="32"></a> Bash script automates the optimization of Debian(Ubuntu) server.

![Xshell_y2vBlAwG56](https://github.com/Onair-santa/Debian-Optimizer/assets/42511409/c2672397-6de5-4878-ba54-9f3a2d0f0bc1)

#### Before running the script, create a key pair and place the public key in the file /.ssh/authorized_keys .

#### SSH password authorization will be disabled and the port will change to 2222, if you have chosen SSH, NFT optimization or Everything

#### Ensure that the `sudo` and `wget` packages are installed on your system:

```
apt install -y sudo wget
```

## 🟢 Run

### 💠 Root Access is Required. If the user is not root, first run:

```
sudo -i
```

### 💠 Then:

```
wget "https://raw.githubusercontent.com/Onair-santa/Debian-Optimizer/main/optimizer.sh" -O optimizer.sh && chmod +x optimizer.sh && bash optimizer.sh
```

### It performs the following tasks:

### 💠 Fix `hosts` file and DNS _(temporarily)_ :

- Check and append 127.0.1.1 and server hostname to `/etc/hosts`. 
  *Original `hosts` file is backed up at `/etc/hosts.bak`.*
- Append `8.8.8.8` and `8.8.4.4` to `/etc/resolv.conf`. 
  *Original `dns` file is backed up at `/etc/resolv.conf.bak`.*

### 💠 Update and Clean the server:

- _Update_
- _AutoRemove_
- _AutoClean_
- _Clean_

### 💠 Install Useful Packages:

 _`curl`_  _`htop`_  _`jq`_  _`nftables`_  _`wget`_ _`speedtest-cli`_ 

### 💠 Install XanMod LTS Kernel :

- Enable BBRv3.
- CloudFlare TCP Optimizations.
- More Details: https://xanmod.org

### 💠 Set the server TimeZone to VPS IP address location.

### 💠 Create & Enable `SWAP` File:

- Swap Path: `"/swapfile"`
- Swap Size: `1Gb`

### 💠 Disable `IPv6` Support.

### 💠 Optimize the `SYSCTL` Configs.

- Optimize `SWAP`.

- Optimize Network Settings.

- Activate `BBR`.

- Optimize the Kernel.
  
    *Original file is backed up at `/etc/sysctl.conf.bak`.*

### 💠 Optimize `SSH`:

- Port 2222 (change 22 → 2222)
- Remove PasswordAuthentication
- Enable PubkeyAuthentication
- Back up the original `sshd_config` file.
- Disable DNS lookups for connecting clients.
- Remove less efficient encryption ciphers.
- Enable and Configure TCP keep-alive messages.
- Allow agent & TCP forwarding.
- Enable gateway ports, Tunneling and compression.
- Enable X11 Forwarding.
    *Original file is backed up at `/etc/ssh/sshd_config.bak`.*

### 💠 Optimize the System Limits:

- Soft and Hard ulimit `-c -d -f -i -l -n -q -s -u -v -x` optimizations.

### 💠 Install & Optimize NFTables

- Open port 2222 for SSH
- Open ports TCP 80 443

### 💠 Install Crowdsec security (the best analog fail2ban)

- More Details: https://github.com/crowdsecurity/crowdsec
- Linux, SSH, Firewall bouncers

### 💠 Install Fail2ban security

- More Details: https://github.com/fail2ban/fail2ban
- Jail enabled: sshd(port=2222), recidive(allport (settings in file jail.local)
- Status command:
  
  ```
  fail2ban-client status
  fail2ban-client status sshd
  fail2ban-client status recidive
  ```

### Disclaimer

This script is provided as-is, without any warranty or guarantee. Use it at your own risk.

### 💠 Credits
- [hawshemi](https://github.com/hawshemi/Linux-Optimizer)
