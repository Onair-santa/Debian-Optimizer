# 📥 Debian Optimizer

## <a href="#"><img src="https://github.com/vpnhood/VpnHood/wiki/images/logo-linux.png" width="32" height="32"></a> Bash script automatically configures and optimizes the  Debian11(Ubuntu20) server. In Debian12 work too, but not work fail2ban... 
![chrome_jLHCdtS4n7](https://github.com/user-attachments/assets/3c7a302a-a57b-45ae-95fc-920469d085f5)

#### Before running the script, create a key pair and place the public key in the file /.ssh/authorized_keys .
```
ssh-keygen -t rsa
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa
```
#### copy private key 
#### SSH password authorization will be disabled and the port will change to 2222, if you have chosen SSH, NFT optimization or Everything

#### Ensure that the `sudo` and `wget` packages are installed on your system:

```
apt install -y sudo wget
```

#### 🟢 Run

#### 💠 Root Access is Required. If the user is not root, first run:

```
sudo -i
```

#### 💠 Then:

```
wget "https://raw.githubusercontent.com/Onair-santa/Debian-Optimizer/main/optimizer.sh" -O optimizer.sh && chmod +x optimizer.sh && bash optimizer.sh
```

### It performs the following tasks:

#### 💠 Fix `hosts` file and DNS _(temporarily)_ :

- Check and append 127.0.1.1 and server hostname to `/etc/hosts`. 
  *Original `hosts` file is backed up at `/etc/hosts.bak`.*
- Append `8.8.8.8` and `8.8.4.4` to `/etc/resolv.conf`. 
  *Original `dns` file is backed up at `/etc/resolv.conf.bak`.*

#### 💠 Update and Clean the server:

- _Update_
- _AutoRemove_
- _AutoClean_

#### 💠 Install Useful Packages:

 _`curl`_  _`htop`_  _`jq`_  _`nftables`_  _`wget`_ _`speedtest-cli`_ 

#### 💠 Install Synth-Shell :

- More detailes https://github.com/andresgongora/synth-shell
![chrome_NvQkCDWzLS](https://github.com/user-attachments/assets/280fbfbe-866c-437e-a714-2e383259f29b)


#### 💠 Set the server TimeZone to VPS IP address location.

#### 💠 Create & Enable `SWAP` File:

- Swap Path: `"/swapfile"`
- Swap Size: `1Gb`

#### 💠 Disable `IPv6` Support.

#### 💠 Optimize the `SYSCTL` Configs.

- Optimize `SWAP`.

- Optimize Network Settings.

- Activate `BBR`.

- Optimize the Kernel.
  
    *Original file is backed up at `/etc/sysctl.conf.bak`.*

#### 💠 Optimize `SSH`:

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

#### 💠 Optimize the System Limits:

- Soft and Hard ulimit `-c -d -f -i -l -n -q -s -u -v -x` optimizations.

#### 💠 Install & Optimize NFTables

- Open port 2222 for SSH
- Open ports TCP 80 443

#### 💠 Install Crowdsec security (optional, analog fail2ban)

- More Details: https://github.com/crowdsecurity/crowdsec
- Linux, SSH, Firewall bouncers

#### 💠 Install Fail2ban security

- More Details: https://github.com/fail2ban/fail2ban
- Jail enabled: sshd(port=2222), recidive(allport (settings in file jail.local)
- Status command:
  
  ```
  fail2ban-client status
  fail2ban-client status sshd
  fail2ban-client status recidive
  ```

#### Disclaimer

This script is provided as-is, without any warranty or guarantee. Use it at your own risk.

#### 💠 Thanks
- [hawshemi](https://github.com/hawshemi/Linux-Optimizer)
- [andresgongora](https://github.com/andresgongora/synth-shell)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Crowdsec](https://github.com/crowdsecurity/crowdsec)
