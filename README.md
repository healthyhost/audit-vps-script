# audit-vps-script

Scans your server to find common issues like weak SSH settings, missing firewalls, lack of updates, and more. Perfect for getting your VPS ready for production.

![Output](./img/output.png)

## Usage

1. Download the script

```bash
$ curl -O https://raw.githubusercontent.com/healthyhost/audit-vps-script/main/audit.sh
```

2. Make it executable:

```bash
$ chmod +x audit.sh
```

3. Run the security audit:

```bash
$ sudo ./audit.sh
```

### Web

Visit [https://auditpvps.com](https://auditvps.com) to run checks through our web app for free and render the results in your browser.

## Requirements

- Ubuntu/Debian-based distributions
- `jq` (temporary dependency, planned for removal)
- Root or sudo privileges

## Security checks

The scripts perform the following checks:

- Root
  - Check that non-root sudo user exists
- Firewall (UFW)
  - Check that UFW is installed
  - Check that UFW is enabled
  - Check that incoming traffic is blocked
- SSH
  - Check that SSH is enabled
  - Check that key-based authentication is enabled
  - Check that root login is disabled
  - Check that password authentication is disabled
  - Check that SSH is listening on port 22
- Fail2Ban
  - Check that Fail2ban is installed
  - Check that Fail2ban is enabled
  - Check that Fail2ban is configured correctly
  - Check that Fail2ban SSH is enabled
  - Check that Fail2ban SSH is in aggressive mode
- Access control
  - Check that `/etc/passwd` is readable by everyone
  - Check that `/etc/shadow` is readable by root only
- System updates
  - Check that automatic system updates are enabled
  - Check that automatic system upgrades are enabled
- Port security
  - Checks that insecure ports are not open

## Contributing

We welcome contributions! If you have any suggestions or improvements, please open an issue or submit a pull request.

## License

MIT

## Roadmap

- [ ] Support for additional Linux distributions:
  - [ ] RHEL/CentOS
  - [ ] Fedora
  - [ ] Alpine Linux
- [ ] Removal of `jq` dependency
- [ ] Warning states (WARN) for non-critical security recommendations
- [ ] Code refactoring to improve readability
