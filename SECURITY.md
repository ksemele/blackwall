# Security policy

blackwall is a client for security infrastructure: it holds Wazuh credentials
and reads alerts and inventory from your fleet. Security reports are taken
seriously and are welcome.

## Reporting a vulnerability

Please report privately through GitHub:
**Security → Report a vulnerability** on
[ksemele/blackwall](https://github.com/ksemele/blackwall/security/advisories/new)
(GitHub private vulnerability reporting). Do not open a public issue, discussion
or pull request for a vulnerability.

Include what you can:

- the version (`blackwall --version`, or the release you installed),
- OS and how you installed it,
- steps to reproduce, or a proof of concept,
- what an attacker gains, and from which position (local user, network path,
  malicious Wazuh agent, malicious manager).

Do not include real hostnames, IPs or credentials; redact them or reproduce in
the [blackwall-stack](https://github.com/ksemele/blackwall-stack) lab.

You should get a first reply within a week. Once a fix is released, the
advisory is published, with credit to you unless you prefer otherwise.

## Supported versions

Only the latest release gets security fixes. Please check that the issue still
exists there (or on `main`) before reporting.

## Scope

In scope, for example:

- **Credential handling:** passwords or tokens from the config or `${VAR}`
  expansion leaking into logs, error messages, the status bar, process
  arguments, temporary files or crash output; the JWT for the Wazuh API being
  exposed or reused where it should not be.
- **TLS verification:** connections that skip or weaken certificate or
  hostname checks when the config does not ask for it (`ca_file`,
  `server_name`, default verification), or downgrade to plain HTTP.
- **SSH tunnels:** config values that inject ssh options or arguments,
  forwards bound to anything but loopback, tunnels that survive `blackwall`
  exiting, or reuse of a shared ssh connection against the documented
  behaviour.
- **Command execution:** anything that makes `blackwall` run a command other
  than the configured `ssh` (or `ssh.command` prefix), or run it with
  attacker-controlled arguments.
- **Untrusted data in the terminal:** alert text, log lines, agent names or
  inventory from Wazuh that reach the terminal with escape sequences, or can
  otherwise change what the user sees or runs.

Out of scope:

- Vulnerabilities in Wazuh itself, OpenSSH, or other software blackwall talks
  to: report those upstream.
- Setups that turn checks off on purpose, such as
  `tls.insecure_skip_verify: true` or `sshpass -p` in `ssh.command`, beyond
  making sure the README warns about them.
- Someone who can already edit your config file or your environment as your
  user.
- The Wazuh stack and Ansible roles in
  [blackwall-stack](https://github.com/ksemele/blackwall-stack): report those
  there.
