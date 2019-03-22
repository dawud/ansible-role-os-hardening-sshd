# OpenSSH server hardening

This role configures the OpenSSH daemon.

## Requirements

None. The required packages are managed by the role.

## Role variables

- From `defaults/main.yml`

```yaml
## OpenSSH server
# Set the package install state for distribution packages
# Options are 'present' and 'latest'
security_package_state: present
# Don't apply OS defaults when set to true
security_sshd_skip_defaults: 'True'
# If the below is false, don't manage the service or reload the SSH
# daemon at all
# yamllint disable-line rule:line-length
security_sshd_manage_service: "{{ false if ansible_virtualization_type == 'docker' else true }}"
# If the below is false, don't reload the ssh deamon on change
security_sshd_allow_reload: "{{ sshd_manage_service }}"
# Ensure sshd is running and enabled at boot time.
security_enable_sshd: 'yes'                                    # V-72235

## Server side configuration
security_sshd_Port: 22
#security_sshd_AddressFamily
#security_sshd_ListenAddress
# Set the allowed ssh protocols.
security_sshd_Protocol: 2                                    # V-72251
#security_sshd_HostKey
#security_sshd_AcceptEnv
security_sshd_AllowAgentForwarding: 'no'
#security_sshd_AllowGroups
security_sshd_AllowStreamLocalForwarding: 'no'
security_sshd_AllowTcpForwarding: 'no'
#security_sshd_AllowUsers
#security_sshd_AuthenticationMethods
#security_sshd_AuthorizedKeysCommand
#security_sshd_AuthorizedKeysCommandUser
#security_sshd_AuthorizedKeysFile
#security_sshd_AuthorizedPrincipalsFile
# Specify a text file to be displayed as the banner/MOTD for all sessions.
security_sshd_banner_file: /etc/issue                         # V-71861 / V-72225
# Deploy a login banner.                                     # V-72225 / V-71863
security_login_banner_text: |
  ------------------------------------------------------------------------------
  * WARNING                                                                    *
  * You are accessing a secured system and your actions will be logged along   *
  * with identifying information. Disconnect immediately if you are not an     *
  * authorized user of this system.                                            *
  ------------------------------------------------------------------------------
#security_sshd_Banner
security_sshd_ChallengeResponseAuthentication: 'yes'
#security_sshd_ChrootDirectory
#security_sshd_Ciphers
# Set a list of allowed ssh ciphers.
# yamllint disable-line rule:line-length
security_sshd_Ciphers: 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'  # V-72221
# Set the interval for max session length and the number of intervals to allow.
security_sshd_ClientAliveCountMax: 0                       # V-72241
security_sshd_ClientAliveInterval: 600                     # V-72237
# Disallow compression or delay after login.
security_sshd_Compression: 'delayed'                       # V-72267
#security_sshd_DenyGroups
#security_sshd_DenyUsers
security_sshd_DisableForwarding: 'yes'
#security_sshd_ExposeAuthenticationMethods
#security_sshd_FingerprintHash
#security_sshd_ForceCommand
#security_sshd_GatewayPorts
# Disallow Generic Security Service Application Program Interface (GSSAPI) auth.
security_sshd_GSSAPIAuthentication: 'no'                            # V-72259
#security_sshd_GSSAPICleanupCredentials
#security_sshd_GSSAPIKeyExchange
#security_sshd_GSSAPIEnablek5users
#security_sshd_GSSAPIStoreCredentialsOnRekey
#security_sshd_GSSAPIStrictAcceptorCheck
#security_sshd_GSSAPIKexAlgorithms
# yamllint disable-line rule:line-length
#security_sshd_HostbasedAcceptedKeyTypes: 'ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-ed25519,ssh-rsa'
# Disallow host based authentication.
security_sshd_HostbasedAuthentication: 'no'                  # V-71959
#security_sshd_HostbasedUsesNameFromPacketOnly
#security_sshd_HostCertificate
#security_sshd_HostKeyAgent
# Disallow rhosts authentication.
security_sshd_IgnoreRhosts: 'yes'                      # V-72243
# Disallow authentication using known hosts authentication.
# yamllint disable-line rule:line-length
security_sshd_IgnoreUserKnownHosts: 'yes'                 # V-72249 / V-72239
#security_sshd_IPQoS
#security_sshd_KbdInteractiveAuthentication
# Disallow Kerberos authentication.
security_sshd_KerberosAuthentication: 'no'                     # V-72261
#security_sshd_KerberosGetAFSToken
#security_sshd_KerberosOrLocalPasswd
#security_sshd_KerberosTicketCleanup
#security_sshd_KerberosUseKuserok
# yamllint disable-line rule:line-length
security_sshd_KexAlgorithms: 'curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256'
#security_sshd_KeyRegenerationInterval
#security_sshd_LoginGraceTime
#security_sshd_LogLevel
# Set the list of allowed Message Authentication Codes (MACs) for ssh.
# yamllint disable-line rule:line-length
security_sshd_MACs: 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'    # V-72253
#security_sshd_MaxAuthTries
#security_sshd_MaxSessions
#security_sshd_MaxStartups
security_sshd_PasswordAuthentication: 'no'
# Disallow logins from users with empty/null passwords.
security_sshd_PermitEmptyPasswords: 'no'      # V-71939 / RHEL-07-010440
#security_sshd_PermitOpen
# Permit direct root logins
security_sshd_PermitRootLogin: 'no'                          # V-72247
#security_sshd_PermitTTY
#security_sshd_PermitTunnel
# Disallow users from overriding the ssh environment variables.
security_sshd_PermitUserEnvironment: 'no'             # V-71957
security_sshd_PermitUserRC: 'no'                      # V-71957
#security_sshd_PidFile
# Print the last login for a user when they log in over ssh.
security_sshd_PrintLastLog: 'yes'                            # V-72245
#security_sshd_PrintMotd
security_sshd_PubkeyAuthentication: 'yes'
#security_sshd_RekeyLimit
#security_sshd_RevokedKeys
#security_sshd_RhostsRSAAuthentication
##security_sshd_RSAAuthentication
#security_sshd_ServerKeyBits
#security_sshd_ServerKeyBits
# Require strict mode checking of home directory configuration files.
security_sshd_StrictModes: 'yes'                       # V-72263
security_sshd_Subsystem: 'sftp sftp-internal'
#security_sshd_SyslogFacility
#security_sshd_TCPKeepAlive
#security_sshd_TrustedUserCAKeys
#security_sshd_UseDNS
#security_sshd_UsePAM
# Require privilege separation at every opportunity.
security_sshd_UsePrivilegeSeparation: 'yes'               # V-72265
#security_sshd_VersionAddendum
#security_sshd_X11DisplayOffset
# Enable X11 forwarding.
security_sshd_X11Forwarding: 'no'                     # V-72303
#security_sshd_X11UseLocalhost
#security_sshd_XAuthLocation
security_sshd_X11MaxDisplays: '10'

## Client side configuration
# yamllint disable-line rule:line-length
security_sshd_HostKeyAlgorithms: 'ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa'
```

- From `vars/main.yml`

```yaml
# RHEL 7 STIG: Packages to add/remove
stig_packages_rhel7:
  - packages:
      - openssh
      - openssh-server
    state: "{{ security_package_state }}"
    enabled: 'True'

# VARS DEFAULTS
# The following are defaults for OS specific configuration in var files in
# this role. They should not be set by role users.
sshd_config_owner: root
sshd_config_group: root
sshd_config_mode: '0600'
sshd_config_file: /etc/ssh/sshd_config
sshd_binary: /usr/sbin/sshd
sshd_service: sshd.socket
sshd_sftp_server: /usr/libexec/openssh/sftp-server
sshd_defaults: {}
sshd_skip_defaults: "{{ security_sshd_skip_defaults }}"
sshd:
  Port: "{{ security_sshd_Port | default('22') }}"
  AddressFamily: "{{ security_sshd_AddressFamily | default('any') }}"
  # yamllint disable-line rule:line-length
  #ListenAddress: "{{ security_sshd_ListenAddress | default('localhost') }}"
  Protocol: "{{ security_sshd_Protocol }}"
  HostKey:
    - /etc/ssh/ssh_host_rsa_key
    - /etc/ssh/ssh_host_ed25519_key
  AcceptEnv:
    - LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
    - LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
    - LC_IDENTIFICATION LC_ALL LANGUAGE
    - XMODIFIERS
  AllowAgentForwarding: "{{ security_sshd_AllowAgentForwarding }}"
  # AllowGroups: "{{ security_sshd_AllowGroups | default('') }}"
  AllowStreamLocalForwarding: "{{ security_sshd_AllowStreamLocalForwarding }}"
  AllowTcpForwarding: "{{ security_sshd_AllowTcpForwarding }}"
  # AllowUsers: "{{ security_sshd_AllowUsers | default('') }}"
  AuthenticationMethods: "{{ security_sshd_AuthenticationMethods | default('any') }}"
  # AuthorizedKeysCommand: "{{ security_sshd_AuthorizedKeysCommand | default('') }}"
  # yamllint disable-line rule:line-length
  # AuthorizedKeysCommandUser: "{{ security_sshd_AuthorizedKeysCommandUser | default('') }}"
  AuthorizedKeysFile: .ssh/authorized_keys
  # yamllint disable-line rule:line-length
  #AuthorizedPrincipalsCommand: "{{ security_sshd_AuthorizedPrincipalsCommand | default('none') }}"
  # yamllint disable-line rule:line-length
  #AuthorizedPrincipalsCommandUser: "{{ security_sshd_AuthorizedPrincipalsCommandUser | default('none') }}"
  #AuthorizedPrincipalsFile: "{{ security_sshd_AuthorizedPrincipalsFile | default('none') }}"
  Banner: "{{ security_sshd_banner_file }}"
  # yamllint disable-line rule:line-length
  ChallengeResponseAuthentication: "{{ security_sshd_ChallengeResponseAuthentication }}"
  # ChrootDirectory: "{{ security_sshd_ChrootDirectory | default('') }}"
  Ciphers: "{{ security_sshd_Ciphers }}"
  ClientAliveCountMax: "{{ security_sshd_ClientAliveCountMax }}"
  ClientAliveInterval: "{{ security_sshd_ClientAliveInterval }}"
  Compression: "{{ security_sshd_Compression }}"
  # DenyGroups: "{{ security_sshd_DenyGroups | default('') }}"
  # DenyUsers: "{{ security_sshd_DenyUsers | default('') }}"
  DisableForwarding: "{{ security_sshd_DisableForwarding | default('no') }}"
  # yamllint disable-line rule:line-length
  ExposeAuthenticationMethods: "{{ security_sshd_ExposeAuthenticationMethods | default('never') }}"
  # FingerprintHash: "{{ security_sshd_FingerprintHash | default('sha256') }}"
  # ForceCommand: "{{ security_sshd_ForceCommand | default('') }}"
  GatewayPorts: "{{ security_sshd_GatewayPorts | default('no') }}"
  GSSAPIAuthentication: "{{ security_sshd_GSSAPIAuthentication }}"
  # yamllint disable-line rule:line-length
  GSSAPICleanupCredentials: "{{ security_sshd_GSSAPICleanupCredentials | default('yes') }}"
  GSSAPIKeyExchange: "{{ security_sshd_GSSAPIKeyExchange | default('no') }}"
  GSSAPIEnablek5users: "{{ security_sshd_GSSAPIEnablek5users | default('no') }}"
  # yamllint disable-line rule:line-length
  GSSAPIStoreCredentialsOnRekey: "{{ security_sshd_GSSAPIStoreCredentialsOnRekey | default('no') }}"
  # yamllint disable-line rule:line-length
  GSSAPIStrictAcceptorCheck: "{{ security_sshd_GSSAPIStrictAcceptorCheck | default('yes') }}"
  # yamllint disable-line rule:line-length
  GSSAPIKexAlgorithms: "{{ security_sshd_GSSAPIKexAlgorithms | default('gss-gex-sha1-,gss-group1-sha1-,gss-group14-sha1-') }}"
  #HostbasedAcceptedKeyTypes: "{{ security_sshd_HostbasedAcceptedKeyTypes }}"
  HostbasedAuthentication: "{{ security_sshd_HostbasedAuthentication }}"
  # yamllint disable-line rule:line-length
  HostbasedUsesNameFromPacketOnly: "{{ security_sshd_HostbasedUsesNameFromPacketOnly | default('no') }}"
  # HostCertificate: "{{ security_sshd_HostCertificate | default('') }}"
  # HostKey: "{{ security_sshd_HostKey | default('') }}"
  # HostKeyAgent: "{{ security_sshd_HostKeyAgent | default('') }}"
  # HostKeyAlgorithms: "{{ security_sshd_HostKeyAlgorithms | default('') }}"
  IgnoreRhosts: "{{ security_sshd_IgnoreRhosts | default('yes') }}"
  IgnoreUserKnownHosts: "{{ security_sshd_IgnoreUserKnownHosts | default('yes') }}"
  IPQoS: "{{ security_sshd_IPQoS | default('lowdelay throughput') }}"
  # yamllint disable-line rule:line-length
  #KbdInteractiveAuthentication: "{{ security_sshd_KbdInteractiveAuthentication }}"
  KerberosAuthentication: "{{ security_sshd_KerberosAuthentication }}"
  # Disabled, as it requires other components to be installed
  # KerberosGetAFSToken: "{{ security_sshd_KerberosGetAFSToken | default('no') }}"
  KerberosOrLocalPasswd: "{{ security_sshd_KerberosOrLocalPasswd | default('yes') }}"
  KerberosTicketCleanup: "{{ security_sshd_KerberosTicketCleanup | default('yes') }}"
  KerberosUseKuserok: "{{ security_sshd_KerberosUseKuserok | default('yes') }}"
  KexAlgorithms: "{{ security_sshd_KexAlgorithms }}"
  # yamllint disable-line rule:line-length
  #KeyRegenerationInterval: "{{ security_sshd_KeyRegenerationInterval | default('3600') }}"
  LoginGraceTime: "{{ security_sshd_LoginGraceTime | default('120') }}"
  LogLevel: "{{ security_sshd_LogLevel | default('INFO') }}"
  MACs: "{{security_sshd_MACs }}"
  MaxAuthTries: "{{ security_sshd_MaxAuthTries | default('6') }}"
  MaxSessions: "{{ security_sshd_MaxSessions | default('10') }}"
  MaxStartups: "{{ security_sshd_MaxStartups | default('10:30:100') }}"
  PasswordAuthentication: "{{ security_sshd_PasswordAuthentication }}"
  PermitEmptyPasswords: "{{ security_sshd_PermitEmptyPasswords }}"
  PermitOpen: "{{ security_sshd_PermitOpen | default('any') }}"
  PermitRootLogin: "{{ security_sshd_PermitRootLogin }}"
  PermitTTY: "{{ security_sshd_PermitTTY | default('yes') }}"
  PermitTunnel: "{{ security_sshd_PermitTunnel | default('no') }}"
  PermitUserEnvironment: "{{ security_sshd_PermitUserEnvironment }}"
  PermitUserRC: "{{ security_sshd_PermitUserRC }}"
  PidFile: "{{ security_sshd_PidFile | default('/var/run/sshd.pid') }}"
  PrintLastLog: "{{ security_sshd_PrintLastLog }}"
  PrintMotd: "{{ security_sshd_PrintMotd | default('yes') }}"
  #PubkeyAcceptedKeyTypes:
  PubkeyAuthentication: "{{ security_sshd_PubkeyAuthentication }}"
  RekeyLimit: "{{ security_sshd_RekeyLimit | default('default none') }}"
  # RevokedKeys: "{{ security_sshd_RevokedKeys | default('') }}"
  #RhostsRSAAuthentication: "{{ security_sshd_RhostsRSAAuthentication | default('no') }}"
  #RSAAuthentication: "{{ security_sshd_RSAAuthentication | default('no') }}"
  #ServerKeyBits: "{{ security_sshd_ServerKeyBits | default('1024') }}"
  ShowPatchLevel: "{{ security_sshd_ShowPatchLevel | default('no') }}"
  StreamLocalBindMask: "{{ security_sshd_StreamLocalBindMask | default('0177') }}"
  StrictModes: "{{ security_sshd_StrictModes}}"
  Subsystem: "{{ security_sshd_Subsystem }}"
  SyslogFacility: AUTHPRIV
  TCPKeepAlive: "{{ security_sshd_TCPKeepAlive | default('yes') }}"
  # TrustedUserCAKeys: "{{ security_sshd_TrustedUserCAKeys | default('') }}"
  UseDNS: "{{ security_sshd_UseDNS | default('yes') }}"
  UsePAM: 'yes'  # FIXME?
  UsePrivilegeSeparation: "{{ security_sshd_UsePrivilegeSeparation }}"
  VersionAddendum: "{{ security_sshd_VersionAddendum | default('none') }}"
  X11DisplayOffset: "{{ security_sshd_X11DisplayOffset | default('10') }}"
  X11Forwarding: "{{ security_sshd_X11Forwarding }}"
  X11MaxDisplays: "{{ security_sshd_X11MaxDisplays }}"
  X11UseLocalhost: "{{ security_sshd_X11UseLocalhost | default('yes') }}"
  XAuthLocation: "{{ security_sshd_XAuthLocation | default('/usr/bin/xauth') }}"
```

## Dependencies

None.

## Example Playbook

This example is to show the range of configuration this role
provides, it is notintended to be used as-is.

```yaml
    ---
    - hosts: servers
      roles:
        - { role: ansible-os-hardening-sshd }
```

## Contributing

This repository uses
[git-flow](http://nvie.com/posts/a-successful-git-branching-model/).
To contribute to the role, create a new feature branch (`feature/foo_bar_baz`),
write [Molecule](http://molecule.readthedocs.io/en/master/index.html) tests for
the new functionality
and submit a pull request targeting the `develop` branch.

Happy hacking!

## License

GPLv3

## Author Information

[David Sastre](david.sastre@redhat.com)
