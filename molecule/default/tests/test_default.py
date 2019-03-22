import os

import pytest

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


@pytest.mark.parametrize("name,version", [
    ("openssh-server", "7.4"),
    ("openssh", "7.4"),
    ("tcp_wrappers-libs", "7.6"),
    ("fipscheck-lib", "1.4.1"),
    ("fipscheck", "1.4.1")
])
def test_openssh_packages(host, name, version):
    pkg = host.package(name)
    assert pkg.is_installed
    assert pkg.version.startswith(version)


def test_openssh_sysconfig_file(host):
    f = host.file('/etc/sysconfig/sshd')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o640
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('AUTOCREATE_SERVER_KEYS: "RSA ED25519"')


@pytest.mark.parametrize("file,mode,group", [
    ("ssh_host_ed25519_key", 0o640, "ssh_keys"),
    ("ssh_host_rsa_key", 0o640, "ssh_keys"),
    ("ssh_host_ed25519_key.pub", 0o644, "root"),
    ("ssh_host_rsa_key.pub", 0o644, "root"),
])
def test_openssh_key_pairs_files(host, file, mode, group):
    f = host.file('/etc/ssh/' + file)

    assert f.exists
    assert f.is_file
    assert f.mode == mode
    assert f.user == 'root'
    assert f.group == group


def test_openssh_banner_file(host):
    f = host.file('/etc/issue')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.sha256sum == '3ddc77e8d66beea069fb376d0710475456eb27c3215ecc24b05c67690a7d6f65'  # noqa E501


def test_openssh_server_configuration_file(host):
    f = host.file('/etc/ssh/sshd_config')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o600
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('Port 22')
    assert f.contains('AddressFamily any')
    assert f.contains('ListenAddress localhost')
    assert f.contains('Protocol 2')
    assert f.contains('HostKey /etc/ssh/ssh_host_rsa_key')
    assert f.contains('HostKey /etc/ssh/ssh_host_ed25519_key')
    assert f.contains('AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES')  # noqa E501
    assert f.contains('AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT')  # noqa E501
    assert f.contains('AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE')
    assert f.contains('AcceptEnv XMODIFIERS')
    assert f.contains('AllowAgentForwarding no')
    assert f.contains('AllowTcpForwarding no')
    assert f.contains('AuthenticationMethods any')
    assert f.contains('AuthorizedKeysFile .ssh/authorized_keys')
    assert f.contains('AuthorizedPrincipalsFile none')
    assert f.contains('Banner /etc/issue')
    assert f.contains('ChallengeResponseAuthentication yes')
    assert f.contains('Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr')  # noqa E501
    assert f.contains('ClientAliveCountMax 0')
    assert f.contains('ClientAliveInterval 600')
    assert f.contains('Compression delayed')
    assert f.contains('ExposeAuthenticationMethods never')
    assert f.contains('GatewayPorts no')
    assert f.contains('GSSAPIAuthentication no')
    assert f.contains('GSSAPICleanupCredentials yes')
    assert f.contains('GSSAPIKeyExchange no')
    assert f.contains('GSSAPIEnablek5users no')
    assert f.contains('GSSAPIStoreCredentialsOnRekey no')
    assert f.contains('GSSAPIStrictAcceptorCheck yes')
    assert f.contains('HostbasedAuthentication yes')
    assert f.contains('HostbasedUsesNameFromPacketOnly no')
    assert f.contains('IgnoreRhosts yes')
    assert f.contains('IgnoreUserKnownHosts yes')
    assert f.contains('IPQoS lowdelay throughput')
    assert f.contains('KbdInteractiveAuthentication yes')
    assert f.contains('KerberosAuthentication no')
    assert f.contains('KerberosOrLocalPasswd yes')
    assert f.contains('KerberosTicketCleanup yes')
    assert f.contains('KerberosUseKuserok yes')
    assert f.contains('KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256')  # noqa E501
    assert f.contains('KeyRegenerationInterval 3600')
    assert f.contains('LoginGraceTime 120')
    assert f.contains('LogLevel INFO')
    assert f.contains('MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256')  # noqa E501
    assert f.contains('MaxAuthTries 6')
    assert f.contains('MaxSessions 10')
    assert f.contains('MaxStartups 10:30:100')
    assert f.contains('PasswordAuthentication no')
    assert f.contains('PermitEmptyPasswords no')
    assert f.contains('PermitOpen any')
    assert f.contains('PermitRootLogin no')
    assert f.contains('PermitTTY yes')
    assert f.contains('PermitTunnel no')
    assert f.contains('PermitUserEnvironment no')
    assert f.contains('PidFile /var/run/sshd.pid')
    assert f.contains('PrintLastLog yes')
    assert f.contains('PrintMotd yes')
    assert f.contains('PubkeyAuthentication yes')
    assert f.contains('RekeyLimit default none')
    assert f.contains('RhostsRSAAuthentication no')
    assert f.contains('RSAAuthentication no')
    assert f.contains('ServerKeyBits 1024')
    assert f.contains('ServerKeyBits 1024')
    assert f.contains('StrictModes yes')
    assert f.contains('Subsystem sftp /usr/libexec/openssh/sftp-server')
    assert f.contains('SyslogFacility AUTHPRIV')
    assert f.contains('TCPKeepAlive yes')
    assert f.contains('UseDNS yes')
    assert f.contains('UsePAM yes')
    assert f.contains('UsePrivilegeSeparation yes')
    assert f.contains('VersionAddendum none')
    assert f.contains('X11DisplayOffset 10')
    assert f.contains('X11Forwarding yes')
    assert f.contains('X11UseLocalhost yes')
    assert f.contains('XAuthLocation /usr/bin/xauth')


# def test_openssh_server_service(host):
#     s = host.service('sshd.socket')
#
#     assert s.is_enabled


def test_openssh_client_configuration_directory(host):
    d = host.file('/etc/ssh/ssh_config.d')

    assert d.exists
    assert d.is_directory
    assert d.mode == 0o755
    assert d.user == 'root'
    assert d.group == 'root'


def test_openssh_client_configuration_file(host):
    f = host.file('/etc/ssh/ssh_config.d/99-ansible-hardening.conf')

    assert f.exists
    assert f.is_file
    assert f.mode == 0o644
    assert f.user == 'root'
    assert f.group == 'root'
    assert f.contains('Host *')
    assert f.contains('ChallengeResponseAuthentication yes')
    assert f.contains('Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr')  # noqa E501
    assert f.contains('HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa')  # noqa E501
    assert f.contains('KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256')  # noqa E501
    assert f.contains('MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256')  # noqa E501
    assert f.contains('PasswordAuthentication no')
    assert f.contains('PubkeyAuthentication yes')
