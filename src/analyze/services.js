/**
 * Port names, and which of them carry credentials in the clear.
 *
 * A port number alone makes a conversation table something you have to
 * translate in your head; "8009 → 5432" means nothing until you know one end
 * is Postgres. The list is deliberately short — the ports people actually meet
 * — rather than a copy of /etc/services, most of which is dead registrations.
 */
export const SERVICES = {
  20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
  53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
  110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
  138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
  162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
  465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer", 520: "rip",
  546: "dhcpv6", 547: "dhcpv6", 587: "submission", 623: "ipmi", 631: "ipp",
  636: "ldaps", 853: "dns-over-tls", 873: "rsync", 989: "ftps-data",
  990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
  1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 1900: "ssdp",
  2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
  3000: "http-alt", 3128: "http-proxy", 3268: "ldap-gc", 3306: "mysql",
  3389: "rdp", 4369: "epmd", 4500: "ipsec-nat-t", 5060: "sip", 5061: "sips",
  5222: "xmpp", 5353: "mdns", 5432: "postgresql", 5555: "http-alt",
  5601: "kibana", 5672: "amqp", 5900: "vnc", 5938: "teamviewer",
  6379: "redis", 6443: "kubernetes", 6667: "irc", 8000: "http-alt",
  8006: "proxmox", 8080: "http-alt", 8086: "influxdb", 8088: "http-alt",
  8443: "https-alt", 8883: "mqtts", 9000: "http-alt", 9090: "prometheus",
  9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
  11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
  51820: "wireguard",
};

/**
 * Protocols whose traffic is readable by anyone on the path. Flagged as a
 * finding rather than a moral judgement: on a capture, "this session's
 * password went past in cleartext" is a fact worth surfacing.
 */
export const CLEARTEXT_PORTS = {
  21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP",
  161: "SNMP", 389: "LDAP", 512: "rexec", 513: "rlogin", 514: "rsh",
  1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
  11211: "memcached", 27017: "MongoDB",
};

/**
 * Which end of a conversation is the server.
 *
 * Without a handshake to go on, the lower port is the better guess — an
 * ephemeral source port is nearly always above 32768 and a listening port
 * nearly always below it.
 */
export function serviceName(port) {
  return SERVICES[port] || null;
}

export function labelPort(port) {
  if (port === "" || port == null) return "";
  const name = SERVICES[port];
  return name ? `${port} (${name})` : String(port);
}

export function likelyServerPort(portA, portB) {
  const a = Number(portA), b = Number(portB);
  if (SERVICES[a] && !SERVICES[b]) return a;
  if (SERVICES[b] && !SERVICES[a]) return b;
  return Math.min(a, b);
}
