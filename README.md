# sshoi — SSH over ICMPv6

Tunnel SSH connections through ICMPv6 Echo Request/Reply packets. Useful when
TCP/UDP are blocked but ICMP is permitted through a firewall or network policy.

## Architecture

```
SSH client ──TCP:2222──► sshoi-client ──ICMPv6 Echo Req──► sshoi-server ──TCP:22──► sshd
                              ◄──────── ICMPv6 Echo Reply ◄───────────────────────────
```

Each SSH connection is a multiplexed **session** identified by a 16-bit session
ID carried inside the ICMPv6 payload. All payloads are encrypted with
**XChaCha20-Poly1305** using a key derived from a shared passphrase via
HKDF-SHA256. The header fields (session ID, sequence, ACK, flags) are
authenticated as AAD, preventing replay or injection attacks.

### Wire Format

```
Offset  Len   Field
0       4     MAGIC        = "SSHI"
4       2     SESSION_ID   uint16 BE
6       4     SEQ          uint32 BE
10      4     ACK          uint32 BE
14      1     FLAGS        SYN=0x01 FIN=0x02 ACK=0x04 DATA=0x08 KA=0x10
15      2     PAYLOAD_LEN  uint16 BE (plaintext bytes)
17      24    NONCE        XChaCha20 nonce (random per packet)
41      N     ENCRYPTED_DATA
41+N    16    POLY1305 TAG
```

### Reliability Layer

- **Send window**: up to 64 unacknowledged packets in flight (configurable)
- **Retransmit**: packets not ACKed within 500 ms are resent (up to 10 attempts)
- **Duplicate detection**: 512-slot sliding window bitmap per session
- **Keepalive**: KA packets every 15 s to keep firewall state alive

## Build

Requires Go 1.22+ and `CAP_NET_RAW` (or root) for raw ICMPv6 sockets.

```sh
go build -o sshoi-client ./cmd/client
go build -o sshoi-server ./cmd/server
```

## Usage

**Server** (run on the host with sshd):

```sh
export SSHOI_PASSPHRASE=your-shared-secret
sudo ./sshoi-server [-sshd 127.0.0.1:22] [-v]
```

**Client** (run on the restricted machine):

```sh
export SSHOI_PASSPHRASE=your-shared-secret
sudo ./sshoi-client -server 2001:db8::1 [-listen 127.0.0.1:2222] [-v]
```

**Connect via SSH**:

```sh
ssh -p 2222 user@127.0.0.1
```

## Flags

### sshoi-client

| Flag | Default | Description |
|------|---------|-------------|
| `-server` | *(required)* | Server IPv6 address |
| `-listen` | `127.0.0.1:2222` | Local TCP listen address |
| `-passphrase` | `$SSHOI_PASSPHRASE` | Shared passphrase |
| `-keepalive` | `15s` | Keepalive interval |
| `-retransmit` | `500ms` | Retransmit timeout |
| `-v` | false | Verbose logging |

### sshoi-server

| Flag | Default | Description |
|------|---------|-------------|
| `-sshd` | `127.0.0.1:22` | Local sshd address |
| `-passphrase` | `$SSHOI_PASSPHRASE` | Shared passphrase |
| `-keepalive` | `15s` | Keepalive interval |
| `-retransmit` | `500ms` | Retransmit timeout |
| `-v` | false | Verbose logging |

## Security Notes

- The ICMPv6 identifier field is set to `0x5348` ("SH") to filter non-sshoi
  pings; this is a convenience filter, not a security mechanism.
- Restrict the server's ICMPv6 receive to trusted source addresses with
  `ip6tables` for defence in depth:
  ```sh
  ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -s 2001:db8::/32 -j ACCEPT
  ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP
  ```
- The passphrase is never used directly; it is always stretched through
  HKDF-SHA256 before reaching the AEAD.

## Comparison with Similar Tools

| Tool | Protocol | Transport | Encryption |
|------|----------|-----------|------------|
| **sshoi** | ICMPv6 | TCP relay | XChaCha20-Poly1305 |
| ptunnel-ng | ICMPv4 | TCP proxy | Optional password |
| icmptunnel | ICMPv4 | TUN/IP | None |
| hans | ICMPv4 | TUN/IP | None |
| iodine | DNS | TUN/IP | Optional |
| slowdns | DNS | TCP relay | Optional |
