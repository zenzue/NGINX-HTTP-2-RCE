# NGINX HTTP/2 RCE

**Read-only vulnerability exposure scanner for CVE-2026-123007 and CVE-2026-123633**

**Author:** Aung Myat Thu  
**Suggested Git repository slug:** `nginx-http2-rce` (Git hosting generally does not permit `/` in repository names)  
**Runtime:** Python 3.9+ managed by [uv](https://docs.astral.sh/uv/)  
**License:** MIT

NGINX HTTP/2 RCE helps defenders **triage possible exposure** to the November 2026 NGINX HTTP/2 memory-corruption vulnerabilities. It supports TLS endpoint checks and local NGINX/Docker metadata inspection, including environments using **Nginx Proxy Manager (NPM)**, **Nginx UI**, **OpenResty**, and **Pangolin/Traefik**.

> **Important:** This is **not** a proof-of-exploitation scanner. It does not reproduce the Rapid7 proof of concept, send malformed HTTP/2 frames, or verify memory corruption. A remote `h2` negotiation means HTTP/2 is reachable **at that TLS termination point**, not that the server is vulnerable. Run only against systems you own or are authorized to test.

## Features

- Assess **CVE-2026-123007** and **CVE-2026-123633** against published upstream NGINX version ranges.
- Check whether a remote HTTPS listener negotiates **HTTP/2 (`h2`)** via TLS ALPN.
- Inspect local NGINX/OpenResty binaries and effective configuration signals (including HTTP/2 and proxy directives).
- Discover relevant running Docker containers, with product hints for NPM, Nginx UI, and Pangolin-related components.
- Treat OpenResty/other forks as **vendor review required**, not automatically equivalent to upstream NGINX.
- Export machine-readable **JSON reports** and scan a list of hosts with limited concurrency.
- No third-party Python dependencies; install and run with **uv**.

## Requirements

- macOS, Linux, or another platform with Python and network access.
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) installed (the recommended runner).
- For `--local`: optional `nginx`, `openresty`, and/or `docker` executables; permissions to execute `nginx -T` and `docker exec` in relevant containers.

### Install uv

```bash
# macOS (Homebrew)
brew install uv

# Linux / macOS (official installer)
curl -LsSf https://astral.sh/uv/install.sh | sh

uv --version
```

Inspect install scripts and follow your organization's approval process before running downloaded shell code. Alternatively install `uv` using your OS package manager.

## Quick start using uv

```bash
# Clone your repository (replace the URL with your actual Git remote)
git clone https://github.com/zenzue/NGINX-HTTP-2-RCE nginx-http2-rce
cd nginx-http2-rce

# Create project environment using the lockfile
uv sync --locked

# Scan one HTTPS endpoint
uv run --locked python nginx2root_scan.py --target proxy.example.com

# Show CLI arguments
uv run --locked python nginx2root_scan.py --help
```

**Direct script mode** (no manual activation):

```bash
uv run --script nginx2root_scan.py --target proxy.example.com
```

The Python file includes PEP 723 inline metadata so `uv` can manage script execution independently. `uv run --locked python ...` uses the project environment and lockfile.

## Usage

### Scan public HTTPS endpoints

```bash
uv run --locked python nginx2root_scan.py \
  --target proxy.example.com \
  --target https://nginxui.example.com:8443 \
  --json report.json
```

Endpoints must be HTTPS hosts/IP addresses, optionally with a port. HTTP URLs and paths are not accepted. A proxy/CDN may terminate TLS before traffic reaches NGINX, so verify the origin independently.

### Scan from a target list

Create `targets.txt` (one hostname or HTTPS URL per line; `#` comments are accepted):

```text
# Authorized infrastructure
proxy.example.com
https://nginxui.example.com:8443
pangolin.example.com
```

```bash
uv run --locked python nginx2root_scan.py \
  --targets-file targets.txt --workers 4 --timeout 5 \
  --json report.json
```

### Inspect local NGINX and running Docker containers

```bash
uv run --locked python nginx2root_scan.py --local --json local-report.json
```

If your host requires elevated privileges for reading configuration or Docker access, run with the permissions appropriate to your environment. For example, after `uv sync --locked`:

```bash
sudo .venv/bin/python nginx2root_scan.py --local --json local-report.json
```

Using `.venv/bin/python` here avoids invoking `uv` as root and preserves the provisioned project Python environment.

### TLS with an internal or self-signed certificate

```bash
uv run --locked python nginx2root_scan.py --target lab.example.com --insecure
```

`--insecure` skips certificate verification and is intended **only** for trusted test environments. It does not change the target server.

### Save JSON to standard output

```bash
uv run --locked python nginx2root_scan.py \
  --target proxy.example.com --json - > report.json
```

### Operator-confirmed vendor patch

```bash
uv run --locked python nginx2root_scan.py --local --vendor-patched
```

**Use only when you have independently confirmed vendor patches.** This flag is a manual operator attestation, not a vulnerability test; it applies to local detections.

## CLI reference

| Option | Function |
| --- | --- |
| `--target HOST` | Scan one HTTPS host or `https://host:port` (repeatable). |
| `--targets-file FILE` | Scan endpoints from a text file. |
| `--local` | Inspect host and relevant running Docker containers. |
| `--timeout SECONDS` | Remote connection timeout (default: `4`). |
| `--workers N` | Concurrent remote handshakes (1–16; default: `8`). |
| `--insecure` | Disable remote TLS certificate validation. |
| `--vendor-patched` | Attest local vendor patches manually. |
| `--json PATH` | Save JSON findings; use `-` for stdout-only output. |
| `--help` | Show all CLI options. |

## Interpreting findings

| Status | Meaning / next step |
| --- | --- |
| `EXPOSED_H2_VERSION_UNKNOWN` | Tested TLS listener negotiated `h2`. Check origin binary, config and package patches. **Not proof of vulnerability.** |
| `NO_H2_ON_TESTED_TLS_ENDPOINT` | No `h2` negotiated at this endpoint; other SNI names, listeners and origin routes may differ. |
| `AFFECTED_VERSION` | Detected upstream NGINX version within the known affected range and HTTP/2 directives found. Verify vendor backports. |
| `AFFECTED_VERSION_H2_UNCONFIRMED` | Detected affected upstream version but did not prove local HTTP/2 exposure. |
| `FIXED_UPSTREAM_VERSION` | Detected upstream version at or above the published fix on a supported release line. Verify actual packaging. |
| `REVIEW_REQUIRED` | Evidence insufficient for a verdict. |
| `FORK_REQUIRES_VENDOR_ADVISORY` | Per-CVE classification for OpenResty and other forks; check vendor advisories. |
| `VENDOR_PATCH_ATTESTED` | Operator asserted local binaries are patched; no independent verification. |
| `NOT_NGINX_PRODUCT` | Container identified as Pangolin/Traefik/Gerbil, not as NGINX; assess other NGINX hops separately. |
| `CHECK_FAILED` | Could not complete the check; inspect reported error. |

### CVE coverage

| CVE | Upstream affected starting version | Upstream fixes referenced | Key prerequisites |
| --- | --- | --- | --- |
| [CVE-2026-123007](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities) | NGINX 1.9.5 | Stable **1.30.7**, mainline **1.31.9** | Reachable HTTP/2 implementation. |
| [CVE-2026-123633](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities) | NGINX 1.19.7 | Stable **1.30.7**, mainline **1.31.9** | HTTP/2 plus relevant proxy/connection-handling conditions. |

**Caution:** These ranges describe **upstream** source builds. Distribution vendors may backport patches without changing the upstream version string. OpenResty, NGINX Plus, Nginx Proxy Manager images and other forks require their own patch verification. Older unsupported version branches are not automatically safe.

### Product notes

- **Nginx Proxy Manager:** Inspect its image/build and bundled OpenResty/NGINX; do not equate the UI release number with the underlying engine's patched state.
- **Nginx UI:** It administers NGINX; inspect the actual installed binary and the effective runtime configuration.
- **Pangolin:** Standard Pangolin deployments use Traefik/Gerbil rather than NGINX; any additional NGINX in front or behind remains in scope.

## Testing

```bash
uv run --locked python -m unittest discover -v
```

The included tests cover NGINX version classification, OpenResty fork treatment, configuration flags, and target parsing. These are **unit tests**, not live exploit tests.

## Security and limitations

1. **Non-destructive:** Remote testing makes a standard TLS handshake using ALPN; it does not probe for RCE or exhaust server resources.
2. **Version-based inference:** Version strings may not reflect downstream backported fixes, fork revisions, or what code is actually loaded.
3. **Configuration inference:** Regex-based inspection of `nginx -T` is heuristic and does not fully resolve context/inheritance or prove the active worker configuration.
4. **TLS topology:** A CDN, WAF, load balancer, or Traefik may terminate HTTP/2 independently of a backend NGINX instance.
5. **CVE-2026-123633:** The scanner does not reproduce its connection/draining preconditions.
6. **Permissions:** Docker and NGINX inspection may fail when the caller lacks privileges; `nginx -T` can include sensitive config material, though reports store only parsed flags.
7. **Scope:** This scanner focuses on **two HTTP/2 CVEs**, not other NGINX, HTTP/3, DNS or unrelated issues from the same security release.

The scanner should be used for **prioritizing verification and remediation**, not as a definitive clean bill of health.

## References

- [NGINX official security advisories](https://nginx.org/en/security_advisories.html)
- [Wiz: NGINX HTTP/2 RCE vulnerabilities](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities)
- [Rapid7 / sfewer-r7: CVE-2026-123007 research repository](https://github.com/sfewer-r7/CVE-2026-123007) — **reference only**; the scanner does not execute the exploit.

## Author and license

Developed by **Aung Myat Thu**. Licensed under the [MIT License](LICENSE).
