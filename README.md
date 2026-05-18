# extractor

Extract IPs, domains, emails, URLs, hashes, and CVEs from any input — built for piping.

```bash
cat file.txt | extractor --domain --url
```

---

## Install

```bash
git clone https://github.com/gitkhayrol/extractor
cd extractor
pip install requests
chmod +x extractor.py

# optional: use as a global command
sudo ln -s $(pwd)/extractor.py /usr/local/bin/extractor
```

---

## Basic Usage

```bash
cat file.txt       | extractor --domain --url
cat access.log     | extractor --ip --dedup
cat malware.bin    | extractor --all
curl https://target.com | extractor --domain --url
```

---

## Flags

**What to extract:**

| Flag | Extracts |
|------|----------|
| `--ip` | IPv4 addresses |
| `--ipv6` | IPv6 addresses |
| `--domain` | Domain names |
| `--email` | Email addresses |
| `--url` | HTTP/HTTPS URLs |
| `--hash` | MD5, SHA1, SHA256, SHA512 |
| `--cve` | CVE identifiers |
| `--all` | Everything |

**Useful extras:**

| Flag | Description |
|------|-------------|
| `--dedup` | Remove duplicates |
| `--no-private` | Skip private/internal IPs |
| `--quiet` / `-q` | Raw output only — good for piping further |
| `--json` | JSON output |
| `--count` | Show counts only |
| `--output FILE` | Save to file |

---

## Examples

```bash
# domains and URLs from any file
cat report.txt | extractor --domain --url

# all IPs, no duplicates, public only
cat access.log | extractor --ip --dedup --no-private

# pipe into other tools
cat file.txt | extractor --ip --quiet | sort -u > ips.txt

# pull domains from a live page
curl -s https://example.com | extractor --domain --dedup

# everything from a binary file
cat malware.apk | extractor --all --output iocs.txt

# just counts
cat big.log | extractor --all --count
```

---

## Requirements

```bash
pip install requests
```

---

## License

MIT
