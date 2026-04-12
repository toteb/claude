---
name: nuclei-template-builder
description: >
  Build, debug, and optimize Nuclei templates (ProjectDiscovery's YAML-based vulnerability scanner DSL).
  Use this skill whenever the user wants to: write a nuclei template, create a vulnerability check,
  build a security scanner template, detect a CVE with nuclei, write fuzzing rules, create network/DNS/HTTP
  protocol checks, build multi-protocol detection templates, write OOB/interactsh-based templates,
  create headless browser automation templates, build workflow chains, or debug/fix existing nuclei templates.
  Also trigger when the user mentions: nuclei, projectdiscovery, template YAML for scanning, or security
  detection templates. Even if they just say "write a check for CVE-XXXX-YYYY" or "detect if X is vulnerable",
  this skill applies.
---

# Nuclei Template Builder

You are an expert at writing Nuclei templates — the YAML-based DSL used by ProjectDiscovery's Nuclei scanner. You produce production-quality templates that follow community conventions, minimize false positives, and are efficient at scale.

## How to use this skill

1. Understand what the user wants to detect (CVE, misconfiguration, technology fingerprint, etc.)
2. Choose the right protocol(s) and approach
3. Write a complete, valid template
4. Explain your design choices briefly

When the user provides a CVE ID, research what you know about the vulnerability first, then build the template. When they describe behavior ("detect if X header is missing"), translate that directly into template logic.

For complex templates, read `references/syntax-reference.md` for the full syntax details on protocols, matchers, extractors, helper functions, variables, and advanced features.

## Template Structure

Every template has this skeleton:

```yaml
id: unique-template-id    # lowercase, hyphens, no spaces
info:
  name: Human Readable Name
  author: author-name
  severity: info|low|medium|high|critical
  description: What this template detects
  reference:
    - https://example.com/advisory
  tags: comma,separated,tags
  metadata:
    max-request: 1         # number of requests template makes
    shodan-query: 'query'  # optional uncover integration

# Protocol block(s) — one or more of: http, dns, tcp, file, headless, ssl, code, websocket
# Then matchers and/or extractors
```

### Severity Guidelines
- **info**: Fingerprinting, technology detection, informational findings
- **low**: Minor misconfigurations, information disclosure with limited impact
- **medium**: Moderate vulnerabilities, significant misconfigs, credential exposure
- **high**: Serious vulnerabilities, RCE, auth bypass, significant data exposure
- **critical**: Trivially exploitable RCE, pre-auth critical vulns, mass-impact issues

### ID Conventions
- CVEs: `CVE-YYYY-NNNNN` (uppercase CVE prefix)
- Tech detection: `tech-name-detect` or `tech-name-version`
- Misconfigs: `descriptive-name` like `git-config-exposure`
- Use lowercase with hyphens, no spaces

## HTTP Protocol

### Basic HTTP (Model-based)

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    headers:
      User-Agent: Mozilla/5.0
    redirects: true
    max-redirects: 3
    matchers:
      - type: word
        words:
          - "[core]"
```

### Dynamic Variables for Paths
| Variable | Example Value (for `https://example.com:443/foo/bar.php`) |
|---|---|
| `{{BaseURL}}` | `https://example.com:443/foo/bar.php` |
| `{{RootURL}}` | `https://example.com:443` |
| `{{Hostname}}` | `example.com:443` |
| `{{Host}}` | `example.com` |
| `{{Port}}` | `443` |
| `{{Path}}` | `/foo` |
| `{{File}}` | `bar.php` |
| `{{Scheme}}` | `https` |

### Raw HTTP Requests
Use raw requests when you need full control over the request (custom methods, smuggling, precise headers):

```yaml
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"admin","password":"{{password}}"}
```

Raw requests support helper functions inline: `Authorization: Basic {{base64('user:pass')}}`

### Request Conditions (Multi-Request Chaining)
Access previous response data with numbered suffixes:

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/step1"
  - method: GET
    path:
      - "{{BaseURL}}/step2"

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && contains(body_2, 'secret')"
```

### Session / Cookies
Cookies are reused between requests by default (browser-like session). Disable with:
```yaml
disable-cookie: true
```

### Payloads & Attack Types

```yaml
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}

        user={{username}}&pass={{password}}
    attack: clusterbomb    # or batteringram, pitchfork
    payloads:
      username:
        - admin
        - root
      password: wordlists/passwords.txt
```

- **batteringram**: Same payload in all positions simultaneously
- **pitchfork**: Parallel iteration (1st from each list, 2nd from each, etc.)
- **clusterbomb**: All combinations (cartesian product)

### Unsafe HTTP (rawhttp)
For request smuggling, malformed requests, CRLF injection:

```yaml
http:
  - raw:
      - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Transfer-Encoding: chunked

        0

        GET /admin HTTP/1.1
    unsafe: true
```

### Race Conditions

```yaml
http:
  - raw:
      - |
        POST /coupon HTTP/1.1
        Host: {{Hostname}}

        code=DISCOUNT
    race: true
    race_count: 10
```

### Connection Pooling

```yaml
http:
  - raw:
      - |
        GET /path HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64('admin:§password§')}}
    attack: batteringram
    payloads:
      password: passwords.txt
    threads: 40
```

### HTTP Pipelining

```yaml
http:
  - raw:
      - |+
        GET /{{path}} HTTP/1.1
        Host: {{Hostname}}
    attack: batteringram
    payloads:
      path: wordlist.txt
    unsafe: true
    pipeline: true
    pipeline-concurrent-connections: 40
    pipeline-requests-per-connection: 25000
```

### HTTP Fuzzing (Unknown Vulnerability Discovery)

```yaml
http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'
          - 'len(body) > 0'
        condition: and

    payloads:
      reflection:
        - "6842'\"><9967"

    stop-at-first-match: true

    fuzzing:
      - part: query          # query|path|header|cookie|body|request
        type: postfix        # replace|prefix|postfix|infix|replace-regex
        mode: single         # single|multiple
        fuzz:
          - "{{reflection}}"

    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"
```

**Fuzzing filters** narrow scope to specific parameters:
```yaml
fuzzing:
  - part: query
    keys:
      - "redirect"
      - "url"
    # or: keys-regex: ["redirect.*"]
    # or: values: ["https?://.*"]
```

**Time-delay analyzer** for blind injection:
```yaml
analyzer:
  name: time_delay
  parameters:
    sleep_duration: 5

matchers:
  - type: word
    part: analyzer
    words:
      - "true"
```

## DNS Protocol

```yaml
dns:
  - name: "{{FQDN}}"
    type: A          # A, NS, CNAME, SOA, PTR, MX, TXT, AAAA
    class: inet
    recursion: true
    retries: 3

    matchers:
      - type: word
        words:
          - "IN\tCNAME"
```

**Matcher parts**: `request`, `rcode`, `question`, `extra`, `answer`, `ns`, `raw`/`body`/`all`

## Network (TCP) Protocol

```yaml
tcp:
  - inputs:
      - data: "{{hex_decode('deadbeef')}}"
      - read-size: 2048
    host:
      - "{{Hostname}}"
    port: 27017           # supports comma-separated: 5432,5433

    matchers:
      - type: word
        words:
          - "MongoDB"
```

For TLS connections: `host: ["tls://{{Hostname}}"]`

**Named reads** for targeted matching:
```yaml
inputs:
  - read-size: 8
    name: banner
matchers:
  - type: word
    part: banner
    words:
      - "SSH-2.0"
```

## File Protocol

```yaml
file:
  - extensions:
      - all
    # denylist:
    #   - jpg
    #   - png
    # max-size: 5242880    # bytes, default 5MB
    # no-recursive: false

    extractors:
      - type: regex
        regex:
          - "AIza[0-9A-Za-z\\-_]{35}"
```

## Headless Protocol (Browser Automation)

```yaml
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}/login"
      - action: waitload
      - action: text
        args:
          by: xpath
          xpath: //input[@name='username']
          value: admin
      - action: click
        args:
          by: xpath
          xpath: //input[@type='submit']
      - action: waitload

    matchers:
      - type: word
        part: body
        words:
          - "Dashboard"
```

**Key actions**: `navigate`, `click`, `rightclick`, `text`, `screenshot`, `script`, `extract`, `select`, `files`, `keyboard`, `sleep`, `waitload`, `waitdom`, `waitidle`, `waitfcp`, `waitstable`, `waitdialog`, `setmethod`, `addheader`, `setheader`, `deleteheader`, `setbody`, `waitevent`, `getresource`, `debug`

**Selectors**: `selector` (CSS, default), `xpath`, `regex`, `js`, `search`

**Script action** (must be function reference):
```yaml
- action: script
  args:
    code: "() => window.secretValue"
  name: secret_val
```

**XSS detection with waitdialog**:
```yaml
- action: waitdialog
  name: alert
  args:
    max-duration: 5s
# Output: alert (bool), alert_type (string), alert_message (string)
```

## Code Protocol

```yaml
code:
  - engine:
      - py
      - python3
    source: |
      import sys
      target = sys.stdin.read().strip()
      print(f"Checking {target}")

    matchers:
      - type: word
        words:
          - "vulnerable"
```

Requires `-code` flag to run. **Parts**: `response` (stdout), `stderr`.

External file: `source: helpers/code/check.py`

Custom args and pattern:
```yaml
code:
  - engine:
      - pwsh
      - powershell
    args:
      - -ExecutionPolicy
      - Bypass
      - -File
    pattern: "*.ps1"
    source: |
      Write-Host "hello"
```

## JavaScript Protocol
For complex protocol-specific exploits (Redis, LDAP, Kerberos, custom protocols) that can't be expressed in YAML DSL. Uses embedded Goja runtime (ECMAScript 5.1). See ProjectDiscovery docs for available JS libraries/modules.

## Matchers

7 matcher types available:

| Type | What it matches |
|------|----------------|
| `status` | HTTP status codes (integer comparison) |
| `size` | Content-Length |
| `word` | String presence in specified part |
| `regex` | Regex pattern in specified part |
| `binary` | Hex-encoded binary data |
| `dsl` | Complex expressions with helper functions |
| `xpath` | XPath queries on XML/HTML |

### Matcher Examples

```yaml
# Status code
matchers:
  - type: status
    status:
      - 200
      - 302

# Word with condition
  - type: word
    words:
      - "admin"
      - "root"
    condition: and      # and|or (default: or)
    part: body          # body|header|all|raw (default: body)

# Regex
  - type: regex
    regex:
      - "token=[a-f0-9]{32}"
    part: header

# Binary (hex)
  - type: binary
    binary:
      - "504B0304"      # ZIP magic bytes
    part: body

# DSL (powerful expressions)
  - type: dsl
    dsl:
      - "status_code == 200 && len(body) > 100"
      - "contains(toupper(body), 'ADMIN')"

# XPath
  - type: xpath
    xpath:
      - "/html/head/title[contains(text(), 'Admin')]"
    part: body

# Hex-encoded word matching
  - type: word
    encoding: hex
    words:
      - "50494e47"
    part: body
```

### Negative Matchers
```yaml
matchers:
  - type: word
    words:
      - "PHPSESSID"
    part: header
    negative: true     # matches when word is NOT found
```

### Multiple Matchers with Condition
```yaml
matchers-condition: and    # and|or (default: or)
matchers:
  - type: word
    words:
      - "PHP"
    part: header
  - type: status
    status:
      - 200
```

### Named Matchers (for fingerprinting)
```yaml
matchers:
  - type: word
    name: php
    words:
      - "X-Powered-By: PHP"
    part: header
  - type: word
    name: nginx
    words:
      - "Server: nginx"
    part: header
```

### Internal Matchers (for flow/multi-protocol)
```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200"
    internal: true    # won't print as separate result
```

### Global Matchers
Apply across all HTTP responses from other templates:
```yaml
http:
  - global-matchers: true
    matchers:
      - type: regex
        name: api_key_leak
        regex:
          - "(?i)api[_-]?key.*['\"][a-zA-Z0-9]{20,}"
        part: body
```
Run with `-egm` flag.

## Extractors

5 extractor types:

```yaml
extractors:
  # Regex
  - type: regex
    part: body
    regex:
      - "Version: ([0-9.]+)"
    group: 1              # capture group (0=full match)

  # Key-Value (headers/cookies)
  - type: kval
    kval:
      - content_type      # use underscore, not hyphen

  # JSON (JQ-like syntax)
  - type: json
    part: body
    json:
      - '.[] | .id'

  # XPath
  - type: xpath
    xpath:
      - '/html/body/div/a'
    attribute: href       # optional attribute extraction

  # DSL
  - type: dsl
    dsl:
      - 'len(body)'
```

### Dynamic Extractors (for chaining requests)
```yaml
extractors:
  - type: regex
    name: csrf_token       # variable name for use in next requests
    part: body
    internal: true         # required for dynamic variables
    group: 1
    regex:
      - 'name="csrf" value="([a-f0-9]+)"'
```
Use in subsequent raw request: `X-CSRF-Token: {{csrf_token}}`

## Variables

Declared at template level, constant throughout execution:

```yaml
variables:
  a1: "static-value"
  a2: "{{base64('hello')}}"
  rand: "{{rand_text_alpha(8)}}"
```

## Preprocessors

`{{randstr}}` generates a random string per template run (consistent within the template). Suffix with numbers for multiple: `{{randstr_1}}`, `{{randstr_2}}`.

```yaml
http:
  - raw:
      - |
        POST /search HTTP/1.1
        Host: {{Hostname}}

        q={{randstr}}
    matchers:
      - type: word
        words:
          - "{{randstr}}"    # reflected value
```

## OOB Testing (Interactsh)

Use `{{interactsh-url}}` anywhere in requests:

```yaml
http:
  - raw:
      - |
        GET /fetch?url=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"           # or "http", "smtp"
      - type: regex
        part: interactsh_request
        regex:
          - ".*"
```

**Parts**: `interactsh_protocol`, `interactsh_request`, `interactsh_response`

## Flow (Conditional Execution & Orchestration)

Flow uses JavaScript (ECMAScript 5.1) to control template execution:

```yaml
flow: http(1) && http(2)     # only run 2nd request if 1st matches
```

Advanced orchestration:
```yaml
flow: |
  ssl();
  for (let vhost of iterate(template["ssl_domains"])) {
    set("vhost", vhost);
    http();
  }
```

**JS Bindings**:
- `protocol_name()` / `protocol_name(index)` / `protocol_name("id")` — execute protocol requests
- `iterate(value)` — safely iterate over any type
- `set("name", value)` — add variable to template context
- `template["key"]` — access template context (all extracted/response values)
- `log(data)` — debug print to stdout
- `new Dedupe()` — deduplication helper (`.Add()`, `.Values()`)

## Multi-Protocol Templates

Combine multiple protocols in one template. Protocols execute sequentially, and all response fields are shared with protocol prefix:

```yaml
id: subdomain-takeover-check

dns:
  - name: "{{FQDN}}"
    type: cname

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - "contains(http_body, 'Domain not found')"
          - "contains(dns_cname, 'github.io')"
        condition: and
```

**Protocol-prefixed variables**: `ssl_subject_cn`, `dns_cname`, `http_body`, `http_header`, `code_response`, etc.

## Workflows

Orchestrate multiple template files:

```yaml
# Generic workflow
workflows:
  - template: http/technologies/jira-detect.yaml
    subtemplates:
      - tags: jira

# Conditional workflow (matcher-based)
workflows:
  - template: http/technologies/tech-detect.yaml
    matchers:
      - name: wordpress
        subtemplates:
          - template: http/cves/wordpress/
      - name: jira
        subtemplates:
          - template: http/cves/jira/
```

Workflows share a unified execution context — named extractors from one template are available in others.

## Key Helper Functions

For the complete list, see `references/syntax-reference.md`. Most commonly used:

**Encoding/Decoding**: `base64()`, `base64_decode()`, `url_encode()`, `url_decode()`, `hex_encode()`, `hex_decode()`, `html_escape()`, `html_unescape()`

**Hashing**: `md5()`, `sha1()`, `sha256()`, `mmh3()`

**String manipulation**: `contains()`, `contains_all()`, `contains_any()`, `to_lower()`, `to_upper()`, `trim()`, `replace()`, `replace_regex()`, `reverse()`, `len()`, `concat()`, `join()`, `starts_with()`, `ends_with()`, `regex()`

**Random generation**: `rand_int()`, `rand_base()`, `rand_text_alpha()`, `rand_text_alphanumeric()`, `rand_text_numeric()`, `rand_char()`, `rand_ip()`

**Comparison**: `compare_versions()`, `equals_any()`

**Time**: `unix_time()`, `date_time()`, `to_unix_time()`, `wait_for()`

**Crypto**: `hmac()`, `aes_gcm()`

**Compression**: `gzip()`, `gzip_decode()`, `zlib()`, `zlib_decode()`

**JSON**: `json_minify()`, `json_prettify()`, `generate_jwt()`

**Deserialization**: `generate_java_gadget(gadget, cmd, encoding)`, `generate_dotnet_gadget(gadget, cmd, formatter, encoding)`

**DNS**: `resolve(host, format)` — format: `4`/`a`, `6`/`aaaa`, `cname`, `ns`, `txt`, `srv`, `ptr`, `mx`, `soa`, `caa`

**IP**: `ip_format(ip, format)` — format index 1-11 for IP obfuscation

## Best Practices

1. **Minimize false positives**: Use multiple matchers with `condition: and`. Combine status code + body content + header checks.

2. **Be specific with IDs and tags**: Use CVE IDs for CVE templates. Add relevant tags like `cve`, `rce`, `lfi`, `sqli`, `xss`, `misconfig`, `exposure`, `tech`, etc.

3. **Set `max-request` metadata**: Always document how many requests the template makes.

4. **Use `stop-at-first-match: true`** for detection templates where you don't need all matches.

5. **Prefer DSL matchers** for complex logic — they're more expressive and precise.

6. **Use `internal: true`** on matchers/extractors that are intermediate steps in flow/multi-protocol templates.

7. **Test with `-debug -svd`** to see all variables and request/response data.

8. **For CVE templates**: Include full `reference` links to advisories, include `classification` block with CVE/CWE/CVSS when available.

9. **Avoid unnecessary requests**: Use `flow` for conditional execution so you don't blast irrelevant targets.

10. **Use `{{randstr}}`** for reflected value detection to avoid false positives from cached responses.

## Common Template Patterns

### CVE Detection
```yaml
id: CVE-2024-XXXXX
info:
  name: Product Name - Vulnerability Type
  author: your-name
  severity: critical
  description: |
    Description of the vulnerability.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2024-XXXXX
    cwe-id: CWE-XXX
  metadata:
    max-request: 1
    shodan-query: 'http.title:"Product Name"'
  tags: cve,cve2024,product,rce
```

### Technology Fingerprinting
```yaml
id: nginx-version-detect
info:
  name: Nginx Version Detection
  author: your-name
  severity: info
  tags: tech,nginx

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: regex
        part: header
        regex:
          - "Server: nginx/[0-9.]+"

    extractors:
      - type: regex
        part: header
        regex:
          - "nginx/([0-9.]+)"
        group: 1
```

### Authenticated Multi-Step
```yaml
id: auth-rce-chain
info:
  name: Auth RCE Chain
  author: your-name
  severity: critical

flow: http(1) && http(2)

http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"user":"admin","pass":"admin"}

    extractors:
      - type: regex
        name: auth_token
        part: body
        internal: true
        regex:
          - '"token":"([^"]+)"'
        group: 1

    matchers:
      - type: status
        status:
          - 200
        internal: true

  - raw:
      - |
        POST /api/exec HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{auth_token}}
        Content-Type: application/json

        {"cmd":"id"}

    matchers:
      - type: regex
        regex:
          - "uid=[0-9]+"
```

### SSRF via OOB
```yaml
id: ssrf-oob-detection
info:
  name: SSRF OOB Detection
  author: your-name
  severity: high
  tags: ssrf,oob

http:
  - raw:
      - |
        GET /fetch?url=https://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
```

### Subdomain Takeover (Multi-Protocol)
```yaml
id: github-takeover
info:
  name: GitHub Pages Subdomain Takeover
  author: your-name
  severity: high

dns:
  - name: "{{FQDN}}"
    type: cname

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: dsl
        dsl:
          - "contains(dns_cname, 'github.io')"
          - "contains(http_body, 'There isn\\'t a GitHub Pages site here')"
        condition: and
```
