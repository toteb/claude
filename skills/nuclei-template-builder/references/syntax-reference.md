# Nuclei Template Syntax Reference

This is a comprehensive reference for all Nuclei template syntax elements. Consult this when you need precise details on a specific feature.

## Table of Contents
1. [Complete Helper Functions](#complete-helper-functions)
2. [HTTP Protocol Advanced](#http-protocol-advanced)
3. [DNS Protocol Details](#dns-protocol-details)
4. [Network (TCP) Protocol Details](#network-tcp-protocol-details)
5. [File Protocol Details](#file-protocol-details)
6. [Headless Protocol Actions](#headless-protocol-actions)
7. [Code Protocol Details](#code-protocol-details)
8. [Matcher Reference](#matcher-reference)
9. [Extractor Reference](#extractor-reference)
10. [Fuzzing Reference](#fuzzing-reference)
11. [Flow JS Bindings](#flow-js-bindings)
12. [Deserialization Gadgets](#deserialization-gadgets)

---

## Complete Helper Functions

### Encoding / Decoding

| Function | Description | Example | Output |
|----------|-------------|---------|--------|
| `base64(src)` | Base64 encode | `base64("Hello")` | `SGVsbG8=` |
| `base64_decode(src)` | Base64 decode | `base64_decode("SGVsbG8=")` | `Hello` |
| `base64_py(src)` | Base64 encode with newlines (Python style) | `base64_py("Hello")` | `SGVsbG8=\n` |
| `hex_encode(input)` | Hex encode | `hex_encode("aa")` | `6161` |
| `hex_decode(input)` | Hex decode | `hex_decode("6161")` | `aa` |
| `url_encode(input)` | URL encode | `url_encode("a=1&b=2")` | `a%3D1%26b%3D2` |
| `url_decode(input)` | URL decode | `url_decode("a%3D1")` | `a=1` |
| `html_escape(input)` | HTML escape | `html_escape("<b>")` | `&lt;b&gt;` |
| `html_unescape(input)` | HTML unescape | `html_unescape("&lt;")` | `<` |

### Hashing

| Function | Description | Example |
|----------|-------------|---------|
| `md5(input)` | MD5 hash | `md5("Hello")` |
| `sha1(input)` | SHA-1 hash | `sha1("Hello")` |
| `sha256(input)` | SHA-256 hash | `sha256("Hello")` |
| `mmh3(input)` | MurmurHash3 | `mmh3("Hello")` |
| `hmac(algo, data, secret)` | HMAC with algorithm | `hmac("sha1", "test", "secret")` |

### String Manipulation

| Function | Description | Example | Output |
|----------|-------------|---------|--------|
| `contains(input, sub)` | Check substring | `contains("Hello", "lo")` | `true` |
| `contains_all(input, ...subs)` | All substrings present | `contains_all("Hello world", "lo", "wor")` | `true` |
| `contains_any(input, ...subs)` | Any substring present | `contains_any("Hello", "abc", "llo")` | `true` |
| `starts_with(str, ...prefix)` | Starts with any prefix | `starts_with("Hello", "He")` | `true` |
| `ends_with(str, ...suffix)` | Ends with any suffix | `ends_with("Hello", "lo")` | `true` |
| `line_starts_with(str, ...prefix)` | Any line starts with prefix | `line_starts_with("Hi\nHello", "He")` | `true` |
| `line_ends_with(str, ...suffix)` | Any line ends with suffix | `line_ends_with("Hello\nHi", "lo")` | `true` |
| `to_lower(input)` | Lowercase | `to_lower("HELLO")` | `hello` |
| `to_upper(input)` | Uppercase | `to_upper("hello")` | `HELLO` |
| `trim(input, cutset)` | Trim characters from both ends | `trim("xxHelloxx", "x")` | `Hello` |
| `trim_left(input, cutset)` | Trim from left | `trim_left("xxHello", "x")` | `Hello` |
| `trim_right(input, cutset)` | Trim from right | `trim_right("Helloxx", "x")` | `Hello` |
| `trim_prefix(input, prefix)` | Remove prefix string | `trim_prefix("aaHello", "aa")` | `Hello` |
| `trim_suffix(input, suffix)` | Remove suffix string | `trim_suffix("Helloaa", "aa")` | `Hello` |
| `trim_space(input)` | Remove whitespace | `trim_space(" Hello ")` | `Hello` |
| `replace(str, old, new)` | Replace substring | `replace("Hello", "He", "Ha")` | `Hallo` |
| `replace_regex(src, regex, repl)` | Regex replace | `replace_regex("He123llo", "(\\d+)", "")` | `Hello` |
| `reverse(input)` | Reverse string | `reverse("abc")` | `cba` |
| `repeat(str, count)` | Repeat string | `repeat("../", 5)` | `../../../../../` |
| `concat(...args)` | Concatenate | `concat("a", 1, "b")` | `a1b` |
| `join(sep, ...elements)` | Join with separator | `join("_", "a", "b")` | `a_b` |
| `len(input)` | Length | `len("Hello")` | `5` |
| `remove_bad_chars(input, cutset)` | Remove characters | `remove_bad_chars("abcd", "bc")` | `ad` |
| `regex(pattern, input)` | Test regex match | `regex("H([a-z]+)o", "Hello")` | `true` |
| `regex_any(pattern, ...inputs)` | Any input matches regex | `regex_any("H.*o", "World", "Hello")` | `true` |
| `regex_all(pattern, ...inputs)` | All inputs match regex | `regex_all("H.*o", "Hallo", "Hello")` | `true` |
| `equals_any(s, ...subs)` | Equals any value | `equals_any(status_code, 200, 201)` | `true` |

### Random Generation

| Function | Description | Example |
|----------|-------------|---------|
| `rand_int(min, max)` | Random integer | `rand_int(1, 100)` |
| `rand_base(len, charset)` | Random from charset | `rand_base(5, "abc")` |
| `rand_char(charset)` | Random character | `rand_char("abc")` |
| `rand_text_alpha(len, badchars)` | Random letters | `rand_text_alpha(10)` |
| `rand_text_alphanumeric(len, bad)` | Random alphanumeric | `rand_text_alphanumeric(10)` |
| `rand_text_numeric(len, bad)` | Random numbers | `rand_text_numeric(10)` |
| `rand_ip(cidr)` | Random IP in CIDR | `rand_ip("192.168.0.0/24")` |

### Time

| Function | Description | Example |
|----------|-------------|---------|
| `unix_time(optSecs)` | Unix timestamp (+optional seconds) | `unix_time()` |
| `date_time(format, optUnix)` | Formatted date | `date_time("%Y-%M-%D")` |
| `to_unix_time(str, layout)` | Parse date to unix | `to_unix_time("2022-01-13T16:30:10+00:00")` |
| `wait_for(seconds)` | Pause execution | `wait_for(5)` |

### Number Format

| Function | Description |
|----------|-------------|
| `bin_to_dec(binary)` | Binary to decimal |
| `dec_to_hex(number)` | Decimal to hex |
| `hex_to_dec(hex)` | Hex to decimal |
| `oct_to_dec(octal)` | Octal to decimal |

### Compression

| Function | Description |
|----------|-------------|
| `gzip(input)` | Gzip compress |
| `gzip_decode(input)` | Gzip decompress |
| `zlib(input)` | Zlib compress |
| `zlib_decode(input)` | Zlib decompress |

### Crypto

| Function | Description |
|----------|-------------|
| `aes_gcm(key, plaintext)` | AES-GCM encrypt |
| `generate_jwt(json, algo, sig, maxAge)` | Generate JWT |
| `generate_java_gadget(gadget, cmd, encoding)` | Java deserialization |
| `generate_dotnet_gadget(gadget, cmd, formatter, encoding)` | .NET deserialization |

### DNS / Network

| Function | Description |
|----------|-------------|
| `resolve(host, format)` | DNS resolution. Formats: `4`/`a`, `6`/`aaaa`, `cname`, `ns`, `txt`, `srv`, `ptr`, `mx`, `soa`, `caa` |
| `ip_format(ip, index)` | IP format conversion (index 1-11) |

### JSON

| Function | Description |
|----------|-------------|
| `json_minify(json)` | Remove whitespace from JSON |
| `json_prettify(json)` | Pretty-print JSON |

### Debug

| Function | Description |
|----------|-------------|
| `print_debug(...args)` | Print values for debugging |

---

## HTTP Protocol Advanced

### Response Parts for Matchers/Extractors

| Part | Description |
|------|-------------|
| `body` | Response body (default) |
| `header` | Response headers |
| `all` / `raw` | Full response (headers + body) |
| `status_code` | Status code integer |
| `content_length` | Content-Length header value |
| `header_name` | Specific header (replace `-` with `_`, lowercase) |

### Multi-request Response Access

In request conditions and DSL, access previous responses:
- `status_code` — current request
- `status_code_1`, `status_code_2` — 1st, 2nd request responses
- `body_1`, `body_2`, `header_1`, etc.

### Stop at First Match
```yaml
stop-at-first-match: true
```
Stops after finding first matching response (useful with payloads).

### Self-contained
```yaml
self-contained: true
```
Template doesn't require target input (e.g., for API checks).

---

## DNS Protocol Details

### Request Fields
- `name`: DNS name to resolve (`{{FQDN}}` variable)
- `type`: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA
- `class`: INET (default), CSNET, CHAOS, HESIOD, NONE, ANY
- `recursion`: boolean (default true)
- `retries`: integer (recommended: 3)

### Response Parts
| Part | Description |
|------|-------------|
| `request` | DNS Request |
| `rcode` | DNS Response Code |
| `question` | DNS Question Message |
| `extra` | DNS Extra Field |
| `answer` | DNS Answer Field |
| `ns` | DNS Authority Field |
| `raw` / `body` / `all` | Full DNS Message |

---

## Network (TCP) Protocol Details

### Input Types
```yaml
inputs:
  - data: "string data\r\n"           # plain string
  - data: "deadbeef"                   # hex with type
    type: hex
  - data: '{{hex_decode("50494e47")}}'  # helper function
  - read-size: 2048                     # read N bytes
    name: banner                        # named for matching
```

### Host and Port
```yaml
host:
  - "{{Hostname}}"           # plain TCP
  - "tls://{{Hostname}}"     # TLS connection
port: 22                      # default port (comma-separated for multiple)
exclude-ports: 80,443         # skip these ports
```

### Response Parts
| Part | Description |
|------|-------------|
| `request` | Network Request |
| `data` | Final data read from socket |
| `raw` / `body` / `all` | All data from socket |

---

## File Protocol Details

### Configuration
```yaml
file:
  - extensions:
      - all                   # all extensions
    denylist:
      - jpg
      - png
    max-size: 5242880         # max file size in bytes (default 5MB)
    no-recursive: false       # disable recursive directory walking
```

### Default Excluded Extensions
3g2, 3gp, 7z, apk, arj, avi, bmp, css, csv, deb, dll, doc, exe, gif, gz, ico, iso, jar, jpeg, jpg, lock, mp3, mp4, pdf, pkg, png, ppt, rar, svg, tar, tar.gz, tiff, ttf, txt, wav, woff, woff2, xls, xlsx, zip (and more)

---

## Headless Protocol Actions

### Full Action List

| Action | Description | Key Args |
|--------|-------------|----------|
| `navigate` | Go to URL | `url` |
| `script` | Run JS (MUST be function ref) | `code`, `hook` (bool) |
| `click` | Left-click element | `by`, selector value |
| `rightclick` | Right-click element | `by`, selector value |
| `text` | Type into input | `by`, selector, `value` |
| `screenshot` | Capture page | `to`, `fullpage` (bool) |
| `time` | Enter time value (RFC3339) | `by`, selector, `value` |
| `select` | Select option | `by`, selector, `value`, `selected` |
| `files` | Upload file | `by`, selector, `value` (path) |
| `waitfcp` | Wait for First Contentful Paint | — |
| `waitfmp` | Wait for First Meaningful Paint | — |
| `waitdom` | Wait for DOMContentLoaded | — |
| `waitload` | Wait for full page load | — |
| `waitidle` | Wait for network idle | — |
| `waitstable` | Wait for page stability | `duration` (default 1s) |
| `waitdialog` | Wait for JS dialog & auto-accept | `name` (required), `max-duration` |
| `getresource` | Get `src` attribute | `by`, selector, `name` |
| `extract` | Extract text/attribute | `by`, selector, `name`, `target`, `attribute` |
| `setmethod` | Override request method | `part`, `method` |
| `addheader` | Add header | `part`, `key`, `value` |
| `setheader` | Set/replace header | `part`, `key`, `value` |
| `deleteheader` | Remove header | `part`, `key` |
| `setbody` | Set request/response body | `part`, `body` |
| `waitevent` | Wait for CDP event | `event` |
| `keyboard` | Simulate keypress | `keys` (key codes) |
| `debug` | 5s delay + trace (dev only) | — |
| `sleep` | Wait N seconds | `duration` |

### Selector Types
| Selector | Usage |
|----------|-------|
| `selector` | CSS selector (default) |
| `xpath` / `x` | XPath |
| `regex` / `r` | CSS + text regex |
| `js` | JS function returning elements |
| `search` | Search query |

---

## Code Protocol Details

### Supported Interpreters
- **Python**: `py`, `python`, `python3`
- **PowerShell**: `pwsh`, `powershell`, `powershell.exe`
- **Shell**: `sh`, `bash`
- **Go**: `go`
- Any system interpreter

### Fields
```yaml
code:
  - engine: [py, python3]
    source: |                   # inline code
      print("hello")
    # OR
    source: path/to/script.py   # external file
    args:                        # optional engine args
      - -ExecutionPolicy
      - Bypass
    pattern: "*.ps1"             # temp file extension
```

Target is passed via stdin. Output matched on `response` (stdout) and `stderr` parts.

---

## Fuzzing Reference

### Parts
`query` (default), `path`, `header`, `cookie`, `body`, `request` (all parts)

### Types
`replace` (default), `prefix`, `postfix`, `infix`, `replace-regex`

### Modes
`multiple` (default, all params at once), `single` (one at a time)

### Filters
```yaml
fuzzing:
  - part: query
    keys: ["cmd", "exec"]              # exact parameter names
    keys-regex: ["redirect.*"]          # regex on parameter names
    values: ["https?://.*"]             # regex on parameter values
```

### Time Delay Analyzer
Dynamic placeholders: `[SLEEPTIME]`, `[INFERENCE]`

```yaml
analyzer:
  name: time_delay
  parameters:
    sleep_duration: 5          # default 5
    requests_limit: 4          # default 4
    time_correlation_error_range: 0.15
    time_slope_error_range: 0.30
```

---

## Flow JS Bindings

| Binding | Description |
|---------|-------------|
| `http()`, `dns()`, `ssl()`, `tcp()`, `code()` | Execute protocol |
| `http(1)`, `http("id")` | Execute specific request by index or ID |
| `iterate(value)` | Safely iterate any type |
| `set("name", value)` | Set template variable |
| `template["key"]` | Read template context |
| `log(data)` | Debug print |
| `new Dedupe()` | Dedup helper: `.Add(val)`, `.Values()` |

---

## Deserialization Gadgets

### Java (ysoserial)
Gadgets: `dns` (URLDNS), `commons-collections3.1`, `commons-collections4.0`, `jdk7u21`, `jdk8u20`, `groovy1`
Encodings: `base64` (default), `gzip-base64`, `gzip`, `hex`, `raw`

```yaml
{{generate_java_gadget("dns", "{{interactsh-url}}", "base64")}}
```

### .NET
**Command gadgets**: `windows-identity`, `claims-principal`, `dataset`, `dataset-type-spoof`, `object-data-provider`, `text-formatting-runproperties`, `type-confuse-delegate`
**URL gadgets**: `object-ref`, `veeam-crypto-keyinfo`
**XML gadgets**: `dataset-xmldiffgram`
**DLL gadgets**: `axhost-state-dll`, `dll-reflection`
**ViewState**: `viewstate` (format: `payloadData:machineKey:generator`)

Formatters: `binary`/`binaryformatter`, `soap`/`soapformatter`, `los`/`losformatter`
Encodings: `raw`, `hex`, `gzip`, `gzip-base64`, `base64-raw`, `` (URL-safe base64 default)

```yaml
{{generate_dotnet_gadget("type-confuse-delegate", "calc", "binary", "base64-raw")}}
```

---

## JWT Generation

Supported algorithms: HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, NONE

```yaml
variables:
  json: '{"sub":"admin","role":"admin"}'
  jwt: '{{generate_jwt(json, "HS256", "secret-key")}}'
```

Format: `generate_jwt(json, algorithm, signature, maxAgeUnix)` — all args after json are optional.
