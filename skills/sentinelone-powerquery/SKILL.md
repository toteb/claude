---
name: sentinelone-powerquery
description: SentinelOne PowerQuery specialist for security and data analysts. Use this skill whenever the user asks to write, fix, explain, translate, or optimize SentinelOne PowerQueries — including detection rules, threat hunting queries, Windows Event Log field extraction, log analytics, MITRE-aligned hunts, reporting, or any S1 Deep Visibility / Singularity Data Lake query. Proactively use when the user mentions S1, SentinelOne, EDR queries, XDR queries, event log parsing, or wants to translate Splunk SPL or KQL into PowerQuery.
---

# SentinelOne PowerQuery Specialist

You are an expert SentinelOne PowerQuery engineer. Your audience is security analysts and data analysts. Default output is a **ready-to-run, commented query block**. Add explanations when the query is complex or the user is learning. For full function reference, see `references/functions.md`.

---

## Query Structure

```
// Comment — use // anywhere
initial_filter_expression        // everything before first | is the filter; no 'filter' keyword needed
| command1 ...
| command2 ...
```

**Core rules:**
- `field = *` — exclude nulls; `!(field = *)` — match nulls only
- `&&` / `||` / `!` OR `AND` / `OR` / `NOT` — both work
- Ternary: `condition ? value_if_true : value_if_false`
- `field contains "term"` — case-insensitive substring; `field contains:matchcase "Term"` — case-sensitive
- `field matches "regex"` — regex match; **always double-escape**: `\\d+`, `\\\\` for `\`
- `* contains "term"` / `* matches "regex"` — search ALL fields (initial filter only)
- Put as many conditions as possible in the initial filter — it's the most efficient place

---

## Commands

### filter
Keep events matching a condition. Required only after the first `|`.
```
event.login.loginIsSuccessful = false
| group ct = count() by event.login.userName
| filter ct > 5
```

### columns
Select, rename, reorder, or compute output fields. Usually the last command.
```
| columns timestamp, endpoint.name, event.login.userName, event.login.loginIsSuccessful
| columns "Friendly Name" = field, isError = (status >= 500)
| columns "Size" = (bytes > 1000000) ? "Large" : "Small"
```
- After `columns`, **only the fields you defined exist** downstream
- `timestamp` auto-formats as datetime; any field ending in `.timestamp` does too

### let
Add computed fields to existing rows. Fields are available to subsequent commands.
```
| let rfc1918 = not net_rfc1918(dst.ip.address)
| let errorRate = (failed / (failed + success)) * 100
| let label = field = "A" ? "Type A" : field = "B" ? "Type B" : "Other"
```
- Cannot overwrite a field created by a preceding command; can overwrite original event fields

### parse
Extract new fields from unstructured text using a format string.
```
| parse "prefix $fieldName$ suffix" from sourceField
| parse "$fieldName{regex=\\d+}$" from sourceField
| parse "Agent-$agentID=identifier$" from endpoint.name
```
- Wrap extracted field in `$...$`
- `{regex=...}` for custom regex (double-escape: `\\d+`)
- `=identifier` extracts word chars; `=digits` extracts numbers
- `$$` escapes a literal `$` in format; `$$$` anchors to end-of-line
- Always `| filter field = *` before parse for performance
- Test with: `| limit 1 | columns test = "sample text" | parse "..." from test`

**⚠️ Critical gotcha — "undefined field" error:**
`parse` only creates a field if it matches **at least one row** in the result. If zero rows match (e.g. the parse pattern is wrong, or no events in the time window contain that text), the field is **never created**, and any downstream `columns` / `filter` referencing it will error with **"undefined field 'X'"**.

**Workaround — `let + replace` pattern (always creates the field):**
```
| let _d = winEventLog.description
| let _raw = replace(_d, "[\\s\\S]*Privileges:[\\t ]+([^\\r\\n]+)[\\s\\S]*", "$1")
| let privileges = _raw = _d ? null : _raw
```
- `let` is unconditional — the field is **always** created
- `replace` returns the input unchanged when the pattern doesn't match → we detect that with `_raw = _d ? null : _raw` and return null
- Use `[\\s\\S]*` instead of `.*` to span newlines (S1 may not honor `(?s)` DOTALL inline flags)
- Use a temp `_raw` field then a separate `let` for the public field — `let` cannot overwrite a field created by a previous `let`
- Use this pattern any time the source field may legitimately be missing OR when the row count is small enough that no rows might match in some windows

**⚠️ S1 regex engine constraints (`replace()` patterns):**
S1's regex implementation in `replace()` is conservative. The following patterns cause **"Unable to parse the entire query"** errors:
- **Non-greedy quantifiers** (`*?`, `+?`) — not supported in `replace()`. Use greedy `[\\s\\S]*` and rely on the natural last-occurrence behavior, or anchor more specifically.
- **Escaped parens** (`\\(text\\)`) — break the parser. Avoid literal parens in `replace()` regex patterns. If you need to match a label like `Package Name (NTLM only):`, parse a different unique substring, e.g. anchor on `Key Length:` (the next field) and capture backwards, or skip the field.
- **`(?s)`, `(?i)`, `(?m)` inline flags** — not honored. Use `[\\s\\S]*` instead of `(?s).*`.
- **Lookarounds** (`(?=...)`, `(?<=...)`) — not supported.

When duplicate field labels exist (e.g. 4624 has `Account Name:` in both Subject and New Logon sections), greedy `[\\s\\S]*Label:` naturally captures the **LAST** occurrence. To grab the FIRST occurrence instead, anchor to a unique preceding label and chain captures — do NOT use `*?`.

### group
Aggregate and summarize. Without `by` → single result. With `by` → one row per group.
```
| group count()
| group count() by event.login.userName
| group hits = count(), ips = array_agg_distinct(dst.ip.address) by endpoint.name
| group avg = mean(latency where success = true) by region
| group count() by timestamp = timebucket('1h'), endpoint.name
```

**Aggregate functions:**

| Function | Description |
|---|---|
| `count()` | Row count |
| `count(expr)` | Count where expr is true/non-null |
| `sum(x)` | Sum |
| `avg(x)` / `mean(x)` / `average(x)` | Average (interchangeable) |
| `min(x)` / `max(x)` | Min / max |
| `median(x)` | Median |
| `p90(x)`, `p95(x)`, `p99(x)`, `pct(N,x)` | Percentiles |
| `stddev(x)` | Standard deviation |
| `estimate_distinct(x)` | HyperLogLog distinct count (~1.3% error) |
| `array_agg(x)` | Array of all values (incl. duplicates) |
| `array_agg_distinct(x)` | Array of unique values |
| `hacklist(x)` | Alias for `array_agg(x)` |
| `any(x)` | Arbitrary value from the group |
| `any_true(x)` | True if any row satisfies x |
| `all_true(x)` | True if all rows satisfy x |
| `newest(x)` | Value from the row with newest timestamp |
| `oldest(x)` | Value from the row with oldest timestamp |
| `max_by(x, y)` | Value of x from the row where y is largest |
| `min_by(x, y)` | Value of x from the row where y is smallest |
| `first(x)` / `last(x)` | First/last value (requires prior `sort`) |

- `where` clause: `count(status >= 500 where region = 'US')`
- Default sort after `group` is ascending by `by` fields; add `| sort` to override

### sort
Order output. Default ascending. `-` prefix for descending.
```
| sort -count
| sort -timestamp, endpoint.name
| sort field1, -field2
```

### limit
Cap output row count. Default 10. Use `sort` before `limit` for top-N patterns.
```
| sort -count | limit 10
| limit 100
```

### top
Fast probabilistic top-K ranking for large datasets. Adds a `rank` column. Use when `group` hits memory limits.
```
| top 10 count() by endpoint.name
| top 5 sum(src.process.tgtFileModificationCount) by agent.uuid, agent.version
```
- Scoring functions: `count()`, `sum()`, `max()`, `min()`
- Results are **estimates** — use `group` when exact counts are required
- Combine `top` + `group` via `sql join` for fast scoping + exact values

### join
Merge multiple subquery results on matching keys.
```
| join
    logins = (event.login.loginIsSuccessful = * | group count() by endpoint.name),
    indicators = (indicator.category = * | group count() by endpoint.name)
  on endpoint.name
```

Join types (default is **inner**):

| Type | Behavior |
|---|---|
| `inner` | Left rows with first right match; unmatched left rows removed |
| `sql inner` | Left rows with ALL right matches (SQL-style) |
| `left` | All left rows; first right match or null |
| `sql left` | All left rows; all right matches or null |
| `outer` | All rows from both; first match or null |
| `sql outer` | All rows from both; all matches or null |

- Max 10 queries for `inner`/`left`; max 2 for `sql inner`/`sql left`
- If field names collide, query name is prepended (e.g., `logins.count`)
- Rename dotted fields with `columns` before nesting joins

### union
Stack results from multiple queries into one table. Schemas don't need to match.
```
| union
    (tgt.file.path contains 'temp' | columns event.time, event.type, tgt.file.path),
    (tgt.file.oldPath contains 'temp' | columns event.time, event.type, tgt.file.path)
```
- Missing fields become null; assign the same name to merge equivalent fields
- Use `| sort` after union to order results; max 10 queries
- Also used with `| limit 1 | columns ...` to generate test data

### compare
Run the same query over a shifted time range, side-by-side. **Must be last command.**
```
| compare last_week = timeshift('1w')
| compare timeshift('-1d')
| compare prev = timeshift(queryspan())     // previous period of same length
| compare next = timeshift('+1h')
```
- Timespans: `5w` `5d` `5h` `5m` `5s`
- Only one `timeshift` currently supported
- Use `sort` before `compare` to sequence output

### transpose
Pivot a column into multiple columns. **Must be last command.**
```
| transpose indicator.category on src.process.storyline.id
| transpose serverHost on timestamp limit 5 with_totals
```
- Each unique value in the transpose column becomes a new column
- `on` sets key columns (not transposed)
- `limit N` / `limit -N` — top/bottom N values only; `with_totals` adds a `total` column
- Max 100 new columns

### lookup
Enrich query results from a config file table (JSON or CSV, max 400KB).
```
| lookup osVersion from machineinfo by endpoint.name
| lookup category from threats.csv by src.process.name =:wildcard process
| lookup subnet_name from subnets.csv by dst.ip.address =:cidr ip
```
- Operators: `=` exact, `=:anycase` case-insensitive, `=:anyof` multi-column, `=:wildcard` (`%` multi-char, `_` single-char), `=:cidr` IP subnet
- Only first matching row joined; no match → null
- Tables live in Config Files under `/datatables/tableName`
- Use `| dataset 'config://datatables/tableName'` to import as a full table for joins

### savelookup
Save query results as a reusable lookup table.
```
| savelookup 'tableName'
| savelookup 'tableName.csv'
| savelookup 'tableName', 'merge'          // merge with existing
```
- Max 100,000 rows, 1.5MB per table; no arrays in results
- `merge` — joins if query uses `group`, otherwise unions
- `replace` — replaces specified columns in existing table

### nolimit
Remove default row/memory limits (up to 3GB). **Do not use in dashboards.**
```
| nolimit
```
- Can be placed anywhere; applies to the whole query
- Only one `nolimit` query runs at a time

---

## Key Functions

For the full reference, see `references/functions.md`.

### Network
```
net_rfc1918(ip)                         // true if RFC1918 private IP
net_private(ip)                         // true for any private IP (v4 or v6)
net_ipsubnet(ip, "10.0.0.0/8")          // CIDR check
net_url_domain("https://example.com")   // → "example.com"
net_url_path(url)                       // URL path component
geo_ip_country_iso(ip)                  // ISO country code e.g. "US"
geo_ip_city(ip)                         // city name
```

### String
```
lower(x) / upper(x)
trim(x) / ltrim(x) / rtrim(x)
substr(x, start, length)
len(x)
replace(x, "regex", "replacement")
format("template %s %d", field1, field2)
isempty(x)                              // null or empty string
string(x)                               // convert to string (no commas)
number(x)                               // convert to number
x.split(' ')                            // string to array
x.extract_matches('\\d+')              // regex matches as array
```

### Time
```
timebucket('1h')                        // truncate to 1-hour bucket
timebucket('1d')                        // daily buckets
timebucket('auto')                      // auto bucket size
querystart()                            // query window start (nanoseconds)
queryend()                              // query window end
queryspan('hours')                      // query duration in hours
simpledateformat(timestamp, "yyyy-MM-dd HH:mm:ss", "GMT+0")
strftime(timestamp, "%Y-%m-%d %H:%M:%S")
```

### Aggregate Across Rows (in `let` after `group`)
```
percent_of_total(count)                 // % share of grand total
running_sum(x)                          // cumulative sum
overall_sum(x)                          // sum across all rows
overall_count()                         // total row count
```

### JSON
```
json_object_value(obj, "field")         // parse JSON string, return named field
```

---

## Common EDR/XDR Fields

### Process
```
src.process.name                        // process name
src.process.cmdline                     // full command line
src.process.image.path                  // full exe path
src.process.pid                         // PID
src.process.storyline.id               // SentinelOne Storyline ID
src.process.parent.name                 // parent process name
src.process.user                        // user running the process
src.process.childProcCount
src.process.tgtFileModificationCount
event.type                              // "Process Creation", "File Modification", etc.
event.category                          // "process", "file", "network", "dns"
```

### Network
```
dst.ip.address / src.ip.address
dst.port.number / src.port.number
network.direction                       // "INCOMING" / "OUTGOING"
network.protocol
```

### File
```
tgt.file.path / tgt.file.name
tgt.file.size / tgt.file.sha256
tgt.file.oldPath                        // pre-rename path
```

### Login
```
event.login.userName
event.login.loginIsSuccessful           // boolean
event.login.type                        // "NETWORK", "INTERACTIVE", "REMOTE_INTERACTIVE", etc.
event.login.sessionId
src.endpoint.ip.address                 // login source IP
```

### Endpoint / Agent
```
endpoint.name                           // hostname
agent.uuid
os.name
site.name
agent.version
```

### Indicators / Threats
```
indicator.category                      // "Evasion", "InfoStealer", "Persistence", etc.
indicator.name
indicator.description
```

---

## Windows Event Log Parsing

Verify field names first: `dataSource.name = 'Windows Event Logs' | limit 1`

**Confirmed field names (winEventLog schema):**
- Event ID: `winEventLog.id` (integer — filter with `= 4769` not `= '4769'`)
- Full description text: `winEventLog.description` (parse this for unstructured fields)
- Channel: `winEventLog.channel`
- Level: `winEventLog.level`
- Provider: `winEventLog.providerName`
- Creation date: `winEventLog.creationDate`
- Raw XML: `winEventLog.xml`

**Pre-parsed sub-fields (use directly, no parse needed):**
- `winEventLog.description.userid` — account name
- `winEventLog.description.accountDomain` — account domain
- `winEventLog.description.securityId` — security/service SID
- `winEventLog.description.objectName` — object name
- `winEventLog.description.objectServer` — object server
- `winEventLog.description.operationType` — operation type
- `winEventLog.description.additionalInformation` — additional info

### Event 4769 — Kerberos Service Ticket Request
```
dataSource.name = 'Windows Event Logs' AND site.name contains 'YourSite'
| filter EventId = '4769'
| parse "Account Name: $krbAccountName$ Account Domain:" from EventDescription
| parse "Account Domain: $krbAccountDomain$ Logon GUID:" from EventDescription
| parse "Service Name: $krbServiceName$ Service ID:" from EventDescription
| parse "Client Address: $krbClientAddress$ Client Port:" from EventDescription
| parse "Client Port: $krbClientPort$ Advertized" from EventDescription
| parse "Failure Code: $krbFailureCode$ Transited" from EventDescription
| columns timestamp, EventId, krbAccountName, krbAccountDomain,
           krbServiceName, krbClientAddress, krbClientPort, krbFailureCode
```
Failure codes: `0x0`=OK, `0x12`=pre-auth required, `0x17`=password expired, `0x18`=bad password, `0x1B`=integrity failure

### Event 4624 — Successful Logon (let + replace pattern)
**Watch out:** 4624 has duplicate field names — `Security ID`, `Account Name`, `Account Domain`, `Logon ID` appear in BOTH the Subject section (the requesting service) AND the New Logon section (the account that actually logged on). Greedy `[\\s\\S]*` naturally picks the **last** occurrence (= New Logon, what you usually want). Anchor with `\\t` (literal tab) to dodge `Network Account Name` / `Network Account Domain` / `Linked Logon ID` substring matches.
```
dataSource.name = 'Windows Event Logs' AND winEventLog.id = 4624
| filter winEventLog.description = *
| let _d = winEventLog.description

// New Logon (the account that actually logged on)
| let _na = replace(_d, "[\\s\\S]*\\tAccount Name:[\\t ]+([^\\r\\n]+)[\\s\\S]*",  "$1")
| let newAccount = _na = _d ? null : _na
| let _nd = replace(_d, "[\\s\\S]*\\tAccount Domain:[\\t ]+([^\\r\\n]+)[\\s\\S]*", "$1")
| let newDomain  = _nd = _d ? null : _nd
| let _nl = replace(_d, "[\\s\\S]*\\tLogon ID:[\\t ]+([^\\r\\n]+)[\\s\\S]*",      "$1")
| let newLogonId = _nl = _d ? null : _nl

// Logon details
| let _lt = replace(_d, "[\\s\\S]*Logon Type:[\\t ]+([^\\r\\n]+)[\\s\\S]*",        "$1")
| let logonType = _lt = _d ? null : _lt
| let _sip = replace(_d, "[\\s\\S]*Source Network Address:[\\t ]+([^\\r\\n]+)[\\s\\S]*", "$1")
| let sourceIp = _sip = _d ? null : _sip
| let _spt = replace(_d, "[\\s\\S]*Source Port:[\\t ]+([^\\r\\n]+)[\\s\\S]*",      "$1")
| let sourcePort = _spt = _d ? null : _spt
| let _wn = replace(_d, "[\\s\\S]*Workstation Name:[\\t ]+([^\\r\\n]+)[\\s\\S]*",  "$1")
| let workstation = _wn = _d ? null : _wn
| let _lp = replace(_d, "[\\s\\S]*Logon Process:[\\t ]+([^\\r\\n]+)[\\s\\S]*",     "$1")
| let logonProcess = _lp = _d ? null : _lp
| let _ap = replace(_d, "[\\s\\S]*Authentication Package:[\\t ]+([^\\r\\n]+)[\\s\\S]*", "$1")
| let authPackage = _ap = _d ? null : _ap

// Logon type label
| let logonTypeLabel =
    logonType = '2'  ? 'Interactive (local)'
  : logonType = '3'  ? 'Network'
  : logonType = '4'  ? 'Batch'
  : logonType = '5'  ? 'Service'
  : logonType = '7'  ? 'Unlock'
  : logonType = '8'  ? 'NetworkCleartext'
  : logonType = '9'  ? 'NewCredentials (RunAs)'
  : logonType = '10' ? 'RemoteInteractive (RDP)'
  : logonType = '11' ? 'CachedInteractive'
  : logonType

| columns
    timestamp,
    "Host"          = endpoint.name,
    "Account"       = newAccount,
    "Domain"        = newDomain,
    "Logon ID"      = newLogonId,
    "Logon Type"    = logonTypeLabel,
    "Source IP"     = sourceIp,
    "Source Port"   = sourcePort,
    "Workstation"   = workstation,
    "Logon Process" = logonProcess,
    "Auth Package"  = authPackage
| sort -timestamp
```
**Logon Types**: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive (RDP), 11=CachedInteractive

### Event 4674 — Privileged Object Operation (let + replace pattern)
**Use this pattern any time you need fields from `winEventLog.description` that are not in the pre-parsed sub-fields list.** `parse` will error with "undefined field" if no row in the time window matches; `let + replace` always creates the field.
```
dataSource.name = 'Windows Event Logs' AND winEventLog.id = 4674
| filter winEventLog.description = *
| let _d = winEventLog.description
| let _li = replace(_d, "[\\s\\S]*Logon ID:[\\t ]+([^\\r\\n]+)[\\s\\S]*",       "$1")
| let logonId       = _li = _d ? null : _li
| let _pn = replace(_d, "[\\s\\S]*Process Name:[\\t ]+([^\\r\\n]+)[\\s\\S]*",   "$1")
| let processName   = _pn = _d ? null : _pn
| let _pv = replace(_d, "[\\s\\S]*Privileges:[\\t ]+([^\\r\\n]+)[\\s\\S]*",     "$1")
| let privileges    = _pv = _d ? null : _pv
| columns
    timestamp,
    "Host"        = endpoint.name,
    "Account"     = winEventLog.description.userid,
    "Domain"      = winEventLog.description.accountDomain,
    "Security ID" = winEventLog.description.securityId,
    "Logon ID"    = logonId,
    "Process"     = processName,
    "Object Name" = winEventLog.description.objectName,
    "Privileges"  = privileges
| sort -timestamp
```
- Description format: `\tLabel:\t[\t]Value\r\n` (tabs separate label/value, `\r\n` between lines)
- `[\\s\\S]*` spans newlines (S1 may not honor `(?s)` DOTALL)
- Pre-parsed sub-fields cover Account/Domain/SecurityId/ObjectName/ObjectServer — use them directly
- 4674 is **noisy**: always pair with a behavioral filter (privilege type, account pattern, object path)

### Event 4625 — Failed Logon
```
dataSource.name = 'Windows Event Logs'
| filter EventId = '4625'
| parse "Account Name: $accountName$ Account Domain:" from EventDescription
| parse "Failure Reason: $failureReason$ Status:" from EventDescription
| parse "Source Network Address: $sourceIP$ Source Port:" from EventDescription
| columns timestamp, accountName, failureReason, sourceIP
```

---

## Common Query Patterns

### Brute-Force / Password Spray
```
event.login.loginIsSuccessful = false
| group failCount = count(), targets = array_agg_distinct(endpoint.name)
  by event.login.userName, src.endpoint.ip.address
| filter failCount > 10
| sort -failCount
| columns event.login.userName, src.endpoint.ip.address, failCount, targets
```

### Outbound PowerShell to Public IPs
```
src.process.name contains "powershell" dst.ip.address = *
| let isPublic = not net_rfc1918(dst.ip.address)
| filter isPublic = true
| group hits = count(), ips = array_agg_distinct(dst.ip.address)
  by endpoint.name, src.process.cmdline, src.process.storyline.id
| sort -hits
```

### Lateral Movement — Network Logins
```
event.category = 'logins'
event.login.type in ("NETWORK", "NETWORK_CREDENTIALS")
event.login.loginIsSuccessful = true
| group count(), sources = array_agg_distinct(src.endpoint.ip.address)
  by endpoint.name, event.login.userName
| sort -count()
```

### Rare Process Execution (Low Prevalence)
```
event.type = "Process Creation" src.process.name = *
| group endpointCount = estimate_distinct(endpoint.name), execCount = count()
  by src.process.name
| filter endpointCount < 3
| sort endpointCount
```

### Time Series — Events per Hour
```
indicator.category = *
| group count = count() by timestamp = timebucket('1h'), indicator.category
| transpose indicator.category on timestamp
```

### Compare This Period vs Last Week
```
indicator.name = "SuspiciousProcess"
| group count = count() by endpoint.name
| sort -count
| compare last_week = timeshift('1w')
```

### Error Rate by App / Region (Log Analytics)
```
status = * serverHost = *
| parse "$app{regex=\\w+}$-$region{regex=\\d+}$" from serverHost
| group success = count(status >= 200 && status <= 299),
         errors  = count(status >= 400 && status <= 599)
  by app, region
| let errorRate = (errors / (success + errors)) * 100
| sort -errorRate
| columns app, region, success, errors, "Error Rate %" = errorRate
```

### Enrich with Lookup Table
```
indicator.category = *
| group count = count() by endpoint.name, indicator.category
| lookup osVersion from machineinfo by endpoint.name
| sort -count
| columns endpoint.name, osVersion, indicator.category, count
```

### Save Results for Later Queries
```
indicator.name = 'EventViewerTampering'
| group count = count() by agent.uuid
| savelookup 'EventViewerTampering_baseline', 'merge'
```

---

## Tips & Gotchas

- **Regex double-escaping**: `\\d+` not `\d+`; `\\\\` for a literal `\`
- **`$` in field values**: Use a trailing literal anchor (e.g., `" Account Domain:"`) — don't rely on `$` delimiter when values may contain `$`
- **`columns` resets schema**: Only the fields defined in `columns` survive downstream
- **`let` vs `columns`**: `let` adds fields to each row; `columns` replaces all output fields
- **`group` default sort**: Ascending by `by` fields; add `| sort` to override
- **`compare` must be last**: No commands after it
- **`transpose` must be last**: No commands after it
- **`nolimit` in dashboards**: Avoid — causes slow loads and errors
- **`newest()` / `oldest()`**: Cannot be used after `group`, `sort`, or `limit`
- **`first()` / `last()`**: Require a `sort` before the `group` command
- **Null handling**: `field = *` excludes nulls; `!(field = *)` matches nulls; `| filter field == null` works after `let` defines the field
- **SQL vs PowerQuery `join`**: Default `join` returns only the first right-table match per row. Use `sql inner join` for full SQL-style cartesian matching
- **`hacklist()`**: Alias for `array_agg()` — both work identically
- **Performance**: Filter aggressively in the initial expression; avoid broad `* contains` on large datasets
