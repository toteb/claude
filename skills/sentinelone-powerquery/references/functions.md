# PowerQuery Function Reference

Full function reference for SentinelOne PowerQuery. Referenced from SKILL.md.

---

## Numeric Functions

| Function | Description |
|---|---|
| `abs(x)` | Absolute value |
| `ceiling(x)` | Round up to integer |
| `floor(x)` | Round down to integer |
| `min(x, y)` | Smaller of x and y |
| `max(x, y)` | Larger of x and y |
| `sqrt(x)` | Square root |
| `exp(x)` | e^x |
| `ln(x)` | Natural log (base-e) |
| `log(x)` | Base-10 log |
| `log(x, y)` | Log of x in base y |
| `pow(x, y)` | x to the power of y |

---

## String Functions

Method chaining supported with `.` — remove the first argument. Example: `len(x)` → `x.len()`

| Function | Description |
|---|---|
| `len(x)` | Character count |
| `lower(x)` | Lowercase |
| `upper(x)` | Uppercase |
| `ltrim(x)` | Remove leading whitespace |
| `ltrim(x, y)` | Remove leading chars found in y |
| `rtrim(x)` | Remove trailing whitespace |
| `rtrim(x, y)` | Remove trailing chars found in y |
| `trim(x)` | Remove leading and trailing whitespace |
| `trim(x, y)` | Remove leading and trailing chars found in y |
| `substr(x, y)` | Copy of x with first y chars removed |
| `substr(x, y, z)` | z characters of x starting at position y |
| `format(fmt, ...)` | Generate formatted string |
| `isempty(x)` | True if null or empty string |
| `isblank(x)` | True if null, empty, or whitespace only |
| `bool(x)` | Convert to boolean (0/null/missing → false) |
| `string(x)` | Convert to string (no number formatting) |
| `number(x)` | Convert string to number (non-numeric → NaN) |
| `pad_version(x)` | Pad dotted version: `'3.19.5'` → `'00003.00019.00005'` |
| `replace(x, y, z)` | Replace regex y with string z in x (case-insensitive; double-escape regex) |

**Examples:**
```
| let mice_length = len(substr("three blind mice", 12))  // 4
| let mice_length = "three blind mice".substr(12).len()  // same, chained
| let clean = replace(src.process.cmdline, "\\s+", " ")  // collapse whitespace
```

---

## JSON Functions

| Function | Description |
|---|---|
| `json_object_value(obj, "field")` | Parse JSON string and return named field value |

**Example:**
```
| let users = json_object_value(payload, "users")      // returns array
| let first = array_get(users, 0)                       // first element (string)
| let name = json_object_value(first, "firstName")      // primitive
```

---

## Network Functions

| Function | Description |
|---|---|
| `net_ip(x)` | True if valid IP address |
| `net_ipv4(x)` | True if valid IPv4 |
| `net_ipv6(x)` | True if valid IPv6 |
| `net_ipsubnet(x, y)` | True if x is within subnet y (e.g., `"1.0.0.0/8"`) |
| `net_private(x)` | True if private IPv4 or IPv6 |
| `net_rfc1918(x)` | True if RFC1918 private IPv4 |
| `net_rfc4193(x)` | True if RFC4193 private IPv6 |

**RFC1918 ranges matched by `net_rfc1918`:**
`10.*`, `172.16-31.*`, `192.168.*`, `127.*`

---

## URL Functions

All require string input. Use `net_url_parts()` to parse all components at once.

| Function | Description |
|---|---|
| `net_url_scheme(url)` | Protocol (e.g., `"https"`) |
| `net_url_netloc(url)` | User and host |
| `net_url_subdomain(url)` | Subdomain portion |
| `net_url_domain(url)` | Registered domain (e.g., `"sentinelone.com"`) |
| `net_url_tld(url)` | Top-level domain (e.g., `"com"`) |
| `net_url_port(url)` | Explicit port number |
| `net_url_path(url)` | Path component |
| `net_url_query(url)` | Query string |
| `net_url_fragment(url)` | Fragment (`#...`) |
| `net_url_userinfo(url)` | User info portion |
| `net_url_parts(url)` | Array of all components in order above |

`net_url_parts()` returns: `[scheme, netloc, subdomain, domain, tld, port, path, query, fragment, userinfo]`

---

## Aggregate Across Rows Functions

Use in `let` after a `group` command to compute across all rows of the result.

| Function | Description |
|---|---|
| `running_sum(x)` | Cumulative sum up to current row |
| `running_count()` | Row number (1, 2, 3, ...) |
| `overall_sum(x)` | Sum across all rows |
| `overall_count()` | Total row count |
| `overall_min(x)` | Min value across all rows |
| `overall_max(x)` | Max value across all rows |
| `overall_avg(x)` / `overall_mean(x)` | Average across all rows |
| `percent_of_total(x)` | x as % of overall_sum(x) |
| `running_percent(x)` | Running total of percent_of_total |

**Example — add % column to a count table:**
```
event.type = "Process Creation" src.process.name = *
| group execCount = count() by src.process.name
| sort -execCount
| let pct = percent_of_total(execCount)
| columns src.process.name, execCount, "% of Total" = pct
```

---

## Array Functions

> Beta — not supported in PowerQuery Alerts. First element index = 0.

### Create Arrays

| Function | Description |
|---|---|
| `array(x, y, z, ...)` | Create array from values (up to 50) |
| `array_from_json(str)` | Parse JSON array string to array |

From `group`: `array_agg(x)`, `array_agg_distinct(x)` — see group command in SKILL.md.

### Operate on Arrays (method chaining with `.`)

| Method | Description |
|---|---|
| `.concat(arr)` | Append arr to end of array |
| `.distinct()` | Return unique values |
| `.expand()` | One row per element (other fields copied) |
| `.filter(func(x) -> expr)` | Remove elements where expr is false |
| `.intersect(arr)` | Keep elements present in arr |
| `.map(func(x) -> expr)` | Transform each element |
| `.set(index, value)` | Replace element at index |
| `.slice(from)` / `.slice(from, to)` | Subarray (negative = from end) |
| `.sort()` / `.sort_desc()` | Sort array ascending/descending |
| `.zip(arr, func(x,y) -> expr)` | Combine two arrays element-wise |
| `.concat(arr)` | Append another array |

### Array to Primitive

| Method | Description |
|---|---|
| `.contains(value)` | True if any element equals value |
| `.get(index)` | Element at index (null if out of bounds) |
| `.len()` | Number of elements |
| `.match_any(func(x) -> expr)` | True if expr is true for any element |
| `.match_all(func(x) -> expr)` | True if expr is true for all elements |
| `.max()` / `.min()` / `.mean()` / `.median()` / `.sum()` | Aggregates |
| `.reduce(init, func(acc,x) -> expr)` | Fold to single value |
| `.to_string()` / `.to_string(delimiter)` | Join to string |
| `array_to_json(arr)` | Convert to JSON string |

### String → Array

| Method | Description |
|---|---|
| `x.split(pattern)` | Split string on delimiter |
| `x.split(pattern, max_count)` | Split with max elements |
| `x.extract_matches(regex)` | Regex matches as array |
| `x.extract_matches(regex, max_count)` | With limit |

**Examples:**
```
| let ips = dst.ip.address.extract_matches('\\d+\\.\\d+\\.\\d+\\.\\d+')
| let parts = tgt.file.path.split('\\\\')
| let last_part = parts.get(parts.len() - 1)
| let big_files = file_sizes.filter(func(x) -> x > 1000000)
| let doubled = counts.map(func(x) -> x * 2)
```

---

## Geolocation Functions

| Function | Description |
|---|---|
| `geo_ip_city(ip[, locale])` | City name |
| `geo_ip_state(ip[, locale])` | State / province |
| `geo_ip_state_iso(ip)` | ISO 3166-2 state code |
| `geo_ip_country(ip[, locale])` | Country name |
| `geo_ip_country_iso(ip)` | ISO 3166-1 country code (e.g., `"US"`) |
| `geo_ip_continent(ip[, locale])` | Continent name |
| `geo_ip_continent_code(ip)` | `"AF"`, `"AS"`, `"EU"`, `"NA"`, `"SA"`, `"OC"`, `"AN"` |
| `geo_ip_location(ip)` | Lat/lon string (e.g., `"39.04,-77.49"`) |
| `geo_is_point(lat_lon)` | True if valid coordinate |
| `geo_distance(ll1, ll2[, "mile"\|"kilometer"])` | Distance between two points |
| `geo_point_within_polygon(lat_lon, wkt)` | True if point is inside WKT polygon |

Locale options: `"de"`, `"en"`, `"es"`, `"fr"`, `"ja"`, `"pt-BR"`, `"ru"`, `"zh-CN"`

---

## Timestamp Functions

`timestamp` is stored as nanoseconds since Unix epoch. Any field named `timestamp` or ending in `.timestamp` auto-formats as datetime.

| Function | Description |
|---|---|
| `simpledateformat(ts)` | Nanoseconds → GMT ISO8601 string |
| `simpledateformat(ts, pattern)` | With Java SimpleDateFormat pattern |
| `simpledateformat(ts, pattern, tz)` | With timezone (e.g., `"GMT+8"`) |
| `simpledateparse(str, pattern)` | String datetime → nanoseconds |
| `strftime(ts)` | Nanoseconds → GMT ISO8601 string |
| `strftime(ts, pattern)` | With strftime pattern |
| `strftime(ts, pattern, tz)` | With timezone |
| `strptime(str, pattern)` | String datetime → nanoseconds |

**Common patterns:**
```
simpledateformat(timestamp, "yyyy-MM-dd HH:mm:ss", "GMT+0")
strftime(timestamp, "%Y-%m-%d %H:%M:%S")
| let day = strftime(timestamp, "%Y-%m-%d")
```

### Java SimpleDateFormat Quick Reference
`yyyy` year, `MM` month, `dd` day, `HH` hour (0-23), `mm` minute, `ss` second, `SSS` ms, `z` timezone

### Strftime Quick Reference
`%Y` year, `%m` month, `%d` day, `%H` hour, `%M` minute, `%S` second, `%Z` timezone

---

## Time Functions

| Function | Description |
|---|---|
| `timebucket(ts, unit)` | Truncate timestamp to bucket start |
| `timebucket(unit)` | Equivalent to `timebucket(timestamp, unit)` |
| `timebucket()` | Auto bucket size |
| `querystart()` | Query window start (nanoseconds) |
| `querystart(unit)` | In specified unit |
| `queryend()` | Query window end (nanoseconds) |
| `queryend(unit)` | In specified unit |
| `queryspan()` | Query duration (nanoseconds) |
| `queryspan(unit)` | In specified unit |

Units: `"days"`, `"hours"`, `"minutes"`, `"seconds"`, or abbreviations: `"5m"`, `"1h"`, `"1d"`, `"1w"`. Use a number 1–500 to divide the window into that many buckets. `"auto"` picks a sensible size.

**Examples:**
```
// Time series grouped by hour
event.type = "Process Creation"
| group count = count() by timestamp = timebucket('1h'), endpoint.name

// Events per minute rate
indicator.category = *
| group eventsPerMinute = count() / queryspan("minutes") by endpoint.name
| sort -eventsPerMinute

// Annotate with query window start
indicator.category = *
| let analysis_start = querystart()
| group count = count() by indicator.category
```
