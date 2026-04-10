# ScopeProof

**Proof-of-testing coverage tracker for Burp Suite.**

ScopeProof gives pentesters a real-time view of which endpoints have been tested, how deeply, and what gaps remain. It captures traffic from every Burp tool automatically and aggregates it into a single coverage dashboard — no manual bookkeeping required.

## Features

- **Real-time traffic capture** — Automatically tracks requests from Proxy, Repeater, Intruder, Scanner, and all other Burp tools.
- **Endpoint aggregation** — Groups requests by normalized endpoint (e.g. `/users/123` and `/users/456` become `/users/{id}`), with smart grouping for Intruder/Scanner payloads.
- **Testing depth classification** — Automatically classifies each endpoint as Thoroughly Tested, Fuzz Tested, Manually Tested, Observed, or Untested based on which tools have interacted with it.
- **Priority scoring** — Ranks untested or under-tested endpoints by risk (write methods, parameters, auth state, status codes).
- **Attack payload detection** — Detects known payload categories (XSS, SQLi, Path Traversal, CMDi, SSTI, SSRF, XXE) in request content. Fully customizable — add your own payloads and categories.
- **Intruder payload generator** — Registered payload generators let you fire your custom payloads directly from Intruder.
- **Scope filtering** — Filter by host (supports wildcards like `*.example.com`), import from Burp's target scope, or load from file.
- **Persistent storage** — All captured data, notes, and tags survive Burp restarts. Auto-saves every 30 seconds.
- **Export** — JSON and CSV export for reports. CSV output is sanitized against formula injection.
- **Context menu integration** — Right-click to mark requests as tested, flag decoder usage, or tag selected text as a payload.
- **ScopeProof Pro upload** — Optionally upload coverage reports to [ScopeProof Pro](https://scopeproof.io) for team dashboards and historical tracking.

## Installation

### From BApp Store

1. Open Burp Suite.
2. Go to **Extensions > BApp Store**.
3. Search for **ScopeProof**.
4. Click **Install**.

### Manual Install

1. Clone and build:
   ```bash
   git clone https://github.com/MockedLabs/ScopeProof.git
   cd ScopeProof
   ./gradlew jar
   ```
2. In Burp Suite, go to **Extensions > Installed > Add**.
3. Set Extension type to **Java**.
4. Select `build/libs/ScopeProof-1.0.0.jar`.

## Requirements

- Burp Suite Professional or Community Edition
- Java 17 or later (bundled with modern Burp releases)

## Usage

Once installed, a **ScopeProof** tab appears in Burp Suite.

### Getting Started

1. **Browse your target** through Burp Proxy as usual. ScopeProof captures traffic automatically.
2. Click **Refresh** to also import existing proxy history and site map entries.
3. Use **Settings > Filters** to set your scope hosts and exclude static resources or noise domains.

### Coverage Table

The main table shows one row per unique endpoint with:

| Column | Description |
|---|---|
| Host | Target hostname |
| Endpoint | Normalized path (dynamic segments replaced with `{id}`, `{uuid}`, etc.) |
| Methods | HTTP methods observed (GET, POST, etc.) |
| Reqs | Total request count |
| Priority | Risk-based priority: Critical, High, Medium, Low |
| Depth | Testing depth: Thoroughly Tested through Untested |
| Tested By | Which tools hit this endpoint and how many times |
| Status Codes | Response status code distribution |
| Tests | Detected payload categories |
| Tag | User-assigned tag |
| Notes | Free-text notes (editable inline) |

### Depth Classification

| Depth | Criteria |
|---|---|
| Thoroughly Tested | Fuzz tested + manually tested + 10 or more requests |
| Fuzz Tested | Hit by Intruder or Scanner |
| Manually Tested | Hit by Repeater, Extensions, or edited in Proxy |
| Observed | 3 or more passive requests |
| Untested | Fewer than 3 passive requests, no active testing |

### Custom Payloads

Open **Settings > Payloads** to manage payload signatures per category. You can:

- Add individual payloads or paste/load lists.
- Use the built-in Intruder payload generator (**ScopeProof - All Payloads** or per-category).
- Right-click selected text in the request editor and choose **Tag Payload (ScopeProof)** to add new signatures on the fly.

### Exports

- **JSON** — Full coverage report including summary statistics and engagement metadata.
- **CSV** — Flat table export for spreadsheets and reporting tools.

## Data Storage

ScopeProof stores data in `~/.scopeproof/`:

| File | Contents |
|---|---|
| `scopeproof_records.json` | Captured traffic records |
| `scopeproof_annotations.json` | Notes and tags |
| `payloads.json` | Custom payload signatures |

## Building from Source

```bash
./gradlew jar
```

The output jar is at `build/libs/ScopeProof-1.0.0.jar`.

### Dependencies

- [Montoya API](https://portswigger.github.io/burp-extensions-montoya-api/) 2025.3 (compile-only)
- [Gson](https://github.com/google/gson) 2.11.0 (bundled in jar)

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Author

[David Mockler](https://github.com/MockedLabs) — [scopeproof.io](https://scopeproof.io)
