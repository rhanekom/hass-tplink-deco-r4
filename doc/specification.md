# TP-Link Deco R4 web interface: reverse engineered specification

Protocol specification for the TP-Link Deco web admin interface as served by
2026-era firmware, written to be sufficient both as a standalone reverse
engineering record and as an implementation reference for the
`tplink_deco_r4` Home Assistant integration.

## 1. Provenance and scope

| Item | Value |
| --- | --- |
| Hardware | Deco **E4R** (master node) |
| Firmware | **1.3.1 Build 20260403 Rel. 8727** |
| Operation mode of the captured unit | **Access Point (AP)** |
| Transport | HTTPS on port 443, self-signed certificate |
| Evidence | Two browser HAR captures of the admin UI, plus the router's own client JavaScript, plus live probing with `scripts/deco_probe.py` |
| Mesh under test | 7 nodes, all E4R, all online |

**How this document was derived.** Three classes of evidence were combined:

1. **Observed wire traffic** from the HAR captures. This gives exact URLs,
   methods, headers, body framing, status codes and ordering. Request and
   response *payloads* on authenticated endpoints are AES-encrypted on the wire
   and the AES key is delivered RSA-encrypted to the router, so the plaintext
   payloads are **not** recoverable from the captures.
2. **The router's own client JavaScript**, served unauthenticated from the
   device and recovered from the captures (`js/libs/encrypt.js`,
   `js/libs/tpEncrypt.js`, `js/su/frame.js`, `js/app/url.js`, and the per-module
   `models.js` / `controllers.js` files). These define the crypto exactly and
   declare every request payload and response field the UI uses.

3. **Live probing** with `scripts/deco_probe.py`, which runs the handshake and
   the read-only endpoints against the reference unit and checks each claim in
   this document. That closed every open question from the capture-only draft
   and corrected several payload details the client JavaScript had implied but
   did not match. Run it with `uv run python scripts/deco_probe.py`.

Every claim below is tagged where it matters:

- **[live]** confirmed against the reference unit by the probe. This is the
  strongest tag: it beats **[js]** wherever the two disagree.
- **[wire]** observed directly in a capture.
- **[js]** read out of the router's client JavaScript. Note that the client's
  field names are what the *UI* binds, which is not always what the firmware
  sends; several **[js]** field names turned out to be wrong.
- **[unverified]** inferred, and still needing confirmation.

No credentials, session identifiers, MAC addresses, IP addresses, SSIDs, RSA
moduli or client names from the captures appear in this document. All example
values are synthetic.

**Not established:** which other Deco models or firmware builds present this
same interface. Record model plus firmware for any device a finding is
confirmed on.

## 2. Protocol overview

The firmware replaced the older `;stok=/login?form=keys` RSA login flow
wholesale. The interface now has these properties:

- **No cookies.** [wire] Not a single `Set-Cookie` or `Cookie` header appears in
  either capture. Session identity is carried **entirely in an `id` query
  parameter** appended to every authenticated URL.
- **Two endpoint families.**
    - `/{?}code=<N>&asyn=<0|1>[&id=<sid>]` -- a low-level numeric-opcode channel
      used for the handshake, login, key exchange and logout. Request and
      response bodies are line-oriented text (CRLF separated), where the first
      line is a zero-padded status code.
    - `/<module>?form=<form>[&id=<sid>]` -- the JSON data API. All authenticated
      calls in this family are wrapped in an AES + RSA-signature envelope.
- **Application-layer encryption ("GDPR mode").** After login the client
  generates a random AES-128 key/IV, hands it to the router RSA-encrypted, and
  from then on every request body and response body in the `?form=` family (and
  the `code=` family) is AES-CBC encrypted. This is layered *inside* TLS.

### 2.1 Endpoint families at a glance

| Family | Auth | Body encoding | Notes |
| --- | --- | --- | --- |
| `/system?form=envar`, `/login?form=check_factory_default` | none | plain JSON | `gdpr:!1` in the client, i.e. exempt from AES [js] |
| `/?code=7&asyn=1` | none | empty request, text response | returns the session-id key material |
| `/?code=16&asyn=0` | none, then session | text | RSA key exchange, AES key upload |
| `/?code=7&asyn=0&id=` | session | RSA hex | the actual login |
| `/?code=11&asyn=0&id=` | session | empty | logout |
| `/admin/**?form=**&id=` | session | `sign=<hex>&data=<b64>` | the JSON data API |
| `/?code=2&asyn=0&id=` | session | same envelope | "vxWorks" block read, used for syslog and timezone tables |

### 2.2 TLS: the transport will not connect out of the box

**This is the first thing that will break an implementation.** A default modern
HTTPS client cannot complete a handshake with this firmware at all, for two
independent reasons, both confirmed live against OpenSSL 3.5.6: [live]

1. `UNSAFE_LEGACY_RENEGOTIATION_DISABLED` -- the server does not advertise the
   RFC 5746 renegotiation extension, so `OP_LEGACY_SERVER_CONNECT` must be set.
2. `WRONG_SIGNATURE_TYPE` -- with that fixed the handshake *still* fails at
   security level 1 or above, because the server signs it with an algorithm
   OpenSSL now refuses by policy. `SECLEVEL=0` is required.

Once both are set the connection negotiates **TLSv1.2** with
**ECDHE-RSA-AES128-GCM-SHA256**, and the certificate is a **2048-bit,
sha256WithRSAEncryption, self-signed** leaf. So the transport itself is sound;
it is OpenSSL's algorithm *policy* that has moved past the firmware, not the
crypto that is weak. Note in particular that `SECLEVEL=0` is **not** needed
because of a weak certificate.

```python
import ssl

def build_ssl_context(verify_ssl: bool = False) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT
    context.set_ciphers("DEFAULT@SECLEVEL=0")
    if verify_ssl:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
```

The relaxations apply whether or not `verify_ssl` is set, because without them
there is no handshake for the flag to verify. `verify_ssl` still controls
certificate and hostname checking, which is what the config-flow tickbox means.

**Integration consequence:** Home Assistant's shared client session
(`async_get_clientsession`) cannot be used, because the integration must supply
its own `SSLContext`. Create a dedicated `aiohttp.ClientSession` with a
`TCPConnector(ssl=build_ssl_context(...))` per config entry and close it on
unload. See `scripts/deco_protocol.py` for a working version.

## 3. Cryptography

All primitives come from `js/libs/encrypt.js` and `js/libs/tpEncrypt.js`. [js]

### 3.1 AES

- **Algorithm:** AES-128-CBC, PKCS#7 padding, ciphertext base64 encoded.
- **Key:** a 16-character string of **ASCII decimal digits**, generated
  client-side (`generateRandomIntString(16)`), used as its UTF-8 bytes.
- **IV:** likewise a 16-character ASCII decimal digit string, UTF-8 bytes.
- **Key string form:** the key and IV are concatenated into a canonical string
  used for both the RSA key upload and the per-request signature:

  ```text
  k=<16 digits>&i=<16 digits>
  ```

### 3.2 RSA

- **Algorithm:** raw RSA with **PKCS#1 v1.5** encryption padding (type 02).
- **Key:** supplied by the router. Modulus and public exponent arrive as
  lowercase/uppercase hex strings from `?code=16&asyn=0` with body `get`. The
  observed modulus is 128 hex characters, i.e. **512-bit RSA (64 bytes)**, and
  the exponent is `010001` (65537). [wire]
- **Output:** hex, **left zero-padded to the modulus length** (128 hex chars).
  The client pads explicitly when the big-integer result is short; an
  implementation must do the same or the router will reject the block.
- **Maximum plaintext per block:** `modulus_bytes - 11` = **53 bytes**. Inputs
  longer than 53 bytes are split into 53-byte chunks, each encrypted
  independently, and the hex blocks concatenated.

### 3.3 The `su.encrypt` obfuscation function

Used only to derive the session id. It is a dictionary-indexed XOR, not a
cipher. Faithful port:

```python
def su_encrypt(text: str, key: str, dictionary: str) -> str:
    """Port of $.su.encrypt from js/libs/encrypt.js."""
    out = []
    len_t, len_k, len_d = len(text), len(key), len(dictionary)
    for i in range(max(len_t, len_k)):
        s = n = 187                      # 0xBB, the padding byte
        if len_t <= i:
            n = ord(key[i])
        elif len_k <= i:
            s = ord(text[i])
        else:
            s, n = ord(text[i]), ord(key[i])
        out.append(dictionary[(s ^ n) % len_d])
    return "".join(out)
```

The stock TP-Link constants (`"RDpbLfCPsJZ7fiv"` as key, and the long built-in
dictionary) are present in the JavaScript as **defaults only**. This firmware
always supplies both operands from the server, so the defaults are never used
on this device.

### 3.4 The request envelope

Every authenticated `?form=` request body is: [js, corroborated by wire framing]

```text
sign=<rsa-hex>&data=<aes-base64>
```

where:

```text
data = base64( AES-128-CBC( utf8( json_payload ) ) )
sign = rsa_hex_concat( "k=" + key + "&i=" + iv + "&s=" + str(seq + len(data)) )
```

Notes that matter for implementation:

- `len(data)` is the length of the **base64 string**, not the ciphertext bytes.
- `seq` is the integer from the key-exchange response. The client **never
  increments it**; the same base `seq` is reused for the life of the session,
  and only `len(data)` varies per request. [js]
- The signed string is typically about 50 characters, so it fits in one 53-byte
  RSA block and `sign` is 128 hex characters. All observed `sign` values were
  exactly 128 hex characters. [wire]
- `Content-Type: text/plain;charset=UTF-8`. [wire]

**Response:** the raw body is the base64 AES ciphertext with no `data=` prefix.
Decrypt, then parse as JSON. [wire, js]

## 4. Login flow

Five HTTP round trips. Order matters: the session id must be computed before
the login call, and the AES key must be uploaded after it.

### Step 0 (optional) -- probe an existing session

```http
POST /?code=7&asyn=1
```

Empty body, no `id`. A **401** response means "not authenticated" and carries
the key material for step 2. A **2xx** response means an existing session is
still valid. [js: `main.js getTmpKey()`]

**401 response body** (CRLF separated): [wire]

```text
00007
00004
00000
<32-character salt>
<255-character dictionary>
00000
```

| Line | Meaning |
| --- | --- |
| 0 | `00007`, echoes the opcode |
| 1 | `00004` |
| 2 | `00000` |
| **3** | **salt**, 32 characters, per-session |
| **4** | **dictionary**, 255 characters, per-session |
| 5 | `00000` |

Lines 3 and 4 are the two server-supplied operands for `su.encrypt`.

> **Trap.** The 255-character dictionary is **not restricted to printable
> ASCII**. One capture's dictionary spanned ordinals 33..126; the other spanned
> **8..126 and contained `0x08`**, which then appeared in the derived session
> id. See section 4.1.

The client discards any cached dictionary and re-fetches it immediately before
each login attempt. [js]

### Step 1 -- enable application-layer encryption

```http
POST /?code=16&asyn=0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

enable
```

Response `00000\r\n` on success. [wire]

### Step 2 -- fetch the RSA public key and sequence number

```http
POST /?code=16&asyn=0
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

get
```

Response (CRLF separated): [wire]

```text
00000
010001
<128 hex characters>
<decimal sequence number>
```

| Line | Meaning |
| --- | --- |
| 0 | status, `00000` = OK |
| 1 | RSA public **exponent**, hex |
| 2 | RSA **modulus**, hex |
| 3 | **sequence number**, decimal |

Note the ordering: the client calls `setRSAKey(data[2], data[1])`, i.e.
**modulus first, exponent second**. Generate the AES key/IV at this point.

### Step 3 -- derive the session id

```python
session_id = su_encrypt(salt, md5_hex(password), dictionary)
```

- `salt` and `dictionary` are lines 3 and 4 from step 0.
- `md5_hex(password)` is the lowercase hex MD5 of the plaintext password,
  32 characters.
- Both operands are 32 characters, so the result is **32 characters** drawn
  from the dictionary alphabet. [wire: both captured ids were 32 characters and
  every character was a member of that session's dictionary]

This value is what the UI stores as `localStorage["id"]` and appends to every
subsequent URL. It is **credential-equivalent**: it is a deterministic function
of the password hash and a server nonce. Treat it as a secret; never log it.

**The username is not used anywhere in this flow.** [js] The local login form
is password-only. See section 8.2 for what this means for the config flow.

#### 4.1 URL-encoding the session id

The id is appended as `&id=<session_id>`. Because the dictionary can contain
control characters and URI-reserved characters, the id **must be percent-encoded**.

Observed browser behaviour: `>` (0x3E) and `0x08` were percent-encoded, while
`|`, `{`, `}`, `[`, `]`, `^`, `!`, `*`, `,`, `$`, `~` were sent literally. [wire]

**RESOLVED.** [live] Both schemes work: strict percent-encoding of everything
outside the unreserved set `A-Za-z0-9-._~`, and the browser's narrower set, are
each accepted by the router. **Use strict encoding** -- it is unambiguous and
needs no knowledge of any particular browser's rules.

What makes this necessary rather than merely tidy: the dictionary the router
generates deliberately excludes the URI-reserved printables (` `, `"`, `#`, `%`,
`&`, `'`, `-`, `/`, `:`, `;`, `=`, `?`, `@`, `\`, `_`, `` ` ``) but does **not**
exclude control bytes. `0x08` has been observed in a live dictionary and in the
resulting session id. A naive implementation that formats the id straight into
the URL therefore works most of the time and fails intermittently, depending on
the password and the session. `+` is also permitted by the dictionary, so any
form-style decoding of the query string on the client side would corrupt it too.

Note also that a URL library will re-normalise the query if given the chance.
With `aiohttp`, build the URL string yourself and wrap it in
`yarl.URL(url, encoded=True)` so yarl leaves the id alone.

### Step 4 -- log in

```http
POST /?code=7&asyn=0&id=<urlencoded session id>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

<128 hex characters>
```

Body is `rsa_encrypt(plaintext_password)` in hex, using the key from step 2.
No `sign=`/`data=` wrapper at this stage. [wire, js]

**Success:** first response line is `00000`. [js]

**Failure:** non-2xx status; the response body's **second** line is a numeric
error code: [js: `localLogin/controllers.js`]

| Code | Meaning |
| --- | --- |
| 0 | Login sessions full |
| 1 | Account locked out |
| 2 | Login timed out |
| 3, 5 | Wrong password. Line 2 holds the failure count; attempts remaining = `10 - count` |
| 6 | Wrong password (no attempts detail) |

The UI enforces a 30-second client-side cooldown after a failed attempt and the
router locks the account after roughly 10 failures. **An integration must not
retry a rejected password automatically** -- a wrong password in the config
entry would otherwise lock the household out of its own router.

Errors surfaced through the JSON API use a different scheme: `-5002` is a bad
password (with `result.failureCount` and `result.attemptsAllowed`) and `-5003`
is max-attempts-exceeded. [js]

### Step 5 -- upload the AES key

```http
POST /?code=16&asyn=0&id=<urlencoded session id>
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

set <128 hex characters>
```

Body is the literal string `set `, a space, then
`rsa_encrypt("k=" + aes_key + "&i=" + aes_iv)` in hex. Response `00000\r\n`. [wire]

From this point the AES envelope of section 3.4 applies to all traffic.

### 4.2 Login sequence summary

```text
POST /?code=7&asyn=1                 -> 401, salt + dictionary
POST /?code=16&asyn=0        "enable"-> 00000
POST /?code=16&asyn=0        "get"   -> 00000, exponent, modulus, seq
  (derive session_id; generate AES key/IV locally)
POST /?code=7&asyn=0&id=...  RSA(pw) -> 00000
POST /?code=16&asyn=0&id=... "set .."-> 00000
```

## 5. Logout

```http
POST /?code=11&asyn=0&id=<urlencoded session id>
```

Empty body, no `Content-Type`. The response is AES-encrypted (a single 16-byte
block, base64) and the UI ignores its content. [wire]

The client then clears the stored id and cached dictionary. [js]

`/system?form=logout` is referenced in the client as a `LOGOUT_URL` constant but
is **never called** by the logout path, which uses `code=11`. [js]

**Integration guidance:** call `code=11` on config-entry unload and on
reauthentication, so abandoned sessions do not accumulate against the router's
session limit (error code 0, "login sessions full", above).

## 6. The JSON data API

### 6.1 Request shape

```http
POST /admin/<module>?form=<form>&id=<urlencoded session id>
Content-Type: text/plain;charset=UTF-8
X-Requested-With: XMLHttpRequest

sign=<128 hex>&data=<base64>
```

The plaintext inside `data` is a JSON object. For reads it is: [js]

```json
{"operation": "read"}
```

or, when the form takes parameters:

```json
{"operation": "read", "params": {"device_mac": "default"}}
```

Other `operation` values seen in the client: `write`, `load`, `insert`,
`update`, `remove`, `login`, `get`, `gmt`, `factory`, `reboot`, `download`,
`upload`, `upgrade`, `local_upgrade`, `check_upgrade`. Only `read` and `get`
are needed for monitoring.

### 6.2 Response shape

Decrypt the base64 body, then parse:

```json
{"error_code": 0, "result": { ... }}
```

Success test, from the client's `successJudge`: [js]

```text
data.success === true || data.error_code === 0 || data.errorcode === 0
```

The client reads the payload as `data.data || data.result`. Distinguished error
codes: [js]

| `error_code` | Meaning | Integration action |
| --- | --- | --- |
| `0` | Success | -- |
| `"timeout"` | Session expired | Re-login |
| `-5001` | User conflict, another session took over | Re-login, back off |
| `"permission denied"` | Not permitted | Surface, do not retry |
| `-5002` | Bad password | Trigger reauth, do **not** retry |
| `-5003` | Max login attempts exceeded | Surface, do **not** retry |

HTTP **401**, **403** and **408** also mean the session is gone and the client
returns to the login page. [js]

**The firmware keeps exactly ONE session, and every login evicts the previous
one.** [live] This is the single most important operational fact about this
interface, and it was measured directly:

- Establish session A, confirm it works. Establish session B. **Session A
  immediately fails with HTTP 403.** Reproducible.
- Opening 4 sessions in sequence and then testing all 4: **exactly 1 works**, the
  newest. Login never refused, so there is no session table to exhaust -- each
  login simply replaces the incumbent.

So the mid-cycle HTTP 403 seen during earlier probing was not rate limiting and
not a timeout: it was another login stealing the session. Two consequences, and
the second one is a design constraint rather than a bug to fix:

1. **A client MUST re-login and retry transparently** on HTTP 401/403/408 or
   `error_code` `"timeout"`/`-5001`, rather than surfacing the error. One retry
   per call is enough; treat a second consecutive failure as real. What must
   **not** be retried is an authentication failure (`-5002`, `-5003`, or login
   codes 1/3/5/6), because each attempt counts toward the router's lockout.
2. **The integration and any human using the router's web UI will evict each
   other continuously.** A 30-second poll means someone logged into the local
   web UI gets kicked out within 30 seconds, repeatedly. There is no protocol
   affordance that avoids this -- no session sharing, no read-only session, no
   keep-alive that coexists. Worth stating plainly in the integration's README,
   and a reason to prefer a longer default refresh interval than the web UI's own
   5-10 seconds. (Whether the *cloud* Deco mobile app shares this local session
   table was not tested. **[unverified]**)

Login error code 0 ("sessions full") was **never reachable** by opening
sessions. [live] It presumably covers some other condition. Logging out on
unload is therefore good manners rather than a defence against lockout.

**Therefore a client MUST re-login and retry transparently on 401/403/408 or
`"timeout"`/`-5001`, rather than surfacing the error.** One retry per call is
enough; treat a second consecutive failure as a real error. What must *not* be
retried is an authentication failure (`-5002`, `-5003`, or login codes 1/3/5/6),
because each attempt counts toward the router's lockout.

`scripts/deco_protocol.py` implements this in `DecoClient.call()`: it catches the
session-expiry class, runs a full fresh login (new session id, new AES key, new
`seq`), and retries once. A partial re-handshake is not sufficient -- the session
id derives from a per-session server salt, so the whole flow has to run again.

One practical consequence for anyone writing tooling against this interface: **two
clients cannot run concurrently**, including two instances of a diagnostic script.
They will evict each other in a loop, and with automatic re-login they will do so
indefinitely.

### 6.3 Encoding conventions

- **Client `name` is base64 encoded** when present. [live] 119 of 128 clients
  had a non-empty name and all 119 decoded cleanly as base64 UTF-8; the
  remaining 9 had **no name at all** (empty string), so a decoder must tolerate
  an empty value rather than assume every client is named.
- **Node `nickname` is plain text** on this firmware. [live] None of the 7 nodes
  used the literal `"custom"` sentinel and no nickname was base64. The
  `nickname == "custom"` -> base64 `custom_nickname` path exists in the client
  JavaScript [js] and other firmware may use it, so handle it defensively, but
  `custom_nickname` was **absent from every `device_list` entry** here.
- **SSIDs and wireless passwords are base64 encoded.** [live]
- **MAC addresses are uppercase, dash separated**: `AA-BB-CC-DD-EE-FF`. [live]
  Confirmed for every node in `device_list`. `device_mac` values passed back to
  the router must use the same form; normalise defensively when matching, since
  Home Assistant's device registry conventionally uses lowercase colons.

**Numeric fields may arrive as strings.** [live] `cpu_usage` and `mem_usage` are
JSON *strings* (`"0.31"`), not numbers, despite the client JavaScript doing
arithmetic on them directly. Coerce with `float()` before any arithmetic, and do
not assume any other numeric-looking field is a native number either.

## 7. Endpoints required by the integration

### 7.1 Operation mode

```text
POST /admin/device?form=mode        payload {"operation": "read"}
```

Returns exactly two fields, `sysmode` and `workmode`; the client maps them to
`{sysMode, workMode}`. [live]

- `sysmode` selects the navigation set: `Router` loads `navigator.json`, `AP`
  loads `navigator.ap.json`. The reference unit reports **`sysmode: "AP"`**, and
  the capture correspondingly fetched `navigator.ap.json`. [live]
- `workmode` on the reference unit is **`"FAP"`**. [live] The client JavaScript
  only ever compares `workmode` against the literal `"RE"` (range extender), so
  `FAP` is simply "not RE" as far as the UI is concerned. Treat `workmode` as an
  opaque string and test only for `"RE"`; do not enumerate it.

Effective mode as the UI computes it: `sysmode`, overridden to `RE` when
`workmode == "RE"`. [js]

Poll this **once per config entry setup**, not on every refresh. It gates which
other endpoints are meaningful: in AP and RE mode the WAN endpoints do not
describe a real uplink.

**Router mode and AP mode expose the same endpoint surface.** [live] The three
navigation trees are served unauthenticated, so they can be compared without
changing any setting, and `config/navigator.json` (Router) is **byte-identical**
to `config/navigator.ap.json` (AP) on this build -- same MD5, same 11 menus:

```text
networkMap, advanced, networkStatus, system, firmwareDeco,
backupRestore, sysLog, timeSettings, cwmp, reboot, sysParams
```

So switching this firmware between Router and AP mode does not add or remove
pages, and therefore should not change the endpoint set or the payload field
names the integration depends on. What differs is the *content* of the WAN
endpoints: in AP mode `wan_ipv4` and `internet` do not describe a real uplink.
Confirming that requires an actual mode switch and remains **[unverified]** (see
10.2).

**RE mode is materially different and should be handled explicitly.**
`config/navigator.re.json` **drops three pages**: `networkMap`, `networkStatus`
and `timeSettings`. [live] `networkMap` is where the client list and the node
topology live, so in range-extender mode the two endpoints this integration is
built around may be unavailable or unpopulated. The client JavaScript
independently hides the topology tree, the WAN panels and the online-upgrade
panel when `workmode == "RE"`. [js]

Recommended behaviour: if `workmode == "RE"`, set up the entry but create only
the entities that can be populated, and log a warning naming the mode rather
than failing opaquely. Whether `client_list` and `device_list` still answer in RE
mode is **[unverified]** -- no RE unit was available.

### 7.2 Deco node list

```text
POST /admin/device?form=device_list  payload {"operation": "read"}
```

Result: `{"device_list": [ ... ]}`. The reference mesh returns **35 fields per
node**, considerably more than the web UI binds. [live] Fields the UI *does* bind
but which are **absent** here: `custom_nickname`, `version`, `new_version`,
`need_to_upgrade` -- those belong to the firmware page's `fw_list` variant of
this response, not the plain `device_list` read. [live]

**Core identity and state**

| Field | Type | Meaning |
| --- | --- | --- |
| `mac` | string | Node MAC, uppercase dash separated. Primary key, and the `device_mac` value elsewhere |
| `device_id` | string | Opaque node id. **The join key for client attribution** (see 7.7) |
| `nickname` | string | Display name, plain text on this firmware |
| `device_model` | string | e.g. `E4R` |
| `device_ip` | string | Node LAN IP |
| `role` | string | `master` or `slave` |
| `group_status` | string | `connected` / `disconnected` (compare lowercased) |
| `inet_status` | string | `online` / `offline` (compare lowercased) |
| `inet_error_msg` | string | `well` when healthy (compare lowercased) |
| `hardware_ver` | string | e.g. `4.0` |
| `software_ver` | string | e.g. `1.3.1 Build 20260403 Rel. 8727`. **Varies between nodes** |
| `device_type` | string | `HOMEWIFISYSTEM` |
| `hw_id`, `oem_id` | string | Identifiers |

**Topology and link quality** (all undocumented by the UI, and useful)

| Field | Type | Meaning |
| --- | --- | --- |
| `previous` | string | Upstream node's MAC. `null` on the master |
| `parent_device_id` | string | Upstream node's `device_id`. Self-referential on the master |
| `master_device_id` | string | The mesh master's `device_id`, same on every node |
| `topology` | object | `{auto, device_id, ...}` on slaves, `null` on the master |
| `signal_level` | object | **Per-band backhaul signal** on a **0-3 scale**, e.g. `{"band2_4": 3, "band5": 3}`. `0` means the band is unused, not "no signal" |
| `connection_type` | array | Backhaul band(s), e.g. `["band5"]`. Empty on the master |
| `is_wired` | bool | Wired backhaul. `null` on slaves that are not wired |
| `port_count` | int | Ethernet ports, `2` on the E4R |

**Capability flags** (all bool/int unless noted): `enable_gateway_feature`,
`set_gateway_support`, `speed_diagnose`, `speed_get_support`, `support_plc`,
`owner_transfer`, `oversized_firmware`, `product_level` (int, `100`),
`zigbee_role` (string, `none`), `bssid_2g`, `bssid_5g`, `bssid_sta_2g`,
`bssid_sta_5g` (strings, empty on the master).

**Online derivation**, exactly as the client computes it: [js]

```python
online = not (
    group_status.lower() == "disconnected"
    or (inet_status.lower() != "online" and inet_error_msg.lower() != "well")
)
```

The client polls this every **10 s**.

This single call supplies **device name, LAN IP, MAC address, per-band mesh
signal and full topology** for every node, and the `device_id` values needed to
attribute clients. It is the backbone of the integration.

`signal_level` and `software_ver` are worth surfacing that the original draft
missed: a per-node mesh-signal sensor comes free, and a per-node firmware
version makes drift across the mesh visible.

**`signal_level` is a 0-3 quality level.** [live] Sampling every value the mesh
reports -- node backhaul plus every client's `linked_device_info.signal_level` --
gave 270 samples spanning **0..3 with all four values present and nothing above
3**:

| Value | Node backhaul | Client links |
| --- | --- | --- |
| 0 | 1 | 185 |
| 1 | 5 | 9 |
| 2 | 1 | 33 |
| 3 | 7 | 29 |

The large count of `0` on client links is the *unused* band: a client associated
on 2.4 GHz reports `{"band2_4": 2, "band5": 0}`. So `0` means "not on this band",
and a client's real signal is the non-zero entry. Present this as a 0-3 level or
map it to text; **do not present it as a percentage**, and do not assume the
scale is the same on other models.

### 7.3 Per-node LAN details

```text
POST /admin/network?form=lan_ip
payload {"operation": "read", "params": {"device_mac": "default"}}
```

`device_mac` accepts `"default"` (the node being talked to) or a specific node
MAC. Unlike `form=performance`, this endpoint **does** honour the parameter:
querying all 7 nodes returned 7 distinct responses. [live]

Actual result keys -- two more than the UI binds: [live]

```json
{
  "mac_addr": "...",
  "lan_ip": {"ip": "...", "mask": "..."},
  "wan_ip": "...",
  "dns_server_ip": "..."
}
```

Largely redundant with `device_list[].mac` / `device_ip`, so the polling plan
skips it. Worth a call when the subnet mask, the node's view of the WAN address,
or its DNS server is wanted.

**`"default"` means "the node you are talking to", not "the master".** [live]
Every slave node serves the full admin API on its own `device_ip`, and it answers
for *itself*: logging in to a slave and reading `lan_ip` with
`device_mac: "default"` returns **that slave's** `mac_addr`, not the master's,
and its `device_list` differs from the master's. The slaves are not proxies. That
matters for the CPU/memory question in 7.5, and it means a future integration
could address a specific node directly if some endpoint ever justified it.

The IPv6 counterpart is `/admin/network?form=ipv6` with the same `device_mac`
parameter, returning `{"lan": {"ip": "..."}}`. [js]

### 7.4 Network SSID

```text
POST /admin/wireless?form=wlan       payload {"operation": "read"}
```

Result is per-band, each band having `host` and `guest` sub-objects. The
reference unit is **dual band**, exposing `band2_4` and `band5_1` only; `band5_2`
is present on tri-band hardware and the client uses its presence as the tri-band
test. [live]

Actual `host` / `guest` keys: [live]

```json
{
  "band2_4": {
    "host":  {"ssid": "<base64>", "password": "<base64>", "enable": true,
              "channel": 0, "encryption_mode": "...",
              "enable_wpa3": false, "enable_hide_ssid": false},
    "guest": { ... same shape ... }
  },
  "band5_1": { "host": { ... }, "guest": { ... } }
}
```

Note that `mode` and `channel_width`, which the client JavaScript binds [js], are
**not present** on this firmware in AP mode. [live] The UI's "network name" is
`b64decode(band2_4.host.ssid)`.

This endpoint is network-wide, not per-node. **Never expose the decoded
`password` fields as entity state or attributes.**

### 7.5 CPU and memory load: do not build sensors on this

```text
POST /admin/network?form=performance  payload {"operation": "read"}
```

Returns exactly two fields: [live]

```json
{"cpu_usage": "0.31", "mem_usage": "0.58"}
```

Both are fractions in 0..1 delivered as **JSON strings**, so coerce with
`float()` and multiply by 100 for a percentage. The web UI polls this every 5 s.

> **The value never changes. This endpoint is not a live metric on this
> firmware.** [live] Four independent observations, and no counter-evidence:
>
> 1. **20 samples over 60 s: one distinct value.** `("0.31", "0.58")` every time.
> 2. **Unmoved under load.** 12 back-to-back `client_list` reads (each costing
>    the router an RSA verify, an AES decrypt, a JSON build over ~130 clients and
>    an AES encrypt) did not budge either figure, during or after.
> 3. **Identical across every node.** All 7 nodes report `"0.31"` / `"0.58"`, and
>    they are *not* proxying -- each slave answers for itself on its own
>    `device_ip` (see 7.3). Seven E4R units independently agreeing to two decimal
>    places is not credible.
> 4. **Identical across runs hours apart**, while `client_list` and
>    `device_list` from the same sessions changed continuously (client counts
>    moving between 127 and 128, online counts between 65 and 69). The session
>    was live; only this endpoint was frozen.
>
> `0.31` and `0.58` are plausible idle figures, which is exactly why this is worth
> stating explicitly: the value looks reasonable and is therefore easy to ship as
> a sensor that silently never moves.
>
> **Recommendation: do not create CPU or memory sensors.** They would be flat
> lines that look like working sensors. If they are wanted anyway, mark them
> clearly as unreliable on this firmware, and re-check with
> `deco_probe.py --check liveness` after any firmware update -- that check exists
> precisely to catch it starting to work.

Two further limitations, both confirmed, that stand regardless:

- **`device_mac` is accepted and ignored.** A bogus MAC
  (`00-00-00-00-00-00`) returns the same payload rather than an error, so the
  parameter is not even validated. [live] The web UI never re-issues this call
  when a different node is selected either. [js]
- **Addressing a node directly does not help.** Logging in to each slave's own
  `device_ip` -- which does work, and does return that node's own data for other
  endpoints -- still yields the same frozen pair. [live]

So even if the value became live, it would describe the node being talked to, and
there is no parameter that reaches another node's figures.

### 7.6 Connected client list

```text
POST /admin/client?form=client_list
payload {"operation": "read", "params": {"device_mac": "default"}}
```

Result: `{"client_list": [ ... ]}`. The **actual** per-client fields, confirmed
live, are below. Several field names in the client JavaScript are wrong:
`enableInternet` and `remainTime` do **not** exist on this firmware, and eight
fields the UI never binds do. [live]

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string (base64) | Client name. Base64 when present, **empty for some clients** |
| `mac` | string | Client MAC, uppercase dash separated |
| `ip` | string | Client IP. `"0.0.0.0"` means no current lease, rendered `-` by the UI |
| `up_speed` | int | Upload rate in **Kbit/s** |
| `down_speed` | int | Download rate in **Kbit/s** |
| `client_type` | string | Device category, see below |
| `connection_type` | string | How it is attached, see below |
| `online` | bool | Currently connected |
| `enable_priority` | bool | QoS priority flag |
| `remain_time` | int | Remaining time for a timed pause (**not** `remainTime`) |
| `linked_device_info` | object | **Which node it is attached to**, see 7.7 |
| `interface` | string | e.g. `iot`, the logical interface it landed on |
| `wire_type` | string | `wireless` or wired |
| `enable_isolation` | bool | Client isolation |
| `link_priority` | object | `{band_auto, device_auto}` |
| `owner_id` | string | Owner association, empty when unset |
| `client_mesh` | bool | Whether the client supports mesh steering |

**`connection_type` values** [live] `band2_4`, `band5`, `wired` were all
observed; `band5_2`, `zigbee` and `bluetooth` are handled by the UI [js] but did
not appear on this dual-band mesh. Anything else renders as `-`.

**`client_type` values** [live] `other` (55), `iot_device` (31), `phone` (19),
`pc` (15), `entertainment` (4), `laptop` (2), `printer` (1), `tablet` (1) across
128 clients. Only `pc`, `phone`, `tablet` and `other` are special-cased by the
UI; the rest fall through to an icon named after the raw value, so **treat this
as an open set** and do not validate against a fixed list.

**Rate units: RESOLVED as Kbit/s.** [live] Driving a smoothly paced download at
a known rate and watching the counters rise:

| Driven | Observed median rise | Ratio if Kbit/s | Ratio if KB/s |
| --- | --- | --- | --- |
| 1025 KB/s = 8202 Kbit/s | +9818 | 1.20x | 9.58x |
| 3075 KB/s = 24597 Kbit/s | +29890 | 1.22x | 9.72x |

The two hypotheses are 8x apart and only Kbit/s is anywhere near 1.0. The
residual ~20% is that client's own background traffic plus link-layer framing,
which the payload byte count excludes; it stays roughly constant in absolute
terms as the driven rate triples, which is what a fixed background offset looks
like. **So publish these as Kbit/s** (multiply by 1000/8 for bytes/s).

Two traps when reproducing this measurement, both of which produced wrong
answers first time round:

- **Pace the traffic smoothly.** Reading large chunks at line speed and then
  sleeping gives the right *average* but a much higher *instantaneous* rate, and
  the router samples the instantaneous rate. That overshot by 50-80%.
- **Use the median of samples and the rise above baseline**, not the absolute
  peak of the busiest client. Other household traffic will out-rank a test
  transfer in absolute terms.

The client polls this every **10 s** and sorts by `online` descending.

### 7.7 Attributing clients to a Deco node

There are two ways to do this, and the cheap one is also the better one.

**The `device_mac` filter** works as documented: [live]

- `{"device_mac": "default"}` -- the **remembered-client inventory**.
- `{"device_mac": "<node mac>"}` -- only the clients **currently attached** to
  that node, where the MAC comes from `device_list[].mac`.

These two are **not** the same set, which the capture-only draft got wrong.
[live] On the reference mesh `default` returned **128** clients while the union
of the seven per-node lists was **79**. The 49-client difference is
remembered-but-not-attached history, and only 1 of those 49 was even flagged
`online`. No client appeared under two nodes, so per-node attribution is
unambiguous.

Implications:

- Use the **per-node view (or the join below) for "connected clients"**. Using
  `default` would report long-departed devices as present.
- `default` is still the right source for a stable inventory of known devices,
  and for a per-client `online` flag.

**The join, which avoids N calls entirely.** Each client carries: [live]

```json
"linked_device_info": {
  "device_id": "<the node's device_id>",
  "connection_type": ["band2_4"],
  "signal_level": {"band2_4": 3, "band5": 0}
}
```

`linked_device_info.device_id` joins to `device_list[].device_id`. Checked
against the per-node filter as ground truth, **79 of 79 clients agreed**, with
none pointing at a different node and none carrying an unknown `device_id`.
[live]

So **one `client_list` call with `device_mac: "default"` plus one `device_list`
call is enough** to attribute every client to its node, instead of one call per
node. That is 2 calls per refresh instead of 1 + N, and it also yields the
per-client mesh signal level for free. Treat a client as currently attached when
its `linked_device_info.device_id` resolves to a known node.

Recommended refresh cycle:

1. `device_list` -> nodes, keyed by both `mac` and `device_id`.
2. `client_list` with `device_mac: "default"` -> every client.
3. Join `client.linked_device_info.device_id` -> node.

Keep the per-node call available as a fallback for firmware where
`linked_device_info` is missing, and log if the join fails to resolve.

### 7.8 Suggested polling plan

| Endpoint | When | Calls |
| --- | --- | --- |
| `/admin/device?form=mode` | Once at setup | 1 |
| `/admin/wireless?form=wlan` | Once at setup, then infrequently | 1 |
| `/admin/device?form=device_list` | Every refresh | 1 |
| `/admin/client?form=client_list` (`default`) | Every refresh | 1 |
| `/admin/network?form=performance` | Only if CPU/memory sensors are shipped anyway (7.5) | 0-1 |
| `/admin/network?form=lan_ip` | Only for the subnet mask or a cross-check | 0 |

That is **2 calls per refresh** regardless of mesh size, thanks to the
`linked_device_info` join -- 3 if `performance` is polled despite being static. At the default 30 s interval that is a tenth of what
the web UI itself does (`device_list` and `client_list` every 10 s, `performance`
every 5 s), so the cadence is comfortably conservative.

A single `DataUpdateCoordinator` should own the whole cycle. Session recovery
belongs **inside the API client**, per call (see 6.2), not in the coordinator: a
mid-cycle eviction should cost one transparent re-login, not a failed refresh.
The coordinator still needs to handle `-5002`/`-5003` by raising
`ConfigEntryAuthFailed` and stopping.

## 8. Config flow specification

### 8.1 Fields

| Key | Label | Type | Default | Validation |
| --- | --- | --- | --- | --- |
| `host` | URL of main node | string | -- | Required. Accept a bare host/IP or a full URL; normalise to `https://<host>` when no scheme is given |
| `verify_ssl` | Verify SSL certificate | boolean | `False` | -- |
| `username` | Username | string | `admin` | Required, non-empty |
| `password` | Password | string (password selector) | -- | Required, 1..32 characters |
| `scan_interval` | Refresh rate (seconds) | integer | `30` | Minimum 10; use a number selector in seconds |

Notes:

- **`verify_ssl` defaults to `False`.** The device serves a self-signed
  certificate for an RFC1918 address, so verification fails by default for
  every real deployment. Defaulting it on would make the happy path fail. Keep
  the tickbox so users with a trusted internal CA can turn it on. Note that the
  tickbox controls **certificate and hostname verification only**: the
  algorithm-policy relaxations in 2.2 apply either way, because without them no
  TLS handshake completes at all.
- **`password` maximum length is 32**, matching the router's own form
  validation (`maxLength: 32, minLength: 1`). [js]
- **`username` is not part of the protocol.** The local login flow sends only
  the password; the session id derives from `md5(password)` alone and no
  username is transmitted anywhere. It is retained in the config flow because
  the requirement calls for it, it matches user expectations from the router's
  own branding, and it leaves room for a future cloud/TP-Link-ID login path
  (`modules/login/tpLogin`, present in the UI but not captured). Store it, and
  **do not** feed it into the id derivation.
- **`scan_interval` default 30 s** is roughly half the aggressiveness of the web
  UI's own 5 s/10 s polling, so it is comfortably within what the firmware
  serves. Enforce a floor of 10 s to keep a misconfiguration from hammering
  household infrastructure.

### 8.2 Flow behaviour

1. **`async_step_user`** shows the schema above.
2. On submit, run the **full login flow of section 4** against the supplied
   host, then immediately call `/admin/device?form=mode` to prove the encrypted
   channel works end to end, then **call logout (`code=11`)** so validation does
   not leave a session behind.
3. Map failures to form errors:

    | Condition | Error key |
    | --- | --- |
    | Connection refused, DNS failure, timeout | `cannot_connect` |
    | TLS verification failure (only reachable with `verify_ssl` on) | `invalid_ssl` |
    | Login code 3, 5, 6, or `-5002` | `invalid_auth` |
    | Login code 1, or `-5003` | `account_locked` |
    | Login code 0 (sessions full) | `too_many_sessions` |
    | Login code 2 | `cannot_connect` |
    | Anything else | `unknown` |

4. **Unique id:** use the **master node's MAC** from `device_list`
   (`role == "master"`), not the host, so the entry survives a DHCP change.
   Fetching `device_list` during validation costs one extra call and is worth
   it. Call `async_set_unique_id` then `_abort_if_unique_id_configured`.
5. **Title:** the master node's decoded nickname, falling back to the host.
6. **Reauth:** on `ConfigEntryAuthFailed`, re-prompt for password only.
7. **Options flow:** allow `scan_interval` and `verify_ssl` to be changed
   without re-entering credentials.

**Never log** the password, the MD5 of the password, the derived session id, the
AES key or IV, or the raw `sign`/`data` bodies. At debug level log endpoint
names and error codes only.

## 9. Other endpoints observed but not required

Documented for completeness. All are session-authenticated and use the AES
envelope unless noted.

### 9.1 Unauthenticated

| Endpoint | Payload | Result | Notes |
| --- | --- | --- | --- |
| `POST /system?form=envar` | `{"operation":"read"}` | `{"error_code":0,"result":{"locale":"EN_US"}}` | **Plain JSON, no encryption.** [wire] Useful as a cheap liveness/identification probe before login |
| `POST /login?form=check_factory_default` | `{"operation":"read"}` | `{"error_code":0,"result":{"is_default":false}}` | **Plain JSON.** [wire] True on a factory-fresh unit that has not completed setup |

Both are declared `gdpr:!1` in the client, which is what exempts them from the
AES envelope. [js]

### 9.2 Network and WAN

| Endpoint | Result | Notes |
| --- | --- | --- |
| `/admin/network?form=wan_ipv4` | `{"wan": {"dial_type", "aftr_name", "ip_info"/"ip1_info": {ip, mask, gateway, dns1, dns2}}}` | `dial_type` is one of `dynamic_ip`, `static_ip`, `pppoe`, `l2tp`, `pptp`, `dslite`, `v6_plus`, `ocn`. `l2tp`/`pptp` use `ip1_info`; `v6_plus` has no mask/gateway/DNS. Meaningless in AP mode |
| `/admin/network?form=internet` | `{"ipv4": {"inet_status": "online"\|"offline"}}` | Simple uplink up/down. A candidate for a future WAN binary sensor |
| `/admin/network?form=ipv6` | `{"lan": {"ip": "..."}}` | Takes `device_mac` |
| `/admin/network?form=dhcp_dial` | `{"is_dhcp", "enable_unicast"}` | DHCP unicast setting |
| `/admin/network?form=igmp_setting` | `{"enable_join_igmpv3"}` | IGMPv3 |
| `/admin/network?form=wifi_network` | `{"enable_wfnetwork"}` | Wi-Fi network toggle. Referenced in the client, not exercised in the captures |

### 9.3 System

| Endpoint | Notes |
| --- | --- |
| `/admin/web?form=extra_component_info` | `{"operation":"get"}`. Feature-detection map. Client reads `is_eg`, `cwmp`, `backup_restore`, `enable_erp` to decide which menus to show. Useful for capability probing |
| `/admin/device?form=timesetting` | `{timezone, continent, tz_region}`; `{"operation":"gmt"}` starts a GMT sync |
| `/admin/device?form=system` | **Write-only, destructive.** `{"operation":"reboot"}` and `{"operation":"factory"}`. Do not call |
| `/admin/cwmp?form=cwmp_info` | TR-069/ACS configuration. Contains `ACS_Password`, `Password`, `STUNPassword`. **Never read or surface this** |
| `/admin/firmware?form=upgrade` | `{hardware_version, firmware_version}` |
| `/admin/cloud?form=firmware_status` | Firmware download/upgrade state machine: `read`, `check_upgrade`, `upgrade`, `local_upgrade`. **Do not call** |
| `/admin/syslog?form=mail` | Log-email settings, contains an SMTP `password`. **Never read** |
| `/admin/log_export?form=feedback_log` | vxWorks block read, see 9.5 |
| `/locale?form=lang` | `{locale, force, rebootTime}` |
| `/locale?form=list` | Available UI languages |

### 9.4 Cloud and other

| Endpoint | Notes |
| --- | --- |
| `/admin/cloud_account?form=get_deviceInfo` | `{device_name}` |
| `/admin/cloud_account?form=check_internet` | Cloud reachability check |
| `/admin/folder_sharing?form=tree` | USB share tree: `{name, branches, modelImg, role, mac, nickname}` |
| `/domain_login?form=dlogin` | IP-conflict / domain login path. Not exercised |
| `/login?form=login` | Declared by the client's `loginProxy` with `{"operation":"login"}` but **never called** on this firmware; the real login is `code=7`. Likely a legacy path |
| `/system?form=logout` | Declared as a constant, never called. Logout is `code=11` |

### 9.5 The `code=2` "vxWorks" block channel

```text
POST /?code=2&asyn=0&id=<session id>
```

A second, far lower-level read interface, and **much larger than the `?form=`
API**. It exposes the firmware's raw configuration and statistics blocks by
numeric id.

**Request.** Same AES + RSA envelope as the JSON API, but the plaintext payload
is a bare JSON *string* rather than an object, because the framework passes the
block specification straight through `JSON.stringify`: [js]

```text
plaintext = "2#3"     (with the quotes -- it is a JSON string)
```

Block ids are joined with `#`, each optionally suffixed `|layer,layer`.
`sysLogStore` uses `blocks: [2, 3]`. [js]

**Response.** A zero-padded numeric status on its own line, then an INI-ish text
body: [live]

```text
00000
id 2|1,0,0
num 22
level 0 1
level 1 3
id 3|1,0,0
num 8
msg 0 Exception:|2026-03-24...
```

`id <n>` opens a section; remaining lines are `name value`, or
`name <index> value` for array fields. `frame.js`'s `parser()` is the reference;
`parse_blocks()` in `scripts/deco_protocol.py` is a port. **Some blocks are not
valid UTF-8**, so decode leniently or handle bytes. [live]

`?code=0&asyn=0` is the matching **clear/write** opcode (the syslog store sends
`systool syslog -clean` through it) and `/syslog.txt?code=0&asyn=0&disposition=1`
downloads the log file. Both are writes; do not call them.

#### 9.5.1 Security: this channel reads far more than the UI shows

> **An authenticated session can read credential material through this channel.**
> [live] A sweep of blocks 0-130 found, among ordinary configuration, fields named
> `defAuthuser` / `defAuthpwd` (block 0), `authKey` (blocks 1 and 11),
> `username` / `username_md5` / `shadow` plus a password-shaped field (block 102),
> a cloud account field (block 62), and a cloud `token` (block 63). Field *names*
> were enumerated deliberately without reading their values.
>
> The practical consequence: **the Deco admin password is not a
> least-privilege credential.** Anything holding it can read the device's stored
> secrets, not merely its status. That raises the bar on how an integration
> stores it, and it is worth knowing before pointing any tooling at a router you
> do not own.
>
> Nothing in this integration needs this channel. Treat any block dump as
> sensitive: `scripts/` writes only to the gitignored `scripts/out/`, and no
> block data belongs in a commit, an issue, or a log.

#### 9.5.2 Block 22: the live WAN statistics the JSON API does not expose

Worth documenting because `form=performance` is static (7.5) while **this block
is genuinely live**. [live]

| Field | Type | Meaning |
| --- | --- | --- |
| `inOctets`, `outOctets` | int | **Monotonic WAN byte counters** |
| `inPkts`, `outPkts` | int | Monotonic WAN packet counters |
| `inRates`, `outRates` | int | Instantaneous WAN rate |
| `ports_in_rate[n]`, `ports_out_rate[n]` | int | Per-Ethernet-port instantaneous rate (3 ports on the E4R) |
| `upTime` | int | Monotonic tick counter, see below |
| `status`, `code` | int | WAN status (`status=1` while up) |
| `ip`, `mask`, `gateway`, `dns[n]` | string | WAN addressing. In AP mode these mirror the LAN |
| `dual*` | mixed | Second/backup WAN, all zeroes when unused |

Confirmed live: over a 363-second window the counters advanced by **+277 MB in**
and **+32 MB out**, and they increase monotonically between every sample. [live]
These are exactly the right shape for Home Assistant `total_increasing` sensors,
with throughput derived from the deltas.

**`upTime` advances at about 64.5 ticks per second.** [live] Measured over two
independent 181-second windows: 64.14 and 64.91 ticks/s, and 64.52 overall --
consistent with a 64 Hz kernel tick, so dividing by 64 yields seconds. Short
samples are useless here: over ~16-second windows the counter moves in quantised
jumps and implies anything from 56 to 71 ticks/s. What the counter measures is
**[unverified]**: it could be system uptime or WAN-link uptime, and telling them
apart needs a known reboot or link drop.

**`inRates` / `outRates` units are [unverified].** They are instantaneous, so
they cannot be checked against an averaged counter delta -- comparing them to
16-second octet averages gave ratios from 0.86x to 11x purely because household
traffic is bursty. The `outRates` comparisons clustered near Kbit/s, which
matches the confirmed unit for client rates (7.6), so Kbit/s is the working
assumption. **Prefer the octet counters**: a monotonic byte counter has no unit
ambiguity.

#### 9.5.3 Other blocks seen

Names only, from a 0-130 sweep. Useful for orientation; none is needed by this
integration. [live]

| Block | Contents |
| --- | --- |
| 0 | Device identity: `brandName`, `deviceId`, `countryCode`, factory defaults **(credentials)** |
| 2, 3 | Syslog entries and exception traces |
| 4, 8 | LAN addressing; DHCP server settings |
| 5 | Web server ports (`port`, `httpsPort`) |
| 6 | MAC access-control list |
| 9, 12 | DHCP leases and address bindings |
| 19, 20 | Port forwarding / virtual servers |
| 22 | **Live WAN statistics** (above) |
| 27, 28 | Time zone / NTP settings, and the current system clock |
| 29 | Wireless flags (`bEnabled`, `bGuestIsolated`, `bAtf`, ...) |
| 32 | IPTV / VLAN tagging |
| 39-42 | IPv6 addressing |
| 51 | Bandwidth control (`upBand`, `downBand`) |
| 62-66, 102 | Cloud account and local account **(credentials)** |
| 84 | Radio tuning (`best_effort_rssi_inc`, band steering weights) |
| 98 | Node list (`deviceId`, `device_model`, `nickname`, `role`) |
| 118 | Mesh/PLC link state (`TrafficEth*`, `capIp`, `capMac`, `linkState`) |
| 122 | Client-type table |
| 124 | Firmware metadata (`firmware_ver`, `modelName`, `releaseDate`) |

**No CPU or memory block exists.** A full sweep of blocks 0-130 found no field
matching `cpu`, `mem`, `ram`, `load`, `heap`, `idle`, `swap` or `temp`. [live]
Combined with 7.5, that closes the question: **CPU and memory usage are not
obtainable from this firmware by any route found.**

### 9.6 Static configuration files

Served unauthenticated over GET, useful for offline analysis: [wire]

| File | Contents |
| --- | --- |
| `/config/models.json` | Model and store definitions |
| `/config/modules.json` | Module registry |
| `/config/classes.json` | Class loader map |
| `/config/navigator.json`, `navigator.ap.json`, `navigator.re.json` | Menu trees per operation mode. Which one the UI fetches reveals the operation mode without authenticating |

## 10. Verification status

Everything below was checked against the reference unit with
`uv run python scripts/deco_probe.py`. The probe reports each claim as
PASS/FAIL/WARN and exits non-zero if any claim regresses, so it doubles as a
conformance test to re-run against new firmware.

### 10.1 Resolved

| Question | Answer |
| --- | --- |
| Does `form=performance` accept `device_mac`? | **It accepts it and ignores it.** A bogus MAC returns the same payload (7.5) |
| Can CPU/memory be read per node? | **No, and worse: the value is static.** It never changes under load, over time, or between nodes. Do not ship these sensors (7.5) |
| Do slave nodes serve the admin API? | **Yes, and they answer for themselves**, not as proxies to the master (7.3) |
| What is the scale of `signal_level`? | **0-3**, where 0 means "band unused". 270 samples, all four values present, none above 3 (7.2) |
| How many concurrent sessions? | **Exactly one.** Every login evicts the previous session (6.2) |
| Do Router and AP mode differ? | **The menu trees are byte-identical**, so the endpoint surface is the same. RE mode drops three pages including the network map (7.1) |
| Does the router accept a fully percent-encoded `id`? | **Yes.** Both strict and browser-style encoding work; use strict (4.1) |
| Are `up_speed`/`down_speed` KB/s or Kbit/s? | **Kbit/s**, confirmed at two driven rates 3x apart (7.6) |
| What separator and case does `mac` use? | **Uppercase, dash separated** (6.3) |
| Does `seq` ever need incrementing? | **No.** 60 calls over 85 s on a fixed `seq` (3.4) |
| Can one call attribute clients to nodes? | **Yes**, via `linked_device_info.device_id`, 79/79 agreement (7.7) |
| Are sessions stable enough to poll? | **Not on their own.** A live session began returning HTTP 403 mid-cycle; transparent re-login and retry is mandatory (6.2) |
| How long does a session last if kept alive? | **At least 12 minutes** of 60-second polling, with no expiry seen. Eviction dominates in practice, so this bound matters little (6.2) |
| Is there any other source of CPU/memory? | **No.** A sweep of `?code=2` blocks 0-130 found no cpu/mem/load/heap field anywhere (9.5.3) |
| Is there live WAN throughput anywhere? | **Yes** -- block 22 carries monotonic `inOctets`/`outOctets`/`inPkts`/`outPkts` plus per-port rates, and they move (9.5.2) |

Corrections the live run forced, all of which would have been bugs:

- **TLS does not connect at all** with a default modern client (2.2). This was
  invisible in the captures, since the browser had already negotiated it.
- **`form=performance` is a static value** (7.5). It looks like a working metric
  and is not one, so it would have shipped as two flat-line sensors.
- **Every login evicts the previous session** (6.2). Without re-login-and-retry
  in the client, any household use of the router's web UI breaks the next poll.
- `cpu_usage` / `mem_usage` are **JSON strings**, not numbers (6.3).
- Client fields are `remain_time`, not `remainTime`; `enableInternet` **does not
  exist** (7.6).
- `device_mac: "default"` and the per-node lists return **different sets**: 128
  remembered clients versus 79 currently attached (7.7).
- `client_type` is an **open set** -- `iot_device`, `entertainment`, `laptop` and
  `printer` all appear beyond the four values the UI special-cases (7.6).
- Some clients have **no name at all** (7.6).
- `device_list` carries **35 fields**, including per-band `signal_level` and
  full topology, and omits four the UI binds (7.2).
- `wlan` omits `mode` and `channel_width` (7.4); `lan_ip` adds `wan_ip` and
  `dns_server_ip` (7.3).

### 10.2 Still open

Every question from the capture-only draft has now been answered. What remains
needs hardware or conditions that were not available.

1. **Router-mode payload content.** The Router and AP navigation trees are
   byte-identical (7.1), so the endpoint surface and field names should not
   change. What is untested is whether `wan_ipv4` / `internet` carry real uplink
   data in Router mode. Switching mode re-runs setup and drops household
   connectivity, so this needs a spare unit or a maintenance window -- it is
   deliberately not something an automated probe should do.
2. **RE-mode behaviour.** `navigator.re.json` drops `networkMap` and
   `networkStatus` (7.1), so `client_list` and `device_list` may be unavailable
   in range-extender mode. No RE unit was available.
3. **Whether the TP-Link cloud mobile app shares the local single-session
   table.** The local web UI definitely does (6.2). Testing this needs a phone
   on the account: open the Deco app, then see whether an established local
   session survives.
4. **What `upTime` in block 22 actually counts** -- system uptime or WAN-link
   uptime. The tick rate is measured (~64.5/s) but the semantics are not, and
   telling them apart needs a known reboot or link drop (9.5.2).
5. **The units of block 22's `inRates` / `outRates`.** Instantaneous, so not
   checkable against averaged counter deltas. Kbit/s is the working assumption
   by analogy with client rates (9.5.2). Prefer the octet counters, which have
   no unit ambiguity.
6. **Whether a per-node `performance` figure exists at all**, on any firmware.
   On this build the value is static everywhere and no block exposes CPU or
   memory, so the answer here is "no route found" rather than "not looked for".
7. **Other models and firmware builds.** Everything is one E4R mesh on one
   build, in AP mode. Record model plus firmware for any device a finding is
   confirmed on. Block ids in particular are firmware-internal and should not be
   assumed stable across models.

## 11. Tooling

Three scripts under `scripts/` implement and exercise this specification. They
are diagnostic tools, not shipped integration code. See
[`../scripts/README.md`](../scripts/README.md).

| File | Purpose |
| --- | --- |
| `scripts/deco_protocol.py` | A working async client: TLS context, crypto primitives, the login/logout handshake, the AES+RSA envelope, transparent re-login, and read-only accessors. The reference implementation to port from |
| `scripts/deco_probe.py` | Runs the protocol against real hardware and checks this document claim by claim, exiting non-zero on a regression. Redacts MACs, IPs, names and SSIDs by default |
| `scripts/deco_open_questions.py` | One-off investigations behind the answers in 10.1: session eviction, the session limit, `signal_level` range, per-node performance, mode surfaces |

```bash
uv run python scripts/deco_probe.py                   # full conformance report
uv run python scripts/deco_probe.py --check crypto    # offline, no router needed
uv run python scripts/deco_probe.py --check liveness   # is performance still static?
uv run python scripts/deco_probe.py --dump            # raw payloads -> scripts/out/
uv run python scripts/deco_open_questions.py all      # the quick investigations
```

Opt-in checks, because each costs more than a read: `--check encoding` and
`--check soak` log in again, `--check rates` downloads tens of MiB to settle the
rate units, and `deco_open_questions.py sessions` / `session-idle` are invasive
or slow respectively.

> **Run only one client at a time.** Because every login evicts the incumbent
> session (6.2), two of these tools running concurrently will fight, and with
> automatic re-login they will do so indefinitely. Unauthenticated `GET`s of
> `/config/*.json` and the module JS create no session and are safe alongside
> anything -- which is how the Router/AP mode comparison in 7.1 was done without
> changing a setting.

## 12. Handling captures safely

HAR and pcap captures of this interface contain the admin password material,
live session ids, the RSA modulus, and the full household device inventory.
They are gitignored (`*.har`, `*.pcap`, `*.pcapng`, `scripts/in/`,
`scripts/out/`). Keep them out of commits, and redact session ids, MACs, IPs,
SSIDs and client names before pasting anything into docs or issues.
