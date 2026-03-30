# 🛡️ Integrating Security Testing into the QA Process: Experience and Practices Based on TryHackMe

From the perspective of a modern QA engineer, security testing is no longer just an exotic skill; it's a necessity. Identifying security defects at the development stage (Shift-Left Testing) is significantly cheaper and more effective than dealing with the aftermath of a real breach. As I deepen my knowledge in cybersecurity, I've found that the methodologies taught on **TryHackMe** perfectly complement the classic QA process.

Below is an exploration of the core types of security tests that any QA engineer can integrate into their daily routine, complete with specific examples, testing techniques, and remediation advice.

![Integrating Security Testing into the QA Process](img.png) ---

## 🏗️ 1. Web Application Testing

This is the most accessible area for QA, where the traditional functional approach intersects with hunting for critical security bugs (based on the OWASP Top 10).

### 1.1 Input Validation & Sanitization
Checking how the system processes special characters. A lack of proper filtering leads to critical vulnerabilities like **SQL Injection (SQLi)** and **Cross-Site Scripting (XSS)**.

* **What it looks like (Examples):**
  * *SQLi payload:* Entering the following into a login field: `admin' OR 1=1 --`
  * *XSS payload:* Entering the following into a comment field: `<script>alert('XSS test')</script>` or `<img src=x onerror=alert(document.domain)>`
* **How QA should test it:**
  * Create a fuzzing list of special characters (`'`, `"`, `<`, `>`, `/`, `;`, `*`).
  * Inject them into all accessible form fields, URL parameters, and search headers.
  * Observe the behavior: does the page crash with a database error (indicator of SQLi), or does the injected script execute in the browser (indicator of XSS)?
* **How to fix it (Advice for Developers):**
  * Use **Prepared Statements (Parameterized Queries)** for database interactions to prevent SQLi.
  * Apply input sanitization and context-aware output encoding (HTML Entity Encoding) before rendering data in the browser to prevent XSS.

### 1.2 Authentication & Session Management
Testing login logic, password recovery processes, and session timeouts.

* **What it looks like (Example):**
  * An attacker intercepts a cookie (e.g., `PHPSESSID=12345abc`) and injects it into their own browser, gaining access to the victim's account without a password (Session Hijacking).
* **How QA should test it:**
  * Log in and copy your Session Token (via DevTools -> Application -> Cookies).
  * Click "Logout".
  * Try to inject the copied token back into the browser and refresh the page. If you are logged back in, this is a critical bug.
  * Verify that the session properly expires after 15-30 minutes of inactivity.
* **How to fix it:**
  * Invalidate (destroy) the session on the server-side immediately upon clicking "Logout".
  * Set the `Secure` flag (transmits only over HTTPS) and the `HttpOnly` flag (prevents access via JavaScript) for all authentication cookies.

### 1.3 Broken Access Control
Verifying the enforcement of the role-based access model. A low-privileged user should never have access to another user's private data or the admin panel.

* **What it looks like (Example):**
  * A standard user sees their profile URL: `https://example.com/api/user?id=105`.
  * They change the ID to `106` (`?id=106`) and can view another user's private data (Insecure Direct Object Reference - IDOR).
  * Alternatively, they manually navigate to `https://example.com/admin_dashboard` and successfully access the admin interface.
* **How QA should test it:**
  * Maintain two test accounts (User A and User B) and one Admin account.
  * Log in as User A, and attempt to perform actions or access URLs strictly intended for User B or the Admin.
* **How to fix it:**
  * Enforce access control checks on the server-side for **every** single request, rather than just hiding UI buttons.

### 1.4 Sensitive Data Exposure
The leakage of sensitive information through unsecured channels or poor API design.

* **What it looks like (Example):**
  * Transmitting a password via a GET request: `http://example.com/login?username=admin&password=secretPassword123` (this data remains in browser histories and ISP logs).
* **How QA should test it:**
  * Open the Network tab in DevTools during authentication or payment processes.
  * Ensure that sensitive data is transmitted via POST methods inside the request body, and that the connection protocol is HTTPS (not HTTP).
* **How to fix it:**
  * Enforce HTTP Strict Transport Security (HSTS) to redirect HTTP traffic to HTTPS.
  * Utilize strong, salted hashing algorithms (like bcrypt) for storing passwords in the database.

---

## 🔐 2. Security Misconfiguration

QA should verify not only the application code but also the infrastructure—how the application and server are configured.

### 2.1 Default Credentials
* **What it looks like:** Leaving default passwords on databases, routers, or CMS admin panels (e.g., `admin/admin`, `root/password`, `tomcat/tomcat`).
* **How QA should test it:** Always attempt to log into the administrative interfaces of third-party system components using standard default credential dictionaries (often found on GitHub).
* **How to fix it:** Disable default accounts before release or force a password change upon the system's first launch.

### 2.2 Directory Browsing
* **What it looks like:** If a user navigates to a folder path (e.g., `https://example.com/assets/images/`), the server displays a file tree instead of a 403 Forbidden page. An attacker might find source code backups here (e.g., `backup.zip`).
* **How QA should test it:** Deliberately remove the filename from a URL (leaving only the directory path) and check the server's response.
* **How to fix it:** Disable Directory Listing in the web server configurations (Apache: `Options -Indexes`, Nginx: `autoindex off;`).

### 2.3 Error Handling
* **What it looks like:** When invalid data is submitted (e.g., letters instead of numbers like `?id=abc`), the server crashes and reveals a Stack Trace: `Uncaught TypeError: mysqli_fetch_assoc()... in /var/www/html/db.php on line 42`. This exposes the technology stack and internal server paths.
* **How QA should test it:** Input invalid data types (Fuzzing) and analyze the resulting error pages (HTTP 500).
* **How to fix it:** Configure Generic Error Pages. Detailed error logs should be written exclusively to internal server files, while the end-user should only see a generic "Something went wrong" message.

---

## 🛠️ 3. Utilizing TryHackMe Tools in the QA Process

To automate and deepen security testing, tools widely covered in TryHackMe modules are ideal. They can easily be repurposed into powerful weapons for a QA engineer.

### 3.1 Nikto (Web Server Scanner)
An excellent command-line tool for quickly scanning a web server for dangerous files, outdated software, and misconfigured headers.

* **How to use it (Command):** `nikto -h http://test-environment.local`
* **QA Value:** Run this after deploying to a staging environment. It will quickly alert you if developers forgot to hide the Apache version or left testing scripts like `info.php` exposed.

### 3.2 Burp Suite (Interception Proxy)
A must-have for any tester (extensively covered in the Web Hacking Fundamentals modules). It acts as a proxy between your browser and the server.

* **How to use it:** 1. Configure your browser to proxy traffic through Burp (usually `127.0.0.1:8080`).
  2. In Burp, ensure "Intercept is ON".
  3. Add an item to your cart on the web app. The request will pause in Burp.
  4. **Manipulation Example:** You spot a parameter like `{"price": "100.00"}`. You change it to `{"price": "0.01"}` and click "Forward".
* **QA Value:** Testing business logic. If the server accepts the manipulated price from the client and processes the transaction, you've found a critical business-logic vulnerability. The server must always validate prices against the database, never trusting client-side input.

### 3.3 OWASP ZAP (Zed Attack Proxy)
A free alternative to Burp Suite that is perfectly suited for automation (QA Automation).

* **How to use it:** It features a robust API. You can launch the "Spider" (a crawler that maps all links) followed by an "Active Scan" (attempting injections into discovered fields).
* **QA Value:** ZAP integrates smoothly into CI/CD pipelines (such as GitLab CI or Jenkins). This allows you to run basic vulnerability scans automatically during every build, blocking the release if critical flaws are detected.

---

### 📝 Conclusion
Implementing security testing does not require a QA engineer to instantly become a professional penetration tester. It is enough to understand the foundational principles (input validation, session management, secure configurations) and integrate these vectors into existing test cases. Utilizing the practical skills gained from platforms like TryHackMe turns an ordinary QA engineer into a true gatekeeper of product quality—protecting not just stability, but the security of the end-users.