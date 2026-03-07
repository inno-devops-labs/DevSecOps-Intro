# SAST Analysis Report -- OWASP Juice Shop (Semgrep)

## SAST Tool Effectiveness

### Types of Vulnerabilities Detected

The **Semgrep** Static Application Security Testing (SAST) tool detected
multiple categories of security vulnerabilities within the analyzed
Juice Shop codebase.

1.  **SQL Injection**
    -   Detected where user-controlled input is concatenated directly
        into SQL queries executed through Sequelize.
    -   Attackers could manipulate database queries and access or modify
        sensitive data.
2.  **Cross-Site Scripting (XSS)**
    -   Occurs when user-controlled data is injected into HTML or
        `<script>` contexts without proper sanitization.
3.  **Path Traversal / Arbitrary File Access**
    -   Express routes pass user-controlled input to `res.sendFile()`
        without validation.
4.  **Open Redirect**
    -   User-controlled URLs are passed directly to `res.redirect()`.
5.  **Hardcoded Secrets**
    -   Cryptographic secrets or credentials embedded directly in the
        source code.
6.  **Unsafe Code Execution**
    -   Usage of `eval()` with potentially user-controlled input.
7.  **HTML Attribute Injection**
    -   Template variables used without quotes inside HTML attributes.
8.  **Directory Listing Exposure**
    -   Express configuration allows directory indexing, exposing
        internal files.

------------------------------------------------------------------------

### Coverage Evaluation

The Semgrep scan analyzed the **OWASP Juice Shop source code** located
under `/src` inside the container.

**Rulesets used:**

-   `p/security-audit`
-   `p/owasp-top-ten`

**Results Summary**

-   Total findings: **25**
-   Severity classification: **Blocking**
-   Multiple backend and frontend files affected.

The scan covered:

-   Backend Express routes (`/src/routes`)
-   Database query logic
-   Angular frontend templates
-   Server configuration files
-   Security utilities

This indicates strong coverage across both **server-side and client-side
code**.

------------------------------------------------------------------------

# Critical Vulnerability Analysis

## 1. SQL Injection

**Vulnerability Type:** SQL Injection\
**Severity:** Blocking\
**File:** `/src/routes/login.ts`\
**Line:** 34

Example vulnerable code:

    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })

**Description**

User-controlled input (`req.body.email` and `req.body.password`) is
concatenated directly into a SQL query.

**Impact**

-   Authentication bypass
-   Unauthorized database access
-   Data manipulation

------------------------------------------------------------------------

## 2. Path Traversal / Arbitrary File Access

**Vulnerability Type:** Path Traversal\
**Severity:** Blocking\
**File:** `/src/routes/fileServer.ts`\
**Line:** 33

Example vulnerable code:

    res.sendFile(path.resolve('ftp/', file))

**Description**

User input is passed directly to `sendFile()` without validation.

**Impact**

-   Access to sensitive files
-   Disclosure of configuration data
-   Potential credential leakage

------------------------------------------------------------------------

## 3. Hardcoded JWT Secret

**Vulnerability Type:** Hardcoded Secret\
**Severity:** Blocking\
**File:** `/src/lib/insecurity.ts`\
**Line:** 56

Example vulnerable code:

    export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })

**Description**

Cryptographic key material is embedded directly in the application
source code.

**Impact**

-   Attackers could forge authentication tokens
-   Unauthorized access to protected resources

------------------------------------------------------------------------

## 4. Unsafe Code Execution (eval)

**Vulnerability Type:** Unsafe Code Execution\
**Severity:** Blocking\
**File:** `/src/routes/userProfile.ts`\
**Line:** 62

Example vulnerable code:

    username = eval(code)

**Description**

The `eval()` function executes arbitrary JavaScript code contained in
the variable.

**Impact**

-   Remote Code Execution
-   Full application compromise

------------------------------------------------------------------------

## 5. Open Redirect

**Vulnerability Type:** Open Redirect\
**Severity:** Blocking\
**File:** `/src/routes/redirect.ts`\
**Line:** 19

Example vulnerable code:

    res.redirect(toUrl)

**Description**

Redirect destination comes from user input without validation.

**Impact**

-   Phishing attacks
-   Redirection to malicious domains

------------------------------------------------------------------------

# Summary

The Semgrep scan identified **25 security findings** across the Juice
Shop project.

The most critical vulnerabilities include:

-   SQL Injection
-   Path Traversal
-   Hardcoded Secrets
-   Unsafe Code Execution
-   Open Redirects

These issues correspond to several categories from the **OWASP Top 10**
and represent significant security risks if left unpatched.