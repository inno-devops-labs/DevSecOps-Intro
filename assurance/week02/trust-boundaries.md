# Trust boundaries

Threat Model v1.0 — CPS 5981 01, Week 02

Boundaries are derived from the zone each element sits in. A flow whose endpoints are in
different zones crosses one. Direction matters: the two directions between the same pair of
zones are separate boundaries, because the assumption being made differs.

Crossing flows: 4  —  distinct boundaries: 3

## 1. User's browser → Application server

**What crosses:** email address and password; search terms 

**Why this is a real boundary:** This is a real boundary because data is coming from the user's browser into the application server. The server has to accept and process information that could have been changed or manipulated by the user. The server is taking the submitted email address, password, and search terms on trust and must validate them before using them.

**Confidence, and what would settle it:** I am moderately confident because I observed the login and search functions, but I did not inspect the application's source code. Inspecting the server-side validation and authentication code and testing how it handles modified input would settle this.

## 2. Application server → User's browser

**What crosses:** session token in a cookie

**Why this is a real boundary:** This is a real boundary because the application server is sending a session token to the user's browser. The browser has to accept the token and use it to maintain the user's logged-in session. The browser is trusting that the server provided a valid session token.

**Confidence, and what would settle it:** I am moderately confident because I observed the login process, but I did not inspect the session-management code or the cookie settings. Inspecting the cookie attributes and session-management code would settle this.

## 3. Application server → Data store

**What crosses:** product records

**Why this is a real boundary:** This is a real boundary because the application server sends product records to a separate data store. The data store is trusting the application to send valid and authorized data. If the application is compromised, an attacker could potentially cause unauthorized changes to stored data.

**Confidence, and what would settle it:** I am moderately confident because the application clearly uses stored product information, but I did not inspect the database configuration or permissions. Inspecting the database access controls, permissions, and application database queries would settle this.
