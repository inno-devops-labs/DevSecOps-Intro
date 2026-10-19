# Abuse cases

Threat Model v1.0 — CPS 5981 01, Week 02

**Mission:** Customers can safely use the online shop to browse products and complete purchases.

Each case names an actor, what they can already do, what they do with it, what stops being
true for the mission, and what that costs.

## Case 1

- **Actor:** Customer with an ordinary account
- **Capability:** Can log in and use normal customer functions
- **Action sequence:** Changes information associated with another user's account through manipulated requests
- **Mission effect:** Customers cannot trust that their account information remains under their control
- **Impact:** Loss of customer trust and possible account compromise

Because Customer with an ordinary account can Changes information associated with another user's account through manipulated requests, Customers cannot trust that their account information remains under their control occurs, costing Loss of customer trust and possible account compromise.

## Case 2

- **Actor:** Someone with no account
- **Capability:** Can access the public website and search for products
- **Action sequence:** Sends a large number of automated search requests to the application
- **Mission effect:** Customers cannot reliably browse products
- **Impact:** Service disruption and lost customer access

Because Someone with no account can Sends a large number of automated search requests to the application, Customers cannot reliably browse products occurs, costing Service disruption and lost customer access.

## Case 3

- **Actor:** Member of staff doing their job
- **Capability:** Can access administrative functions provided for their job
- **Action sequence:** Uses their authorized access to view or change more customer or product information than necessary
- **Mission effect:** Customers cannot trust that their information is only accessed for legitimate business purposes
- **Impact:** Privacy loss and possible exposure of customer information

Because Member of staff doing their job can Uses their authorized access to view or change more customer or product information than necessary, Customers cannot trust that their information is only accessed for legitimate business purposes occurs, costing Privacy loss and possible exposure of customer information.

## Case 4

- **Actor:** Automated client
- **Capability:** Can send requests to the public web application
- **Action sequence:** Automatically submits repeated requests to search and retrieve product information
- **Mission effect:** Customers cannot reliably use the shop when application resources are consumed by automated requests
- **Impact:** Reduced availability and disruption to customers

Because Automated client can Automatically submits repeated requests to search and retrieve product information, Customers cannot reliably use the shop when application resources are consumed by automated requests occurs, costing Reduced availability and disruption to customers.

## Case 5

- **Actor:** Customer with an ordinary account
- **Capability:** Can log in and receive a session token
- **Action sequence:** Attempts to use a session token or account information belonging to another customer
- **Mission effect:** Customers cannot trust that only they can access their accounts
- **Impact:** Unauthorized account access and loss of customer trust

Because Customer with an ordinary account can Attempts to use a session token or account information belonging to another customer, Customers cannot trust that only they can access their accounts occurs, costing Unauthorized account access and loss of customer trust.

## Case 6

- **Actor:** Someone with no account
- **Capability:** Can access public product information and interact with the website
- **Action sequence:** Attempts to upload a malicious or inappropriate file through an available upload function
- **Mission effect:** Customers cannot trust that the shop's stored content is safe and appropriate
- **Impact:** Potential security risk, inappropriate content, or damage to the application

Because Someone with no account can Attempts to upload a malicious or inappropriate file through an available upload function, Customers cannot trust that the shop's stored content is safe and appropriate occurs, costing Potential security risk, inappropriate content, or damage to the application.
