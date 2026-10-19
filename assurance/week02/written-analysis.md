# Written analysis — Threat Model v1.0

CPS 5981 01, Week 02

**Fork:** _not answered_
**Commit:** _not answered_
**Visibility:** _not answered_
**Collaborators:** none
**Declared AI use:** none

## 1. Which of your abuse cases are supported by evidence you gathered, and which rest on reasoning about the design?

Case 2 and Case 4 have some support from what I observed because I confirmed that the application accepts search requests and responds with product information, although I did not perform a denial-of-service test. The missing CSP finding also provides evidence of a security weakness in the web application. The other abuse cases mainly rest on reasoning about the design because I did not directly test account manipulation, session-token misuse, unauthorized staff access, or malicious file uploads.

## 2. What does STRIDE not surface for this target?

STRIDE does not clearly surface business-logic problems or situations where an authorized user misuses a legitimate function. For example, a customer or staff member could use a function in a way that is technically allowed but causes an unintended business impact. STRIDE also does not by itself show how serious the impact would be to customers or the business.

## 3. Which trust boundary are you least confident about, and what would settle it?

I am least confident about the application server to data store boundary. I observed the application using product information, but I did not inspect the database configuration, permissions, or queries. Inspecting the database access controls and the application's database code would give me more confidence about this boundary.

## 4. If this system had twice as many users, which case moves up your list, and why?

Case 4, involving an automated client sending repeated requests, would move up my list. With twice as many users, the application would already have more normal traffic, so automated repeated requests could consume more resources and make it harder for normal customers to use the shop.
