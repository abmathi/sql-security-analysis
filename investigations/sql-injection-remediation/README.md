# SQL Injection Exploitation and Remediation — Application Security Investigation

## Executive Summary

This investigation documents an authorized SQL injection security exercise involving vulnerable database queries, information disclosure, and application-level remediation.

The investigation included examining SQL injection behavior, using UNION-based queries to retrieve database information, enumerating database structure, and independently testing vulnerable Python application code.

The independent security assessment extended the guided exercise by examining how unsafe SQL query construction could permit user-controlled input to alter database operations.

The remediation phase focused on parameterized queries and validation of the modified application behavior.

The objective was to demonstrate practical application security analysis, controlled vulnerability testing, secure database access, and evidence-based remediation.

## Investigation Scenario

A database-backed application processes user input and constructs SQL queries to retrieve information.

When an application incorporates untrusted input directly into SQL statements, an attacker may be able to manipulate the intended query structure.

The investigation examines this vulnerability class in an authorized training environment.

The guided exercises explore SQL injection techniques and their potential effects on database confidentiality.

The independent investigation focuses on identifying vulnerable query construction in Python and applying a safer database-query implementation.

This report documents the observed results of controlled testing rather than exploitation of a production application.

## Investigation Scope

| Component | Investigation Purpose |
| --- | --- |
| SQL database | Examine query execution and database responses |
| UNION-based SQL injection | Investigate unintended data extraction |
| Database schema enumeration | Identify accessible database structure |
| Python application code | Analyze vulnerable SQL query construction |
| User-controlled input | Examine how untrusted values affect queries |
| Parameterized queries | Separate SQL instructions from supplied data |
| Independent validation | Compare vulnerable and remediated behavior |
| Screenshot evidence | Support technical findings and conclusions |

### Investigation Objectives

1. Examine the SQL injection scenario and affected database operations.
2. Demonstrate UNION-based data extraction in the authorized environment.
3. Investigate database schema enumeration.
4. Identify the security implications of exposed database information.
5. Analyze vulnerable SQL query construction in Python.
6. Perform an independent SQL injection test.
7. Modify the vulnerable code using parameterized queries.
8. Compare observed behavior before and after remediation.
9. Document remaining limitations and applicable secure coding practices.

## Evidence Sources and Methodology

### Evidence Sources

The investigation uses four screenshots collected during the original IBM security exercises and independent testing.

The preserved project notes provide the scenario, exercise instructions, investigation activities, and observed results.

### Investigation Methodology

| Phase | Analyst Activity |
| --- | --- |
| Vulnerability analysis | Examine unsafe SQL query construction |
| Controlled exploitation | Test UNION-based SQL injection behavior |
| Information disclosure assessment | Review retrieved data and database structure |
| Independent testing | Evaluate vulnerable Python application code |
| Remediation | Apply parameterized database queries |
| Verification | Compare vulnerable and remediated results |
| Reporting | Document findings, security implications, and evidence limitations |

### Evidence Standards

All testing was conducted in an authorized lab environment.

The investigation distinguishes between the behavior demonstrated during testing and broader risks associated with SQL injection.

A successful SQL injection test does not independently establish that the same technique would work against other databases or applications.

Likewise, parameterizing the tested query does not establish that an entire application is free of SQL injection vulnerabilities.

The technical findings will be supported by the preserved screenshots and independent exercise documentation.

## Investigation Organization

The report will document four findings:

1. UNION-Based SQL Injection and Data Extraction
2. Database Schema Enumeration
3. Independent SQL Injection Exploitation
4. Parameterized Query Remediation and Validation

The final sections will summarize security implications, remediation outcomes, evidence limitations, skills demonstrated, and supporting screenshots.

## Investigation Findings

### Finding 1 — UNION-Based SQL Injection and Data Extraction

#### Investigation Context

The IBM SQL injection exercise simulated an online store with a product search feature backed by a MySQL database.

The lab environment contained two tables:

- `products` — Product names, descriptions, and prices.
- `users` — Usernames, passwords, and email addresses.

The objective was to demonstrate how unsafe SQL query construction could allow information from the `users` table to appear in a query intended to retrieve product information.

The exercise used the database `vulnerable_db` and the phpMyAdmin SQL interface.

#### Vulnerable Query Construction

The lab described a product search query that incorporated user-controlled input directly into a SQL statement:

```sql
SELECT * FROM products WHERE name = '$productName';
```

When untrusted input is concatenated into the SQL statement without proper parameterization, it can potentially change the intended query structure.

The lab supplied a UNION-based injection example that appended a second SELECT statement targeting the `users` table.

The preserved screenshot showed the following query executed in phpMyAdmin:

```sql
SELECT name, description, price
FROM products
WHERE name = 'Laptop'
UNION
SELECT username, password, email
FROM users;
```

The query combined three selected columns from the `products` table with three columns from the `users` table.

Both SELECT statements returned the same number of columns, allowing their results to be combined.

#### Observed Query Results

The screenshot displayed the message:

**Showing rows 0 - 3 (4 total, Query took 0.0007 seconds.)**

The results contained one product record and three user records.

| Result Type | First Column | Second Column | Third Column |
| --- | --- | --- | --- |
| Product | `Laptop` | High performance laptop | `999.99` |
| User | `alice` | `password123` | `alice@example.com` |
| User | `bob` | `qwerty` | `bob@example.com` |
| User | `charlie` | `letmein` | `charlie@example.com` |

![UNION-based SQL query exposing user records](evidence/01-union-data-extraction.png)

*Figure 1 — phpMyAdmin results showing a UNION-based query combining product information with three user records from the `users` table.*

The displayed columns retained the labels `name`, `description`, and `price` from the first SELECT statement.

However, the later rows contained data from the `users` table.

As a result, the `description` column displayed passwords and the `price` column displayed email addresses for those rows.

The screenshot confirmed that the SQL statement returned user information alongside product information.

#### Security Impact Analysis

The result illustrated how UNION-based SQL injection can compromise database confidentiality when an application permits untrusted input to alter SQL statements.

A product lookup should not ordinarily expose authentication-related records from a separate user table.

In the demonstrated query, the UNION operation allowed data from `users` to appear in the product-query result set.

The lab's example database stored passwords in plaintext, increasing the sensitivity of the disclosed records.

A production application should store passwords using an appropriate password-hashing algorithm rather than plaintext.

The exercise also highlighted why database permissions matter.

An application database account should not possess unnecessary access to sensitive tables.

Restricting database privileges can limit the potential impact of certain injection vulnerabilities, although it does not replace secure query construction.

#### Evidence Interpretation

The preserved screenshot was captured from phpMyAdmin.

It directly established that the combined SQL query executed and returned four rows, including three records from the `users` table.

The screenshot did not show a browser-based product search form, an HTTP request carrying an injection payload, or the application's query-construction code.

Therefore, the observed result demonstrates the database behavior underlying the lab's UNION-based SQL injection scenario.

It should not be interpreted as independent proof of exploitation through a deployed web application's input field.

#### Analyst Assessment

**Assessment: UNION-based SQL query successfully returned user information alongside product data in the authorized MySQL lab.**

The query returned four rows, including one product record and three user records containing usernames, plaintext passwords, and email addresses.

This demonstrated the confidentiality impact that could result if a vulnerable application allowed user input to alter the intended product-search query.

The preserved screenshot confirms database query behavior; it does not independently establish application-level injection delivery.

The next finding examines database schema enumeration and the information that can be discovered about underlying database structures.

### Finding 2 — Database Schema Enumeration

#### Investigation Context

Following the UNION-based data extraction exercise, the next phase examined how database metadata could be retrieved using a similar SQL technique.

The objective was to identify database tables through the MySQL `INFORMATION_SCHEMA` metadata interface.

The exercise used the existing `vulnerable_db` database, containing the `products` and `users` tables.

The security concern was that knowledge of internal database structure could help an attacker identify potentially sensitive data sources.

#### Database Metadata Enumeration

MySQL provides the `INFORMATION_SCHEMA` database, which contains metadata describing database objects, including tables and columns.

The `information_schema.tables` view exposes information about database tables visible to the querying account.

The original exercise demonstrated how a UNION operation could combine ordinary application data with table names retrieved from this metadata view.

The preserved screenshot displayed the following statement in phpMyAdmin:

```sql
SELECT name, description, price
FROM products
WHERE name = 'Laptop'
UNION
SELECT table_name, NULL, NULL
FROM information_schema.tables
WHERE table_schema = 'vulnerable_db';
```

The first SELECT statement retrieved information from the `products` table.

The second SELECT statement retrieved table names from `information_schema.tables`, restricted to the `vulnerable_db` schema.

The UNION operator combined the two result sets.

Both SELECT statements returned three expressions, preserving column-count compatibility.

The two NULL expressions acted as placeholders for the second and third output columns.

#### Observed Enumeration Results

The phpMyAdmin interface displayed:

**Showing rows 0 - 2 (3 total, Query took 0.0023 seconds.)**

The query returned three rows:

| Result Type | Name | Description | Price |
| --- | --- | --- | --- |
| Product record | `Laptop` | High performance laptop | `999.99` |
| Database table | `products` | NULL | NULL |
| Database table | `users` | NULL | NULL |

![MySQL database schema enumeration](evidence/02-database-schema-enumeration.png)

*Figure 2 — phpMyAdmin showing a UNION-based query against `information_schema.tables`, revealing the `products` and `users` tables in database `vulnerable_db`.*

The first row contained the expected product information.

The remaining two rows disclosed table names from the target database.

The result demonstrated that metadata about the database structure could be included in the output of a query originally intended to retrieve product information.

The identified tables were:

- `products` — the application's product information table.
- `users` — the table containing user account information in the lab environment.

The screenshot did not display column names or the internal definitions of either table.

#### Security Impact Analysis

Database schema enumeration can assist an attacker in understanding how an application stores and organizes information.

Identifying a `users` table may indicate that authentication-related or account-related information is present in the database.

Knowledge of table names can inform additional testing for unauthorized data access.

In this exercise, enumeration was particularly relevant because Finding 1 demonstrated that the `users` table contained usernames, plaintext passwords, and email addresses.

Together, the two findings illustrated how an unsafe query interface could expose both database records and structural metadata.

However, knowing a table name does not automatically grant access to its contents.

The actual impact of SQL injection depends on the vulnerable query, database permissions, application behavior, and accessible database objects.

#### Evidence Interpretation

The screenshot was captured in phpMyAdmin, where the UNION-based SQL statement was executed directly.

It established that the query returned metadata identifying the `products` and `users` tables within `vulnerable_db`.

The screenshot did not independently show the SQL statement being injected through a web application input field.

It also did not establish that additional schemas, tables, or columns were enumerated.

The result therefore demonstrates database metadata disclosure through the executed SQL statement, consistent with the lab's SQL injection scenario.

#### Defensive Considerations

The exercise highlighted several important application security controls.

**Parameterized queries**

Applications should treat user-supplied values as data rather than allowing them to alter SQL syntax.

Proper parameterization is the primary remediation for SQL injection in supported query contexts.

**Least-privilege database access**

Application database accounts should receive only the permissions required for their intended operations.

Restricting unnecessary database access can reduce the impact of a successfully exploited vulnerability.

**Error and response handling**

Applications should avoid unnecessarily exposing internal database details in user-facing errors or responses.

However, suppressing errors alone does not prevent SQL injection.

**Secure application testing**

Security testing should examine whether user-controlled input can alter SQL query structure.

Database schema enumeration may be one indicator that a query is executing unintended SQL instructions.

#### Analyst Assessment

**Assessment: UNION-based SQL query disclosed the names of two tables in the authorized MySQL lab database.**

The preserved screenshot showed a successful query against `information_schema.tables`, restricted to schema `vulnerable_db`.

The output contained three rows: the original `Laptop` product record and the table names `products` and `users`.

This demonstrated how database metadata could be retrieved through a UNION-based query.

The screenshot confirmed direct database query execution, but did not independently prove injection through a deployed application's input field.

The next investigation phase examines independent testing against vulnerable Python application code.

### Finding 3 — Independent SQL Injection Exploitation

#### Investigation Context

After completing the guided SQL injection exercises, I developed a separate local Python application to independently reproduce the vulnerability.

The objective was to determine whether unsafe SQL query construction could allow user-controlled input to alter database query logic and access unintended records.

This investigation used a deliberately vulnerable Python script, a local SQLite database, and interactive terminal input.

Unlike the guided phpMyAdmin exercises, the independent application accepted a product name from the user and incorporated that value into a SQL statement.

This allowed direct testing of the application's input-handling behavior.

#### Independent Lab Environment

The test environment consisted of:

| Component | Configuration |
| --- | --- |
| Operating environment | Kali Linux |
| Application language | Python |
| Database engine | SQLite |
| Vulnerable application | `vulnerable_search.py` |
| Application input | Interactive product-name prompt |
| Intended database table | `products` |
| Additional database table | `users` |
| Vulnerable behavior | Dynamic SQL construction using an f-string |

The application was designed to retrieve a product record based on a supplied name.

The local database also contained user records for evaluating the impact of unauthorized data retrieval.

#### Vulnerable SQL Query Construction

The Python application constructed its SQL statement using an f-string:

```python
query = f"SELECT id, name, price FROM products WHERE name = '{search}'"
```

The variable `search` contained the value supplied at the product-name prompt.

Because the value was inserted directly into the SQL statement, characters supplied by the user could become part of the executable query syntax.

The application did not separate user-controlled data from SQL instructions.

This unsafe query-construction pattern was the root cause of the vulnerability.

#### Test 1 — Boolean-Based SQL Injection

The first test used a Boolean condition to alter the product query.

I executed the application:

```bash
python3 vulnerable_search.py
```

At the prompt, I supplied:

```text
Laptop' or '1 = 1
```

The application displayed the constructed query:

```sql
SELECT id, name, price
FROM products
WHERE name = 'Laptop' or '1 = 1'
```

The condition `'1 = 1'` evaluates to true.

As a result, the WHERE clause no longer restricted the query to the requested laptop record.

The terminal returned:

```text
(1, 'Laptop', 999.99)
(2, 'Smartphone', 699.99)
(3, 'Tablet', 299.99)
```

The application returned all three product records.

This confirmed that user-controlled input successfully changed the query's selection logic.

#### Test 2 — UNION-Based SQL Injection

The second test investigated whether the vulnerable application could retrieve records from the `users` table.

I ran the same application again and supplied:

```text
Laptop' union select * from 'users
```

The resulting SQL statement was:

```sql
SELECT id, name, price
FROM products
WHERE name = 'Laptop' union select * from 'users'
```

The injected UNION operation combined the product query with a SELECT statement targeting the `users` table.

In this test database, both SELECT statements returned three columns, allowing the result sets to be combined.

The terminal displayed:

```text
(1, 'Laptop', 999.99)
(1, 'alice', 'password123')
(2, 'bob', 'qwerty')
(3, 'charlie', 'letmein')
```

The first row contained the requested product.

The remaining three rows contained user account information from the additional table.

This demonstrated that the vulnerable application retrieved records outside the intended product-search scope.

![Independent SQL injection exploitation in Python](evidence/03-independent-sqli-exploitation.png)

*Figure 3 — Kali Linux terminal showing two successful SQL injection tests against `vulnerable_search.py`: Boolean-based query manipulation returning all products and UNION-based extraction revealing three user records.*

#### Evidence Interpretation

The screenshot documented two successful executions of `vulnerable_search.py`.

The first execution demonstrated Boolean manipulation of a SQL WHERE clause.

The second demonstrated UNION-based extraction of user records from a separate database table.

The displayed SQL statements were consistent with direct interpolation of the supplied input values.

Unlike the earlier guided phpMyAdmin screenshots, this evidence showed the injection values being entered into an application prompt and subsequently affecting the application's query results.

The evidence supports successful exploitation of the deliberately vulnerable local Python application.

The screenshot did not establish exploitation of an externally hosted service, a production database, or an HTTP-based web application.

#### Security Impact Analysis

The independent tests demonstrated two distinct effects of unsafe SQL query construction.

**Query logic manipulation**

The Boolean-based input caused the application to return records beyond the requested product.

This demonstrated how user input could change the meaning of an application's database query.

**Unauthorized data retrieval**

The UNION-based input caused the application to retrieve usernames and plaintext passwords from the `users` table.

This illustrated the potential confidentiality impact of SQL injection when an application's database connection can access sensitive records.

In a production environment, the consequences could include disclosure of sensitive information or other unauthorized database operations, depending on the database account's permissions and the vulnerable query context.

The test database used plaintext passwords for demonstration purposes. Production applications should use appropriate password-hashing mechanisms.

#### Root Cause Analysis

The vulnerability originated from constructing executable SQL statements with untrusted user input.

The affected pattern was:

```python
query = f"SELECT id, name, price FROM products WHERE name = '{search}'"
```

The application treated the supplied product name as part of the SQL source text.

Because the input was not parameterized, SQL operators and expressions supplied by the user could modify the intended query.

The resulting behavior was demonstrated by:

1. An always-true condition causing the query to return every product.
2. A UNION operation causing the query to retrieve records from the `users` table.

The next phase focuses on preventing these behaviors using parameterized SQL queries.

#### Analyst Assessment

**Assessment: SQL injection vulnerability independently reproduced in a local Python and SQLite application.**

The first test demonstrated that Boolean-based input modified the product search query and returned all three product records.

The second test demonstrated that UNION-based input retrieved three user records containing usernames and plaintext passwords.

The screenshot confirmed that both payloads were supplied through the application's interactive product-name prompt and affected the resulting SQL queries.

The root cause was direct interpolation of untrusted input into executable SQL statements.

This established a reproducible vulnerable baseline for the remediation and retesting documented in Finding 4.