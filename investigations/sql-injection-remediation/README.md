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