# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AXIAM (Access eXtended Identity and Authorization Management) is an open-source IAM solution built with **Rust** and **SurrealDB**, targeting microservices and IoT environments. It aims to compete with Keycloak, Okta, and Auth0, with a focus on security compliance (GDPR, CyberSecurity Act, ISO27001, OWASP ASVS, OWASP Cumulus).

## Technology Stack

- **Backend**: Rust
- **Database**: SurrealDB (distributed)
- **Frontend**: React
- **API**: RESTful, documented with OpenAPI
- **Deployment**: Docker, Kubernetes
- **SDKs**: Planned for Rust, Python, TypeScript, Java, C#, Go

## Core Domain Model

- **Users** authenticate via username/password, social login, or MFA
- **Roles** are collections of permissions, can be global or resource-specific, and support inheritance through resource hierarchies
- **Permissions** define actions on resources; **scopes** provide sub-resource granularity
- **Resources** are organized hierarchically; role assignments on parent resources cascade to children unless overridden
- **Service accounts** are used for automated/machine-to-machine authentication
- **Federation** via SAML and OpenID Connect enables cross-domain SSO

## Authentication & Authorization Protocols

- OAuth2 for authorization
- OpenID Connect for authentication/identity
- MFA support

## Development Process

- Each roadmap step and artifact requires a **signed commit** before proceeding to the next
- Use **feature branches** for different stages; keep main clean
- Development artifacts (design docs, roadmap, etc.) go in the `claude_dev/` directory as Markdown files
- CI/CD via GitHub Actions (build, test, deploy pipelines)

## Build & Run (once scaffolded)

```bash
cargo build            # Build the project
cargo test             # Run all tests
cargo test <test_name> # Run a single test
cargo run              # Run the application
```
