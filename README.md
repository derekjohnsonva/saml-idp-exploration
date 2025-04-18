# SAML IdP Demo

A SAML Identity Provider (IdP) implementation built with Rust, using the Samael
lbrary for SAML operations.

## Overview

This project implements a basic SAML 2.0 Identity Provider that can:

- Serve SAML metadata to Service Providers (SPs)
- Handle SP-initiated SAML flows
- Support IdP-initiated SAML flows
- Expose certificate downloads in DER and PEM formats
- Work specifically with Okta as a Service Provider

The application is designed as a demonstration tool to understand SAML
authentication flows and to test SAML integration with Service Providers.

## Features

- **Persistent Certificates**: Generated certificates are saved to disk and
reused between restarts
- **SP and IdP-initiated SSO**: Supports both authentication flows
- **Certificate Downloads**: Exposes endpoints to download signing certificates
- **User Attribute Mapping**: Provides required attributes to SPs like Okta
- **Friendly Landing Page**: Includes links to important endpoints
- **Detailed Logging**: Includes comprehensive logging for debugging
- **Okta Compatibility**: Specifically configured to work with Okta as an SP

## Getting Started

### Prerequisites

- Rust and Cargo (latest stable version)
- OpenSSL development packages

### Running the Application

1. Clone the repository

```bash
git clone https://github.com/yourusername/saml-idp-exploration.git
cd saml-idp-exploration
```

1. Build the project

```bash
cargo build
```

1. Run the server

```bash
cargo run
```

For development with hot reloading:

```bash
watchexec -e rs -r cargo run
```

### Logging

By default, it will log at the INFO level.

If you want more detailed logs, you can set the RUST_LOG environment variable:

```bash
RUST_LOG=debug cargo run
```

For even more verbose logging:

```bash
RUST_LOG=trace cargo run
```

### Endpoints

- `/` - Landing page with links to key functions
- `/metadata` - SAML metadata for this IdP
- `/certificate/pem` - Download the signing certificate in PEM format
- `/certificate/der` - Download the signing certificate in DER format
- `/sso` - SP-initiated SSO endpoint
- `/idp-init` - IdP-initiated SSO endpoint

When using IdP-initiated flow, use a username with a period (e.g., `john.doe`)
to get proper first and last name extraction.

## Configuration

Edit `src/config.rs` to modify:

- The IdP's entity ID
- SP settings (entity ID and ACS URL)
- Whether assertions should be signed

## Acknowledgements

- [Samael](https://github.com/caicancai/samael) - SAML library for Rust

