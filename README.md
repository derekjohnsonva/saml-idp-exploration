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

Specifically, it is designed to demonstrate how we can sidestep traditional auth
in Okta by using our own Identity Provider.

## Features

- **Persistent Certificates**: Generated certificates are saved to disk and
  reused between restarts
- **SP and IdP-initiated SSO**: Supports both authentication flows
- **Certificate Downloads**: Exposes endpoints to download signing certificates
- **User Attribute Mapping**: Provides required attributes to SPs like Okta based on user database
- **Friendly Landing Page**: Includes links to important endpoints
- **Detailed Logging**: Includes comprehensive logging for debugging
- **Okta Compatibility**: Specifically configured to work with Okta as an SP

## Getting Started

### Prerequisites

- Rust and Cargo (latest stable version)
- OpenSSL development packages. This is used by the [samael](https://github.com/njaremko/samael) package for signing responses. To install, run

```bash
apt-get update && \
   apt-get install -y \
   libxml2-dev \
   libxmlsec1-dev \
   clang \
   libltdl-dev \
   pkg-config \
```

_Optional_ - You can use a [devcontainer](https://code.visualstudio.com/docs/devcontainers/containers) to work on and run this project. This will simplify requirements management. While trying to build on a mac, I experienced a lot of issues related to `xmlsec`. The [devcontainer.json](.devcontainer/devcontainer.json) file is available and will get you running with minimal troubleshooting required.

### Running the Application

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

When using IdP-initiated flow, provide a `user_id` that exists in the user database (e.g., `john.doe`).

## Configuration

### Environment Variables

The application uses environment variables for configuration. Create a `.env` file in the root directory based on the provided `.env_example`:

```env
IDP_ENTITY_ID=https://your-idp-url.example.com
SP_ENTITY_ID=https://your-sp-entity-id.example.com
SP_ACS_URL=https://your-sp-acs-url.example.com
USER_DATABASE_PATH=users.yaml
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
```

**Required environment variables:**

- `IDP_ENTITY_ID`: Your Identity Provider's entity ID
- `SP_ENTITY_ID`: Service Provider's entity ID (e.g., from Okta)
- `SP_ACS_URL`: Service Provider's Assertion Consumer Service URL
- `USER_DATABASE_PATH`: Path to your user database YAML file

**Optional environment variables:**

- `SERVER_HOST`: Host address to bind the server to (defaults to 127.0.0.1)
- `SERVER_PORT`: Port to run the server on (defaults to 8080)

All required environment variables must be set for the application to start successfully. The application will exit with an error if any required variable is missing.

### User Database

The application now uses a YAML file (`users.yaml`) as a user database. Each user entry contains:

- `user_id`: Unique identifier for the user
- `first_name`: User's first name
- `last_name`: User's last name
- `email`: User's email address
- `mobile_phone`: (Optional) User's mobile phone number
- `attributes`: (Optional) Additional custom attributes as key-value pairs

Example of a user entry:

```yaml
- user_id: john.doe
  first_name: John
  last_name: Doe
  email: john.doe@example.com
  mobile_phone: "555-123-4567"
  attributes:
    department: Engineering
    role: Developer
```

Users are validated during SSO requests, and only users defined in the database can authenticate.

## Known Issues

Currently, there is a bug in the [Samael](https://github.com/caicancai/samael) library that causes all builds that require the `xmlsec` feature flag to fail. This bug is documented [here](https://github.com/njaremko/samael/issues/69). Because of this, we are using a forked and modified version of the Samael library that I created [here](https://github.com/derekjohnsonva/samael). Hopefully, this issue will be resolved. Additionally, there is a merge request that will greatly improve SAML response signing by reducing the use for the [rust-xmlsec](https://github.com/voipir/rust-xmlsec) library.

## Acknowledgements

- [Samael](https://github.com/caicancai/samael) - SAML library for Rust
