# SAML IdP

I was having a hard time configuring IdP's (Shibboleth) to work for my specific
use case.
Because of this, I am making my own, super simple IdP.

## Instructions

Start running with hot module reload using

```bash
watchexec -e rs -r cargo run
```

By default, it will log at the INFO level.
If you want more detailed logs, you can set the RUST_LOG environment variable:
`RUST_LOG=debug cargo run`

For even more verbose logging:
`RUST_LOG=trace cargo run`
