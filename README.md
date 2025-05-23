# Digital Credentials API Matcher implementation
This crate provides a matcher implementation for the Digital Credentials API written in Rust.

## Build
To build use the following command:
```
cargo build --release --target wasm32-wasip1
```

You might need to add the `wasm32-wasip1` target:
```
rustup target add wasm32-wasip1
```

> Note: The `wasi` runtime used by google chrome seems to not expose randomness through wasi. This means any construct relaying on randomness (e.g. `HashMap`) will silently fail. If the matcher does not what you'd expect, have a look at the import table (e.g. convert the wasm to a wat an check the first few lines) and see if the `random_get` function is imported.

## Usage
The `default` feature implements the same credential format as the https://github.com/digitalcredentialsdev/CMWallet matcher, with an addition of an optional top level `debug` field. If the `debug` field is set in the credential database, the matcher will put error messages as "found-credentials" to give some UI hint on what went wrong.
