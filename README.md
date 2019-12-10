# Ocaml bindings to the Rust crate [`threshold_crypto`](https://crates.io/crates/threshold_crypto)

These bindings allow the use of a high-performance, security audited Rust library
[`threshold_crypto`](https://crates.io/crates/threshold_crypto) in Ocaml.


## Compilation

`opam` should be [installed](https://opam.ocaml.org/doc/Install.html) and the following steps should
be performed, skipping the first three steps if there is already a global sandbox with compiler
version 4.09 or above.

```
opam init -a --bare
opam update
# Create a global compiler sandbox with Ocaml compiler version 4.09 or above.
opam switch create 4.09 ocaml-base-compiler.4.09.0
eval $(opam env)
# Create a local sandbox using the compiler above.
opam switch create -yw --unlock-base --deps-only . --locked --with-doc --with-test --empty
opam install -yw --unlock-base --deps-only ./threshold_crypto.opam --locked --with-doc --with-test
eval $(opam env)
dune build
```


## Examples

* [`threshold_enc.ml`](./examples/threshold_enc.ml) - an example of threshold encryption and
  decryption. Run with `dune exec examples/threshold_enc.exe`.
