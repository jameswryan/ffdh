# ffdh
ffdh is a Rust library for Finite-Field Diffie-Hellman.

ffdh only supports 4096-bit parameters from [RFC3526](https://www.ietf.org/rfc/rfc3526.txt) (group id 16).
ffdh also only supports ephemeral Diffie-Hellman, and does *not* allow choosing a private key.

## WARNING
ffdh should not be used by anyone for any purpose.
This library has *not* been assessed for constant time operation, and the underlying bignum library has not been chosen for _promising_ constant time operation.


## License
Licensed under either of 

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0), or
- [MIT License](https://opensource.org/licenses/MIT)

at your option

### Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
