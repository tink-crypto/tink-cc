# BoringSSL FIPS

This Bazel repository facilitates building BoringSSL with the FIPS validated
module
[BoringCrypto](https://csrc.nist.gov/Projects/Cryptographic-Module-Validation-Program/Certificate/3678),
which can then be used in Tink. Note that this gives no guarantee that you use
BoringSSL in a FIPS compliant manner when used. It is strongly recommended to
read the official
[security policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3678.pdf)
for BoringCrypto.

To build Tink with BoringCrypto use
`--override_module=boringssl=third_party/boringssl_fips`, with Bazel module, and
`--override_repository=boringssl=third_party/boringssl_fips`. Tink then offers a
[FIPS-only mode](https://developers.google.com/tink/FIPS) which will restrict
the usage to algorithms which are FIPS approved *and* utilize the BoringCrypto
module.
