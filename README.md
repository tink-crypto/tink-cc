# Tink C++

<!-- GCP Ubuntu --->

[tink_cc_bazel_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-bazel-gcp-ubuntu.svg
[tink_cc_bazel_absl_status_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-bazel-absl-status-gcp-ubuntu.svg
[tink_cc_bazel_fips_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-bazel-fips-gcp-ubuntu.svg
[tink_cc_cmake_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-cmake-gcp-ubuntu.svg
[tink_cc_cmake_openssl_badge_gcp_ubuntu]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-cmake-openssl-gcp-ubuntu.svg

<!-- MacOS --->

[tink_cc_bazel_badge_macos]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-bazel-macos-external.svg
[tink_cc_bazel_absl_status_badge_macos]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-bazel-absl-status-macos-external.svg
[tink_cc_cmake_badge_macos]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-cmake-macos-external.svg
[tink_cc_cmake_openssl_badge_macos]: https://storage.googleapis.com/tink-kokoro-build-badges/tink-cc-cmake-openssl-macos-external.svg

**Test**                         | **GCP Ubuntu**                                                                    | **MacOS**
-------------------------------- | --------------------------------------------------------------------------------- | ---------
Tink (Bazel)                     | [![Bazel_GcpUbuntu][tink_cc_bazel_badge_gcp_ubuntu]](#)                           | [![Bazel_MacOs][tink_cc_bazel_badge_macos]](#)
Tink using Abseil Status (Bazel) | [![Bazel_Abseil_Status_GcpUbuntu][tink_cc_bazel_absl_status_badge_gcp_ubuntu]](#) | [![Bazel_Abseil_Status_MacOs][tink_cc_bazel_absl_status_badge_macos]](#)
Tink FIPS (Bazel)                | [![Bazel_Fips_GcpUbuntu][tink_cc_bazel_fips_badge_gcp_ubuntu]](#)                 | N/A
Tink (CMake)                     | [![CMake_GcpUbuntu][tink_cc_cmake_badge_gcp_ubuntu]](#)                           | [![CMake_MacOs][tink_cc_cmake_badge_macos]](#)
Tink using OpenSSL (CMake)       | [![CMake_OpenSsl_GcpUbuntu][tink_cc_cmake_openssl_badge_gcp_ubuntu]](#)           | [![CMake_OpenSsl_MacOs][tink_cc_cmake_openssl_badge_macos]](#)


Using crypto in your application [shouldn't have to][devs_are_users_too_slides]
feel like juggling chainsaws in the dark. Tink is a crypto library written by a
group of cryptographers and security engineers at Google. It was born out of our
extensive experience working with Google's product teams,
[fixing weaknesses in implementations](https://github.com/google/wycheproof),
and providing simple APIs that can be used safely without needing a crypto
background.

Tink provides secure APIs that are easy to use correctly and hard(er) to misuse.
It reduces common crypto pitfalls with user-centered design, careful
implementation and code reviews, and extensive testing. At Google, Tink is one
of the standard crypto libraries, and has been deployed in hundreds of products
and systems.

To get a quick overview of Tink's design please take a look at
[Tink's goals](https://developers.google.com/tink/design/goals_of_tink).

The official documentation is available at https://developers.google.com/tink.

[devs_are_users_too_slides]: https://www.usenix.org/sites/default/files/conference/protected-files/hotsec15_slides_green.pdf

## Contact and mailing list

If you want to contribute, please read [CONTRIBUTING](docs/CONTRIBUTING.md) and
send us pull requests. You can also report bugs or file feature requests.

If you'd like to talk to the developers or get notified about major product
updates, you may want to subscribe to our
[mailing list](https://groups.google.com/forum/#!forum/tink-users).

## Maintainers

Tink is maintained by (A-Z):

-   Moreno Ambrosin
-   Taymon Beal
-   Daniel Bleichenbacher
-   William Conner
-   Thai Duong
-   Thomas Holenstein
-   Stefan Kölbl
-   Charles Lee
-   Cindy Lin
-   Fernando Lobato Meeser
-   Atul Luykx
-   Rafael Misoczki
-   Sophie Schmieg
-   Laurent Simon
-   Elizaveta Tretiakova
-   Jürg Wullschleger

Alumni:

-   Haris Andrianakis
-   Tanuj Dhir
-   Quan Nguyen
-   Bartosz Przydatek
-   Enzo Puig
-   Veronika Slívová
-   Paula Vidas
