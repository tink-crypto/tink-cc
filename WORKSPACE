# NOTE: This WORKSPACE file for Tink C++ is deprecated in favor of MODULE.bazel.

workspace(name = "tink_cc")

# Run with --override_repository=boringssl=third_party/boringssl_fips to use
# the FIPS module.

load("@tink_cc//:tink_cc_deps.bzl", "tink_cc_deps", "tink_cc_testonly_deps")

tink_cc_deps()

tink_cc_testonly_deps()

load("@tink_cc//:tink_cc_deps_init.bzl", "tink_cc_deps_init")

tink_cc_deps_init()
