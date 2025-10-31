"""Dependencies of Tink C++."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def tink_cc_deps():
    """Loads dependencies of C++ Tink."""

    # Basic rules we need to add to bazel.
    # Release from 2024-06-03.
    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
        ],
    )

    # This is needed to call `py_repositories()` in tink_cc_deps_init, which avoids failures such as [1].
    #
    # [1] https://github.com/bazelbuild/rules_python/issues/1560
    maybe(
        http_archive,
        name = "rules_python",
        sha256 = "9c6e26911a79fbf510a8f06d8eedb40f412023cf7fa6d1461def27116bff022c",
        strip_prefix = "rules_python-1.1.0",
        url = "https://github.com/bazelbuild/rules_python/releases/download/1.1.0/rules_python-1.1.0.tar.gz",
    )

    # -------------------------------------------------------------------------
    # Protobuf.
    # -------------------------------------------------------------------------
    # proto_library, cc_proto_library and java_proto_library rules implicitly
    # depend respectively on:
    #   * @com_google_protobuf//:proto
    #   * @com_google_protobuf//:cc_toolchain
    #   * @com_google_protobuf//:java_toolchain
    # This statement defines the @com_google_protobuf repo.
    # Release X.29.3 from 2025-01-08.

    maybe(
        http_archive,
        name = "rules_java",
        urls = [
            "https://github.com/bazelbuild/rules_java/releases/download/8.6.3/rules_java-8.6.3.tar.gz",
        ],
        sha256 = "6d8c6d5cd86fed031ee48424f238fa35f33abc9921fd97dd4ae1119a29fc807f",
    )

    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "6544e5ceec7f29d00397193360435ca8b3c4e843de3cf5698a99d36b72d65342",
        strip_prefix = "protobuf-30.2",
        urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v30.2/protobuf-30.2.zip"],
        repo_mapping = {"@abseil-cpp": "@com_google_absl"},
    )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "1692f77d1739bacf3f94337188b78583cf09bab7e420d2dc6c5605a4f86785a1",
        strip_prefix = "abseil-cpp-20250814.1",
        urls = [
            "https://github.com/abseil/abseil-cpp/releases/download/20250814.1/abseil-cpp-20250814.1.tar.gz",
        ],
    )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    maybe(
        http_archive,
        name = "boringssl",
        sha256 = "f96733fc3df03d4195db656d1b7b8c174c33f95d052f811f0ecc8f4e4e3db332",
        strip_prefix = "boringssl-0.20251002.0/",
        url = "https://github.com/google/boringssl/releases/download/0.20251002.0/boringssl-0.20251002.0.tar.gz",
    )

    # -------------------------------------------------------------------------
    # rules_license.
    # -------------------------------------------------------------------------
    # Release from 2024-09-05. Required by BoringSSL.
    maybe(
        http_archive,
        name = "rules_license",
        sha256 = "26d4021f6898e23b82ef953078389dd49ac2b5618ac564ade4ef87cced147b38",
        url = "https://github.com/bazelbuild/rules_license/releases/download/1.0.0/rules_license-1.0.0.tar.gz",
    )

def tink_cc_testonly_deps():
    """Test only dependencies for tink-cc."""

    # -------------------------------------------------------------------------
    # Wycheproof.
    # -------------------------------------------------------------------------
    # Commit from 2025-09-01.
    # Corresponds to wycheproof-v0-vectors tag.
    maybe(
        http_archive,
        name = "wycheproof",
        strip_prefix = "wycheproof-b51abcfb8dafa5316791e57cf48512a2147d9671",
        url = "https://github.com/c2sp/wycheproof/archive/b51abcfb8dafa5316791e57cf48512a2147d9671.zip",
        sha256 = "56ba9f3deba06b1cc33430a770a9b6bd6ddc8af69188ea0b46d10bda60176978",
        build_file = "@//testvectors:wycheproof.BUILD.bazel",
    )

    # -------------------------------------------------------------------------
    # GoogleTest/GoogleMock.
    # -------------------------------------------------------------------------
    # Release from 2024-07-31.
    maybe(
        http_archive,
        name = "googletest",
        sha256 = "65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c",
        strip_prefix = "googletest-1.17.0",
        url = "https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz",
    )

    # -------------------------------------------------------------------------
    # Google Benchmark.
    # -------------------------------------------------------------------------
    # Release from 2024-11-28.
    maybe(
        http_archive,
        name = "com_google_benchmark",
        sha256 = "32131c08ee31eeff2c8968d7e874f3cb648034377dfc32a4c377fa8796d84981",
        strip_prefix = "benchmark-1.9.1",
        urls = [
            "https://github.com/google/benchmark/archive/refs/tags/v1.9.1.tar.gz",
        ],
    )
