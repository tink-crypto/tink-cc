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
        name = "com_google_protobuf",
        sha256 = "e9b9ac1910b1041065839850603caf36e29d3d3d230ddf52bd13778dd31b9046",
        strip_prefix = "protobuf-29.3",
        urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protobuf-29.3.zip"],
    )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "b396401fd29e2e679cace77867481d388c807671dc2acc602a0259eeb79b7811",
        strip_prefix = "abseil-cpp-20250127.1",
        urls = [
            "https://github.com/abseil/abseil-cpp/releases/download/20250127.1/abseil-cpp-20250127.1.tar.gz",
        ],
    )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    maybe(
        http_archive,
        name = "boringssl",
        sha256 = "b2d64c4d52c505d60b0fb86833568dc4762445910d7a7757ff9b172e5556cb01",
        strip_prefix = "boringssl-0.20250415.0/",
        url = "https://github.com/google/boringssl/releases/download/0.20250415.0/boringssl-0.20250415.0.tar.gz",
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
    # Commit from 2019-12-17.
    maybe(
        http_archive,
        name = "wycheproof",
        sha256 = "eb1d558071acf1aa6d677d7f1cabec2328d1cf8381496c17185bd92b52ce7545",
        strip_prefix = "wycheproof-d8ed1ba95ac4c551db67f410c06131c3bc00a97c",
        url = "https://github.com/google/wycheproof/archive/d8ed1ba95ac4c551db67f410c06131c3bc00a97c.zip",
    )

    # -------------------------------------------------------------------------
    # GoogleTest/GoogleMock.
    # -------------------------------------------------------------------------
    # Release from 2024-07-31.
    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "78c676fc63881529bf97bf9d45948d905a66833fbfa5318ea2cd7478cb98f399",
        strip_prefix = "googletest-1.16.0",
        url = "https://github.com/google/googletest/releases/download/v1.16.0/googletest-1.16.0.tar.gz",
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
