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

    # Same as the one loaded by @com_google_protobuf [1]. This is needed to call
    # `py_repositories()` in tink_cc_deps_init, which avoids failures such as [2].
    #
    # [1] https://github.com/protocolbuffers/protobuf/blob/v26.1/protobuf_deps.bzl#L96
    # [2] https://github.com/bazelbuild/rules_python/issues/1560
    maybe(
        http_archive,
        name = "rules_python",
        sha256 = "9d04041ac92a0985e344235f5d946f71ac543f1b1565f2cdbc9a2aaee8adf55b",
        strip_prefix = "rules_python-0.26.0",
        url = "https://github.com/bazelbuild/rules_python/releases/download/0.26.0/rules_python-0.26.0.tar.gz",
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
    # Release X.26.1 from 2024-03-26.
    maybe(
        http_archive,
        name = "com_google_protobuf",
        sha256 = "023e2bb164b234af644c5049c6dac1d9c9f6dd2acb133b960d9009105b4226bd",
        strip_prefix = "protobuf-27.4",
        urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v27.4/protobuf-27.4.tar.gz"],
    )

    # -------------------------------------------------------------------------
    # Abseil.
    # -------------------------------------------------------------------------
    # Release from 2024-04-08.
    maybe(
        http_archive,
        name = "com_google_absl",
        sha256 = "f50e5ac311a81382da7fa75b97310e4b9006474f9560ac46f54a9967f07d4ae3",
        strip_prefix = "abseil-cpp-20240722.0",
        urls = [
            "https://github.com/abseil/abseil-cpp/releases/download/20240722.0/abseil-cpp-20240722.0.tar.gz",
        ],
    )

    # -------------------------------------------------------------------------
    # BoringSSL.
    # -------------------------------------------------------------------------
    # Release from 2024-10-03.
    maybe(
        http_archive,
        name = "boringssl",
        sha256 = "812f77dd57fef845c4ed630430f1f8efc7e255c4d572fa58b71e6e3ce1692a4a",
        strip_prefix = "boringssl-0.20240930.0/",
        url = "https://github.com/google/boringssl/releases/download/0.20240930.0/boringssl-0.20240930.0.tar.gz",
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

    # -------------------------------------------------------------------------
    # Rapidjson.
    # -------------------------------------------------------------------------
    # Release from 2016-08-25 (still the latest release as of 2022-05-05).
    maybe(
        http_archive,
        build_file = "@tink_cc//:third_party/rapidjson.BUILD.bazel",
        name = "rapidjson",
        sha256 = "bf7ced29704a1e696fbccf2a2b4ea068e7774fa37f6d7dd4039d0787f8bed98e",
        strip_prefix = "rapidjson-1.1.0",
        url = "https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz",
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
        sha256 = "7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926",
        strip_prefix = "googletest-1.15.2",
        url = "https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz",
    )
