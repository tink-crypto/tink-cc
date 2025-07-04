"""Initialization of dependencies of C++ Tink."""

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")
load("@rules_java//java:rules_java_deps.bzl", "rules_java_dependencies")
load("@rules_python//python:repositories.bzl", "py_repositories")

def tink_cc_deps_init():
    """Initializes dependencies of C++ Tink."""
    rules_java_dependencies()

    # Needed to avoid https://github.com/bazelbuild/rules_python/issues/1560. See also
    # https://github.com/bazelbuild/rules_python/blob/main/CHANGELOG.md#changed-6.
    py_repositories()

    # Initialize Protobuf dependencies.
    protobuf_deps()
