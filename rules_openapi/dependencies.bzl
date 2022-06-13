load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def rules_openapi_dependencies():
    maybe(
        http_archive,
        name = "aspect_rules_js",
        sha256 = "6b218d2ab2e365807d1d403580b2c865a771e7fda9449171b2abd9765d0299b3",
        strip_prefix = "rules_js-0.12.1",
        url = "https://github.com/aspect-build/rules_js/archive/refs/tags/v0.12.1.tar.gz",
    )

    maybe(
        http_archive,
        name = "cgrindel_bazel_starlib",
        sha256 = "163a45d949fdb96b328bb44fe56976c610c6728c77118c6cd999f26cedca97eb",
        strip_prefix = "bazel-starlib-0.2.1",
        urls = [
            "http://github.com/cgrindel/bazel-starlib/archive/v0.2.1.tar.gz",
        ],
        patches = ["@com_github_scionproto_scion//rules_openapi:rules_starlib.patch"],
        patch_args = ["-p1"],
    )
