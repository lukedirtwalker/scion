load("@aspect_rules_js//js:repositories.bzl", "rules_js_dependencies")
load("@rules_nodejs//nodejs:repositories.bzl", "DEFAULT_NODE_VERSION", "nodejs_register_toolchains")
load("@aspect_rules_js//npm:npm_import.bzl", "npm_translate_lock")

def rules_openapi_install_yarn_dependencies():
    rules_js_dependencies()

    nodejs_register_toolchains(
        name = "nodejs",
        node_version = DEFAULT_NODE_VERSION,
    )

    npm_translate_lock(
        name = "npm",
        pnpm_lock = "@com_github_scionproto_scion//rules_openapi//tools:pnpm-lock.yaml",
    )
