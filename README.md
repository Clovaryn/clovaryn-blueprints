# Clovaryn Blueprints

This repository contains public Clovaryn blueprint package source. A blueprint package is a declarative architecture package that defines intent schemas, families, variants, safety rules, Terraform Jinja templates, examples, tests, and package documentation.

The compiler lives outside this repository. This repository must not contain compiler runtime secrets, Cloud SQL credentials, API keys, Secret Manager values, Terraform state, local environment files, service account keys, internal tokens, private user data, or generated runtime artifacts.

## Package Authors

Blueprint authors create and maintain:

- `clovaryn.package.toml`
- `schemas/*.json`
- `families/*.yaml`
- `variants/*.yaml`
- `rules/*.yaml`
- `templates/terraform/*.tf.j2`
- `examples/*.intent.toml`
- package tests and docs

Terraform templates are source templates only. Do not commit rendered `.tf` files or rendered `terraform.tfvars` files.

## Official And Community Packages

Official packages live under `packages/official` and are maintained by Clovaryn maintainers.

Community packages are planned under `packages/community`. Community packages must be submitted by pull request and must pass validation before publishing.

## Package Path Convention

Official packages use:

```text
packages/official/<provider>-<capability>-<pattern>/<semver>/
```

Community packages will use:

```text
packages/community/<publisher>/<package-name>/<semver>/
```

Package names must be lowercase kebab-case and match `package.name` in `clovaryn.package.toml`. Version folders must be exact semantic versions such as `1.0.0`; do not use `latest`.

## Required Package Structure

```text
clovaryn.package.toml
schemas/
families/
variants/
rules/
templates/
examples/
tests/
docs/
```

## Forbidden Files

Do not add secrets, credentials, environment files, Terraform state, generated Terraform output, backend config, private keys, service account keys, local cache folders, logs, or generated runtime artifacts.

Examples must use public-safe placeholders such as `123456789012`, `ca-central-1`, `your-container-image`, `your-project-name`, and `REPLACE_ME`.

## Publishing Model

Validated packages will be published to the Clovaryn registry by a deterministic publishing flow. RAG or LLM systems may recommend packages, but deterministic package metadata, rules, compiler behavior, and validators remain the source of truth.
