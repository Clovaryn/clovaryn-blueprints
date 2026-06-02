# Contributing

Contributions must be submitted by pull request. Keep packages declarative and public-safe.

## Requirements

- Do not include credentials, secrets, private user data, account-specific state, backend config, service account keys, or generated output.
- Do not include arbitrary code execution, shell hooks, Terraform provisioners, or deployment scripts that bypass validation.
- Include package examples and tests for supported behavior.
- Include negative tests for unsafe behavior where applicable.
- Use source templates such as `.tf.j2`; do not commit rendered `.tf` files.
- Confirm you have the right to submit the blueprint package.
- Contributions are submitted under this repository's license.
- Include a DCO-style sign-off when requested by maintainers.

## Package Review

Official packages are owned by Clovaryn maintainers. Community package submissions require maintainer review before merge and must pass the current validation checklist before publishing.

