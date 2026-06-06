# AWS S3 Private Bucket

This official Clovaryn package generates Terraform source for a private AWS S3 bucket with public access blocked, ownership controls, versioning support, and server-side encryption.

The package is intended for private object storage. It does not configure public website hosting, public bucket policies, public ACLs, CloudFront, replication, lifecycle transitions, or cross-account access.

## Safety Properties

- S3 public access block is enabled.
- Public bucket ACLs and public bucket policies are forbidden.
- Bucket ownership controls use `BucketOwnerEnforced`.
- Server-side encryption is required.
- `force_destroy` is exposed but defaults to `false` in examples.

## Inputs

See `schemas/intent.schema.json` and `examples/dev.intent.toml` for the supported intent fields.

## Templates

Terraform output is rendered from source templates under `templates/terraform`. Only `.tf.j2` templates and public-safe helper templates are committed here.

OpenTofu support is compatibility-mode support for this package. The package still provides Terraform-language `.tf.j2` templates under `templates/terraform`; the compiler selects the OpenTofu target, emits files under `generated/opentofu`, and provides `tofu` command guidance. This package does not provide `.tofu` templates or a separate `templates/opentofu` directory.

