# Architecture

The `aws-s3-private-bucket` package creates a private S3 object storage baseline.

## Resources

- `aws_s3_bucket`
- `aws_s3_bucket_ownership_controls`
- `aws_s3_bucket_public_access_block`
- `aws_s3_bucket_versioning`
- `aws_s3_bucket_server_side_encryption_configuration`

## Security Model

The bucket is not public. The package requires S3 public access block and server-side encryption, and it does not render public ACLs, public bucket policies, or website hosting resources.

OpenTofu support uses Terraform-language compatibility mode. The same `.tf.j2` templates are used for Terraform and OpenTofu targets.

