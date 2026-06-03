# AWS Private ECS Backend

This official Clovaryn package generates Terraform source for an AWS ECS Fargate backend behind an internal Application Load Balancer.

The package is intended for internal-only services. It requires private subnet IDs, an existing VPC, allowed internal CIDR ranges, and an existing ECS cluster ARN supplied in generated Terraform variables.

## Safety Properties

- ECS tasks use private subnets.
- ECS tasks set `assign_public_ip = false`.
- The Application Load Balancer is internal.
- The internal ALB uses private subnets.
- ECS service ingress comes from the ALB security group, not public CIDR ranges.

## Inputs

See `schemas/intent.schema.json` and `examples/dev.intent.toml` for the supported intent fields.

## Templates

Terraform output is rendered from source templates under `templates/terraform`. Only `.tf.j2` templates and public-safe helper templates are committed here.

