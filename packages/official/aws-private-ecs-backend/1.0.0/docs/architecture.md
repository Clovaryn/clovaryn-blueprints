# Architecture

The package models a private AWS ECS Fargate service.

```text
Internal client
  -> Internal Application Load Balancer
  -> ECS service security group
  -> ECS Fargate task
  -> CloudWatch Logs
```

The ALB and ECS service both use `private_subnet_ids`. The ECS task definition includes an execution role and CloudWatch log configuration. The ECS service network configuration disables public task IP assignment.

Public ingress to ECS is blocked by package rules and compiler validation.

