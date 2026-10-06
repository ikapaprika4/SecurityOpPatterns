# AWS Deployment (ECR + Fargate)

This documents the AWS side of `evtxkit`: containerized, stored in ECR, and run serverless via ECS Fargate.

## Status

> **Updated.** The upload → analyse → report service built on top of this
> (S3 uploads bucket, two Lambda functions, an upload page, per-person access
> codes) is documented step by step in [`aws/UPLOAD-FLOW.md`](aws/UPLOAD-FLOW.md).
> This page covers the original container setup it builds on.

- **Working:** image build → ECR push → Fargate task → CloudWatch logs, and the S3 wrapper (`s3_wrapper.py`) in the image: it analyses an uploaded file and writes `reports/<job id>/report.md` and `status.json` to the reports bucket, or, without an input file, runs plain evtxkit and uploads its output. Both were run on AWS (eu-north-1) in October 2026.
- **Task role:** `evtxkitTaskRole` may read the uploads bucket (`s3:GetObject`) and write the reports bucket (`s3:PutObject`), and nothing else.
- **Automated by CI:** tests, the image build and a smoke test on every push to `main` or `full-toolkit-pipeline`; the registry push and the ECR deploy run on `main` only. The two Lambda functions and the buckets are **not** deployed by CI: they are set up by hand following the runbook.

## Architecture

- **ECR** (`evtxkit` repository) — stores the built image
- **IAM roles** — `ecsTaskExecutionRole` (lets Fargate pull the image + write logs), `evtxkitTaskRole` (lets the running code write to S3, currently unused by the deployed image)
- **ECS cluster** (`evtxkit-cluster`) + **Fargate task** — runs the container serverlessly, no managed EC2 instances
- **CloudWatch Logs** (`/ecs/evtxkit`) — captures container output
- **S3 bucket** (`evtxkit-reports-<account-id>`) — destination for reports, once the wrapper image is redeployed

## Config files (`aws/`)

- `task-definition.json` — the ECS task definition (image, roles, resources, log config)
- `trust-policy.json` / `task-role-trust-policy.json` — IAM trust policies (who can assume each role)
- `s3-write-policy.json` — custom IAM policy scoping the task role to `s3:PutObject` on one bucket only

## Running it

```bash
# Build, tag, push
docker build -f Dockerfile.evtxkit -t evtxkit:v1 .
docker tag evtxkit:v1 <account-id>.dkr.ecr.eu-north-1.amazonaws.com/evtxkit:v1
docker push <account-id>.dkr.ecr.eu-north-1.amazonaws.com/evtxkit:v1

# Run on Fargate
aws ecs run-task \
  --cluster evtxkit-cluster \
  --task-definition evtxkit-task \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[SUBNET_ID],securityGroups=[SG_ID],assignPublicIp=ENABLED}" \
  --region eu-north-1

# Check the result
aws logs tail /ecs/evtxkit --region eu-north-1 --since 5m
```

## Known gaps

- No CI/CD automation for the AWS deployment path
- S3 upload path built but not deployed in the current image
- Public subnet + public IP used for simplicity; a production setup would use a private subnet with a NAT Gateway instead