# AWS Deployment (ECR + Fargate)

This documents the AWS side of `evtxkit`: containerized, stored in ECR, and run serverless via ECS Fargate.

## Status

- **Working:** image build → ECR push → Fargate task → CloudWatch logs. Verified end-to-end, including from a second machine authenticated to the same AWS account.
- **Built but not currently wired in:** an S3 upload wrapper (`s3_wrapper.py`) and a scoped task role (`evtxkitTaskRole`) for writing scan reports to S3. The role and bucket exist; the currently-deployed image does not include the wrapper, so nothing is actively uploading right now.
- **Manual, not automated:** every step here is run by hand via the AWS CLI. This isn't yet wired into the GitHub Actions pipeline that builds/pushes to Docker Hub.

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