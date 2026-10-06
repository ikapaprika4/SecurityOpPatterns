# Upload → analyse → report: runbook

A page where someone uploads a Windows event log and gets an evtxkit report
back, and the commands that put it on AWS one piece at a time.

**The code is tested on this machine against stand-ins for AWS
(`python run_tests.py`). None of the `aws` or `docker` commands below has been
run from this repo.** They are written for Git Bash, from the repository
root, in region `eu-north-1`. Read each one before running it.

## How it works

| Step | Where | What happens |
|---|---|---|
| 1 | page → `evtxkit-upload-api` | `POST /api/uploads` returns a new job id and a pre-signed upload for `uploads/<job id>/<file name>` |
| 2 | browser → S3 | The file goes straight to the uploads bucket; it never passes through a function |
| 3 | S3 → `evtxkit-start-analysis` | The new object starts one Fargate task with `INPUT_BUCKET` and `INPUT_KEY` set |
| 4 | task (`s3_wrapper.py`) | Writes `reports/<job id>/status.json` (`running`), analyses the file, uploads `reports/<job id>/report.md`, **deletes the upload**, rewrites the status (`done`, or `failed` and why) |
| 5 | page → `evtxkit-upload-api` | `GET /api/jobs/<job id>` every few seconds until the job is done, then shows the report |

The job id is in the upload's key, so a report always traces back to its
upload. Without the two `INPUT_*` variables the image behaves like plain
evtxkit (`rules`, `--help`, …), which is what CI and the Kubernetes job use.

The task exits 0 when a report was produced, even one with critical findings,
and 1 when the job failed. The reason is in `status.json` and in CloudWatch.

**The service does not keep the customer's data.** The uploaded file is deleted
as soon as the analysis has ended, whether it worked or not (`status.json`
records `input_deleted`; if the delete fails, the job still finishes and the
bucket's one-day rule removes the file). The report, which quotes the log, is
removed by a one-day rule on the reports bucket, which means within two days:
S3 expires on whole days, counted to the next UTC midnight. CloudWatch gets
only counts and timings from a job, for example
`job … analysed: exit=1 events=21 findings=2 worst=critical input_deleted=True`:
never the report, and never the analyser's own error text, which can quote the
file. What is kept for 30 days is metadata: file names, who uploaded (the job id
starts with the person's name), IP addresses of failed sign-ins, and the counts.
In pass-through mode (CI, `rules`) the whole transcript is logged as before:
there is no customer data in it.

Limits, all environment variables on the task: `MAX_INPUT_BYTES` (default
64 MB), `ANALYSIS_TIMEOUT_SECONDS` (default 900), `REPORT_FORMAT` (default
`markdown`). Analysis needs roughly 6× the file size in memory (measured:
18 MB → 113 MB, 74 MB → 471 MB), which is why `task-definition.json` asks for
2048 MB.

## Try it on this machine first

No AWS account, no Docker:

```bash
python tools/local_upload_flow.py
```

Open the link it prints and drop `samples/evtxkit/rdp_brute_force.jsonl` on
the page. The page, both functions, `s3_wrapper.py` and evtxkit are the real
code; S3 is a dict in memory and the "Fargate task" is a thread. It shows that
the pieces fit together. It cannot show that the policies, the bucket settings
or the task definition are right: the steps below do that.

## 0. Check what is live first

```bash
aws ecs list-task-definition-families --status ACTIVE --region eu-north-1
aws ecr describe-images --repository-name evtxkit --region eu-north-1 --output table
aws iam list-role-policies --role-name evtxkitTaskRole
```

Found there on 2026-10-05: two task definition families. `evtxkit` has one
revision, `:4` (image `v3`, 512 MB, made by hand). `evtxkit-task` is at `:6`
(registered by CI from this folder's `task-definition.json`, image tagged with
a commit SHA). A third, `my-container`, is unrelated. This flow continues
`evtxkit-task`, the family `task-definition.json` and CI use, and leaves
`evtxkit:4` as it is. To continue `evtxkit` instead, change the name in
`task-definition.json`, `lambda-start-analysis-policy.json` (two lines),
`.github/workflows/ci.yml` and the commands below.

## 2. Create the uploads bucket

Private, and a rule deletes anything in it after one day (S3's smallest, so
within two). The task deletes each upload as soon as it has been analysed; the
rule is only the backstop for a task that dies first. These are other people's
Windows logs, so they should not sit there.

```bash
aws s3api create-bucket --bucket evtxkit-uploads-772325758655 --region eu-north-1 --create-bucket-configuration LocationConstraint=eu-north-1
aws s3api put-public-access-block --bucket evtxkit-uploads-772325758655 --region eu-north-1 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-lifecycle-configuration --bucket evtxkit-uploads-772325758655 --region eu-north-1 --lifecycle-configuration file://aws/uploads-bucket-lifecycle.json
```

The reports bucket gets the same treatment, because a report quotes the
customer's log. Its rule is also one day (the bucket itself already existed;
a first version of this rule, applied on 2026-10-06, used 7 days, and applying
the file again replaces it):

```bash
aws s3api put-bucket-lifecycle-configuration --bucket evtxkit-reports-772325758655 --region eu-north-1 --lifecycle-configuration file://aws/reports-bucket-lifecycle.json
```

A rule deletes objects asynchronously, usually within a day of when they are
due. To keep a report, download it from the page first.

## 3. Let the task read and delete uploads

One more inline policy on the task role: `s3:GetObject` on the uploads bucket,
and `s3:DeleteObject` on `uploads/*` there, so that it can remove a file once it
has been analysed. Nothing else. The existing `S3WriteAccess` policy stays as it
is.

```bash
aws iam put-role-policy --role-name evtxkitTaskRole --policy-name S3ReadUploads --policy-document file://aws/s3-read-uploads-policy.json
```

The wrapper makes four kinds of S3 call: `HeadObject` and `GetObject` on the
upload (both authorised by `s3:GetObject`), `DeleteObject` on the same upload
when it is done, and `PutObject` on the reports bucket. Put this policy on the
role **before** the image that deletes is in use: until then a delete is refused,
logged, and recorded as `"input_deleted": false`, and the one-day rule does the
job.

## 4. Build and push the image under a new tag

Commit first, so the tag identifies exactly what is in the image. Never reuse
a tag.

```bash
TAG=$(git rev-parse --short HEAD)
REPO=772325758655.dkr.ecr.eu-north-1.amazonaws.com/evtxkit
aws ecr get-login-password --region eu-north-1 | docker login --username AWS --password-stdin 772325758655.dkr.ecr.eu-north-1.amazonaws.com
docker build --platform linux/amd64 -f Dockerfile.evtxkit -t $REPO:$TAG .
docker run --rm $REPO:$TAG --help
docker push $REPO:$TAG
```

The `docker run … --help` line is the same smoke test CI runs: it must print
evtxkit's usage and exit 0 with no AWS configuration at all.

`--platform linux/amd64` matters on an ARM laptop: the task definition names
no platform, so Fargate runs x86-64, and an ARM image would not start.

## 5. Register a new task definition revision

Task definitions cannot be edited; this writes a copy of
`task-definition.json` with the new image and registers it as a new revision.
Before registering, check the two role lines: `executionRoleArn` must be
`ecsTaskExecutionRole` and `taskRoleArn` must be `evtxkitTaskRole`.

```bash
sed -E "s|(/evtxkit):[^\"]+|\1:$TAG|" aws/task-definition.json > aws/task-definition-updated.json
grep -E '"image"|RoleArn' aws/task-definition-updated.json
aws ecs register-task-definition --cli-input-json file://aws/task-definition-updated.json --region eu-north-1 --query "taskDefinition.[family,revision]" --output text
```

The command stays `["rules"]`. An analysis job ignores it: with `INPUT_BUCKET`
and `INPUT_KEY` set the wrapper runs `analyze <the upload> -f markdown`
itself, so nothing has to remember to override the command.

## 6. Prove it by hand

Upload a bundled sample, run the task with the two `INPUT_*` variables, and
look at the result. `run-task-overrides.example.json` holds the overrides, so
there is no JSON to quote on the command line; its `INPUT_KEY` must match the
key used in the first command.

```bash
aws s3 cp samples/evtxkit/rdp_brute_force.jsonl s3://evtxkit-uploads-772325758655/uploads/manual-test-1/rdp_brute_force.jsonl
TASK=$(aws ecs run-task --cluster evtxkit-cluster --task-definition evtxkit-task --launch-type FARGATE --region eu-north-1 --network-configuration "awsvpcConfiguration={subnets=[subnet-03f1948ab29775079],securityGroups=[sg-0aac35e37f78a3f63],assignPublicIp=ENABLED}" --overrides file://aws/run-task-overrides.example.json --query "tasks[0].taskArn" --output text | tr -d '\r')
echo $TASK
aws ecs wait tasks-stopped --cluster evtxkit-cluster --tasks $TASK --region eu-north-1
aws ecs describe-tasks --cluster evtxkit-cluster --tasks $TASK --region eu-north-1 --query "tasks[0].containers[0].[exitCode,reason]" --output text
```

If `echo $TASK` prints `None`, the task did not start: run the `run-task`
command again without `--query` and read its `failures` list.

Then the two things to check:

```bash
aws s3 cp s3://evtxkit-reports-772325758655/reports/manual-test-1/status.json -
aws s3 cp s3://evtxkit-reports-772325758655/reports/manual-test-1/report.md - | head -20
MSYS_NO_PATHCONV=1 aws logs tail /ecs/evtxkit --region eu-north-1 --since 15m
```

(`MSYS_NO_PATHCONV=1` stops Git Bash rewriting `/ecs/evtxkit` into a Windows
path.)

**Working** looks like this: exit code `0`; `status.json` has
`"state": "done"`, `"report_key": "reports/manual-test-1/report.md"` and
`"high_or_critical_findings": true`; the report's first line is
``# evtxkit analysis: `rdp_brute_force.jsonl` `` and it lists
`EVTX-LOGON-BRUTE-01`; CloudWatch shows the same report plus an
`Uploaded to s3://…` line.

Then repeat with a real `.evtx` exported from a Windows machine. That is the
format a customer will actually upload, and it is read by evtxkit's own
reader on Linux, so it is the more important test.

Worth trying once as well, to see the failure path: upload a text file that
is not a log. Expect exit code `1` and `"state": "failed"` with a reason; it
must never come back as a clean report.

Remove the test objects when done:

```bash
aws s3 rm s3://evtxkit-uploads-772325758655/uploads/manual-test-1/ --recursive
aws s3 rm s3://evtxkit-reports-772325758655/reports/manual-test-1/ --recursive
```

## 7. Start the task automatically

`aws/lambda/start_analysis/handler.py` does by itself what step 6 did by
hand. Do this only once step 6 works: it adds nothing that step 6 has not
proven, except the trigger.

These commands, and step 8's, need an identity that may create Lambda
functions, set a bucket's notification and CORS, and set log retention. The
key CI uses cannot (checked 2026-10-05), and widening a key that lives in
GitHub is not worth it for a one-time setup: use an admin profile and add
`--profile <name>` to each command.

Its role may do three things (`lambda-start-analysis-policy.json`):

| Statement | Allows | Why |
|---|---|---|
| `RunTheAnalysisTask` | `ecs:RunTask`, on the `evtxkit-task` definition, in `evtxkit-cluster` only | The one call the function makes. Both spellings of the task definition are listed because the function names the family, and ECS then checks the ARN without a revision number |
| `PassTheTasksTwoRoles` | `iam:PassRole`, for `ecsTaskExecutionRole` and `evtxkitTaskRole` only, to ECS tasks only | ECS requires it of whoever starts a task that uses those roles |
| `WriteItsOwnLog` | `logs:CreateLogStream`, `logs:PutLogEvents` on its own log group | Not in the brief's list; without it a failure leaves no trace. Drop the statement if you do not want it |

```bash
aws iam create-role --role-name evtxkitStartAnalysisRole --assume-role-policy-document file://aws/lambda-trust-policy.json
aws iam put-role-policy --role-name evtxkitStartAnalysisRole --policy-name StartAnalysisTask --policy-document file://aws/lambda-start-analysis-policy.json
MSYS_NO_PATHCONV=1 aws logs create-log-group --log-group-name /aws/lambda/evtxkit-start-analysis --region eu-north-1
MSYS_NO_PATHCONV=1 aws logs put-retention-policy --log-group-name /aws/lambda/evtxkit-start-analysis --retention-in-days 30 --region eu-north-1
# the task's own log: a job logs only counts and timings now, but logs from before that change
# hold whole reports, so keep it short (3 days) until they have aged out
MSYS_NO_PATHCONV=1 aws logs put-retention-policy --log-group-name /ecs/evtxkit --retention-in-days 3 --region eu-north-1
```

Package and create the function. `tools/build_lambdas.py` writes both zips to
`build/`; the trigger's is one file, and `boto3` comes with the Lambda runtime.

```bash
python tools/build_lambdas.py
aws lambda create-function --function-name evtxkit-start-analysis --runtime python3.12 --handler handler.handler --role arn:aws:iam::772325758655:role/evtxkitStartAnalysisRole --zip-file fileb://build/start-analysis.zip --timeout 30 --memory-size 128 --region eu-north-1 --environment "Variables={ECS_CLUSTER=evtxkit-cluster,TASK_DEFINITION=evtxkit-task,SUBNETS=subnet-03f1948ab29775079,SECURITY_GROUPS=sg-0aac35e37f78a3f63,UPLOADS_BUCKET=evtxkit-uploads-772325758655}"
aws lambda put-function-event-invoke-config --function-name evtxkit-start-analysis --maximum-retry-attempts 2 --maximum-event-age-in-seconds 300 --region eu-north-1
```

If `create-function` says the role "cannot be assumed by Lambda", wait ten
seconds and run it again: a new role takes a moment to exist everywhere.

Let the bucket invoke the function, then tell the bucket to do so. The source
ARN and account make sure only this bucket, in this account, can. The second
command replaces the bucket's whole notification configuration, which is
right for a bucket that has none yet.

```bash
aws lambda add-permission --function-name evtxkit-start-analysis --statement-id AllowTheUploadsBucket --action lambda:InvokeFunction --principal s3.amazonaws.com --source-arn arn:aws:s3:::evtxkit-uploads-772325758655 --source-account 772325758655 --region eu-north-1
aws s3api put-bucket-notification-configuration --bucket evtxkit-uploads-772325758655 --region eu-north-1 --notification-configuration file://aws/uploads-bucket-notification.json
```

Test it: the same upload as step 6 under a new job id, and no `run-task`.

```bash
aws s3 cp samples/evtxkit/rdp_brute_force.jsonl s3://evtxkit-uploads-772325758655/uploads/trigger-test-1/rdp_brute_force.jsonl
MSYS_NO_PATHCONV=1 aws logs tail /aws/lambda/evtxkit-start-analysis --region eu-north-1 --since 5m
aws s3 cp s3://evtxkit-reports-772325758655/reports/trigger-test-1/status.json -
```

**Working** looks like this: the function's log has one line starting
`{"started": {"job_id": "trigger-test-1"`; within a minute or two
`status.json` exists and ends up at `"state": "done"`. A line starting
`{"failed":` carries ECS's own reason (most often a missing permission or a
wrong name in the function's environment). Remove the test objects as in
step 6.

## 8. The page

`aws/lambda/upload_api/` is the page and its API in one function with a
function URL. Its role (`lambda-upload-api-policy.json`):

| Statement | Allows | Why |
|---|---|---|
| `WhatAPreSignedUploadMayDo` | `s3:PutObject` on `uploads/*` in the uploads bucket | A pre-signed upload can do what its signer can, and no more. Each one is further limited to a single key, 64 MB and five minutes |
| `ReadJobStatusAndReports` | `s3:GetObject` on `reports/*` in the reports bucket | To read `status.json` and the report, and to sign the report's download link |
| `WriteItsOwnLog` | as in step 7 | |

The function that faces the internet cannot start tasks or pass roles, and
the one that starts tasks cannot read or write a single object.

```bash
aws iam create-role --role-name evtxkitUploadApiRole --assume-role-policy-document file://aws/lambda-trust-policy.json
aws iam put-role-policy --role-name evtxkitUploadApiRole --policy-name SignUploadsReadReports --policy-document file://aws/lambda-upload-api-policy.json
MSYS_NO_PATHCONV=1 aws logs create-log-group --log-group-name /aws/lambda/evtxkit-upload-api --region eu-north-1
MSYS_NO_PATHCONV=1 aws logs put-retention-policy --log-group-name /aws/lambda/evtxkit-upload-api --retention-in-days 30 --region eu-north-1
```

The page is open to the internet, so the API behind it asks for an access
code, one per person: without one, anyone who finds the address could run
tasks on your account. The function holds only a fingerprint (SHA-256) of each
code, never the code, so a leaked setting cannot be used to sign in.
`tools/access_codes.py` makes the codes and the function's environment. Run it
in your own terminal, so the codes are shown to you and nobody else, and give
each person theirs. Names are lowercase letters and digits (`alice`).

```bash
python tools/build_lambdas.py
python tools/access_codes.py alice bob --env-file build/upload-api-environment.json
aws lambda create-function --function-name evtxkit-upload-api --runtime python3.12 --handler handler.handler --role arn:aws:iam::772325758655:role/evtxkitUploadApiRole --zip-file fileb://build/upload-api.zip --timeout 15 --memory-size 256 --region eu-north-1 --environment file://build/upload-api-environment.json
```

Give it an address. A public function URL needs both permissions; with only
the first, every request gets a 403. If the CLI does not know
`--invoked-via-function-url`, it is older than that rule: update it.

```bash
aws lambda create-function-url-config --function-name evtxkit-upload-api --auth-type NONE --region eu-north-1
aws lambda add-permission --function-name evtxkit-upload-api --statement-id FunctionURLAllowPublicAccess --action lambda:InvokeFunctionUrl --principal "*" --function-url-auth-type NONE --region eu-north-1
aws lambda add-permission --function-name evtxkit-upload-api --statement-id FunctionURLInvokeAllowPublicAccess --action lambda:InvokeFunction --principal "*" --invoked-via-function-url --region eu-north-1
```

Last, let that one address post to the bucket from a browser. This fills the
address into a copy of `uploads-bucket-cors.json` and prints the address to
hand out.

```bash
URL=$(aws lambda get-function-url-config --function-name evtxkit-upload-api --region eu-north-1 --query FunctionUrl --output text | tr -d '\r')
sed "s|https://PAGE-ORIGIN|${URL%/}|" aws/uploads-bucket-cors.json > build/uploads-bucket-cors.json
grep AllowedOrigins build/uploads-bucket-cors.json
aws s3api put-bucket-cors --bucket evtxkit-uploads-772325758655 --region eu-north-1 --cors-configuration file://build/uploads-bucket-cors.json
echo "$URL"
```

Open the address, type one person's code, and upload
`samples/evtxkit/rdp_brute_force.jsonl`, then a real
`.evtx`.

**Working** looks like this: the bar fills during the upload; "Waiting for
the analysis to start" for about a minute; then "High or critical findings"
with the report under it, and the download button saves a `.md` file.

If it does not:

| What you see | Where to look |
|---|---|
| "The access code is missing or wrong." | The code is not one `tools/access_codes.py` made for this function's `USERS`. The function keeps only fingerprints, so a lost code cannot be looked up: make a new one |
| "The service is not set up yet." | `UPLOADS_BUCKET`, `REPORT_BUCKET` or `USERS` is missing, or `USERS` is not valid; the function's log says which |
| "The upload did not go through." straight away | The bucket's CORS rule: its origin must be the page's address exactly, with no `/` at the end |
| "The upload was refused" | `evtxkitUploadApiRole` lacks `s3:PutObject` on `uploads/*`, or the link was more than five minutes old |
| "The analysis did not start." after six minutes | The trigger: `aws logs tail /aws/lambda/evtxkit-start-analysis` |
| A plain `Forbidden` instead of the page | The second `add-permission` command above |

To update a function's own code later, run `python tools/build_lambdas.py`
and then
`aws lambda update-function-code --function-name <name> --zip-file fileb://build/<zip> --region eu-north-1`
(`upload-api.zip` for `evtxkit-upload-api`, `start-analysis.zip` for the
trigger). Settings are separate: `update-function-code` leaves them as they are.

## The sample logs on the page

Under the upload box the page lists sample logs, for a tester who has no
Windows log to hand. Pressing one loads it from the site and fills the box;
pressing Analyse then sends it through exactly the same steps as a file of
your own: S3, the trigger, a Fargate task, the report. Each entry says what
the report should contain, for example "Expect: High or critical findings
(EVTX-LOGON-BRUTE-01, ...)". The list needs a valid access code, like
everything else on the API.

- `aws/lambda/upload_api/samples.json` lists them (file, title, what it
  shows, the worst severity and the rules evtxkit should report).
- The files are the repository's own `samples/evtxkit/*`, copied into the zip
  by `tools/build_lambdas.py`: there is one copy of each, and the build stops
  if a listed file is missing.
- `tests/test_upload_flow.py` runs evtxkit on every listed sample and fails if
  the worst severity, the rules or the exit code differ from what the page
  promises, so the page cannot go on telling testers something false.
- To add one: put the file in `samples/evtxkit/`, add an entry to
  `samples.json`, run the tests, rebuild, and update the function's code.

## People and their codes

Each person has a name (`alice`) and a code only they hold. The name is the
start of every job id (`alice-<128 random bits>`), so a person can only see
their own jobs, and the function's log says who uploaded what (`upload_signed`
has the name). The function's `USERS` setting is
`{"alice": "<fingerprint>", ...}`: fingerprints, not codes.

Read the current setting, change it with the tool, write it back. The tool
shows new codes once; it cannot show an existing one again. Run only the tool
line you need.

```bash
aws lambda get-function-configuration --function-name evtxkit-upload-api --region eu-north-1 --query "Environment.Variables.USERS" --output text > build/current-users.json
python tools/access_codes.py carol --keep @build/current-users.json --env-file build/upload-api-environment.json
python tools/access_codes.py --keep @build/current-users.json --remove bob --env-file build/upload-api-environment.json
python tools/access_codes.py alice --keep @build/current-users.json --remove alice --env-file build/upload-api-environment.json
aws lambda update-function-configuration --function-name evtxkit-upload-api --environment file://build/upload-api-environment.json --region eu-north-1
```

In order: add carol, take bob out, give alice a new code. A removed or replaced
code stops working as soon as the update has finished, a few seconds. What the
person uploaded stays where it is until it expires. A function's whole
environment is limited to 4 KB, about 30 people; past that, keep the
fingerprints in SSM Parameter Store, or move to a real login (Cognito).

Typing the code is safer than a link that carries it (`ADDRESS/#code=CODE`):
a link ends up in browser history and in chats.

### Codes that stop by themselves

Give anyone who is only borrowing the page, such as a reviewer, a last day. The
code works through the whole of that day (UTC) and then answers "This access
code has expired", with nothing to remember to remove. The function's log
records the attempt (`auth_expired`, with the person's name and IP address).

```bash
python tools/access_codes.py reviewer --keep @build/current-users.json --expire reviewer=2026-10-20 --env-file build/upload-api-environment.json
python tools/access_codes.py --keep @build/current-users.json --expire reviewer=2026-11-03 --env-file build/upload-api-environment.json
python tools/access_codes.py --keep @build/current-users.json --expire reviewer=none --env-file build/upload-api-environment.json
```

The first makes a new person with a last day, the second moves it, and the
third clears it. Moving or clearing a date for someone who already has a code
does not change their code. Then write the setting back with
`update-function-configuration`, as above. In `USERS` a person with a last day
looks like `{"sha256": "<fingerprint>", "expires": "2026-10-20"}`; a person
without one stays a plain fingerprint.

What a visitor is told: under the page, a short notice says that we don't keep
their files (the log is deleted as soon as it has been analysed, the report is
removed automatically within two days), to upload only logs they may share, and
that "no findings" does not prove a system is clean. Tests keep the notice true:
they check the one-day rules and that the task really deletes the upload and
keeps the report out of its log.

### Moving from the first version's single code

The first version of this page had one shared code in an `ACCESS_CODE`
setting. To move to people, update the code and then replace the environment,
which also drops `ACCESS_CODE`. For a few seconds in between, the API answers
503.

```bash
python tools/build_lambdas.py
python tools/access_codes.py alice bob --env-file build/upload-api-environment.json
aws lambda update-function-code --function-name evtxkit-upload-api --zip-file fileb://build/upload-api.zip --region eu-north-1
aws lambda wait function-updated-v2 --function-name evtxkit-upload-api --region eu-north-1
aws lambda update-function-configuration --function-name evtxkit-upload-api --environment file://build/upload-api-environment.json --region eu-north-1
```

## The CI deploy key

CI's deploy job (pushes to `main` only) signs in with the IAM user
`github-actions-deploy`, whose access key is stored in GitHub's secrets. A key
stored there should be able to do only what the workflow does. On 2026-10-06 it
was changed from four full-access AWS policies (IAM, S3, ECS and ECR, which
together would have let anyone holding the key create themselves an admin role
and read every upload and report) to one inline policy,
`aws/ci-deploy-policy.json`:

| Statement | Allows | Used for |
|---|---|---|
| `EcrLogin` | `ecr:GetAuthorizationToken` | `amazon-ecr-login` |
| `PushTheEvtxkitImage` | the five push calls, on the `evtxkit` repository only | `docker push` |
| `RegisterTheTaskDefinition` | `ecs:RegisterTaskDefinition` | `register-task-definition` |
| `RunTheTestTask` | `ecs:RunTask` on `evtxkit-task`, in `evtxkit-cluster` only | the smoke-test run |
| `PassTheTasksTwoRoles` | `iam:PassRole` for the two task roles, to ECS tasks only | both of the above |

It was checked before it was applied: AWS's policy simulator (`aws iam
simulate-custom-policy`) gave the expected answer for 35 cases, the 11 above
allowed and 24 dangerous ones (creating roles or users, attaching policies,
minting keys, reading either bucket, touching the Lambda functions, running
another task definition or cluster) denied. After it was applied, real calls
confirmed that the ECR login works and that IAM, S3, Lambda, ECS listing and
logs are refused. What has **not** been run is the deploy job itself: the next
push to `main` is that test, and if the policy is missing something, the job
fails with an AccessDenied that names the action to add.

```bash
aws iam put-user-policy --user-name github-actions-deploy --policy-name CiDeploy --policy-document file://aws/ci-deploy-policy.json
aws iam detach-user-policy --user-name github-actions-deploy --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
aws iam detach-user-policy --user-name github-actions-deploy --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam detach-user-policy --user-name github-actions-deploy --policy-arn arn:aws:iam::aws:policy/AmazonECS_FullAccess
aws iam detach-user-policy --user-name github-actions-deploy --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess
```

Consequences:

- The key can no longer do administrative work. The runbook's other commands
  (Lambda, bucket settings, IAM, log retention) need a separate admin identity,
  or a temporary policy attached in the console and removed afterwards. If the
  key is also what the AWS CLI on your PC uses, that PC can no longer run them.
- To roll back, re-attach the four managed policies in the console (IAM, Users,
  `github-actions-deploy`, Permissions).
- `ecs:RegisterTaskDefinition` cannot be limited to one resource, so a holder
  of the key could register a task definition of their own and run it as
  `evtxkit-task` with the task role. That is the least a deploy key can have.
- Next step, if you want no stored key at all: let GitHub Actions sign in with
  OpenID Connect to a role that has this same policy (the workflow then needs
  `permissions: id-token: write` and `role-to-assume`).

## Switching it off

The page stops answering as soon as its address is gone; nothing else has to
be touched, and the manual path of step 6 keeps working.

```bash
aws lambda delete-function-url-config --function-name evtxkit-upload-api --region eu-north-1
```

To stop uploads starting tasks as well:

```bash
aws s3api put-bucket-notification-configuration --bucket evtxkit-uploads-772325758655 --notification-configuration "{}"
```

## What this first version leaves out

- **Rate limiting.** A function URL has none. A person's code is the only
  gate, so anyone holding a code can start as many tasks as they like. For real customers, put
  the same function behind an API Gateway HTTP API (it sends the same event
  format, so the code does not change) or CloudFront with WAF, and give each
  customer a real login (Amazon Cognito).
- **A retry queue for the trigger.** If ECS refuses to start a task three
  times in a row, that upload is never analysed and the page says so after
  six minutes. The reason is in the trigger's log; nothing re-drives it.
- **Automated deployment.** CI builds and registers the task, not these two
  functions.

## Checking the policies against the code

The four permission policies in this folder were written by hand from the
calls the code makes, and `tests/test_upload_flow.py` fails if one of them
grows a wildcard or a resource it should not have. For an independent check:

```bash
uvx iam-policy-autopilot@latest generate-policies "$(pwd)/s3_wrapper.py" "$(pwd)/aws/lambda/start_analysis/handler.py" "$(pwd)/aws/lambda/upload_api/handler.py" --region eu-north-1 --account 772325758655 --service-hints s3 ecs --pretty
```

It reads the SDK calls in the source. It cannot see that a pre-signed upload
needs `s3:PutObject`, because signing is not a call to AWS.
