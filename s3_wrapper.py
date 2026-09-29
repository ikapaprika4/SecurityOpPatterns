import subprocess
import sys
import os
import datetime
import boto3

# Run evtxkit exactly as before, capturing its output instead of just printing it
result = subprocess.run(
    ["python3", "-m", "evtxkit"] + sys.argv[1:],
    capture_output=True, text=True
)

output = result.stdout
print(output)  # still print it, so CloudWatch logs keep showing it too

# Upload it to S3
bucket = os.environ["REPORT_BUCKET"]
timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
key = f"reports/report-{timestamp}.txt"

s3 = boto3.client("s3")
s3.put_object(Bucket=bucket, Key=key, Body=output)
print(f"Uploaded to s3://{bucket}/{key}")