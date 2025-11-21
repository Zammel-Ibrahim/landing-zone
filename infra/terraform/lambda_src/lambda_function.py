import boto3
import os
import time

ec2 = boto3.client('ec2')
ssm = boto3.client('ssm')

def lambda_handler(event, context):
    secondary_az = os.environ.get("SECONDARY_AZ")
    tag_prefix = os.environ.get("TAG_PREFIX", "web-")

    # Find stopped instances in secondary AZ with Name tag starting with tag_prefix
    filters = [
        {'Name': 'availability-zone', 'Values': [secondary_az]},
        {'Name': 'instance-state-name', 'Values': ['stopped']},
        {'Name': 'tag:Name', 'Values': [f"{tag_prefix}*"]}
    ]
    instances = []
    resp = ec2.describe_instances(Filters=filters)
    for r in resp.get('Reservations', []):
        for i in r.get('Instances', []):
            instances.append(i['InstanceId'])

    if not instances:
        return {"started": [], "message": "no stopped instances found in secondary AZ"}

    ec2.start_instances(InstanceIds=instances)

    # Wait for instances to be running
    waiter = ec2.get_waiter('instance_running')
    waiter.wait(InstanceIds=instances, WaiterConfig={'Delay': 10, 'MaxAttempts': 30})

    try:
        ssm_resp = ssm.send_command(
            InstanceIds=instances,
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["systemctl start httpd || true", "systemctl start postgresql || true"]},
            TimeoutSeconds=600
        )
        return {"started": instances, "ssm_command_id": ssm_resp.get('Command', {}).get('CommandId')}
    except Exception as e:
        return {"started": instances, "ssm_error": str(e)}