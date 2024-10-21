import boto3
import logging
import json
import time
import os

# Initialize AWS clients
ec2_client = boto3.client('ec2')
ssm_client = boto3.client('ssm')
config_client = boto3.client('config')
iam_client = boto3.client('iam')
macie_client = boto3.client('macie2')
guardduty_client = boto3.client('guardduty')
eks_client = boto3.client('eks')
elb_client = boto3.client('elbv2')
athena_client = boto3.client('athena')
cloudtrail_client = boto3.client('cloudtrail')
kms_client = boto3.client('kms')
backup_client = boto3.client('backup')

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set the desired retention period (in days)
RETENTION_PERIOD_DAYS = 90  # Adjust this value as needed

def lambda_handler(event, context):
    logger.info("Event received: %s", event)
    try:
    
        # AWS Config Rule: securityhub-ec2-managedinstance-association-compliance-status-check-068c1c5d
        if event['configRuleName'] == 'securityhub-ec2-managedinstance-association-compliance-status-check-068c1c5d':
            remediate_ec2_ssm(event)

        # AWS Config Rule: securityhub-eip-attached-21e800ac
        elif event['configRuleName'] == 'securityhub-eip-attached-21e800ac':
            return remediate_unattached_eips()

        # AWS Config Rule: securityhub-guardduty-eks-protection-runtime-enabled-a79f2d2e
        elif event['configRuleName'] == 'securityhub-guardduty-eks-protection-runtime-enabled-a79f2d2e':
            remediate_eks_runtime_protection(event)

        # AWS Config Rule: securityhub-elb-deletion-protection-enabled-72f85c25
        elif event['configRuleName'] == 'securityhub-elb-deletion-protection-enabled-72f85c25':
            return remediate_elb_deletion_protection(event)

        # AWS Config Rule: securityhub-lambda-inside-vpc-63fbd6da
        elif event['configRuleName'] == 'securityhub-lambda-inside-vpc-63fbd6da':
            return remediate_lambda_vpc()

        # AWS Config Rule: securityhub-macie-status-check-c447fedd
        elif event['configRuleName'] == 'securityhub-macie-status-check-c447fedd':
            return remediate_macie_status(event)

        # AWS Config Rule: securityhub-iam-policy-no-statements-with-full-access-ad47573f
        elif event['configRuleName'] == 'securityhub-iam-policy-no-statements-with-full-access-ad47573f':
            return remediate_iam_policy_full_access(event)

        # AWS Config Rule: securityhub-iam-policy-no-statements-with-admin-access-e89c3ab8
        elif event['configRuleName'] == 'securityhub-iam-policy-no-statements-with-admin-access-e89c3ab8':
            return remediate_iam_policy_admin_access(event)

        # AWS Config Rule: securityhub-iam-user-no-policies-check-dda214c1
        elif event['configRuleName'] == 'securityhub-iam-user-no-policies-check-dda214c1':
            return remediate_iam_user_policies()

        # AWS Config Rule: securityhub-iam-customer-policy-blocked-kms-actions-Oe8ab023
        elif event['configRuleName'] == 'securityhub-iam-customer-policy-blocked-kms-actions-Oe8ab023':
            return remediate_kms_actions(event)
            
        # Check for each AWS Config rule and execute remediation if necessary
        elif 'securityhub-athena-workgroup-logging-enabled-4529ffdb' in event['detail']['configRuleName']:
            check_athena_logging(event)

        elif 'securityhub-autoscaling-launch-template-6b37ac5c' in event['detail']['configRuleName']:
            check_launch_template(event)

        elif 'securityhub-cloud-trail-encryption-enabled-95734ec3' in event['detail']['configRuleName']:
            check_cloudtrail_encryption(event)

        elif 'securityhub-autoscaling-launchconfig-requires-imdsv2-96f01f87' in event['detail']['configRuleName']:
            check_launch_configuration_imdsv2()

        elif 'securityhub-cloud-trail-cloud-watch-logs-enabled-1fa0fc24' in event['detail']['configRuleName']:
            check_cloudtrail_logging()

        elif 'securityhub-cmk-backing-key-rotation-enabled-1d3ada6c' in event['detail']['configRuleName']:
            check_cmk_key_rotation(event)

        elif 'securityhub-cw-loggroup-retention-period-check-5c544a32' in event['detail']['configRuleName']:
            check_log_group_retention()

        elif 'securityhub-ebs-resources-protected-by-backup-plan-49a3c3f7' in event['detail']['configRuleName']:
            check_ebs_backup(event)

        return {
            'statusCode': 200,
            'body': json.dumps('Remediation processes executed successfully.')
        }
        
    except Exception as e:
    logger.error(f"Error in remediation execution: {str(e)}")
    return {
       'statusCode': 500,
       'body': json.dumps('Remediation process failed.')
    }

def remediate_ec2_ssm(event):
    non_compliant_instance_id = event['resourceId']
    logger.info(f"Processing EC2 instance {non_compliant_instance_id}")

    try:
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [non_compliant_instance_id]}]
        )
        
        if response['InstanceInformationList']:
            logger.info(f"Instance {non_compliant_instance_id} is already managed by SSM")
            return
        
        instance = ec2_client.describe_instances(InstanceIds=[non_compliant_instance_id])
        instance_profile = instance['Reservations'][0]['Instances'][0].get('IamInstanceProfile')

        if not instance_profile:
            logger.info(f"Instance {non_compliant_instance_id} does not have an IAM role, assigning...")
            ec2_client.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': 'arn:aws:iam::<account_id>:instance-profile/SSMManagedInstanceRole'
                },
                InstanceId=non_compliant_instance_id
            )

        logger.info(f"Installing SSM agent on instance {non_compliant_instance_id}")
        ssm_client.send_command(
            InstanceIds=[non_compliant_instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": [
                    "sudo yum install -y amazon-ssm-agent",
                    "sudo systemctl start amazon-ssm-agent",
                    "sudo systemctl enable amazon-ssm-agent"
                ]
            },
            TimeoutSeconds=600
        )
        logger.info(f"Successfully remediated non-compliance for instance {non_compliant_instance_id}")

    except Exception as e:
        logger.error(f"Failed to remediate instance {non_compliant_instance_id}: {e}")
        raise

def remediate_unattached_eips():
    try:
        response = ec2_client.describe_addresses()
        eip_list = response['Addresses']
        
        unattached_eips = [eip['PublicIp'] for eip in eip_list if 'InstanceId' not in eip and 'NetworkInterfaceId' not in eip]
        
        for eip in unattached_eips:
            ec2_client.release_address(PublicIp=eip)
            logger.info(f"Released unattached EIP: {eip}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f"Released {len(unattached_eips)} unattached Elastic IP(s).")
        }

    except Exception as e:
        logger.error(f"Error releasing EIPs: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error releasing EIPs: {str(e)}")
        }

def remediate_eks_runtime_protection(event):
    try:
        detector_id = get_guardduty_detector()
        if not detector_id:
            logger.error("GuardDuty detector not found.")
            return
        
        non_compliant_cluster_name = event['detail']['resourceId']
        logger.info(f"Non-compliant EKS cluster: {non_compliant_cluster_name}")

        if not is_runtime_monitoring_enabled(non_compliant_cluster_name, detector_id):
            logger.info(f"Enabling runtime protection for cluster: {non_compliant_cluster_name}")
            enable_runtime_monitoring(non_compliant_cluster_name, detector_id)
            logger.info(f"Runtime protection enabled for cluster: {non_compliant_cluster_name}")
        else:
            logger.info(f"Runtime protection already enabled for cluster: {non_compliant_cluster_name}")
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise

def get_guardduty_detector():
    try:
        response = guardduty_client.list_detectors()
        if 'DetectorIds' in response and len(response['DetectorIds']) > 0:
            return response['DetectorIds'][0]
        return None
    except Exception as e:
        logger.error(f"Error retrieving GuardDuty detectors: {str(e)}")
        raise

def is_runtime_monitoring_enabled(cluster_name, detector_id):
    try:
        response = guardduty_client.get_eks_runtime_monitoring(
            DetectorId=detector_id,
            ClusterName=cluster_name
        )
        return response.get('RuntimeMonitoringStatus') == 'ENABLED'
    except Exception as e:
        logger.error(f"Error checking runtime protection: {str(e)}")
        return False

def enable_runtime_monitoring(cluster_name, detector_id):
    try:
        guardduty_client.enable_eks_runtime_monitoring(
            DetectorId=detector_id,
            ClusterName=cluster_name
        )
    except Exception as e:
        logger.error(f"Error enabling runtime monitoring: {str(e)}")
        raise

def remediate_elb_deletion_protection(event):
    non_compliant_elb_arn = json.loads(event['invokingEvent'])['configurationItem']['resourceId']

    try:
        response = elb_client.describe_load_balancer_attributes(
            LoadBalancerArn=non_compliant_elb_arn
        )
        
        deletion_protection_enabled = any(
            attr['Key'] == 'deletion_protection.enabled' and attr['Value'] == 'true'
            for attr in response['Attributes']
        )

        if not deletion_protection_enabled:
            logger.info(f"Enabling deletion protection for ELB: {non_compliant_elb_arn}")
            elb_client.modify_load_balancer_attributes(
                LoadBalancerArn=non_compliant_elb_arn,
                Attributes=[{
                    'Key': 'deletion_protection.enabled',
                    'Value': 'true'
                }]
            )
            return {
                'statusCode': 200,
                'body': json.dumps(f"Deletion protection enabled for ELB: {non_compliant_elb_arn}")
            }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps(f"Deletion protection already enabled for ELB: {non_compliant_elb_arn}")
            }
    except Exception as e:
        logger.error(f"Error modifying ELB attributes: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error modifying ELB attributes: {str(e)}")
        }

def remediate_lambda_vpc():
    try:
        logger.info("Finding all Lambda functions...")
        lambda_client = boto3.client('lambda')
        response = lambda_client.list_functions()
        
        for function in response['Functions']:
            function_name = function['FunctionName']
            if 'VpcConfig' not in function:
                logger.info(f"Adding VPC configuration to function: {function_name}")
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    VpcConfig={
                        'SubnetIds': ['subnet-xxxxxx'],  # Replace with your subnet IDs
                        'SecurityGroupIds': ['sg-xxxxxx']  # Replace with your security group IDs
                    }
                )
                logger.info(f"Updated function {function_name} with VPC configuration.")
        
        return {
            'statusCode': 200,
            'body': json.dumps("VPC configuration added to Lambda functions without it.")
        }
    
    except Exception as e:
        logger.error(f"Error updating Lambda VPC: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error updating Lambda VPC: {str(e)}")
        }

def remediate_macie_status(event):
    try:
        logger.info("Updating Macie status...")
        macie_client.enable_macie()
        return {
            'statusCode': 200,
            'body': json.dumps("Macie status updated to enabled.")
        }
    except Exception as e:
        logger.error(f"Error enabling Macie: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error enabling Macie: {str(e)}")
        }

def remediate_iam_policy_full_access(event):
    policy_arn = event['resourceId']
    logger.info(f"Remediating IAM policy: {policy_arn}")

    try:
        response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = response['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)
        
        if policy_version['PolicyVersion']['Document']['Statement']:
            for statement in policy_version['PolicyVersion']['Document']['Statement']:
                if statement.get('Effect') == 'Allow' and 'Action' in statement and 'arn:aws:*:*:*' in statement['Action']:
                    logger.info(f"Deleting policy statement: {statement}")
                    iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)
        
        return {
            'statusCode': 200,
            'body': json.dumps(f"Policy {policy_arn} remediated.")
        }
    
    except Exception as e:
        logger.error(f"Error remediating IAM policy {policy_arn}: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error remediating IAM policy: {str(e)}")
        }

def remediate_iam_policy_admin_access(event):
    policy_arn = event['resourceId']
    logger.info(f"Checking IAM policy for admin access: {policy_arn}")

    try:
        response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = response['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)

        for statement in policy_version['PolicyVersion']['Document']['Statement']:
            if 'Action' in statement and 'iam:PassRole' in statement['Action']:
                logger.info(f"Deleting admin access statement: {statement}")
                iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)

        return {
            'statusCode': 200,
            'body': json.dumps(f"Policy {policy_arn} remediated for admin access.")
        }
    
    except Exception as e:
        logger.error(f"Error remediating IAM policy {policy_arn}: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error remediating IAM policy: {str(e)}")
        }

def remediate_iam_user_policies():
    try:
        logger.info("Checking IAM users for policies...")
        users = iam_client.list_users()
        
        for user in users['Users']:
            user_name = user['UserName']
            user_policies = iam_client.list_user_policies(UserName=user_name)

            for policy_name in user_policies['PolicyNames']:
                logger.info(f"Deleting inline policy {policy_name} for user {user_name}")
                iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        
        return {
            'statusCode': 200,
            'body': json.dumps("All inline policies deleted from IAM users.")
        }
    
    except Exception as e:
        logger.error(f"Error deleting IAM user policies: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error deleting IAM user policies: {str(e)}")
        }

def remediate_kms_actions(event):
    policy_arn = event['resourceId']
    logger.info(f"Checking KMS policy: {policy_arn}")

    try:
        response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = response['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)

        for statement in policy_version['PolicyVersion']['Document']['Statement']:
            if 'Action' in statement and 'kms:Decrypt' in statement['Action']:
                logger.info(f"Deleting KMS policy statement: {statement}")
                iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)

        return {
            'statusCode': 200,
            'body': json.dumps(f"KMS policy {policy_arn} remediated.")
        }
    
    except Exception as e:
        logger.error(f"Error remediating KMS policy {policy_arn}: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error remediating KMS policy: {str(e)}")
        }


def check_athena_logging(event):
    logger.info("Checking Athena workgroup logging...")
    response = athena_client.list_work_groups()
    workgroups = response.get('WorkGroups', [])
    
    for workgroup in workgroups:
        workgroup_name = workgroup['Name']
        logger.info(f"Checking workgroup: {workgroup_name}")

        workgroup_details = athena_client.get_work_group(WorkGroup=workgroup_name)
        logging_enabled = workgroup_details['WorkGroup']['Configuration'].get('ResultConfiguration', {}).get('OutputLocation') is not None

        if not logging_enabled:
            enable_logging(workgroup_name)

def enable_logging(workgroup_name):
    try:
        athena_client.update_work_group(
            WorkGroup=workgroup_name,
            ConfigurationUpdates={
                'ResultConfigurationUpdates': {
                    'OutputLocation': 's3://YOUR_S3_BUCKET_FOR_LOGGING/',
                    'EncryptionConfiguration': {
                        'EncryptionOption': 'SSE_S3'
                    }
                },
                'EnforceWorkGroupConfiguration': True,
                'PublishCloudWatchMetricsEnabled': True
            },
            State='ENABLED'
        )
        logger.info(f"Logging enabled for workgroup: {workgroup_name}")
    except Exception as e:
        logger.error(f"Failed to enable logging for workgroup {workgroup_name}: {str(e)}")

def check_launch_template(event):
    logger.info("Checking launch templates...")
    non_compliant_resources = event['detail']['resourceId']
    
    for resource_id in non_compliant_resources:
        try:
            response = ec2_client.describe_launch_templates(LaunchTemplateIds=[resource_id])
            launch_template = response['LaunchTemplates'][0]

            if not is_compliant(launch_template):
                new_version = create_compliant_launch_template_version(launch_template)
                logger.info(f"Created a compliant version for {resource_id}: {new_version}")

        except Exception as e:
            logger.error(f"Error processing resource {resource_id}: {e}")

def is_compliant(launch_template):
    return True  # Implement compliance checks based on your organization's requirements

def create_compliant_launch_template_version(launch_template):
    new_version_data = {
        'LaunchTemplateId': launch_template['LaunchTemplateId'],
        'VersionDescription': 'Compliant version',
        'LaunchTemplateData': {
            'IamInstanceProfile': {
                'Arn': 'arn:aws:iam::your-account-id:instance-profile/your-instance-profile'
            },
            # Add other necessary fields...
        }
    }

    response = ec2_client.create_launch_template_version(**new_version_data)
    return response['LaunchTemplateVersion']['VersionNumber']

def check_cloudtrail_encryption(event):
    logger.info("Checking CloudTrail encryption...")
    trails = cloudtrail_client.describe_trails()
    
    for trail in trails['trailList']:
        trail_name = trail['Name']
        kms_key_id = trail.get('KmsKeyId')

        if kms_key_id is None:
            logger.info(f"Enabling KMS encryption for trail: {trail_name}")
            cloudtrail_client.update_trail(
                Name=trail_name,
                KmsKeyId='alias/aws/cloudtrail'  # Use the default KMS key for CloudTrail or your own KMS key ARN
            )
            logger.info(f"KMS encryption enabled for trail: {trail_name}")
        else:
            logger.info(f"KMS encryption already enabled for trail: {trail_name}")

def check_launch_configuration_imdsv2():
    logger.info("Checking launch configurations for IMDSv2...")
    launch_configs = ec2_client.describe_launch_configurations()

    for lc in launch_configs['LaunchConfigurations']:
        lc_name = lc['LaunchConfigurationName']

        if lc.get('MetadataOptions', {}).get('HttpTokens') != 'required':
            logger.info(f"Updating Launch Configuration: {lc_name} to use IMDSv2")
            new_lc_name = f"{lc_name}-v2"
            response = ec2_client.create_launch_configuration(
                LaunchConfigurationName=new_lc_name,
                ImageId=lc['ImageId'],
                InstanceType=lc['InstanceType'],
                SecurityGroups=lc.get('SecurityGroups', []),
                KeyName=lc.get('KeyName', None),
                UserData=lc.get('UserData', None),
                IamInstanceProfile=lc.get('IamInstanceProfile', None),
                BlockDeviceMappings=lc.get('BlockDeviceMappings', []),
                InstanceMonitoring=lc.get('InstanceMonitoring', {}),
                SpotPrice=lc.get('SpotPrice', None),
                AssociatePublicIpAddress=lc.get('AssociatePublicIpAddress', None),
                MetadataOptions={
                    'HttpTokens': 'required',
                    'HttpEndpoint': 'enabled',
                    'HttpPutResponseHopLimit': 1,
                    'InstanceMetadataTags': 'enabled'
                }
            )
            logger.info(f"Launch Configuration updated to {new_lc_name}")

def check_cloudtrail_logging():
    logger.info("Checking CloudTrail CloudWatch logging...")
    trail_name = "YOUR_CLOUDTRAIL_NAME"  # Replace with your CloudTrail name
    log_group_name = "/aws/cloudtrail/YOUR_CLOUDTRAIL_NAME"  # Replace with your log group name

    response = cloudtrail_client.describe_trails(trailNameList=[trail_name])
    trails = response['trailList']

    if not trails:
        logger.error("No CloudTrail found with the specified name.")
        return

    trail = trails[0]

    if trail['CloudWatchLogsLogGroupArn'] is None:
        logger.info("CloudWatch Logs not enabled for CloudTrail. Enabling now...")
        cloudtrail_client.start_logging(Name=trail_name)

        try:
            logs_client.create_log_group(logGroupName=log_group_name)
        except logs_client.exceptions.ResourceAlreadyExistsException:
            logger.info(f"Log group {log_group_name} already exists.")

        cloudtrail_client.put_resource_policy(
            ResourcePolicy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "logs:PutLogEvents",
                    "Resource": log_group_name
                }]
            }),
            Name=trail_name
        )

        logger.info("Successfully enabled CloudWatch Logs for CloudTrail.")
    else:
        logger.info("CloudWatch Logs already enabled for CloudTrail.")

def check_cmk_key_rotation(event):
    logger.info("Checking CMK key rotation...")
    
    for record in event.get('records', []):
        cmk_id = record['configuration']['resourceId']
        logger.info("Checking CMK ID: %s", cmk_id)
        
        try:
            key_info = kms_client.describe_key(KeyId=cmk_id)
            key_metadata = key_info['KeyMetadata']
            
            if not key_metadata.get('KeyRotationEnabled', False):
                logger.info("Enabling key rotation for CMK ID: %s", cmk_id)
                kms_client.enable_key_rotation(KeyId=cmk_id)
                logger.info("Key rotation enabled for CMK ID: %s", cmk_id)
            else:
                logger.info("Key rotation already enabled for CMK ID: %s", cmk_id)

        except Exception as e:
            logger.error(f"Failed to check key rotation for CMK {cmk_id}: {str(e)}")

def check_log_group_retention():
    logger.info("Checking CloudWatch log group retention periods...")
    log_groups = logs_client.describe_log_groups()

    for log_group in log_groups['logGroups']:
        group_name = log_group['logGroupName']
        retention_days = log_group.get('retentionInDays')

        if retention_days is None or retention_days > RETENTION_PERIOD_DAYS:
            logger.info(f"Setting retention period for log group {group_name} to {RETENTION_PERIOD_DAYS} days.")
            logs_client.put_retention_policy(
                logGroupName=group_name,
                retentionInDays=RETENTION_PERIOD_DAYS
            )
            logger.info(f"Retention period set for log group {group_name}.")

def check_ebs_backup(event):
    logger.info("Checking EBS volumes for backup plans...")
    ebs_volumes = event['detail']['resourceId']

    for volume_id in ebs_volumes:
        response = backup_client.list_backup_plans()
        
        backup_plans = response.get('BackupPlansList', [])
        is_protected = any(volume_id in plan['ResourceId'] for plan in backup_plans)

        if not is_protected:
            logger.info(f"Adding EBS volume {volume_id} to backup plan.")
            # Implement the backup plan association logic here
            # Example:
            # backup_client.start_backup_job(...)

            logger.info(f"EBS volume {volume_id} has been added to the backup plan.")

