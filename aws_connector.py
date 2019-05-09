# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

from aws_consts import *

import uuid
import json
import boto3
import datetime


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


def _json_fallback(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return obj


class AwsConnector(BaseConnector):
    # NOTE: EC2 Actions
    ACTION_ID_LOOKUP_INSTANCE = "lookup_instance"
    ACTION_ID_STOP_INSTANCE = "stop_instance"
    ACTION_ID_START_INSTANCE = "start_instance"
    ACTION_ID_CREATE_INSTANCE = "create_instance"
    ACTION_ID_QUARANTINE = "quarantine_instance"
    ACTION_ID_SNAPSHOT = "snapshot_instance"
    ACTION_ID_BLACKLIST = "blacklist_ip"
    ACTION_ID_WHITELIST = "whitelist_ip"
    ACTION_ID_DISABLE_EC2 = "disable_ec2_access"
    ACTION_ID_ENABLE_EC2 = "enable_ec2_access"
    ACTION_ID_DISABLE_SG_ACCESS = "disable_sg_access"
    ACTION_ID_ENABLE_SG_ACCESS = "enable_sg_access"
    ACTION_ID_REMOVE_SG_INGRESS = "remove_sg_ingress"
    ACTION_ID_ASG_DETACH_INSTANCE = "asg_detach_instance"

    # NOTE: IAM Actions
    ACTION_ID_DISABLE_ACCT = "disable_user_acct"
    ACTION_ID_ENABLE_ACCT = "enable_user_acct"

    # NOTE: Lambda Actions
    ACTION_ID_INVOKE_LAMBDA_FUNCTION = "invoke_lambda_function"

    def __init__(self):

        # Call the BaseConnectors init first
        super(AwsConnector, self).__init__()

        self._state = None
        self._client = None

    def _get_client(self, service='ec2'):

        def aws_credentials_exist(config):

            """
            Both the access key and secret key must exist
            to build the client. We recommend configuring a role
            and instance profile. This is a more secure way to access
            the AWS API
            """
            aws_cred_config_vars = [AWS_ACCESS_KEY, AWS_SECRET_KEY]
            aws_creds = [
                cred for cred in (config.get(aws_cred) for aws_cred in aws_cred_config_vars) if cred is not None
            ]
            print(len(aws_creds))
            return len(aws_creds) == 2

        config = self.get_config()
        region_name = config.get(AWS_REGION)

        if aws_credentials_exist(config):
            access_key = config.get(AWS_ACCESS_KEY)
            secret_key = config.get(AWS_SECRET_KEY)

            # NOTE: Access key and secret key specified
            self._client = boto3.client(
                service,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region_name
            )

            return

        # NOTE: Use instance profile by default
        self._client = boto3.client(
            service,
            region_name=region_name
        )

    def _assume_role(self, role, action_result, service='ec2'):

        self.debug_print("Assuming role, {0}".format(role))
        try:
            assumed_role = self._client.assume_role(RoleArn=role, RoleSessionName="AssumedRole")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'Error occured while processing the given role: {0}. Error: {1}'.format(role, str(e)))

        creds = assumed_role['Credentials']

        self._client = boto3.client(
            service,
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=self.get_config().get(AWS_REGION)
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        try:
            self.save_progress("Creating AWS client...")
            self._get_client()
            self.save_progress("Test Service Call...")
            self._client.describe_regions()
            self.save_progress("Successfully connected to AWS")

        except Exception as e:
            self.save_progress("Test Connectivity Failed")
            self.append_to_message(AWS_ERR_CONNECTIVITY_TEST)
            return action_result.set_status(phantom.APP_ERROR, AWS_ERR_SERVER_CONNECTION, e)

        return self.set_status_save_progress(
            phantom.APP_SUCCESS,
            AWS_SUCC_CONNECTIVITY_TEST
        )

    def _handle_lookup_instance(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='autoscaling')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='autoscaling')
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_instance_id = param[EC2_IP_INSTANCE_ID]

        try:
            instance = self._lookup_instance(ip_instance_id)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        if instance is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                AWS_RETURNED_NO_DATA
            )

        instance = json.dumps(instance, default=_json_fallback)
        instance = json.loads(instance)
        action_result.add_data(instance)

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {}".format(instance["InstanceId"])
        )

        return action_result.get_status()

    def _handle_asg_detach_instance(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='autoscaling')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='autoscaling')
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_instance_id = param[EC2_IP_INSTANCE_ID]

        try:
            instance = self._lookup_instance(ip_instance_id)
            self._asg_detach_instance(instance, action_result)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        if instance is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                AWS_RETURNED_NO_DATA
            )

        instance = json.dumps(instance, default=_json_fallback)
        instance = json.loads(instance)
        action_result.add_data(instance)

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {}".format(instance["InstanceId"])
        )

        return action_result.get_status()

    def _handle_stop_instance(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_instance_id = param[EC2_IP_INSTANCE_ID]

        try:
            instance = self._lookup_instance(ip_instance_id)
            if instance is None:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    AWS_RETURNED_NO_DATA
                )
            self._stop_instance(instance)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        instance = json.dumps(instance, default=_json_fallback)
        instance = json.loads(instance)
        action_result.add_data(instance)

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {} was stopped.".format(instance["InstanceId"])
        )

        return action_result.get_status()

    def _handle_start_instance(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_instance_id = param[EC2_IP_INSTANCE_ID]

        try:
            instance = self._lookup_instance(ip_instance_id)
            if instance is None:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    AWS_RETURNED_NO_DATA
                )
            self._start_instance(instance)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        instance = json.dumps(instance, default=_json_fallback)
        instance = json.loads(instance)
        action_result.add_data(instance)

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {} was started.".format(instance["InstanceId"])
        )

        return action_result.get_status()

    def _handle_create_instance(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        image_id = param[EC2_IMAGE_ID]
        instance_type = param[EC2_INSTANCE_TYPE]
        key_name = param[EC2_SSH_KEY_NAME]
        security_group_ids = param[SECURITY_GROUP_IDS]
        subnet_id = param[SUBNET_ID]
        associate_public_ip_address = param[ENI_ASSOCIATE_PUBLIC_IP_OPTION]
        delete_eni_on_termination = param[ENI_DELETE_ON_TERMINATON_OPTION]
        eni_description = param.get(ENI_DESCRIPTION)
        tags = param.get(EC2_TAGS)
        wait_for_status_checks = param[EC2_WAIT_FOR_STATUS_CHECKS_OPTION]

        try:
            create_instance_response = self._create_instance(
                image_id=image_id,
                instance_type=instance_type,
                key_name=key_name,
                security_group_ids=security_group_ids,
                subnet_id=subnet_id,
                associate_public_ip_address=associate_public_ip_address,
                delete_eni_on_termination=delete_eni_on_termination,
                eni_description=eni_description,
                tags=tags,
                wait_for_status_checks=wait_for_status_checks
            )

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {0} was created.".format(
                create_instance_response["InstanceId"]
            )
        )

        return action_result.get_status()

    def _handle_quarantine(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_instance_id = param[EC2_IP_INSTANCE_ID]

        try:
            instance = self._lookup_instance(ip_instance_id)
            if instance is None:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    AWS_RETURNED_NO_DATA
                )
            self._quarantine_instance(instance)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        instance = json.dumps(instance, default=_json_fallback)
        instance = json.loads(instance)
        action_result.add_data(instance)

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {} was quarantined successfully.".format(
                instance["InstanceId"]
            )
        )

        return action_result.get_status()

    def _handle_snapshot(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_instance_id = param[EC2_IP_INSTANCE_ID]

        try:
            instance = self._lookup_instance(ip_instance_id)
            if instance is None:
                return action_result.set_status(
                    phantom.APP_ERROR,
                    AWS_RETURNED_NO_DATA
                )
            self._snapshot_instance(instance)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        instance = json.dumps(instance, default=_json_fallback)
        instance = json.loads(instance)
        action_result.add_data(instance)

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Instance Id: {} was snapshotted successfully.".format(
                instance["InstanceId"]
            )
        )

        return action_result.get_status()

    def _handle_blacklist_ip(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_address = param[IP_ADDRESS]

        try:
            self._blacklist_ip(ip_address)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully Blacklisted: {}".format(ip_address)
        )

        return action_result.get_status()

    def _handle_whitelist_ip(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        ip_address = param[IP_ADDRESS]

        try:
            self._whitelist_ip(ip_address)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully Whitelisted: {}".format(ip_address)
        )

        return action_result.get_status()

    def _handle_disable_acct(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='iam')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='iam')
            if phantom.is_fail(resp):
                return action_result.get_status()

        username = param[AWS_USERNAME]

        try:
            self._disable_account(username)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully disabled: {}".format(username)
        )

        return action_result.get_status()

    def _handle_enable_acct(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='iam')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='iam')
            if phantom.is_fail(resp):
                return action_result.get_status()

        username = param[AWS_USERNAME]

        try:
            self._enable_account(username)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully enabled: {}".format(username)
        )

        return action_result.get_status()

    def _handle_disable_ec2_access(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='iam')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='iam')
            if phantom.is_fail(resp):
                return action_result.get_status()

        username = param[AWS_USERNAME]

        try:
            self._disable_ec2_access(username)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully disabled EC2 access: {}".format(username)
        )

        return action_result.get_status()

    def _handle_enable_ec2_access(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='iam')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='iam')
            if phantom.is_fail(resp):
                return action_result.get_status()

        username = param[AWS_USERNAME]

        try:
            self._enable_ec2_access(username)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully enabled EC2 access: {}".format(username)
        )

        return action_result.get_status()

    def _handle_disable_sg_access(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='iam')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='iam')
            if phantom.is_fail(resp):
                return action_result.get_status()

        username = param[AWS_USERNAME]

        try:
            self._disable_sg_access(username)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully disabled security group access: {}".format(username)
        )

        return action_result.get_status()

    def _handle_enable_sg_access(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='iam')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='iam')
            if phantom.is_fail(resp):
                return action_result.get_status()

        username = param[AWS_USERNAME]

        try:
            self._enable_sg_access(username)

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully enabled security group access: {}".format(username)
        )

        return action_result.get_status()

    def _handle_remove_sg_ingress(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client()
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result)
            if phantom.is_fail(resp):
                return action_result.get_status()

        sg_id = param[SECURITY_GROUP_ID]
        sg_item = param[SECURITY_GROUP_ITEM]

        try:
            response = self._remove_sg_ingress(sg_id, sg_item, action_result)
            if phantom.is_fail(response):
                return action_result.get_status()

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully revoke security group ingress rule"
        )

        return action_result.get_status()

    def _handle_invoke_lambda_function(self, param):

        action_result = ActionResult(dict(param))
        self.add_action_result(action_result)

        if 'role' not in param:
            self._get_client(service='lambda')
        else:
            self._get_client(service='sts')
            resp = self._assume_role(param['role'], action_result, service='lambda')
            if phantom.is_fail(resp):
                return action_result.get_status()

        lambda_function_name = param[LAMBDA_FUNCTION_NAME]
        lambda_invocation_type = param[LAMBDA_INVOCATION_TYPE]
        lambda_payload = param.get(LAMBDA_PAYLOAD)

        try:
            if lambda_payload:
                invocation_response = self._invoke_lambda(
                    lambda_function_name,
                    lambda_invocation_type,
                    lambda_payload
                )

                serialized_invocation_response = invocation_response['Payload'].read()
                action_result.add_data(
                    json.loads(serialized_invocation_response)
                )

            elif not lambda_payload:
                invocation_response = self._invoke_lambda(
                    lambda_function_name,
                    lambda_invocation_type,
                )

        except Exception as e:
            action_result.set_status(phantom.APP_ERROR, AWS_ERR, e)
            return action_result.get_status()

        action_result.set_status(
            phantom.APP_SUCCESS,
            "Successfully invoked lambda function: {}".format(lambda_function_name)
        )

        return action_result.get_status()

    def _stop_instance(self, instance):
        self._client.stop_instances(
            InstanceIds=[
                instance["InstanceId"],
            ]
        )

    def _start_instance(self, instance):
        self._client.start_instances(
            InstanceIds=[
                instance["InstanceId"],
            ]
        )

    def _create_instance(
        self,
        image_id,
        instance_type,
        key_name,
        security_group_ids,
        subnet_id,
        associate_public_ip_address,
        delete_eni_on_termination,
        eni_description,
        tags,
        wait_for_status_checks
    ):
        reservation = self._client.run_instances(
            ImageId=image_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    'AssociatePublicIpAddress': associate_public_ip_address,
                    'DeleteOnTermination': delete_eni_on_termination,
                    'Description': eni_description,
                    'DeviceIndex': 0,
                    'SubnetId': subnet_id,
                },
            ],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': self._parse_tags(tags)
                },
            ]
        )

        instance = reservation['Instances'][0]
        instance_id = reservation['Instances'][0]['InstanceId']

        if wait_for_status_checks:
            instance_status_check_waiter = self._client.get_waiter('instance_status_ok')

            # NOTE: Poll until new instance passes status checks
            instance_status_check_waiter.wait(
                InstanceIds=[
                    instance_id,
                ],
            )

        # NOTE: Add sg's for external access
        self._client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[security_group_ids]
        )

        return instance

    def _parse_tags(self, serialized_tags):
        tags_list = []
        tags = json.loads(serialized_tags)

        for tag_key, tag_val in tags.items():
            ec2_boto_tags_schema = {
                "Key": tag_key,
                "Value": tag_val,
            }
            tags_list.append(ec2_boto_tags_schema)

        return tags_list

    def _blacklist_ip(self, ip_address):
        nacls = self._client.describe_network_acls()

        for nacl in nacls["NetworkAcls"]:
            min_rule_id = min(
                rule['RuleNumber'] for rule in nacl["Entries"] if not rule["Egress"]
            )
            if min_rule_id < 1:
                raise Exception("Rule number is less than 1")
            self._client.create_network_acl_entry(
                CidrBlock='{}/32'.format(ip_address),
                Egress=False,
                NetworkAclId=nacl["NetworkAclId"],
                Protocol='-1',
                RuleAction='deny',
                RuleNumber=min_rule_id - 1,
            )

    def _whitelist_ip(self, ip_address):
        nacls = self._client.describe_network_acls()

        for nacl in nacls["NetworkAcls"]:
            for rule in nacl["Entries"]:
                if rule["CidrBlock"] == '{}/32'.format(ip_address):
                    self._client.delete_network_acl_entry(
                        NetworkAclId=nacl["NetworkAclId"],
                        Egress=rule["Egress"],
                        RuleNumber=rule["RuleNumber"]
                    )

    def _quarantine_instance(self, instance):
        instance_id = instance["InstanceId"]
        vpc_id = instance["VpcId"]

        # NOTE: Create a quarantine security with no ingress or egress rules
        sg = self._client.create_security_group(
            GroupName='Quarantine-{}'.format(str(uuid.uuid4().fields[-1])[:6]),
            Description='Quarantine for {}'.format(instance_id),
            VpcId=vpc_id
        )
        sg_id = sg["GroupId"]

        # NOTE: Remove the default egress group
        self._client.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',
                    'FromPort': 0,
                    'ToPort': 65535,
                    'IpRanges': [
                        {
                            'CidrIp': REVOKE_ALL_EGRESS_CIDR
                        },
                    ]
                }
            ]
        )

        # NOTE: Assign security group to instance
        self._client.modify_instance_attribute(InstanceId=instance_id, Groups=[sg_id])
        self._add_tag(
            self._client,
            instance_id,
            "Quarantine",
            "true"
        )
        self._add_tag(
            self._client,
            sg_id,
            "Name",
            "Phantom Quarantine {}".format(instance_id)
        )

    def _snapshot_instance(self, instance):
        instance_id = instance["InstanceId"]
        blockmappings = instance["BlockDeviceMappings"]
        for device in blockmappings:
            snapshot = self._client.create_snapshot(
                VolumeId=device["Ebs"]["VolumeId"],
                Description="Created by Phantom for {}".format(instance_id)
            )
            self._add_tag(
                self._client,
                snapshot["SnapshotId"],
                "Name", "Phantom Snapshot {}".format(instance_id)
            )

    def _lookup_instance(self, ip_instance_id):
        """
        Returns an EC2 instance
        """
        import re
        instance_id_match = re.match(r'i-[a-z-0-9]', ip_instance_id)
        # NOTE: https://aws.amazon.com/blogs/aws/theyre-here-longer-ec2-resource-ids-now-available/
        #       As EC2 demand continues to grow, the len of resource id's may change again...
        if instance_id_match:
            instance_id_length = len(ip_instance_id)
            if instance_id_length == 19:
                return self._get_instance_from_instance_id(ip_instance_id)

            else:
                raise Exception(EC2_INSTANCEID_INVALID.format(ip_instance_id, str(instance_id_length)))

        # NOTE: Consider using https://pypi.python.org/pypi/IPy/ if need be.
        #       Assume IP is passed and let boto err surface if
        #       ip_instance_id malformed or None
        else:
            return self._get_instance_from_ip(ip_instance_id)

    def _get_instance_from_ip(self, ip_address):

        public_ip_filter = [
            {
                'Name': 'ip-address',
                'Values': [
                    ip_address,
                ]
            },
        ]
        reservations = self._client.describe_instances(Filters=public_ip_filter)

        if len(reservations['Reservations']) == 0:
            private_ip_filter = [
                {
                    'Name': 'private-ip-address',
                    'Values': [
                        ip_address,
                    ]
                },
            ]
            reservations = self._client.describe_instances(Filters=private_ip_filter)

        if len(reservations['Reservations']) == 1:
            instance = reservations['Reservations'][0]['Instances'][0]
        else:
            instance = None

        return instance

    def _get_instance_from_instance_id(self, instance_id):

        instance_id_filter = [
            {
                'Name': 'instance-id',
                'Values': [
                    instance_id,
                ]
            },
        ]
        reservations = self._client.describe_instances(Filters=instance_id_filter)

        if len(reservations['Reservations']) == 1:
            instance = reservations['Reservations'][0]['Instances'][0]
        else:
            instance = None

        return instance

    def _disable_account(self, username):
        self._client.put_user_policy(
            UserName=username,
            PolicyName='PhantomBlockAllPolicy',
            PolicyDocument="{\"Version\":\"2012-10-17\", \"Statement\""
                           ":{\"Effect\":\"Deny\", \"Action\":\"*\", "
                           "\"Resource\":\"*\"}}"
        )

    def _enable_account(self, username):
        self._client.delete_user_policy(
            UserName=username,
            PolicyName='PhantomBlockAllPolicy',
        )

    def _disable_ec2_access(self, username):
        self._client.put_user_policy(
            UserName=username,
            PolicyName='PhantomBlockEc2Policy',
            PolicyDocument="{\"Version\":\"2012-10-17\", \"Statement\""
                           ":{\"Effect\":\"Deny\", \"Action\":\"*\", "
                           "\"Resource\":\"ec2:*\"}}"
        )

    def _enable_ec2_access(self, username):
        self._client.delete_user_policy(
            UserName=username,
            PolicyName='PhantomBlockEc2Policy',
        )

    def _disable_sg_access(self, username):
        self._client.put_user_policy(
            UserName=username,
            PolicyName='PhantomBlockSecurityGroupPolicy',
            PolicyDocument="{\"Version\":\"2012-10-17\", \"Statement\""
                           ":{\"Effect\":\"Deny\", \"Action\": [ "
                           "\"ec2:AuthorizeSecurityGroupIngress\", "
                           "\"ec2:RevokeSecurityGroupIngress\", "
                           "\"ec2:AuthorizeSecurityGroupEgress\", "
                           "\"ec2:RevokeSecurityGroupEgress\" ], "
                           "\"Resource\":\"*\"}}"
        )

    def _enable_sg_access(self, username):
        self._client.delete_user_policy(
            UserName=username,
            PolicyName='PhantomBlockSecurityGroupPolicy',
        )

    def _remove_sg_ingress(self, sg_id, item, action_result):

        action_result.add_data("item")
        action_result.add_data(item)

        remove_item = json.loads(item)
        if not isinstance(remove_item, dict):
            return action_result.set_status(phantom.APP_ERROR, 'Please provide the item in JSON format')

        # NOTE: Need to map parameters because of first letter
        # casing is different (lower case in event,
        # upper case for input to API call)
        map_params = {
            'IpProtocol': remove_item['ipProtocol'],
            'FromPort': remove_item['fromPort'],
            'ToPort': remove_item['toPort'],
            'IpRanges': [
                {
                    'CidrIp': remove_item['ipRanges']['items'][0]['cidrIp']
                },
            ]
        }

        self._client.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[map_params]
        )
        return action_result.set_status(phantom.APP_SUCCESS)

    def _add_tags(self, client, resource_id, tags_list):
        self._client.create_tags(
            Resources=[
                resource_id,
            ],
            Tags=tags_list
        )

    def _add_tag(self, client, resource_id, tag_key, tag_valueue):
        self._client.create_tags(
            Resources=[
                resource_id,
            ],
            Tags=[
                {
                    'Key': tag_key,
                    'Value': tag_valueue
                },
            ]
        )

    def _asg_detach_instance(self, instance, action_result):
        response = self._client.describe_auto_scaling_instances(
            InstanceIds=[
                instance["InstanceId"],
            ],
            MaxRecords=1
        )

        asg_name = None
        instances = response['AutoScalingInstances']
        if instances[0]:
            asg_name = instances[0]['AutoScalingGroupName']

        if asg_name is not None:
            response = self._client.detach_instances(
                InstanceIds=[
                    instance["InstanceId"],
                ],
                AutoScalingGroupName=asg_name,
                ShouldDecrementDesiredCapacity=False
            )

    def _invoke_lambda(
        self,
        lambda_function_name,
        invocation_type,
        payload=None
    ):
        """
        invocation_type: 'RequestResponse' | 'Event'
        """

        if payload:
            lambda_invocation_response = self._client.invoke(
                FunctionName=lambda_function_name,
                InvocationType=invocation_type,
                Payload=payload,
            )

        elif not payload:
            lambda_invocation_response = self._client.invoke(
                FunctionName=lambda_function_name,
                InvocationType=invocation_type,
            )

        return lambda_invocation_response

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)

        elif action_id == self.ACTION_ID_LOOKUP_INSTANCE:
            ret_val = self._handle_lookup_instance(param)

        elif action_id == self.ACTION_ID_STOP_INSTANCE:
            ret_val = self._handle_stop_instance(param)

        elif action_id == self.ACTION_ID_START_INSTANCE:
            ret_val = self._handle_start_instance(param)

        elif action_id == self.ACTION_ID_CREATE_INSTANCE:
            ret_val = self._handle_create_instance(param)

        elif action_id == self.ACTION_ID_QUARANTINE:
            ret_val = self._handle_quarantine(param)

        elif action_id == self.ACTION_ID_SNAPSHOT:
            ret_val = self._handle_snapshot(param)

        elif action_id == self.ACTION_ID_BLACKLIST:
            ret_val = self._handle_blacklist_ip(param)

        elif action_id == self.ACTION_ID_WHITELIST:
            ret_val = self._handle_whitelist_ip(param)

        elif action_id == self.ACTION_ID_DISABLE_ACCT:
            ret_val = self._handle_disable_acct(param)

        elif action_id == self.ACTION_ID_ENABLE_ACCT:
            ret_val = self._handle_enable_acct(param)

        elif action_id == self.ACTION_ID_DISABLE_EC2:
            ret_val = self._handle_disable_ec2_access(param)

        elif action_id == self.ACTION_ID_ENABLE_EC2:
            ret_val = self._handle_enable_ec2_access(param)

        elif action_id == self.ACTION_ID_DISABLE_SG_ACCESS:
            ret_val = self._handle_disable_sg_access(param)

        elif action_id == self.ACTION_ID_ENABLE_SG_ACCESS:
            ret_val = self._handle_enable_sg_access(param)

        elif action_id == self.ACTION_ID_REMOVE_SG_INGRESS:
            ret_val = self._handle_remove_sg_ingress(param)

        elif action_id == self.ACTION_ID_ASG_DETACH_INSTANCE:
            ret_val = self._handle_asg_detach_instance(param)

        elif action_id == self.ACTION_ID_INVOKE_LAMBDA_FUNCTION:
            ret_val = self._handle_invoke_lambda_function(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        """
        # get the asset config
        config = self.get_config()

        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AwsConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
