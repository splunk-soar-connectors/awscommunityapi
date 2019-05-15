
# NOTE: Assets
AWS_ACCESS_KEY = "access_key"
AWS_SECRET_KEY = "secret_key"
AWS_REGION = "region"

# NOTE: EC2 Params
EC2_IP_INSTANCE_ID = "ip_instance_id"
SECURITY_GROUP_ID = "sg_id"
SECURITY_GROUP_ITEM = "sg_item"
EC2_IMAGE_ID = "image_id"
EC2_INSTANCE_TYPE = "instance_type"
EC2_SSH_KEY_NAME = "ssh_key_name"
SECURITY_GROUP_IDS = "security_group_ids"
SUBNET_ID = "subnet_id"
ENI_ASSOCIATE_PUBLIC_IP_OPTION = "eni_associate_public_ip"
ENI_DELETE_ON_TERMINATON_OPTION = "eni_delete_on_termination"
ENI_DESCRIPTION = "eni_description"
EC2_TAGS = "tags"
EC2_WAIT_FOR_STATUS_CHECKS_OPTION = "wait_for_status_checks"
REVOKE_ALL_EGRESS_CIDR = "0.0.0.0/0"

# NOTE: IAM params
AWS_USERNAME = "user_name"

# NOTE: Lambda params
LAMBDA_FUNCTION_NAME = "lambda_function_name"
LAMBDA_INVOCATION_TYPE = "lambda_invocation_type"
LAMBDA_PAYLOAD = "lambda_payload"

# NOTE: General params
IP_ADDRESS = "ip"

# NOTE: General AWS Messages
AWS_ERR = "AWS failed"
AWS_SUCC = "AWS successful"
AWS_RETURNED_NO_DATA = "AWS did not return any information"
AWS_ERR_SERVER_CONNECTION = "Connection to server failed"
AWS_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
AWS_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"

# NOTE: EC2 Messages
EC2_INSTANCEID_INVALID = 'Instance id: {0} length: {1} is invalid. EC2 instance ids are 19 chars by default'
