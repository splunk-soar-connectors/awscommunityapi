[comment]: # "Auto-generated SOAR connector documentation"
# AWS Community App

Publisher: Booz Allen Hamilton  
Connector Version: 1\.0\.5  
Product Vendor: Amazon Web Services  
Product Name: AWS  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.0\.1068  

A Phantom integration that facilitates interaction with the AWS API

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a AWS asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**access\_key** |  optional  | password | AWS access key
**secret\_key** |  optional  | password | AWS secret key
**region** |  optional  | string | AWS region

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[block ip](#action-block-ip) - Block IP by adding a rule to every subnet NACL accessible by credentials  
[unblock ip](#action-unblock-ip) - Unblock IP by removing any block rules from NACLs  
[disable acct](#action-disable-acct) - Disables an AWS IAM user account  
[enable acct](#action-enable-acct) - Enables an AWS IAM user account  
[remove access](#action-remove-access) - Removes EC2 Access for a given IAM user  
[enable access](#action-enable-access) - Enable EC2 Access for a given IAM user  
[remove sg access](#action-remove-sg-access) - Removes Security Group Access for a given IAM user  
[enable sg access](#action-enable-sg-access) - Enable Security Group Access for a given IAM user  
[remove sg ingress](#action-remove-sg-ingress) - Removes ingress rule from security group  
[lookup instance](#action-lookup-instance) - Return AWS EC2 instance information using IP address or Instance Id  
[create instance](#action-create-instance) - Creates an AWS instance from an image id  
[start instance](#action-start-instance) - Start EC2 instance  
[stop instance](#action-stop-instance) - Stop EC2 instance  
[snapshot instance](#action-snapshot-instance) - Snapshot AWS instance that has the given IP address  
[quarantine instance](#action-quarantine-instance) - Quarantines AWS instance that has the given IP address  
[asg detach instance](#action-asg-detach-instance) - Detaches an instance from an auto\-scaling group  
[invoke lambda](#action-invoke-lambda) - Invoke an AWS Lambda function  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'block ip'
Block IP by adding a rule to every subnet NACL accessible by credentials

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to block | string |  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock ip'
Unblock IP by removing any block rules from NACLs

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP address to unblock | string |  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'disable acct'
Disables an AWS IAM user account

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_name** |  required  | Account's user name to disable | string |  `user name` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'enable acct'
Enables an AWS IAM user account

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_name** |  required  | Account's user name | string |  `user name` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove access'
Removes EC2 Access for a given IAM user

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_name** |  required  | Account's user name | string |  `user name` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'enable access'
Enable EC2 Access for a given IAM user

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_name** |  required  | Account's user name | string |  `user name` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove sg access'
Removes Security Group Access for a given IAM user

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_name** |  required  | Account's user name | string |  `user name` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'enable sg access'
Enable Security Group Access for a given IAM user

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user\_name** |  required  | Account's user name | string |  `user name` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.user\_name | string |  `user name` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'remove sg ingress'
Removes ingress rule from security group

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sg\_id** |  required  | AWS Security Group Id | string | 
**sg\_item** |  required  | AWS Security Group Item to remove | string | 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.sg\_id | string | 
action\_result\.parameter\.sg\_item | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup instance'
Return AWS EC2 instance information using IP address or Instance Id

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_instance\_id** |  required  | IP address or Instance Id of instance to lookup | string |  `aws bah instance id`  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_instance\_id | string |  `aws bah instance id`  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string |  `ip` 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create instance'
Creates an AWS instance from an image id

Type: **generic**  
Read only: **False**

This action allows you to create a new AWS instance\. To tag the instance, pass a json string in the playbook with the tags\. Refer to this example \- tags\: json\.dumps\(\{"Name"\: "MyNewInstance", "DeployedByPhantom"\: "true" \}\)

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**image\_id** |  required  | AMI id of instance to create | string | 
**instance\_type** |  required  | Type of instance to create | string | 
**ssh\_key\_name** |  required  | SSH key name to access instance | string | 
**security\_group\_ids** |  required  | Security group ids to attach for instance access | string | 
**subnet\_id** |  required  | Target subnet for the instance to be deployed in | string | 
**eni\_associate\_public\_ip** |  required  | Associate a public ip with the instance | boolean | 
**eni\_delete\_on\_termination** |  required  | Preference to delete or keep ENI when terminating the instance | boolean | 
**eni\_description** |  optional  | Description attached to the ENI on creation | string | 
**tags** |  optional  | JSON string with tags attached to ec2 instance on creation | string | 
**wait\_for\_status\_checks** |  required  | Option to wait for the created instance to pass status checks before continuing\. | boolean | 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.eni\_associate\_public\_ip | string | 
action\_result\.parameter\.eni\_delete\_on\_termination | string | 
action\_result\.parameter\.eni\_description | string | 
action\_result\.parameter\.image\_id | string | 
action\_result\.parameter\.instance\_type | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.parameter\.security\_group\_ids | string | 
action\_result\.parameter\.ssh\_key\_name | string | 
action\_result\.parameter\.subnet\_id | string | 
action\_result\.parameter\.tags | string | 
action\_result\.parameter\.wait\_for\_status\_checks | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string | 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'start instance'
Start EC2 instance

Type: **correct**  
Read only: **False**

Start an EC2 instance up

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_instance\_id** |  required  | IP address or Instance Id of instance to lookup | string |  `aws bah instance id`  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_instance\_id | string |  `aws bah instance id`  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string |  `ip` 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'stop instance'
Stop EC2 instance

Type: **contain**  
Read only: **False**

Stop an EC2 instance

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_instance\_id** |  required  | IP address or Instance Id of instance to lookup | string |  `aws bah instance id`  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_instance\_id | string |  `aws bah instance id`  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string |  `ip` 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'snapshot instance'
Snapshot AWS instance that has the given IP address

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_instance\_id** |  required  | IP address or Instance Id of instance to lookup | string |  `aws bah instance id`  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_instance\_id | string |  `aws bah instance id`  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string |  `ip` 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine instance'
Quarantines AWS instance that has the given IP address

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_instance\_id** |  required  | IP address or Instance Id of instance to lookup | string |  `aws bah instance id`  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_instance\_id | string |  `aws bah instance id`  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string |  `ip` 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'asg detach instance'
Detaches an instance from an auto\-scaling group

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_instance\_id** |  required  | IP address or Instance Id of instance to lookup | string |  `aws bah instance id`  `ip` 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_instance\_id | string |  `aws bah instance id`  `ip` 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data | string | 
action\_result\.data\.\*\.AmiLaunchIndex | numeric | 
action\_result\.data\.\*\.Architecture | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.DeviceName | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.AttachTime | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.Status | string | 
action\_result\.data\.\*\.BlockDeviceMappings\.\*\.Ebs\.VolumeId | string | 
action\_result\.data\.\*\.ClientToken | string | 
action\_result\.data\.\*\.EbsOptimized | boolean | 
action\_result\.data\.\*\.Hypervisor | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Arn | string | 
action\_result\.data\.\*\.IamInstanceProfile\.Id | string | 
action\_result\.data\.\*\.ImageId | string | 
action\_result\.data\.\*\.InstanceId | string | 
action\_result\.data\.\*\.InstanceType | string | 
action\_result\.data\.\*\.KeyName | string | 
action\_result\.data\.\*\.LaunchTime | string | 
action\_result\.data\.\*\.Monitoring\.State | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachTime | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.AttachmentId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeleteOnTermination | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.DeviceIndex | numeric | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Attachment\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Description | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Groups\.\*\.GroupName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.MacAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.NetworkInterfaceId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.OwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.IpOwnerId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Association\.PublicIp | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.Primary | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.PrivateIpAddresses\.\*\.PrivateIpAddress | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.Status | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.SubnetId | string | 
action\_result\.data\.\*\.NetworkInterfaces\.\*\.VpcId | string | 
action\_result\.data\.\*\.Placement\.AvailabilityZone | string | 
action\_result\.data\.\*\.Placement\.GroupName | string | 
action\_result\.data\.\*\.Placement\.Tenancy | string | 
action\_result\.data\.\*\.PrivateDnsName | string | 
action\_result\.data\.\*\.PrivateIpAddress | string |  `ip` 
action\_result\.data\.\*\.PublicDnsName | string | 
action\_result\.data\.\*\.PublicIpAddress | string |  `ip` 
action\_result\.data\.\*\.RootDeviceName | string | 
action\_result\.data\.\*\.RootDeviceType | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupId | string | 
action\_result\.data\.\*\.SecurityGroups\.\*\.GroupName | string | 
action\_result\.data\.\*\.SourceDestCheck | boolean | 
action\_result\.data\.\*\.State\.Code | numeric | 
action\_result\.data\.\*\.State\.Name | string | 
action\_result\.data\.\*\.StateTransitionReason | string | 
action\_result\.data\.\*\.SubnetId | string | 
action\_result\.data\.\*\.Tags\.\*\.Key | string | 
action\_result\.data\.\*\.Tags\.\*\.Value | string | 
action\_result\.data\.\*\.VirtualizationType | string | 
action\_result\.data\.\*\.VpcId | string | 
action\_result\.summary | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'invoke lambda'
Invoke an AWS Lambda function

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**lambda\_function\_name** |  required  | Name of the Lambda function to invoke | string | 
**lambda\_invocation\_type** |  required  | Type of invocation | string | 
**lambda\_payload** |  optional  | JSON payload to pass to the Lambda function | string | 
**role** |  optional  | ARN of Role to run action as | string |  `aws bah role arn` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.lambda\_function\_name | string | 
action\_result\.parameter\.lambda\_invocation\_type | string | 
action\_result\.parameter\.lambda\_payload | string | 
action\_result\.parameter\.role | string |  `aws bah role arn` 
action\_result\.data | string | 
action\_result\.data\.\*\.FunctionError | string | 
action\_result\.data\.\*\.LogResult | numeric | 
action\_result\.data\.\*\.Payload | string | 
action\_result\.data\.\*\.StatusCode | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 