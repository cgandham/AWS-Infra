# infrastructure
Terraform script for the following:
create VPC
create 3 subnets under the VPC
create internet gateway
create route table with subnets and route
RDS, RDS subnet group, parameter group
DynamoDB Table, S3 Buckets, Code deploy,
Load balancer, Target group, Auto scaling Group,
IAM Policies, Security Groups, Route53

# To import certificate in ACM -->
aws acm import-certificate --certificate fileb://certificate.pem --certificate-chain fileb://intermediary.pem --private-key fileb://privateKey.pem
