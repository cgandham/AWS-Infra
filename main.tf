provider "aws" {
  version = "~> 2.0"
	region = "${var.aws_region}"
}

# create the VPC
resource "aws_vpc" "csye6225_VPC" {
  cidr_block           = "${var.vpc_cidr}"
  enable_dns_support   = true
  enable_dns_hostnames = true
  enable_classiclink_dns_support = true
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = "csye6225_VPC"
  }
} 
//variable "VPC_Name" {}
 
# data "aws_vpc" "Subnet1_VPC_ID" {
#   id = "${var.VPC_Name}"
# }

# output "VPC_ID" {
#   value = "${aws_vpc.VPC1.id}"
# }

# create the Subnet1
resource "aws_subnet" "csye6225_subnet1" {
  vpc_id                  = "${aws_vpc.csye6225_VPC.id}"//"${var.VPC_ID}"//"${data.aws_vpc.Subnet1_VPC_ID.id}"//
  cidr_block              = "${var.subnet1_cidr}"
  map_public_ip_on_launch = true
  availability_zone       = "${var.availabilityZone1}"  
  tags = {
   Name = "csye6225_subnet1"// "${var.Subnet1_Name}"
  }
} 
# create the Subnet2
resource "aws_subnet" "csye6225_subnet2" {
  vpc_id                  = "${aws_vpc.csye6225_VPC.id}"//"${var.VPC_ID}"//"${data.aws_vpc.Subnet1_VPC_ID.id}"//
  cidr_block              = "${var.subnet2_cidr}"
  map_public_ip_on_launch = true
  availability_zone       = "${var.availabilityZone2}"  
  tags = {
   Name = "csye6225_subnet2"
  }
} 
# create the Subnet3
resource "aws_subnet" "csye6225_subnet3" {
  vpc_id                  = "${aws_vpc.csye6225_VPC.id}"
  cidr_block              = "${var.subnet3_cidr}"
  map_public_ip_on_launch = true
  availability_zone       = "${var.availabilityZone3}"  
  tags = {
   Name = "csye6225_subnet3"
  }
} 

# Create the Internet Gateway
resource "aws_internet_gateway" "csye6225_Internet_Gateway" {
 vpc_id = "${aws_vpc.csye6225_VPC.id}"
 tags = {
        Name = "csye6225_Internet_Gateway"
  }
} 

# Create the Route Table
resource "aws_route_table" "csye6225_Route_Table" {
 vpc_id = "${aws_vpc.csye6225_VPC.id}"
 route {
    cidr_block = "${var.routeTable_cidr}"
    gateway_id = "${aws_internet_gateway.csye6225_Internet_Gateway.id}"
  }
 tags = {
        Name = "csye6225_Route_Table"
  }
} 

resource "aws_route_table_association" "csye6225_route_table_subnet1" {
  subnet_id      = "${aws_subnet.csye6225_subnet1.id}"
  route_table_id = "${aws_route_table.csye6225_Route_Table.id}"
}
resource "aws_route_table_association" "csye6225_route_table_subnet2" {
  subnet_id      = "${aws_subnet.csye6225_subnet2.id}"
  route_table_id = "${aws_route_table.csye6225_Route_Table.id}"
}
resource "aws_route_table_association" "csye6225_route_table_subnet3" {
  subnet_id      = "${aws_subnet.csye6225_subnet3.id}"
  route_table_id = "${aws_route_table.csye6225_Route_Table.id}"
}

# Create the Application Security Group
resource "aws_security_group" "application" {
  vpc_id       = "${aws_vpc.csye6225_VPC.id}"
  name         = "application"
  description  = "Application Security Group"

  //commenting because using load balancer security group to launch instance

  # allow ingress of port 22
  # ingress {
  #   cidr_blocks = ["${var.ingressCIDRblock}"]    
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"
  # } 

  # allow ingress of port 80
  # ingress {
  #   cidr_blocks = ["${var.ingressCIDRblock}"]    
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  # } 

  # allow ingress of port 443
  # ingress {
  #   cidr_blocks = ["${var.ingressCIDRblock}"]  
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  # } 

  # allow ingress of port 8080
  # ingress {
  #   cidr_blocks = ["${var.ingressCIDRblock}"]  
  #   from_port   = 8080
  #   to_port     = 8080
  #   protocol    = "tcp"
  # } 
  
  # allow egress of all ports
   egress {
     from_port   = 0
     to_port     = 0
     protocol    = "-1"
     cidr_blocks = ["0.0.0.0/0"]
   }
  
  tags = {
   Name = "Application Security Group"
   Description = "Application Security Group"
  }
} 

# Create the DB Security Group //GIVE Source of the traffic  
resource "aws_security_group" "database" {
  vpc_id       = "${aws_vpc.csye6225_VPC.id}"
  name         = "database"
  description  = "database Security Group"
  
  # allow ingress of port 3306
  # ingress {
  #   cidr_blocks = "${var.ingressCIDRblock}"  
  #   from_port   = 3306
  #   to_port     = 3306
  #   protocol    = "tcp"
  # } 
   egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
   Name = "Database Security Group"
   Description = "Database Security Group"
  }
} 

resource "aws_security_group_rule" "databaseSecurityGroupRule" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  security_group_id = "${aws_security_group.database.id}"
  # cidr_blocks = ["0.0.0.0/0"]
  source_security_group_id = "${aws_security_group.application.id}"
}

#DynamoDB
resource "aws_dynamodb_table" "csye6225_dynamodb_table" {
  name           = "csye6225"
  hash_key       = "id"
  write_capacity     = 10
  read_capacity      = 10

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "dynamodb-table-1"
    Environment = "dev"
  }
}

#encrypted key
 resource "aws_kms_key" "mykey" {
   description  = "This key is used to encrypt bucket objects"
   #deletion_window_in_days = 30
 }

#S3 Bucket
resource "aws_s3_bucket" "webapp_chandana_gandham5" {
  bucket = "webapp.chandana.gandham5"
  force_destroy = true
  acl    = "private"
  versioning {
    enabled = true
  }
  server_side_encryption_configuration {
     rule {
       apply_server_side_encryption_by_default {
         kms_master_key_id = "${aws_kms_key.mykey.arn}"
         sse_algorithm     = "aws:kms"
       }
     }
   } 
  lifecycle_rule{
     enabled = true
    transition {
      days = 30
      storage_class = "STANDARD_IA"
    }
  }
}

#create subnet group
 resource "aws_db_subnet_group" "rdssubnetgrp" {
   name       = "rdssubnetgrp"
  subnet_ids = ["${aws_subnet.csye6225_subnet2.id}", "${aws_subnet.csye6225_subnet3.id}"]
  tags = {
     Name = "My DB subnet group"
   }
 }

#encrypted key
#  resource "aws_kms_key" "rdskey" {
#    description  = "This key is used to encrypt rds instance"
#    #deletion_window_in_days = 30
#  }

#Parameter Group
resource "aws_db_parameter_group" "rds-parameter-group"{
  name    = "rds-parameter-group"
  family = "mysql5.7"

  parameter {
  #   name         =  "rds.force_ssl"
  #   value        = "1"
  #   //apply_method = "pending-reboot"
  name = "performance_schema"
  value = "1"
  apply_method = "pending-reboot"
   }
}

#RDS Instance //CHECK SUBNET //attach db security group to rds
resource "aws_db_instance" "rdsinstance" {
  multi_az             = false
  identifier           = "csye6225-su2020"
 // db_subnet_group_name = "${aws_db_subnet_group.rdssubnetgrp.id}"
  storage_encrypted    = true
 // kms_key_id           = "${aws_kms_key}"
  publicly_accessible  = false
  allocated_storage    = 20
  storage_type         = "gp2"
  parameter_group_name = "${aws_db_parameter_group.rds-parameter-group.name}"//"default.mysql5.7"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "webapp"
  username             = "admin"
  password             = "very_strong_password"
  db_subnet_group_name = "${aws_db_subnet_group.rdssubnetgrp.name}"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  skip_final_snapshot  = true
 // storage_encrypted    = true
 // kms_key_id           = "${aws_kms_key}"
}


#keypair
 resource "aws_key_pair" "awsInstance" {
   key_name   = "awsInstance"
   public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0HZNXnyqcbVj7Yj6CZbI55RRY0KiB2UMWdT0Ztre1GWjWhCnksAScDY00MT80rFlwURRqXPWb0F2w5hiNQEy7JdF/FCxtivvxp7FJpkaSwBWoYiD9rlUu7P8SUyP8Ex4xTplWcP/zlT9CZTqspi5PrVfa6IbUC7jaF7yfyH91gPMUzCtKH77yjBc33Ijw6t5iUxPVXkbxDxAtv+PrCuDylj/b/Z9pDvRbqYB2OOQI2JaF4sJoARLAyv0+pR1lVc+0YKdylnVsIygRruZc3t48GikfL2h8Wnt0t9jomKKtxTetrPH9iMuWD9njdF60latitogTdOADukc1jCZzFoxnAXgu7pIexWKUiCDxY/+XUw0FIZbMiwc2GmU7FQmo5Hez2P/AhdMUW9nMxHDHMAT+r+e86oKLvSkuM1ZsWmj8gM5yaAxBqsBwBk57bmHnRtFastBN2HU666XJgCVdm/fVO+WSYQL46ioARrCiMx00WxTwPE/aCKVcQFkNB2oqSTk= chandana@chandana-HP-Pavilion-Notebook"
}

#________________________________________________________________

#IAM Policy 5
resource "aws_iam_policy" "webapps3" {
  name        = "webapps3"
  description = "A webapps3 policy"//file("${path.module}/hello.txt")
   policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement":  [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::webapp.chandana.gandham5"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::webapp.chandana.gandham5/*"
            ]
        }
    ]
}
EOF
}

#IAM Role 1
resource "aws_iam_role" "ec2-csye6225" {
  name        = "ec2-csye6225-policy"
  description = "A ec2-csye6225 policy"//file("${path.module}/hello.txt")
    path = "/"

  assume_role_policy = data.aws_iam_policy_document.ec2policy1doc.json
}
# <<EOF
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Action": "sts:AssumeRole",
#             "Principal": {
#                "Service": "ec2.amazonaws.com"
#             },
#             "Effect": "Allow",
#             "Sid": ""
#         }
#     ]
# }
# EOF

#3
data "aws_iam_policy_document" "ec2policy1doc"{
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

#______________________________________________________________

#attaching policy to role
resource "aws_iam_policy_attachment" "ec2-csye6225-attach" {
  name       = "ec2-csye6225-attachment"
  roles      = ["${aws_iam_role.ec2-csye6225.name}"]
  policy_arn = "${aws_iam_policy.webapps3.arn}"
}

#________________________________________________

resource "aws_iam_policy" "cloudwatch-ami" {
  name        = "cloudwatch-ami"

   policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:PutParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        }
    ]
}
EOF
}
#attaching policy to role
resource "aws_iam_policy_attachment" "ec2-csye6225-attach2" {
  name       = "ec2-csye6225-attachment2"
  roles      = ["${aws_iam_role.ec2-csye6225.name}"]
  policy_arn = "${aws_iam_policy.cloudwatch-ami.arn}"
}

#________________________________________________________
# #Creating the IAM instance profile 2
 resource "aws_iam_instance_profile" "iam_instance_profile2" {
   name  = "iam_instance_profile2"
   role =  "${aws_iam_role.ec2-csye6225.name}"
 }

data "template_file" "init" {
  template = "${file("./webdata.sh")}"
  vars = {
    rds_endpoint = "${aws_db_instance.rdsinstance.address}" 
    ACCESS_KEY = "${var.access_key_id}"
    SECRET_KEY = "${var.secret_key_id}"
    }
}

#________________Load Balancer_______________________________________ 
data "aws_availability_zones" "all" {}

resource "aws_lb_target_group" "LBTargetGroup" {
  health_check {
    interval            = 10
    path                = "/"
    protocol            = "HTTP"
    timeout             = 5
    healthy_threshold   = 5
    unhealthy_threshold = 2
  }
  name        = "LBTargetGroup"
  port        = 8080
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = "${aws_vpc.csye6225_VPC.id}"
  
}

resource "aws_lb" "awsLB" {
  name     = "awsLB"
  internal = false
  enable_deletion_protection = false
  security_groups = [
    "${aws_security_group.LoadBalancer.id}"//"${aws_security_group.application.id}",
  ]
  //availability_zones      = ["${data.aws_availability_zones.all.names}"]

  subnets = ["${aws_subnet.csye6225_subnet1.id}", "${aws_subnet.csye6225_subnet2.id}"]

  tags = {
    Name = "awsLB"
  }

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}

resource "aws_lb_listener" "my-test-alb-listner" {
  load_balancer_arn = "${aws_lb.awsLB.arn}"
  port              =  443 // 80
  protocol          = "HTTPS" //arn:aws:acm:us-east-1:576607646506:certificate/2caedf33-b2ee-46ed-b820-bccfa811ee50
  //certificate_arn   = "arn:aws:acm:us-east-1:576607646506:certificate/2caedf33-b2ee-46ed-b820-bccfa811ee50"
  certificate_arn    = "${var.certificate_arn}"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.LBTargetGroup.arn}"
  }
}

# Create the Load Balancer Security Group
resource "aws_security_group" "LoadBalancer" {
  vpc_id       = "${aws_vpc.csye6225_VPC.id}"
  name         = "LoadBalancer"
  description  = "LoadBalancer Security Group"
  
  # allow ingress of port 22
  #  ingress {
  #    cidr_blocks = ["${var.ingressCIDRblock}"]    
  #    from_port   = 22
  #    to_port     = 22
  #    protocol    = "tcp"
  #  } 

  # allow ingress of port 80--for HTTP
  # ingress {
  #    cidr_blocks = ["${var.ingressCIDRblock}"]    
  #    from_port   = 80
  #    to_port     = 80
  #    protocol    = "tcp"
  #  } 

  # allow ingress of port 443-- HTTPS
   ingress {
     cidr_blocks = ["${var.ingressCIDRblock}"]  
     from_port   = 443
     to_port     = 443
     protocol    = "tcp"
   } 

  # allow ingress of port 8080
   ingress {
     cidr_blocks = ["${var.ingressCIDRblock}"]  
     from_port   = 8080
     to_port     = 8080
     protocol    = "tcp"
   } 
  
  # allow egress of all ports
   egress {
     from_port   = 0
     to_port     = 0
     protocol    = "-1"
     cidr_blocks = ["0.0.0.0/0"]
   }
  
  tags = {
   Name = "Load Balancer Security Group"
   Description = "Load Balancer Security Group"
  }
} 

#new security group rule to allow only LB traffic to application
resource "aws_security_group_rule" "allowOnlyLBtraffic"{
  type = "ingress"
  from_port = 8080
  to_port   = 8080
  protocol  = "tcp"
  security_group_id = "${aws_security_group.application.id}"
  source_security_group_id = "${aws_security_group.LoadBalancer.id}"
}

#________________Load Balancer end_______________________________________ 
#________________scale up policy_______________________________________ 


resource "aws_autoscaling_policy" "auto-scaling-policy-scale-up"{
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
  name = "WebServerScaleUpPolicy"
  adjustment_type = "ChangeInCapacity"
  scaling_adjustment = "1"
  cooldown = "60"
  //policy_type = "AWS::AutoScaling::ScalingPolicy"
}

resource "aws_cloudwatch_metric_alarm" "cpu-alarm-scale-up" {
  alarm_description = "Scale-up if CPU > 90% for 1 minutes"//90%
  alarm_name = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods = "1"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "60"//300
  statistic = "Average"
  threshold = "98"//90
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.asg.name}"
  }
    actions_enabled = true
    alarm_actions = ["${aws_autoscaling_policy.auto-scaling-policy-scale-up.arn}"]

}

#________________scale up policy end__________________________

#________________scale down policy_______________________________________ 

resource "aws_autoscaling_policy" "auto-scaling-policy-scale-down" {
  autoscaling_group_name = "${aws_autoscaling_group.asg.name}"
  name = "WebServerScaleDownPolicy"
  adjustment_type = "ChangeInCapacity"
  scaling_adjustment = "-1"
  cooldown = "60"
 // policy_type = "AWS::AutoScaling::ScalingPolicy"
}

resource "aws_cloudwatch_metric_alarm" "cpu-alarm-scale-down" {
  alarm_name = "CPUAlarmLow"
  alarm_description = "Scale-down if CPU < 10% for 10 minutes"//70%
  comparison_operator = "LessThanThreshold"
  evaluation_periods = "1"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "60"//300
  statistic = "Average"
  threshold = "6"//70
  dimensions = {
    "AutoScalingGroupName" = "${aws_autoscaling_group.asg.name}"
  }
  actions_enabled = true
  alarm_actions = ["${aws_autoscaling_policy.auto-scaling-policy-scale-down.arn}"]

}

#________________scale down policy end_______________________


#____________DNS Route 53__________________________ 

//resource "aws_cloudfront_distribution" "example_cdn" {  }

resource "aws_route53_zone" "hostedzone" {
  name   = "prod.chandanawebapp.me"
}
# create dns record of type "A"
//data "aws_elastic_beanstalk_hosted_zone" "current" {}

resource "aws_route53_record" "route53" {
  zone_id = "${aws_route53_zone.hostedzone.zone_id}"
  //name    = "${data.aws_route53_zone.hostedzone.name}"
  name    = "prod.chandanawebapp.me"
  type    = "A"
 // ttl     = "300"
  alias {
    name = "${aws_lb.awsLB.dns_name}"
    zone_id = "${aws_lb.awsLB.zone_id}"
  // name    = "${aws_elastic_beanstalk_environment.eb_env.cname}"
  // zone_id = "${data.aws_elastic_beanstalk_hosted_zone.current.id}"
   evaluate_target_health = false
  }
  
}

#____________DNS Route 53 end__________________________
#____________aws auto scaling group__________________________

resource "aws_launch_configuration" "asg-config" {
  name = "asg-config"
  image_id = "${var.ami_id}"
  instance_type = "t2.micro"
  security_groups = ["${aws_security_group.application.id}"]
  associate_public_ip_address = true
  
  iam_instance_profile = "${aws_iam_instance_profile.iam_instance_profile2.name}"
  //disable_api_termination = false
  key_name = "${aws_key_pair.awsInstance.key_name}"

  root_block_device {
    volume_size           = "${var.EC2_ROOT_VOLUME_SIZE}"
    volume_type           = "${var.EC2_ROOT_VOLUME_TYPE}"
    delete_on_termination = "${var.EC2_ROOT_VOLUME_DELETE_ON_TERMINATION}"
  }
  user_data = "${data.template_file.init.rendered}"
  lifecycle {
    create_before_destroy = true
  }
}




resource "aws_autoscaling_group" "asg" {
  name                    = "csye6225_asg" 
  launch_configuration    = "${aws_launch_configuration.asg-config.id}"
  default_cooldown        = 60
  min_size                = "2"
  max_size                = "5"
  desired_capacity        = "2"
 // vpc_zone_identifier  = ["${aws_subnet.csye6225_subnet2.id}", "${aws_subnet.csye6225_subnet3.id}"]
  target_group_arns    = ["${aws_lb_target_group.LBTargetGroup.arn}"]
   vpc_zone_identifier  = ["${aws_subnet.csye6225_subnet1.id}","${aws_subnet.csye6225_subnet3.id}"]
   
  //vpc_security_group_ids = ["${aws_security_group.application.id}"]
  //availability_zones      = ["${data.aws_availability_zones.all.names}"]
  //target_group_arns       = ["${var.target_group_arn}"]
  //health_check_type       = "ELB"
   lifecycle {
    create_before_destroy = true
  }
   tag {
     key = "Name"
     value = "asg-ec2"
     propagate_at_launch = true
   }

}


#____________aws auto scaling group end__________________________ 

#aws Instance


// Create S3 bucket to save the unzipped build artifacts- EC2 Codedeploy to pick 
resource "aws_s3_bucket" "codedeploy_chandanawebapp_me2" {
  bucket = "codedeploy.chandanawebapp.me2"
  acl    = "private"
  force_destroy = true
  tags = {
    Name        = "codedeploy.chandanawebapp.me2"
    Environment = "Prod"
  }
  
  lifecycle_rule {
    id      = "log"
    enabled = true

    prefix = "log/"

    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA" 
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}

// Codedeploy application
resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}



//creates cloud deploy deployment group
resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name              = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
  autoscaling_groups    = ["${aws_autoscaling_group.asg.name}"]
   deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type = "IN_PLACE"
  }

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "csye6225Webapp"
    }
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
}

#________________________SNS TOPIC______________________________________

resource "aws_sns_topic" "csye6225" {
    name = "csye6225"
}
#________________________SQS___________________________________

resource "aws_sqs_queue" "emailQ" {
    name = "emailQ"
    
    //emails that are lost are queued in deadLetterQ
    //redrive_policy  = "{\"deadLetterTargetArn\":\"${aws_sqs_queue.deadLetterQ.arn}\",\"maxReceiveCount\":5}"
   // visibility_timeout_seconds = 300

    tags = {
        Environment = "prod"
    }
}

# resource "aws_sqs_queue" "deadLetterQ" {
#     name = "deadLetterQ"
# }


#__policy for SQS to receive events from the SNS topic

resource "aws_sqs_queue_policy" "SQS_queue_policy" {
    queue_url = "${aws_sqs_queue.emailQ.id}"

    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Id": "sqspolicy",
  "Statement": [
    {
      "Sid": "First",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "${aws_sqs_queue.emailQ.arn}",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "${aws_sns_topic.csye6225.arn}"
        }
      }
    }
  ]
}
POLICY
}

#___LAMBDA

# data "archive_file" "lambda_zip" {
#   type        = "zip"
#   source_file = "${file("./demo.js")}"//"${path.module}/lambda/example.js"
#   output_path = "${file("./demo.zip")}"//"${path.module}/lambda/example.zip"
  
# }

resource "aws_lambda_function" "csye6225_lambda" {
  filename      = "./demo.zip"//"lambda_function_payload.zip"
  function_name = "LambdaFunction"
  role          = "${aws_iam_role.lambda_role.arn}"
  handler       = "faas.cloud.demo.Events.EmailTask::handleRequest"

  source_code_hash = "${filebase64sha256("./demo.zip")}"

  runtime = "java8"
  memory_size = 2400
  timeout = 120
  environment {
    variables = {
      foo = "bar"
    }
  }
}

#____subscription to allow SQS to receive notifications from the SNS topic
resource "aws_sns_topic_subscription" "SQS_subscription" {
    topic_arn = "${aws_sns_topic.csye6225.arn}"
    protocol = "lambda"
    endpoint  = "${aws_lambda_function.csye6225_lambda.arn}"
}


#__assigning role of a lambda function to our lambda
resource "aws_iam_role" "lambda_role" {
    name = "LambdaRole"
    assume_role_policy = data.aws_iam_policy_document.lambda-assume-role-policy.json
}

#assume_role_policy JSON data for Lambda Functions 
data "aws_iam_policy_document" "lambda-assume-role-policy" {
 statement {
 actions = ["sts:AssumeRole"]

 principals {
 type = "Service"
 identifiers = ["lambda.amazonaws.com"]
 }
 }
}

//To give SNS access to Lambda function 
resource "aws_lambda_permission" "allow_sns" {
 action = "lambda:*"
 function_name = "${aws_lambda_function.csye6225_lambda.function_name}"
 principal = "sns.amazonaws.com"
 source_arn = "arn:aws:sns:us-east-1:576607646506:csye6225"
}

//Attach S3 access policy to lambda
resource "aws_iam_role_policy_attachment" "S3AccessToLambdaRole" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
 role = "${aws_iam_role.lambda_role.name}"
}
//Attach DynamoDB access policy to lambda
resource "aws_iam_role_policy_attachment" "DynamoDBAccessToLambdaRole" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
 role = "${aws_iam_role.lambda_role.name}"
}
//Attach SNS access policy to lambda
resource "aws_iam_role_policy_attachment" "SNSAccessToLambdaRole" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
 role = "${aws_iam_role.lambda_role.name}"
}

//Attach SQS access policy to lambda
resource "aws_iam_role_policy_attachment" "SQSAccessToLambdaRole" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
 role = "${aws_iam_role.lambda_role.name}"
}
//Attach SES access policy to lambda
resource "aws_iam_role_policy_attachment" "SESAccessToLambdaRole" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
 role = "${aws_iam_role.lambda_role.name}"
}
//Give basic execution access to lambda
resource "aws_iam_role_policy_attachment" "BasicExecutionAccessToLambdaRole" {
 policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
 role = "${aws_iam_role.lambda_role.name}"
}

//Attach SNS policy to EC2 Role
resource "aws_iam_role_policy_attachment" "SNSAccessToEC2Role" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
 role = "${aws_iam_role.ec2-csye6225.name}"
}
//Attach SQS policy to EC2 Role
resource "aws_iam_role_policy_attachment" "SQSAccessToEC2Role" {
 policy_arn = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
 role = "${aws_iam_role.ec2-csye6225.name}"
}


#______________________circleci-lambda-policies______________________________

//Policy to update lambda through circleci
resource "aws_iam_policy" "circleci-updatelambda-policy" {
 name = "circleci-updatelambda-policy"
 description = "Allows cicd user to access lambda function"

 policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Allow",
 "Action": [
 "cloudformation:DescribeChangeSet",
 "cloudformation:DescribeStackResources",
 "cloudformation:DescribeStacks",
 "cloudformation:GetTemplate",
 "cloudformation:ListStackResources",
 "cloudwatch:*",
 "cognito-identity:ListIdentityPools",
 "cognito-sync:GetCognitoEvents",
 "cognito-sync:SetCognitoEvents",
 "dynamodb:*",
 "ec2:DescribeSecurityGroups",
 "ec2:DescribeSubnets",
 "ec2:DescribeVpcs",
 "events:*",
 "iam:GetPolicy",
 "iam:GetPolicyVersion",
 "iam:GetRole",
 "iam:GetRolePolicy",
 "iam:ListAttachedRolePolicies",
 "iam:ListRolePolicies",
 "iam:ListRoles",
 "iam:PassRole",
 "iot:AttachPrincipalPolicy",
 "iot:AttachThingPrincipal",
 "iot:CreateKeysAndCertificate",
 "iot:CreatePolicy",
 "iot:CreateThing",
 "iot:CreateTopicRule",
 "iot:DescribeEndpoint",
 "iot:GetTopicRule",
 "iot:ListPolicies",
 "iot:ListThings",
 "iot:ListTopicRules",
 "iot:ReplaceTopicRule",
 "kinesis:DescribeStream",
 "kinesis:ListStreams",
 "kinesis:PutRecord",
 "kms:ListAliases",
 "lambda:*",
 "logs:*",
 "s3:*",
 "sns:ListSubscriptions",
 "sns:ListSubscriptionsByTopic",
 "sns:ListTopics",
 "sns:Publish",
 "sns:Subscribe",
 "sns:Unsubscribe",
 "sqs:ListQueues",
 "sqs:SendMessage",
 "tag:GetResources",
 "xray:PutTelemetryRecords",
 "xray:PutTraceSegments"
 ],
 "Resource": "*"
 }
 ]
}
EOF
}

//Attaching policy to update lambda function through circleci
resource "aws_iam_user_policy_attachment" "circleci-attach-lambda-update-Policy" {
 user = "${aws_iam_user.cicd.name}"
 policy_arn = "${aws_iam_policy.circleci-updatelambda-policy.arn}"
}

#______________________circleci-lambda-policies-end______________________________




