// CodeDeployEC2ServiceRole IAM Role for EC2 Instance(s) 4
resource "aws_iam_role" "CodeDeployEC2ServiceRole" {
  name = "CodeDeployEC2ServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}

// CodeDeploy S3 policy 
resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement":  [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

#ataching 6
resource "aws_iam_role_policy_attachment" "attachWebappS3toEC2" {
  policy_arn = "${aws_iam_policy.webapps3.arn}"
  role = "${aws_iam_role.ec2-csye6225.name}"
}

#7
resource "aws_iam_role_policy_attachment" "ec2-csye6225_attach" {
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"
  role = "${aws_iam_role.ec2-csye6225.name}"
}

#___________________________________________________________________---------------

//  8
resource "aws_iam_user" "cicd" {
  name = "cicd"
}

//9
resource "aws_iam_policy" "circleci-Upload-To-S3" {
  name        = "circleci-Upload-To-S3"

   policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.chandanawebapp.me2"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.chandanawebapp.me2/*"
            ]
        }
    ]
}
EOF
}

//10
resource "aws_iam_user_policy_attachment" "attachuploadtoS3policy" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-Upload-To-S3.arn}"
}

// 11
resource "aws_iam_policy" "circleci-Code-Deploy" {
  name        = "circleci-Code-Deploy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "codedeploy:PutLifecycleEventHookExecutionStatus",
                "codedeploy:DeleteGitHubAccountToken",
                "codedeploy:BatchGetDeploymentTargets",
                "codedeploy:DeleteResourcesByExternalId",
                "codedeploy:GetDeploymentTarget",
                "codedeploy:StopDeployment",
                "codedeploy:ContinueDeployment",
                "codedeploy:ListDeploymentTargets",
                "codedeploy:ListApplications",
                "codedeploy:CreateCloudFormationDeployment",
                "codedeploy:ListOnPremisesInstances",
                "codedeploy:ListGitHubAccountTokenNames",
                "codedeploy:ListDeploymentConfigs",
                "codedeploy:SkipWaitTimeForInstanceTermination"
            ],
            "Resource": "*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "codedeploy:*",
            "Resource": [
                "arn:aws:codedeploy:us-east-1:576607646506:deploymentgroup:csye6225-webapp/csye6225-webapp-deployment",
                "arn:aws:codedeploy:us-east-1:576607646506:application:csye6225-webapp",
                "arn:aws:codedeploy:us-east-1:576607646506:instance:csye6225Webapp",
                "arn:aws:codedeploy:us-east-1:576607646506:deploymentconfig:CodeDeployDefault.AllAtOnce"
            ]
        }
    ]
}
EOF
}
//11
resource "aws_iam_user_policy_attachment" "attachcodedeployPolicy" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-Code-Deploy.arn}"
}

resource "aws_iam_policy" "circleci-ec2-ami" {
  name        = "circleci-ec2-ami"
  description = "Allows cicd user to build new AMI"

   policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# Attach cicd-ec2-ami policy to cicd user
resource "aws_iam_user_policy_attachment" "attachec2amipolicy" {
  user       = "${aws_iam_user.cicd.name}"
  policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"
}

#=======================================================================

# resource "aws_iam_role" "CodeDeployServiceRole" {
#     name = "CodeDeployServiceRole"
#     assume_role_policy = data.assume_role_policy_document.odedeploy-doc-assume.json 
    
# }
#  assume_role_policy = <<EOF
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

resource "aws_iam_role" "CodeDeployServiceRole" {
  name        = "CodeDeployServiceRole"
  assume_role_policy = data.aws_iam_policy_document.assumecodedeployPolicy.json
}

data   "aws_iam_policy_document" "assumecodedeployPolicy" {
 statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }
  }
 }

resource "aws_iam_role_policy_attachment" "AttchassumeCodeDeployPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role = "${aws_iam_role.CodeDeployServiceRole.name}"
}

#_______________________________________CLOUD WATCH IAM POLICY

# resource "aws_iam_policy" "cloudwatch-ami" {
#   name        = "cloudwatch-ami"

#    policy = <<EOF
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Action": [
#                 "cloudwatch:PutMetricData",
#                 "ec2:DescribeTags",
#                 "logs:PutLogEvents",
#                 "logs:DescribeLogStreams",
#                 "logs:DescribeLogGroups",
#                 "logs:CreateLogStream",
#                 "logs:CreateLogGroup"
#             ],
#             "Resource": "*"
#         },
#         {
#             "Effect": "Allow",
#             "Action": [
#                 "ssm:GetParameter",
#                 "ssm:PutParameter"
#             ],
#             "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
#         }
#     ]
# }
# EOF
# }

# Attach cloudwatch-ami policy to cicd user
# resource "aws_iam_user_policy_attachment" "attach_cloudwatchami_policy" {
#   user       = "${aws_iam_user.cicd.name}"
#   policy_arn = "${aws_iam_policy.cloudwatch-ami.arn}"
# }



