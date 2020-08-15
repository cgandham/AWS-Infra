
 variable "VPC_Name" {
  // type = string
}

#  variable "Subnet1_Name" {
#    type = "string"
#  }

//variable "VPC_ID" { }

# data "aws_vpc" "Subnet1_VPC_ID" {
#   id = "${var.VPC_Name}"
# }

# variable "Subnet2_Name" {
#   type = "string"
# }
# variable "Subnet3_Name" {
#   type = "string"
# }




variable "aws_region" {
	default = "us-east-1"
}

variable "vpc_cidr" {
	default = "10.0.0.0/16"
}

variable "subnet1_cidr" {
	default = "10.0.0.0/24"
}
variable "subnet2_cidr" {
	default = "10.0.3.0/24"
}
variable "subnet3_cidr" {
	default = "10.0.2.0/24"
}

variable "routeTable_cidr" {
	default = "0.0.0.0/0"
}

variable "availabilityZone1" {
     default = "us-east-1a"
}
variable "availabilityZone2" {
     default = "us-east-1b"
}
variable "availabilityZone3" {
     default = "us-east-1c"
}

variable "ingressCIDRblock" {
 
    default =  "0.0.0.0/0" 
}

variable "egressCIDRblock" {
  //  type = "list"
    default = "0.0.0.0/0"//["0.0.0.0/0" ]
}

variable "EC2_ROOT_VOLUME_SIZE" {
  //type    = "string"
  default = "20"
  description = "The volume size for the root volume in GiB"
}
variable "EC2_ROOT_VOLUME_TYPE" {
//  type    = "string"
  default = "gp2"
  description = "The type of data storage: standard, gp2, io1"
}

variable "ami_id" { 
    //  type = "string"
}

variable "EC2_ROOT_VOLUME_DELETE_ON_TERMINATION" {
  default = true
  description = "The type of data storage: standard, gp2, io1"
}

variable "access_key_id" { }
variable "secret_key_id" { }
variable "certificate_arn"{ }

# variable "dburl"{
#   type = "string"
#  // default = "jdbc:mysql://${rds_endpoint}:3306/csye6225-su2020"
# }