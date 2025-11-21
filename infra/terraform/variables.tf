variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1c"]
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.4.0/24"]
}

variable "private_gie_cidrs" {
  type    = list(string)
  default = ["10.0.2.0/24", "10.0.5.0/24"]
}

variable "private_gic_cidrs" {
  type    = list(string)
  default = ["10.0.3.0/24", "10.0.6.0/24"]
}

variable "ami" {
  type        = string
  description = "AMI id for EC2 instances (if empty, will lookup Amazon Linux 2023 minimal in region)"
  default     = ""
}

variable "key_name" {
  type    = string
  default = "PF-key"
  description = "SSH keypair name to attach to EC2 instances"
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "haproxy_instance_type" {
  type    = string
  default = "t3.small"
}

variable "ssh_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

variable "domain_name" {
  type    = string
  default = "example.gesfie.com"
}

variable "hosted_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for the domain (set before apply)"
  default     = "Z03289393TDOFY56SYW0Z"
}