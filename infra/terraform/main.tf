terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project = "bi-site-active-passive"
    }
  }
}

# AMI lookup: Amazon Linux 2023 minimal if var.ami not set
data "aws_ssm_parameter" "amzn_2023_minimal" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-minimal-kernel-6.12-x86_64"
}

locals {
  resolved_ami = var.ami != "" ? var.ami : data.aws_ssm_parameter.amzn_2023_minimal.value
  azs = var.availability_zones
}
# Generate SSH key pair locally and upload public key to AWS as PF-key
resource "tls_private_key" "pf_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "pf_key" {
  key_name   = var.key_name
  public_key = tls_private_key.pf_key.public_key_openssh
  tags = { Name = var.key_name }
}

# VPC and network
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "bi-site-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = { Name = "vpc-igw" }
}

resource "aws_subnet" "public" {
  for_each = zipmap(var.availability_zones, var.public_subnet_cidrs)
  vpc_id = aws_vpc.main.id
  cidr_block = each.value
  availability_zone = each.key
  map_public_ip_on_launch = true
  tags = { Name = "public-${each.key}" }
}

resource "aws_subnet" "private_gie" {
  for_each = zipmap(var.availability_zones, var.private_gie_cidrs)
  vpc_id = aws_vpc.main.id
  cidr_block = each.value
  availability_zone = each.key
  map_public_ip_on_launch = false
  tags = { Name = "private-gie-${each.key}" }
}

resource "aws_subnet" "private_gic" {
  for_each = zipmap(var.availability_zones, var.private_gic_cidrs)
  vpc_id = aws_vpc.main.id
  cidr_block = each.value
  availability_zone = each.key
  map_public_ip_on_launch = false
  tags = { Name = "private-gic-${each.key}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  for_each = aws_subnet.public
  subnet_id = each.value.id
  route_table_id = aws_route_table.public.id
}

# Security groups
resource "aws_security_group" "haproxy_sg" {
  name   = "sghaproxy"
  vpc_id = aws_vpc.main.id
  description = "Allow HTTP/HTTPS and SSH from internet to HAProxy"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "haproxy-sg" }
}

resource "aws_security_group" "web_sg" {
  name   = "sgweb"
  vpc_id = aws_vpc.main.id
  description = "Allow HTTP from haproxy and Postgres from VPC"

  ingress {
    description = "HTTP from haproxy"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.haproxy_sg.id]
  }
  ingress {
    description = "Postgres from VPC"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "web-sg" }
}

# IAM role for EC2 (SSM)
data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2_ssm_role" {
  name = "ec2-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-ssm-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

# HAProxy instances (one per public subnet)
resource "aws_instance" "haproxy" {
  for_each = aws_subnet.public
  ami           = local.resolved_ami
  instance_type = var.haproxy_instance_type
  subnet_id     = each.value.id
  key_name      = aws_key_pair.pf_key.key_name
  associate_public_ip_address = true
  vpc_security_group_ids = [aws_security_group.haproxy_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  tags = { Name = "haproxy-${each.key}" }

  user_data = <<-EOF
              #!/bin/bash
              set -e
              dnf update -y
              dnf install -y haproxy
              systemctl enable haproxy

              cat > /etc/haproxy/haproxy.cfg <<'HAPROXYCFG'
              global
                log /dev/log local0
              defaults
                log global
                mode http
                timeout connect 5s
                timeout client  50s
                timeout server  50s

              frontend http-in
                bind *:80
                acl is_gie path_beg /gie
                acl is_gic path_beg /gic
                acl is_health path_beg /health
                http-request return status 200 content-type "text/plain" lf-string "OK" if is_health
                use_backend backend_gie if is_gie
                use_backend backend_gic if is_gic
                default_backend backend_gie

              backend backend_gie
                mode http
                balance roundrobin
                option httpchk GET /web1/health
                http-check expect status 200
                cookie SRV insert indirect nocache
                server web1 10.0.2.10:80 check
                server web2 10.0.2.11:80 check

              backend backend_gic
                mode http
                balance roundrobin
                option httpchk GET /web2/health
                http-check expect status 200
                cookie SRV insert indirect nocache
                server web1 10.0.5.10:80 check
                server web2 10.0.5.11:80 check
              
              EOF
}

# Web+DB instances: one t3.medium per private subnet (GIE and GIC)
resource "aws_instance" "web_gie" {
  for_each = { for az in local.azs : az => az }
  ami           = local.resolved_ami
  instance_type = var.instance_type
  subnet_id     = aws_subnet.private_gie[each.key].id
  key_name      = aws_key_pair.pf_key.key_name
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  tags = { Name = "web-gie-${each.key}" }

  user_data = <<-EOF
            #!/bin/bash
            set -e

            # Mise à jour et installation
            dnf update -y
            dnf install -y httpd
            amazon-linux-extras enable postgresql18
            dnf install -y postgresql18-server

            # Activation des services
            systemctl enable httpd
            systemctl start httpd

            # Création des dossiers web1 et web2
            mkdir -p /var/www/html/web1
            mkdir -p /var/www/html/web2

            # Fichiers index.html
            echo "<h1>web1 - $(hostname)</h1>" > /var/www/html/web1/index.html
            echo "<h1>web2 - $(hostname)</h1>" > /var/www/html/web2/index.html

            # Fichiers health
            echo "OK" > /var/www/html/web1/health
            echo "OK" > /var/www/html/web2/health

            # Initialisation PostgreSQL 18
            /usr/bin/postgresql-setup --initdb
            systemctl enable postgresql
            systemctl start postgresql
            EOF
}

resource "aws_instance" "web_gic" {
  for_each = { for az in local.azs : az => az }
  ami           = local.resolved_ami
  instance_type = var.instance_type
  subnet_id     = aws_subnet.private_gic[each.key].id
  key_name      = aws_key_pair.pf_key.key_name
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  tags = { Name = "web-gic-${each.key}" }

  user_data = <<-EOF
            #!/bin/bash
            set -e

            # Mise à jour et installation
            dnf update -y
            dnf install -y httpd
            amazon-linux-extras enable postgresql18
            dnf install -y postgresql18-server

            # Activation des services
            systemctl enable httpd
            systemctl start httpd

            # Création des dossiers web1 et web2
            mkdir -p /var/www/html/web1
            mkdir -p /var/www/html/web2

            # Fichiers index.html
            echo "<h1>web1 - $(hostname)</h1>" > /var/www/html/web1/index.html
            echo "<h1>web2 - $(hostname)</h1>" > /var/www/html/web2/index.html

            # Fichiers health
            echo "OK" > /var/www/html/web1/health
            echo "OK" > /var/www/html/web2/health

            # Initialisation PostgreSQL 18
            /usr/bin/postgresql-setup --initdb
            systemctl enable postgresql
            systemctl start postgresql
            EOF
}

# NLB + target group for HAProxy instances
resource "aws_lb" "nlb" {
  name               = "front-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [for s in aws_subnet.public : s.id]
  enable_deletion_protection = false
  tags = { Name = "front-nlb" }
}

resource "aws_lb_target_group" "haproxy_tg" {
  name     = "haproxy-tg"
  port     = 80
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id
  target_type = "instance"
  health_check {
    path = "/health"
    matcher = "200-399"
    interval = 30
    timeout  = 5
    healthy_threshold = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group_attachment" "haproxy_attach" {
  for_each = aws_instance.haproxy
  target_group_arn = aws_lb_target_group.haproxy_tg.arn
  target_id        = each.value.id
  port             = 80
}

resource "aws_lb_listener" "nlb_listener" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 80
  protocol          = "TCP"
  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.haproxy_tg.arn
  }
}

# Route53 health check and failover records
resource "aws_route53_health_check" "haproxy_primary" {
  depends_on = [aws_lb.nlb]
  fqdn = aws_lb.nlb.dns_name
  port = 80
  type = "HTTP"
  resource_path = "/health"
  failure_threshold = 2
  request_interval = 30
}

# enregistrement A unique (alias) pointant sur le NLB
resource "aws_route53_record" "app" {
  count   = var.hosted_zone_id != "" ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_lb.nlb.dns_name
    zone_id                = aws_lb.nlb.zone_id
    evaluate_target_health = true
  }

}

# SNS + CloudWatch alarm (approximation for NLB)
resource "aws_sns_topic" "failover" {
  name = "failover-topic"
}

resource "aws_cloudwatch_metric_alarm" "haproxy_down" {
  alarm_name          = "haproxy-primary-down"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 30
  statistic           = "Minimum"
  threshold           = 1
  dimensions = {
    LoadBalancer = aws_lb.nlb.arn_suffix
  }
  alarm_actions = [aws_sns_topic.failover.arn]
}

# Lambda role and policy
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda-failover-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_ec2_start_policy" {
  name = "lambda-ec2-ssm-start"
  role = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:StartInstances",
          "ec2:DescribeInstances",
          "ssm:SendCommand",
          "ec2:DescribeInstanceStatus"
        ],
        Effect = "Allow",
        Resource = "*"
      }
    ]
  })
}

# Package Lambda from local folder lambda_src (lambda_src must exist)
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/lambda_src/lambda.zip"
}

resource "aws_lambda_function" "failover_action" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "start-passive-instances"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  environment {
    variables = {
      PRIMARY_AZ   = var.availability_zones[0]
      SECONDARY_AZ = var.availability_zones[1]
      TAG_PREFIX   = "web-"
    }
  }
  depends_on = [aws_iam_role_policy.lambda_ec2_start_policy]
}

resource "aws_sns_topic_subscription" "lambda_sub" {
  topic_arn = aws_sns_topic.failover.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.failover_action.arn
}

resource "aws_lambda_permission" "allow_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.failover_action.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.failover.arn
}


# Add NatGateway,Elastic Ip and route entries to the internet gateway

# --- Elastic IPs for NAT (one per public subnet / AZ)
resource "aws_eip" "nat" {
  for_each = aws_subnet.public
  vpc = true
  tags = {
    Name = "nat-eip-${each.key}"
  }
}

# --- NAT Gateways (one per public subnet / AZ)
resource "aws_nat_gateway" "nat" {
  for_each = aws_subnet.public
  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = each.value.id
  tags = {
    Name = "nat-gw-${each.key}"
  }

  depends_on = [aws_internet_gateway.igw]
}

# --- Private route tables (one per AZ) that route 0.0.0.0/0 to the NAT in the same AZ
resource "aws_route_table" "private" {
  for_each = aws_subnet.public
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "private-rt-${each.key}"
  }

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[each.key].id
  }
}

# --- Associate private_gie subnets to their AZ-specific private route table
resource "aws_route_table_association" "private_gie_assoc" {
  for_each = aws_subnet.private_gie
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}

# --- Associate private_gic subnets to their AZ-specific private route table
resource "aws_route_table_association" "private_gic_assoc" {
  for_each = aws_subnet.private_gic
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private[each.key].id
}