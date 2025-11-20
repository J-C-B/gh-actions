# Security Bad Practices Examples
# This file contains intentionally insecure configurations for testing Lacework detection

# 1. Public S3 Bucket with no encryption
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-12345"
  
  # Missing encryption configuration
  # Missing versioning
  # Missing logging
}

resource "aws_s3_bucket_public_access_block" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_bucket" {
  bucket = aws_s3_bucket.public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_bucket.arn}/*"
      },
    ]
  })
}

# 2. IAM Role with Admin Access
resource "aws_iam_role" "admin_role" {
  name = "admin-role-bad-practice"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_role" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 3. Security Group with Open Ingress Rules
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Security group with open access - BAD PRACTICE"

  ingress {
    description = "Allow all inbound"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow all UDP"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "open-security-group"
  }
}

# 4. RDS Instance with Public Access
resource "aws_db_instance" "public_db" {
  identifier     = "public-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage     = 20
  storage_type          = "gp2"
  publicly_accessible   = true  # BAD: Database exposed to internet
  skip_final_snapshot  = true
  deletion_protection = false  # BAD: No deletion protection

  db_name  = "mydb"
  username = "admin"
  password = "WeakPassword123"  # BAD: Weak password in code

  # Missing encryption at rest
  # Missing backup configuration
}

# 5. EC2 Instance with Public IP and No Security Group
resource "aws_instance" "exposed_instance" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t2.micro"
  associate_public_ip_address = true  # BAD: Public IP

  # No security group specified - uses default
  # No user data hardening
  # No IAM role restrictions

  tags = {
    Name = "exposed-instance"
  }
}

# 6. CloudTrail Not Enabled or Misconfigured
resource "aws_cloudtrail" "missing_trail" {
  name = "missing-cloudtrail"

  s3_bucket_name = aws_s3_bucket.public_bucket.id
  
  # Missing: is_multi_region_trail = true
  # Missing: enable_logging = true
  # Missing: include_global_service_events = true
  # Missing: enable_log_file_validation = true
}

# 7. S3 Bucket with Versioning Disabled
resource "aws_s3_bucket" "no_versioning" {
  bucket = "bucket-no-versioning-12345"
  
  # Missing versioning configuration
  # Missing lifecycle policies
  # Missing encryption
}

# 8. IAM User with Access Keys and Admin Policy
resource "aws_iam_user" "admin_user" {
  name = "admin-user-bad"
}

resource "aws_iam_user_policy_attachment" "admin_user" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "admin_user" {
  user = aws_iam_user.admin_user.name
  # BAD: Access keys should be rotated and not stored in Terraform
}

# 9. Lambda Function with Overly Permissive Execution Role
resource "aws_iam_role" "lambda_execution" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy" "lambda_execution" {
  name = "lambda-execution-policy"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"  # BAD: Wildcard action
        Resource = "*"  # BAD: Wildcard resource
      },
    ]
  })
}

# 10. ECR Repository with Public Access
resource "aws_ecr_repository" "public_repo" {
  name                 = "public-container-repo"
  image_tag_mutability = "MUTABLE"  # BAD: Should be IMMUTABLE

  image_scanning_configuration {
    scan_on_push = false  # BAD: Should scan on push
  }
}

resource "aws_ecr_repository_policy" "public_repo" {
  repository = aws_ecr_repository.public_repo.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PublicPull"
        Effect = "Allow"
        Principal = "*"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
        ]
      },
    ]
  })
}

# 11. API Gateway without authentication
resource "aws_api_gateway_rest_api" "public_api" {
  name        = "public-api"
  description = "API without authentication - BAD"
}

resource "aws_api_gateway_method" "public_method" {
  rest_api_id   = aws_api_gateway_rest_api.public_api.id
  resource_id   = aws_api_gateway_rest_api.public_api.root_resource_id
  http_method   = "GET"
  authorization = "NONE"  # BAD: No authorization
}

# 12. CloudFront distribution with insecure origin
resource "aws_cloudfront_distribution" "insecure_distribution" {
  enabled = true
  
  origin {
    domain_name = aws_s3_bucket.public_bucket.bucket_domain_name
    origin_id   = "S3-${aws_s3_bucket.public_bucket.id}"
    
    # BAD: No origin access control
  }
  
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.public_bucket.id}"
    
    forwarded_values {
      query_string = true
      cookies {
        forward = "all"  # BAD: Forwarding all cookies
      }
    }
    
    viewer_protocol_policy = "allow-all"  # BAD: Should be redirect-to-https
  }
  
  restrictions {
    geo_restriction {
      restriction_type = "none"  # BAD: No geo restrictions
    }
  }
}

# 13. ElastiCache without encryption
resource "aws_elasticache_cluster" "unencrypted_cache" {
  cluster_id           = "unencrypted-cache"
  engine               = "redis"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  
  # BAD: No encryption at rest
  # BAD: No encryption in transit
  # BAD: No auth token
}

# 14. KMS key with overly permissive policy
resource "aws_kms_key" "permissive_key" {
  description = "KMS key with permissive policy - BAD"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAll"
        Effect = "Allow"
        Principal = {
          AWS = "*"  # BAD: Allows all AWS accounts
        }
        Action   = "kms:*"
        Resource = "*"
      },
    ]
  })
}

# 15. VPC without flow logs
resource "aws_vpc" "no_flow_logs" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # BAD: No flow logs configured
  # BAD: No default security group restrictions
}

# 16. EKS cluster with public endpoint
resource "aws_eks_cluster" "public_endpoint" {
  name     = "public-eks-cluster"
  role_arn = aws_iam_role.admin_role.arn
  
  vpc_config {
    subnet_ids = []
    endpoint_public_access  = true  # BAD: Public endpoint
    endpoint_private_access = false  # BAD: No private endpoint
  }
  
  # BAD: No encryption configuration
  # BAD: No logging enabled
  # BAD: No OIDC provider
}

# 17. Secrets Manager secret with plaintext value
resource "aws_secretsmanager_secret" "plaintext_secret" {
  name = "plaintext-secret"
  
  # BAD: Storing secret in plaintext in Terraform
}

resource "aws_secretsmanager_secret_version" "plaintext_secret" {
  secret_id = aws_secretsmanager_secret.plaintext_secret.id
  secret_string = jsonencode({
    username = "admin"
    password = "SuperSecretPassword123"  # BAD: In plaintext
    api_key  = "sk_live_1234567890abcdef"  # BAD: API key in plaintext
  })
}

# 18. Route53 hosted zone with public records
resource "aws_route53_zone" "public_zone" {
  name = "example.com"
  
  # BAD: No DNSSEC enabled
  # BAD: No query logging
}

# 19. Auto Scaling Group without health checks
resource "aws_autoscaling_group" "no_health_checks" {
  name                = "asg-no-health-checks"
  vpc_zone_identifier  = []
  min_size            = 1
  max_size            = 10
  desired_capacity    = 2
  
  # BAD: No health check configuration
  # BAD: No termination policies
  # BAD: No scaling policies
}

# 20. CloudWatch Log Group without retention
resource "aws_cloudwatch_log_group" "no_retention" {
  name = "/aws/lambda/no-retention"
  
  # BAD: No retention policy - logs never expire
  # BAD: No encryption
}

# 21. DynamoDB table without encryption
resource "aws_dynamodb_table" "unencrypted_table" {
  name           = "unencrypted-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  
  # BAD: No server-side encryption
  # BAD: No point-in-time recovery
  # BAD: No backup configuration
}

# 22. SNS topic with public subscription
resource "aws_sns_topic" "public_topic" {
  name = "public-sns-topic"
  
  # BAD: No encryption
  # BAD: No access policy restrictions
}

resource "aws_sns_topic_policy" "public_topic_policy" {
  arn = aws_sns_topic.public_topic.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = "SNS:Publish"
        Resource = aws_sns_topic.public_topic.arn
      },
    ]
  })
}

# 23. SQS queue without encryption
resource "aws_sqs_queue" "unencrypted_queue" {
  name = "unencrypted-queue"
  
  # BAD: No encryption
  # BAD: No dead letter queue
  # BAD: No visibility timeout
}

# 24. IAM policy with wildcard resources and actions
resource "aws_iam_policy" "wildcard_policy" {
  name        = "wildcard-policy"
  description = "Policy with wildcards - BAD"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"  # BAD: All actions
        Resource = "*"  # BAD: All resources
      },
    ]
  })
}

# 25. Network ACL allowing all traffic
resource "aws_network_acl" "open_nacl" {
  vpc_id = aws_vpc.no_flow_logs.id

  ingress {
    rule_no    = 100
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  tags = {
    Name = "open-network-acl"
  }
}

