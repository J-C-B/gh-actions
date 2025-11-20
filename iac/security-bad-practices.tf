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

