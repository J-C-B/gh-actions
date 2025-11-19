# Test file for secret detection
# This file contains fake AWS credentials for testing purposes
# Testing native Lacework PR comments with token input - v9

variable "aws_access_key_id" {
  description = "AWS Access Key ID"
  default     = "AKIAIOSFODNN7EXAMPLE"
  sensitive   = true
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key"
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  sensitive   = true
}

# Example usage in a provider block
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}

# Another example in a resource
resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # Hardcoded credentials (bad practice)
  user_data = <<-EOF
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  EOF
}

# New secrets for testing - using fake patterns that won't trigger GitHub push protection
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-12345"
  
  # GitHub token example (fake pattern)
  tags = {
    github_token = "ghp_TEST1234567890abcdefghijklmnopqrstuvwxyzFAKE"
    api_key      = "sk_test_FAKE1234567890abcdefghijklmnopqrstuvwxyz"
  }
}

# Database credentials
resource "aws_db_instance" "test_db" {
  identifier = "test-db"
  engine     = "postgres"
  
  # Hardcoded database password
  password = "TestPassword123!@#FAKE"
  username = "admin"
}

# API keys in variables (using fake patterns)
variable "stripe_secret_key" {
  default = "sk_test_FAKE1234567890abcdefghijklmnopqrstuvwxyz"
}

variable "slack_webhook_url" {
  default = "https://hooks.slack.com/services/TEST00000/BTEST00000/FAKETESTTOKEN123456789"
}

# Additional secret types
variable "jwt_token" {
  default = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZha2UgVGVzdCJ9.FAKE"
}

variable "private_key" {
  default = "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYDATAHERE1234567890\n-----END RSA PRIVATE KEY-----"
}
