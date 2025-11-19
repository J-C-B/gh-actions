# Security test file for credential detection
# This file contains fake credentials for testing Lacework secret detection
# Updated with new secret types for comprehensive testing

variable "aws_access_key_id" {
  description = "AWS Access Key ID"
  default     = "AKIAUPDATED123456789"
  sensitive   = true
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key"
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYUPDATEDKEY456"
  sensitive   = true
}

# Example usage in a provider block
provider "aws" {
  access_key = "AKIAUPDATED123456789"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYUPDATEDKEY456"
  region     = "eu-west-1"
}

# Another example in a resource
resource "aws_instance" "test" {
  ami           = "ami-98765432"
  instance_type = "t3.large"
  
  # Hardcoded credentials (bad practice)
  user_data = <<-EOF
    export AWS_ACCESS_KEY_ID=AKIAUPDATED123456789
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYUPDATEDKEY456
  EOF
}

# New secrets for testing - using fake patterns that won't trigger GitHub push protection
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-updated-99999"
  
  # GitHub token example (fake pattern)
  tags = {
    github_token = "ghp_UPDATEDTOKEN1234567890abcdefghijklmnopqrstuvwxyzNOTREAL"
    test_api_key = "test_key_UPDATEDFAKE1234567890abcdefghijklmnopqrstuvwxyz"
  }
}

# Database credentials
resource "aws_db_instance" "test_db" {
  identifier = "test-db-updated"
  engine     = "postgres"
  
  # Hardcoded database password
  password = "UpdatedPassword789!@#NOTREAL"
  username = "dbuser"
}

# API keys in variables (using fake patterns)
variable "payment_api_key" {
  default = "api_key_UPDATEDFAKE1234567890abcdefghijklmnopqrstuvwxyz"
}

variable "slack_webhook_url" {
  default = "https://hooks.slack.com/services/TUPDATED00/BUPDATED00/FAKEUPDATEDTOKEN123456789"
}

# Additional secret types
variable "jwt_token" {
  default = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMTIyMzM0NDU1IiwibmFtZSI6IlVwZGF0ZWQgRmFrZSBUb2tlbiJ9.UPDATEDFAKE"
}

variable "private_key" {
  default = "-----BEGIN RSA PRIVATE KEY-----\nUPDATEDFAKEKEYDATAHERE111222333444555\n-----END RSA PRIVATE KEY-----"
}

# Azure service principal
variable "azure_client_secret" {
  default = "UPDATED~Azure~Client~Secret~9876543210~zyxwvutsrqponmlkj"
}

# Google Cloud service account key
variable "gcp_service_account_key" {
  default = "{\"type\":\"service_account\",\"project_id\":\"updated-fake-test-project\",\"private_key_id\":\"UPDATED1234567890abcdef\"}"
}

# New: Docker Hub credentials
variable "docker_password" {
  default = "UpdatedDockerPassword123!@#NOTREAL"
}

# New: MongoDB connection string
variable "mongodb_uri" {
  default = "mongodb://admin:UpdatedMongoPass456!@#@cluster.mongodb.net/dbname"
}

# New: Redis password
variable "redis_password" {
  default = "UpdatedRedisPass789!@#NOTREAL"
}
