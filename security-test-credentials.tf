# Security test file for credential detection
# This file contains fake credentials for testing Lacework secret detection
# Updated with new secret types for comprehensive testing

variable "aws_access_key_id" {
  description = "AWS Access Key ID"
  default     = "AKIAEXAMPLE123456789"
  sensitive   = true
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key"
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY123"
  sensitive   = true
}

# Example usage in a provider block
provider "aws" {
  access_key = "AKIAEXAMPLE123456789"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY123"
  region     = "us-west-2"
}

# Another example in a resource
resource "aws_instance" "test" {
  ami           = "ami-98765432"
  instance_type = "t3.medium"
  
  # Hardcoded credentials (bad practice)
  user_data = <<-EOF
    export AWS_ACCESS_KEY_ID=AKIAEXAMPLE123456789
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY123
  EOF
}

# New secrets for testing - using fake patterns that won't trigger GitHub push protection
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-new-54321"
  
  # GitHub token example (fake pattern)
  tags = {
    github_token = "ghp_FAKETESTTOKEN1234567890abcdefghijklmnopqrstuvwxyzNOTREAL"
    test_api_key = "test_key_NOTREALFAKE1234567890abcdefghijklmnopqrstuvwxyz"
  }
}

# Database credentials
resource "aws_db_instance" "test_db" {
  identifier = "test-db-new"
  engine     = "mysql"
  
  # Hardcoded database password
  password = "NewTestPassword456!@#NOTREAL"
  username = "dbadmin"
}

# API keys in variables (using fake patterns)
variable "payment_api_key" {
  default = "api_key_NOTREALFAKE1234567890abcdefghijklmnopqrstuvwxyz"
}

variable "slack_webhook_url" {
  default = "https://hooks.slack.com/services/TNOTREAL00/BNOTREAL00/FAKENOTREALTOKEN123456789"
}

# Additional secret types
variable "jwt_token" {
  default = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEwIiwibmFtZSI6Ik5ldyBGYWtlIFRlc3QifQ.NOTREALFAKE"
}

variable "private_key" {
  default = "-----BEGIN RSA PRIVATE KEY-----\nFAKENOTREALKEYDATAHERE9876543210\n-----END RSA PRIVATE KEY-----"
}

# Azure service principal
variable "azure_client_secret" {
  default = "NOTREAL~Azure~Client~Secret~1234567890~abcdefghijklmnop"
}

# Google Cloud service account key
variable "gcp_service_account_key" {
  default = "{\"type\":\"service_account\",\"project_id\":\"fake-test-project-notreal\",\"private_key_id\":\"NOTREAL1234567890abcdef\"}"
}
