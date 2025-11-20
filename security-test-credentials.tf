# Security test file for credential detection
# This file contains fake credentials for testing Lacework secret detection
# Updated with new secret types for comprehensive testing

variable "aws_access_key_id" {
  description = "AWS Access Key ID"
  default     = "AKIASYNCTEST987654321"
  sensitive   = true
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key"
  default     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSYNCTEST789"
  sensitive   = true
}

# Example usage in a provider block
provider "aws" {
  access_key = "AKIASYNCTEST987654321"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSYNCTEST789"
  region     = "ap-southeast-1"
}

# Another example in a resource
resource "aws_instance" "test" {
  ami           = "ami-55555555"
  instance_type = "t3.xlarge"
  
  # Hardcoded credentials (bad practice)
  user_data = <<-EOF
    export AWS_ACCESS_KEY_ID=AKIASYNCTEST987654321
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYSYNCTEST789
  EOF
}

# New secrets for testing - using fake patterns that won't trigger GitHub push protection
resource "aws_s3_bucket" "test_bucket" {
  bucket = "test-bucket-sync-88888"
  
  # GitHub token example (fake pattern)
  tags = {
    github_token = "ghp_SYNCTESTTOKEN9876543210zyxwvutsrqponmlkjihgfedcbaNOTREAL"
    test_api_key = "test_key_SYNCTESTFAKE9876543210zyxwvutsrqponmlkjihgfedcba"
  }
}

# Database credentials
resource "aws_db_instance" "test_db" {
  identifier = "test-db-sync"
  engine     = "mariadb"
  
  # Hardcoded database password
  password = "SyncTestPassword999!@#NOTREAL"
  username = "syncuser"
}

# API keys in variables (using fake patterns)
variable "payment_api_key" {
  default = "api_key_SYNCTESTFAKE9876543210zyxwvutsrqponmlkjihgfedcba"
}

variable "slack_webhook_url" {
  default = "https://hooks.slack.com/services/TSYNCTEST00/BSYNCTEST00/FAKESYNCTESTTOKEN987654321"
}

# Additional secret types
variable "jwt_token" {
  default = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTg4ODc3NzY2NTU0IiwibmFtZSI6IlN5bmMgVGVzdCBUb2tlbiJ9.SYNCTESTFAKE"
}

variable "private_key" {
  default = "-----BEGIN RSA PRIVATE KEY-----\nSYNCTESTFAKEKEYDATAHERE999888777666555\n-----END RSA PRIVATE KEY-----"
}

# Azure service principal
variable "azure_client_secret" {
  default = "SYNCTEST~Azure~Client~Secret~9876543210~zyxwvutsrqponmlkj"
}

# Google Cloud service account key
variable "gcp_service_account_key" {
  default = "{\"type\":\"service_account\",\"project_id\":\"sync-fake-test-project\",\"private_key_id\":\"SYNCTEST9876543210zyxwvuts\"}"
}

# Docker Hub credentials
variable "docker_password" {
  default = "SyncDockerPassword999!@#NOTREAL"
}

# MongoDB connection string
variable "mongodb_uri" {
  default = "mongodb://syncadmin:SyncMongoPass999!@#@cluster.mongodb.net/syncdb"
}

# Redis password
variable "redis_password" {
  default = "SyncRedisPass999!@#NOTREAL"
}

# New: Twilio API credentials
variable "twilio_auth_token" {
  default = "SYNCTESTtwilioauth1234567890abcdefghijklmnop"
}

# New: SendGrid API key
variable "sendgrid_api_key" {
  default = "SG.SYNCTEST1234567890abcdefghijklmnopqrstuvwxyz"
}

# New: Mailgun API key
variable "mailgun_api_key" {
  default = "key-SYNCTEST1234567890abcdefghijklmnopqrstuv"
}
