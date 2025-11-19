# Test file for secret detection
# This file contains fake AWS credentials for testing purposes
# Testing native Lacework PR comments with token input (v8)

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

