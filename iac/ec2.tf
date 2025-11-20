resource "aws_default_vpc" "insecure_vpc" {
  tags = {
    Name = "insecure_vpc"
    Description = "Default insecure AWS VPC."
   }
}

resource "aws_default_subnet" "insecure_subnet" {
  availability_zone = "${var.region}-1a"

  tags = {
    Name = "insecure_subnet"
    Description = "Default insecure subnet."
   }

}

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = ""

  // Open all inbound traffic from any source
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  // Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  vpc_id = aws_default_vpc.insecure_vpc.id

  tags = {
    Name = "insecure_security_group"
    Description = "Default insecure security group."
   }

}

resource "aws_instance" "insecure_instance" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"

  // Insecure: Assign a public IP directly to the instance.
  associate_public_ip_address = true

  // Insecure: Use a hardcoded SSH key (private key should not be exposed).
  key_name = "insecure-key"

  // Insecure: Open SSH access to the world
  security_groups = [aws_security_group.insecure_sg.name]

  // Insecure: Not use the default VPC for Terraform workflows.
  // Potential security risk: Default VPC does not have a lot of the critical security features that standard VPC comes with.

  root_block_device {
    encrypted = false
    volume_size = 8
    volume_type = "standard"
  }

  user_data = templatefile("templates/linux_userdata.tpl", {
    AWS_ACCESS_KEY_ID     = var.aws_access_key_id
    AWS_SECRET_ACCESS_KEY = var.aws_secret_access_key
    AWS_DEFAULT_REGION    = var.aws_region
  })

  tags = {
    Name = "insecure_instance"
    Description = "Insecure AWS EC2 instance."
  }

}

resource "aws_ebs_volume" "insecure_volume" {
  availability_zone = "eu-west-1a"
  encrypted         = false
  size              = 40

  tags = {
    Name = "insecure_volume"
    Description = "Insecure AWS EBS volume."
  }

}

resource "aws_volume_attachment" "insecure_volume_attachment" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.insecure_volume.id
  instance_id = aws_instance.insecure_instance.id
}

# BAD: EC2 instance with hardcoded credentials in user data
resource "aws_instance" "bad_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # BAD: No encryption on root volume
  root_block_device {
    encrypted = false
    volume_type = "standard"  # BAD: Should use gp3
  }
  
  # BAD: Hardcoded AWS credentials in user data
  user_data = <<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    export DB_PASSWORD=SuperSecret123!
  EOF
  
  # BAD: Public IP with open security group
  associate_public_ip_address = true
  vpc_security_group_ids = [aws_security_group.insecure_sg.id]
  
  # BAD: No IAM instance profile
  # BAD: No monitoring enabled
}

# BAD: Security group allowing SSH from anywhere
resource "aws_security_group" "bad_ssh_sg" {
  name        = "bad-ssh-sg"
  description = "Allows SSH from anywhere - BAD"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # BAD: SSH open to world
  }
  
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # BAD: RDP open to world
  }
}

# BAD: EBS volume without encryption
resource "aws_ebs_volume" "unencrypted_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # BAD: Should be true
  type              = "gp2"  # BAD: Should use gp3
  iops              = 100
}

# BAD: EC2 instance with metadata service v1 (vulnerable to SSRF)
resource "aws_instance" "metadata_v1_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # BAD: Should be "required"
    http_put_response_hop_limit = 1
  }
}

# BAD: Launch template with overly permissive IAM role
resource "aws_launch_template" "bad_template" {
  name_prefix   = "bad-template-"
  image_id      = "ami-12345678"
  instance_type = "t2.micro"
  
  iam_instance_profile {
    name = aws_iam_instance_profile.bad_profile.name
  }
  
  # BAD: No user data hardening
  # BAD: No security group restrictions
}

resource "aws_iam_instance_profile" "bad_profile" {
  name = "bad-instance-profile"
  role = aws_iam_role.admin_role.name  # BAD: Using admin role
}

# BAD: EC2 instance with user data containing secrets
resource "aws_instance" "secrets_in_userdata" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # BAD: Secrets hardcoded in user data
    export DATABASE_URL="postgresql://admin:Password123!@db.example.com:5432/mydb"
    export API_KEY="test_api_key_FAKE1234567890abcdefghijklmnop_NOTREAL"
    export REDIS_PASSWORD="redis-secret-password-123"
    
    # BAD: No secrets management
    echo "Starting application with hardcoded credentials"
  EOF
  )
}

# BAD: EC2 instance without termination protection
resource "aws_instance" "no_termination_protection" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # BAD: No disable_api_termination = true
  # BAD: No instance metadata service v2 enforcement
}

# BAD: Security group with self-referencing rules
resource "aws_security_group" "self_reference_sg" {
  name        = "self-reference-sg"
  description = "Security group with self-referencing rules - BAD"
  
  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    self            = true  # BAD: Allows all traffic from itself
    cidr_blocks     = ["0.0.0.0/0"]  # BAD: Also allows from anywhere
  }
}

# BAD: EC2 instance with detailed monitoring disabled
resource "aws_instance" "no_monitoring" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  monitoring = false  # BAD: Should be true for production
  
  # BAD: No CloudWatch alarms configured
}

