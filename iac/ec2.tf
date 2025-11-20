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

# BAD: EC2 instance with public AMI sharing sensitive snapshot
resource "aws_ami_launch_permission" "public_ami" {
  image_id   = "ami-0abcdef1234567890"
  account_id = "*"
}

# BAD: EC2 instance that disables ufw/iptables and exposes services
resource "aws_instance" "no_firewall_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  subnet_id     = aws_default_subnet.insecure_subnet.id
  associate_public_ip_address = true

  vpc_security_group_ids = [aws_security_group.insecure_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    ufw disable
    iptables -F
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
    service ssh restart
  EOF
}

# BAD: Bastion host with shared credentials
resource "aws_instance" "shared_bastion" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.small"
  subnet_id     = aws_default_subnet.insecure_subnet.id
  key_name      = "shared-bastion-key"
  user_data = <<-EOF
    #!/bin/bash
    useradd devs
    echo "devs:changeme" | chpasswd
  EOF
}

# BAD: EC2 instance that writes private keys to disk
resource "aws_instance" "debug_jump_box" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.small"

  associate_public_ip_address = true
  subnet_id                   = aws_default_subnet.insecure_subnet.id
  vpc_security_group_ids      = [aws_security_group.insecure_sg.id]

  user_data = <<-EOF
    #!/bin/bash
    cat <<'KEY' >/home/ubuntu/id_rsa
    -----BEGIN PRIVATE KEY-----
    TESTFAKEPRIVATEKEYDATA1234567890
    -----END PRIVATE KEY-----
    KEY
    chmod 600 /home/ubuntu/id_rsa
  EOF

  # BAD: Root block device not encrypted or backed up
  root_block_device {
    encrypted   = false
    volume_size = 10
  }
}

# BAD: Security group rule exposing database port to the internet
resource "aws_security_group_rule" "open_database_port" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.insecure_sg.id
  description       = "Public database access - BAD"
}

# BAD: Launch configuration with hardcoded secrets and no IMDSv2
resource "aws_launch_configuration" "legacy_launch_config" {
  name_prefix   = "legacy-"
  image_id      = "ami-0abcdef1234567890"
  instance_type = "t2.small"
  security_groups = [
    aws_security_group.insecure_sg.id
  ]

  user_data = <<-EOF
    #!/bin/bash
    export API_TOKEN="test_api_token_FAKE1234567890"
    export SMTP_PASSWORD="smtp-password-plain"
  EOF

  lifecycle {
    create_before_destroy = true
  }
}

# BAD: Auto Scaling group without health checks or scaling policies
resource "aws_autoscaling_group" "legacy_asg" {
  name                      = "legacy-asg"
  min_size                  = 1
  max_size                  = 5
  desired_capacity          = 3
  launch_configuration      = aws_launch_configuration.legacy_launch_config.name
  vpc_zone_identifier       = [aws_default_subnet.insecure_subnet.id]
  health_check_type         = "EC2"
  health_check_grace_period = 0  # BAD: No grace period
  force_delete              = true

  tag {
    key                 = "Environment"
    value               = "legacy"
    propagate_at_launch = true
  }
}

# BAD: Instance with IMDS totally disabled causing scripts to fail closed
resource "aws_instance" "imds_disabled_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t2.micro"
  subnet_id     = aws_default_subnet.insecure_subnet.id

  metadata_options {
    http_endpoint               = "disabled"
    http_tokens                 = "optional"
    http_put_response_hop_limit = 1
  }

  # BAD: No monitoring or backup strategy
}

# BAD: IAM user with inline admin policy and exposed keys
resource "aws_iam_user" "legacy_user" {
  name = "legacy-admin"
  path = "/legacy/"
  tags = {
    Environment = "legacy"
  }
}

resource "aws_iam_user_policy" "legacy_admin_policy" {
  name = "legacy-admin-policy"
  user = aws_iam_user.legacy_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_access_key" "legacy_user_key" {
  user = aws_iam_user.legacy_user.name
}

# BAD: Store IAM access key in plain text SSM parameter
resource "aws_ssm_parameter" "plain_iam_key" {
  name  = "/legacy/iam_key"
  type  = "String"  # BAD: Should be SecureString
  value = aws_iam_access_key.legacy_user_key.secret
}

# BAD: EC2 instance enabling password authentication and root login
resource "aws_instance" "password_enabled_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t2.micro"
  subnet_id     = aws_default_subnet.insecure_subnet.id

  user_data = <<-EOF
    #!/bin/bash
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo 'root:password123' | chpasswd
  EOF

  vpc_security_group_ids = [aws_security_group.insecure_sg.id]
}

