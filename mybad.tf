terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }
}

# 6. Create open Security Group to allow port 22,80,443
resource "aws_security_group" "jbportsteraformer" {
  name        = "jbportstera_traffic"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.jb-vpc.id
    ingress {
    description = "API Access"
    from_port   = 8089
    to_port     = 8089
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "UI Access"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HEC Access"
    from_port   = 8088
    to_port     = 8088
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }   
  ingress {
    description = "S2S Access"
    from_port   = 9997
    to_port     = 9997
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }    
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "terraterraagent"
  }
}
# 7. Create a network interface with an ip in the subnet that was created in step 4
resource "aws_network_interface" "terraagent-nic" {
  subnet_id       = aws_subnet.subnet-1.id
  private_ips     = ["10.0.1.40"]
  security_groups = [aws_security_group.jbportstera.id]
  tags = {
    Name = "terraterraagent"
  }
}
# 8. Assign an elastic IP to the network interface created in step 7
resource "aws_eip" "terraagent" {
  vpc                       = true
  network_interface         = aws_network_interface.terraagent-nic.id
  associate_with_private_ip = "10.0.1.40"
  depends_on                = [aws_internet_gateway.gw]
  tags = {
    Name = "terraterraagent"
  }
}