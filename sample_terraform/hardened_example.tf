resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from office only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }
}

resource "aws_db_instance" "primary" {
  identifier           = "prod-db"
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  publicly_accessible  = false
  storage_encrypted    = true
  password             = var.db_password
}

variable "db_password" {
  type      = string
  sensitive = true
}
