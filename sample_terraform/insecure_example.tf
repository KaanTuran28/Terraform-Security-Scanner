resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "primary" {
  identifier          = "prod-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = true
  password            = "SuperSecretPassword123"
}
