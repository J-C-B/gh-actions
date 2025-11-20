resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"
  ignore_public_acls = false

  versioning {
    enabled = false
  }
  
  tags = {
    Name = "My Test Bucket"
  }
}

resource "aws_s3_bucket_policy" "insecure_policy" {
  bucket = aws_s3_bucket.insecure_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["s3:GetObject"],
        Effect   = "Allow",
        Resource = join("", [ "arn:aws:s3:::", aws_s3_bucket.insecure_bucket.id, "/*" ]),
        Principal = "*",
      },
    ],
  })
}

resource "aws_s3_bucket_public_access_block" "insecure_public_access_block" {
    bucket = aws_s3_bucket.insecure_bucket.id

    block_public_acls = false

    restrict_public_buckets = false
}

# BAD: S3 bucket without encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "unencrypted-data-bucket-12345"
  
  # BAD: No encryption configuration
  # BAD: No versioning
  # BAD: No logging
}

# BAD: S3 bucket with public read-write access
resource "aws_s3_bucket" "public_rw_bucket" {
  bucket = "public-read-write-bucket-12345"
  acl    = "public-read-write"  # BAD: Public write access
}

resource "aws_s3_bucket_policy" "public_rw_policy" {
  bucket = aws_s3_bucket.public_rw_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Principal = "*"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.public_rw_bucket.arn}/*"
      },
    ]
  })
}

# BAD: S3 bucket with server-side encryption disabled
resource "aws_s3_bucket" "no_encryption_bucket" {
  bucket = "no-encryption-bucket-12345"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bad_encryption" {
  bucket = aws_s3_bucket.no_encryption_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # BAD: Should use KMS
    }
    bucket_key_enabled = false  # BAD: Should be true
  }
}
