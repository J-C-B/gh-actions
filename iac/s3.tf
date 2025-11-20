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
  # BAD: No lifecycle policies
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
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl"]
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

# BAD: S3 bucket with website hosting enabled (public access)
resource "aws_s3_bucket_website_configuration" "public_website" {
  bucket = aws_s3_bucket.insecure_bucket.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "error.html"
  }
}

# BAD: S3 bucket without MFA delete protection
resource "aws_s3_bucket_versioning" "no_mfa" {
  bucket = aws_s3_bucket.insecure_bucket.id

  versioning_configuration {
    status = "Enabled"
    # BAD: mfa_delete not set (should require MFA for deletion)
  }
}

# BAD: S3 bucket with CORS allowing all origins
resource "aws_s3_bucket_cors_configuration" "open_cors" {
  bucket = aws_s3_bucket.insecure_bucket.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE"]
    allowed_origins = ["*"]  # BAD: Allows all origins
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# BAD: S3 bucket with object lock disabled
resource "aws_s3_bucket" "no_object_lock" {
  bucket = "no-object-lock-bucket-12345"
  
  # BAD: No object lock configuration
  # BAD: Objects can be deleted/modified without retention
}

# BAD: S3 bucket with replication to public bucket
resource "aws_s3_bucket_replication_configuration" "bad_replication" {
  role   = aws_iam_role.admin_role.arn
  bucket = aws_s3_bucket.insecure_bucket.id

  rule {
    id     = "replicate-to-public"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.public_rw_bucket.arn
      storage_class = "STANDARD"
    }
    
    # BAD: Replicating to a public bucket
  }
}

# BAD: S3 bucket notification to public SNS topic
resource "aws_s3_bucket_notification" "public_notification" {
  bucket = aws_s3_bucket.insecure_bucket.id

  topic {
    topic_arn = aws_sns_topic.public_topic.arn
    events    = ["s3:ObjectCreated:*"]
  }
  
  # BAD: Notifications sent to public topic
}

# BAD: S3 bucket with no access logging
resource "aws_s3_bucket" "no_logging" {
  bucket = "no-logging-bucket-12345"
  
  # BAD: No logging configuration
  # BAD: Cannot track access patterns
}

# BAD: S3 bucket with lifecycle policy that deletes too quickly
resource "aws_s3_bucket_lifecycle_configuration" "aggressive_deletion" {
  bucket = aws_s3_bucket.insecure_bucket.id

  rule {
    id     = "delete-quickly"
    status = "Enabled"

    expiration {
      days = 1  # BAD: Deletes objects after 1 day
    }
    
    # BAD: No transition to cheaper storage
  }
}
