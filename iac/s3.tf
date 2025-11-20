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

# BAD: Access logs written to same public bucket
resource "aws_s3_bucket_logging" "self_logging" {
  bucket = aws_s3_bucket.insecure_bucket.id
  target_bucket = aws_s3_bucket.insecure_bucket.id  # BAD: Logging to same bucket
  target_prefix = "logs/"
}

# BAD: Bucket access point with public network origin
resource "aws_s3_access_point" "public_access_point" {
  bucket = aws_s3_bucket.public_rw_bucket.id
  name   = "public-access-point"

  public_access_block_configuration {
    block_public_acls       = false
    block_public_policy     = false
    ignore_public_acls      = false
    restrict_public_buckets = false
  }
}

# BAD: S3 bucket object containing plaintext credentials
resource "aws_s3_bucket_object" "plaintext_creds" {
  bucket  = aws_s3_bucket.insecure_bucket.id
  key     = "config/creds.txt"
  content = <<-EOF
    username=admin
    password=PlaintextPassword123!
    api_token=test_api_token_FAKE987654321
  EOF
  acl     = "public-read"
}

# BAD: Bucket ACL explicitly allowing everyone
resource "aws_s3_bucket_acl" "explicit_public_acl" {
  bucket = aws_s3_bucket.insecure_bucket.id
  acl    = "public-read-write"
}

# BAD: Replication configuration pointing to untrusted account
resource "aws_s3_bucket" "untrusted_bucket" {
  bucket = "untrusted-destination-bucket-12345"
}

resource "aws_s3_bucket_replication_configuration" "untrusted_replication" {
  depends_on = [aws_s3_bucket_public_access_block.insecure_public_access_block]
  role       = aws_iam_role.admin_role.arn
  bucket     = aws_s3_bucket.insecure_bucket.id

  rule {
    id     = "replicate-all"
    status = "Enabled"

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket        = aws_s3_bucket.untrusted_bucket.arn
      storage_class = "STANDARD"
      account       = "123456789012" # BAD: Hardcoded account
    }
  }
}

# BAD: S3 bucket lifecycle that archives immediately without review
resource "aws_s3_bucket_lifecycle_configuration" "immediate_glacier" {
  bucket = aws_s3_bucket.untrusted_bucket.id

  rule {
    id     = "archive-immediately"
    status = "Enabled"

    transition {
      days          = 0
      storage_class = "GLACIER"
    }
  }
}

# BAD: Compliance bucket with object lock disabled storing PII
resource "aws_s3_bucket" "compliance_bucket" {
  bucket = "compliance-bucket-no-lock"
  object_lock_enabled = false
}

resource "aws_s3_bucket_object" "pii_dump" {
  bucket = aws_s3_bucket.compliance_bucket.id
  key    = "exports/patient-data.csv"
  content = "name,ssn\nAlice,123-45-6789\nBob,987-65-4321"
  acl     = "private"
}
