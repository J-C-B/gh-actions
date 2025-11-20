resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read-write"
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
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
        Effect   = "Allow",
        Resource = join("", [ "arn:aws:s3:::", aws_s3_bucket.insecure_bucket.id, "/*" ]),
        Principal = "*",
      },
      {
        Sid    = "AllowAnyAccountFullControl",
        Action = ["s3:*"],
        Effect = "Allow",
        Resource = [
          join("", [ "arn:aws:s3:::", aws_s3_bucket.insecure_bucket.id ]),
          join("", [ "arn:aws:s3:::", aws_s3_bucket.insecure_bucket.id, "/*" ])
        ],
        Principal = "*"
      }
    ],
  })
}

resource "aws_s3_bucket_public_access_block" "insecure_public_access_block" {
    bucket = aws_s3_bucket.insecure_bucket.id

    block_public_acls = false
    block_public_policy = false

    restrict_public_buckets = false
}
resource "aws_s3_bucket" "sensitive_exports" {
  bucket        = "sensitive-exports-example"
  acl           = "public-read"
  force_destroy = true

  versioning {
    enabled = false
  }

  logging {
    target_bucket = aws_s3_bucket.insecure_bucket.id
    target_prefix = "logs/"
  }
}

resource "aws_s3_bucket_public_access_block" "sensitive_exports_public_access" {
  bucket = aws_s3_bucket.sensitive_exports.id

  block_public_acls   = false
  block_public_policy = false
}

resource "aws_s3_bucket_policy" "sensitive_exports_policy" {
  bucket = aws_s3_bucket.sensitive_exports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEveryoneFullControl"
        Effect   = "Allow"
        Principal = "*"
        Action   = "s3:*"
        Resource = [
          join("", ["arn:aws:s3:::", aws_s3_bucket.sensitive_exports.id]),
          join("", ["arn:aws:s3:::", aws_s3_bucket.sensitive_exports.id, "/*"])
        ]
      }
    ]
  })
}

resource "aws_s3_bucket_object" "config_dump" {
  bucket = aws_s3_bucket.sensitive_exports.id
  key    = "config/leaked-config.txt"
  content = <<-EOT
    db_username=admin
    db_password=AnotherFakePassword987!
    github_token=ghp_FAKEEXAMPLETOKENFORTESTINGONLY0987654321
  EOT
}
