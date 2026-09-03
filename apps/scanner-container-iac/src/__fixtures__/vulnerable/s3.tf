resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
  acl    = "public-read"
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
  acl    = "public-read-write"
}
