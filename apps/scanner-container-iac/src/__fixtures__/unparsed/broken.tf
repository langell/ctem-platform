resource "aws_s3_bucket" "broken" {
  bucket = "nope"
  acl    =
