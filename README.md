# cloudfront-jwt-auth
Lambda@Edge function to validate JWT token

This Lambda can be used in AWS CloudFront, to protect the assets in the S3 bucket. For each request to CloudFront (whether cached or not), it verifies that a valid JWT token is present in the request. The token can be passed in the 'Authorization' header (with prefix 'Bearer'), or specified in the query-string of the request.
