# aws4_request

An AWS Signature Version 4 client implementation, useful for making
authenticated requests to services such as AWS S3.

[![Package Version](https://img.shields.io/hexpm/v/aws4_request)](https://hex.pm/packages/aws4_request)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/aws4_request/)

```sh
gleam add aws4_request
```
```gleam
import gleam/httpc
import aws4_request
import gleam/http/request

pub fn main() {
  let access_key_id = "AKIDEXAMPLE"
  let secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
  let region = "us-east-1"
  let service = "iam"
  let date_time = #(#(2015, 8, 30), #(12, 36, 0))
  let assert Ok(request) =
    request.to("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
  let request = request.Request(..request, headers: [
    #("host", "iam.amazonaws.com"),
    #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
  ])
  let request =
    request
    |> request.set_method(http.Get)
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.sign(
      request,
      date_time,
      access_key_id,
      secret_access_key,
      region,
      service,
    )

  // Now send the signed request with a HTTP client
  httpc.send(signed_request)
}
```

Further documentation can be found at <https://hexdocs.pm/buckets>.
