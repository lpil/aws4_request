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
  let assert Ok(request) =
    request.to("https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")
  let request =
    request
    |> request.set_header(
      "content-type",
      "application/x-www-form-urlencoded; charset=utf-8",
    )
    |> request.set_method(http.Get)
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.signer(
      access_key_id: "AKIDEXAMPLE",
      secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      region: "us-east-1",
      service: "iam",
    )
    |> aws4_request.with_date_time(date_time)
    |> aws4_request.sign_bits(request)

  // Now send the signed request with a HTTP client
  httpc.send_bit(signed_request)
}
```

Further documentation can be found at <https://hexdocs.pm/aws4_request>.
