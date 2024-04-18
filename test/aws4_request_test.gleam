//// Unit tests for aws4_request.

import aws4_request
import gleam/http
import gleam/http/request
import gleam/option.{None, Some}
import gleeunit
import gleeunit/should

/// Run tests.
pub fn main() {
  gleeunit.main()
}

/// Common mock values used in all tests.
const access_key_id = "AKIDEXAMPLE"

const secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

const session_token = "SESSIONTOKENEXAMPLE"

const region = "us-east-1"

const service = "iam"

const date_time = #(#(2015, 8, 30), #(12, 36, 0))

const url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"

const input_headers = [
  #("host", "iam.amazonaws.com"),
  #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
]

/// Test signing a Request(BitArray) without a token.
pub fn sign_bits_test() {
  let request =
    get_request()
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.sign_bits(
      request,
      date_time,
      access_key_id,
      secret_access_key,
      None,
      region,
      service,
    )
  let expected_headers = [
    #(
      "authorization",
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,Signature=dd479fa8a80364edf2119ec24bebde66712ee9c9cb2b0d92eb3ab9ccdc0c3947",
    ),
    #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
    #("host", "iam.amazonaws.com"),
    #(
      "x-amz-content-sha256",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    #("x-amz-date", "20150830T123600Z"),
  ]
  check_request(request, signed_request, expected_headers)
}

/// Test signing a Request(String) without a token.
pub fn sign_string_test() {
  let request =
    get_request()
    |> request.set_body("")

  let signed_request =
    aws4_request.sign_string(
      request,
      date_time,
      access_key_id,
      secret_access_key,
      None,
      region,
      service,
    )
  let expected_headers = [
    #(
      "authorization",
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,Signature=dd479fa8a80364edf2119ec24bebde66712ee9c9cb2b0d92eb3ab9ccdc0c3947",
    ),
    #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
    #("host", "iam.amazonaws.com"),
    #(
      "x-amz-content-sha256",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    #("x-amz-date", "20150830T123600Z"),
  ]
  check_request(request, signed_request, expected_headers)
}

/// Test signing a Request(BitArray) with a token.
pub fn sign_bits_with_token_test() {
  let request =
    get_request()
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.sign_bits(
      request,
      date_time,
      access_key_id,
      secret_access_key,
      Some(session_token),
      region,
      service,
    )
  let expected_headers = [
    #(
      "authorization",
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature=015a22644e1b67bb6fcf5ce9bf5ee1c4a9300ce940a2a709d6df19f768f3500f",
    ),
    #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
    #("host", "iam.amazonaws.com"),
    #(
      "x-amz-content-sha256",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    #("x-amz-date", "20150830T123600Z"),
    #("x-amz-security-token", session_token),
  ]
  check_request(request, signed_request, expected_headers)
}

/// Test signing a Request(String) with a token.
pub fn sign_string_with_token_test() {
  let request =
    get_request()
    |> request.set_body("")

  let signed_request =
    aws4_request.sign_string(
      request,
      date_time,
      access_key_id,
      secret_access_key,
      Some(session_token),
      region,
      service,
    )
  let expected_headers = [
    #(
      "authorization",
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature=015a22644e1b67bb6fcf5ce9bf5ee1c4a9300ce940a2a709d6df19f768f3500f",
    ),
    #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
    #("host", "iam.amazonaws.com"),
    #(
      "x-amz-content-sha256",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    #("x-amz-date", "20150830T123600Z"),
    #("x-amz-security-token", session_token),
  ]
  check_request(request, signed_request, expected_headers)
}

fn get_request() -> request.Request(_) {
  let assert Ok(request) = request.to(url)
  let request = request.Request(..request, headers: input_headers)
  request
  |> request.set_method(http.Get)
}

fn check_request(
  request: request.Request(_),
  signed_request: request.Request(_),
  expected_headers: List(#(String, String)),
) {
  signed_request.body
  |> should.equal(request.body)

  signed_request.method
  |> should.equal(request.method)

  signed_request.path
  |> should.equal(request.path)

  signed_request.query
  |> should.equal(request.query)

  signed_request.scheme
  |> should.equal(request.scheme)

  signed_request.host
  |> should.equal(request.host)

  signed_request.port
  |> should.equal(request.port)

  signed_request.headers
  |> should.equal(expected_headers)
}
