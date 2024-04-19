import aws4_request
import gleam/http
import gleam/http/request
import gleeunit
import gleeunit/should

pub fn main() {
  gleeunit.main()
}

const access_key_id = "AKIDEXAMPLE"

const secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

const region = "us-east-1"

const service = "iam"

const date_time = #(#(2015, 8, 30), #(12, 36, 0))

const url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"

const input_headers = [
  #("host", "iam.amazonaws.com"),
  #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
]

pub fn sign_bits_test() {
  let assert Ok(request) = request.to(url)
  let request = request.Request(..request, headers: input_headers)
  let request =
    request
    |> request.set_method(http.Get)
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.sign_bits(
      request,
      date_time,
      access_key_id,
      secret_access_key,
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
  validate_request(request, signed_request, expected_headers)
}

pub fn sign_string_test() {
  let assert Ok(request) = request.to(url)
  let request = request.Request(..request, headers: input_headers)
  let request =
    request
    |> request.set_method(http.Get)
    |> request.set_body("")

  let signed_request =
    aws4_request.sign_string(
      request,
      date_time,
      access_key_id,
      secret_access_key,
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
  validate_request(request, signed_request, expected_headers)
}

fn validate_request(
  request: request.Request(a),
  signed_request: request.Request(a),
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
