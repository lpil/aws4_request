import aws4_request
import gleam/http
import gleam/http/request
import gleeunit
import gleeunit/should

pub fn main() {
  gleeunit.main()
}

pub fn sign_test() {
  let access_key_id = "AKIDEXAMPLE"
  let secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
  let region = "us-east-1"
  let service = "iam"
  let date_time = #(#(2015, 8, 30), #(12, 36, 0))
  let url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
  let input_headers = [
    #("host", "iam.amazonaws.com"),
    #("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
  ]

  let assert Ok(request) = request.to(url)
  let request = request.Request(..request, headers: input_headers)
  let request =
    request
    |> request.set_method(http.Get)
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.signer(access_key_id:, secret_access_key:, region:, service:)
    |> aws4_request.with_date_time(date_time)
    |> aws4_request.sign_bits(request)

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
  |> should.equal([
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
  ])
}

pub fn sign_no_path_test() {
  let access_key_id = "minioadmin"
  let secret_access_key = "miniopass"
  let region = "us-east-1"
  let service = "s3"
  let date_time = #(#(2024, 08, 29), #(10, 33, 12))
  let url = "http://localhost:9000"
  let input_headers = [#("host", "localhost:9000")]

  let assert Ok(request) = request.to(url)
  let request = request.Request(..request, headers: input_headers)
  let request =
    request
    |> request.set_method(http.Get)
    |> request.set_body(<<>>)

  let signed_request =
    aws4_request.signer(access_key_id:, secret_access_key:, region:, service:)
    |> aws4_request.with_date_time(date_time)
    |> aws4_request.sign_bits(request)

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

  request.get_header(signed_request, "authorization")
  |> should.be_ok
  |> should.equal(
    "AWS4-HMAC-SHA256 Credential=minioadmin/20240829/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=524a2bfacb1bb9636a178879dac21e955479f4a2c01b00466d1a19568e5cc2a0",
  )

  request.get_header(signed_request, "host")
  |> should.be_ok
  |> should.equal("localhost:9000")

  request.get_header(signed_request, "x-amz-date")
  |> should.be_ok
  |> should.equal("20240829T103312Z")
}
