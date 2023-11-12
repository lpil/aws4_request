-module(aws4_request_ffi).

-export([authorization_header/1]).

-record(credentials, {
    access_key_id :: binary(),
    secret_access_key :: binary(),
    region :: binary()
}).

-record(request, {
    credentials :: #credentials{},
    service :: binary(), % "s3"
    http_method :: atom(), % get
    host :: binary(), % Bucket ++ ".s3.amazonaws.com"
    path :: binary(), % "/" ++ ObjectKey,
    query :: binary() % "wibble=wobble&bibble=babble"
}).




authorization_header(Request) ->
    #request{
        credentials = Credentials,
        service = Service,
        http_method = HttpMethod,
        host = Host,
        path = Path,
        query = Query
    } = Request,
    #credentials{
        access_key_id = AccessKeyId,
        secret_access_key = SecretKey,
        region = Region
    } = Credentials,

    % TODO: timestamp
    {{Year, Month, Day}, {Hour, Minute, Second}} = calendar:universal_time(),
    Date = unicode:characters_to_binary(io_lib:format(
        "~4..0w~2..0w~2..0w", [Year, Month, Day]
    )),
    Timestamp = unicode:characters_to_binary(io_lib:format(
        "~sT~2..0w~2..0w~2..0wZ", [Date, Hour, Minute, Second]
    )),

    % Step 3: Create the canonical request
    CanonicalRequest = HttpMethod ++ "\n/" ++ Path ++ "\n" ++ Query ++ "\nhost:" ++ Host ++ "\nx-amz-date:" ++ Timestamp ++ "\nx-amz-security-token:\nUNSIGNED-PAYLOAD",

    % Step 4: Create the string to sign
    Scope = Date ++ "/" ++ Region ++ "/" ++ Service ++ "/aws4_request",
    StringToSign = "AWS4-HMAC-SHA256\n" ++ Timestamp ++ "\n" ++ Scope ++ "\n" ++ crypto:sha256(CanonicalRequest),

    % Step 5: Generate the signing key
    KDate = crypto:mac(sha256, "AWS4" ++ SecretKey, Timestamp),
    KRegion = crypto:mac(sha256, KDate, Region),
    KService = crypto:mac(sha256, KRegion, Service),
    KSigning = crypto:mac(sha256, KService, "aws4_request"),

    % Step 6: Calculate the signature
    Signature = crypto:mac(sha256, KSigning, StringToSign),
    SignatureHex = binary:bin_to_list(crypto:encode16(Signature)),

    % Step 7: Create the authorization header
    AuthorizationHeader = "AWS4-HMAC-SHA256 Credential=" ++ AccessKeyId ++ "/" ++ Scope ++ ", SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=" ++ SignatureHex,

    AuthorizationHeader.
