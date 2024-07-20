# ASPI SNAP Utilities

Utilty based on Standard Nasional API Pembayaran (Indonesia nationals payment standard API).
https://www.aspi-indonesia.or.id/standar-dan-layanan/standar-open-api-pembayaran-indonesia-snap/

## Features:
- Generate signature
  - Symmetric
  - Asymmetric
- Generate timestamp (for `X-TIMESTAMP` request header) based on current date time.
- Encode request body

## Example:

```java
String timestamp = SnapAspiUtils.generateTimestamp();
String method = "POST";
String uri = "/v1.0/account-inquiry-external";
String accessToken = "R04XSUbnm1GXNmDiXx9ysWMpFWBr";
String requestBody = SnapAspiUtils.encodeRequestBody("{\"data\":\"payload content\"}");
String privateKeyString = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAgwi2Ay8pwSKAgctKaL81qvBvsnUnje9E4LZj7+897FblfoBk5NhOvM3X2nL/gNZJdRMIs7P/jyldLIA8HRU9IwIDAQABAkADA9xMTnWDgCu80NSxfFTbzhSD4rY6Sdsn4IqEJtkh6wUO7NZCjX1M4p7fME8UbbvCdba0eSas++3nrWBHmaBhAiEA/1Gd9KMoyOO/CEoVoKDLxO8/MvI6QXU9hrArEz/BA2cCIQCDYjUUsGmbLJgE5r4WxWuW0v0PGnR0ZuPgvPbHmGv+5QIhAKpHCI1rc3vnSDSDFEF4e+3vkbqsieW2Bz6Yp2HDFzrpAiAFEu7f3KxHbOJ2Ff8zW+56xa02PxxOPocAb+vL64wILQIgW6iC9HMTomG6QrRspuNjlm9ynjF5uxjqaTYWdBGr3EA=";
String stringToSign = SnapAspiUtils.generateStringToSign(method, uri, requestBody, accessToken, timestamp);
System.out.println(stringToSign);

PrivateKey privateKey = SnapAspiUtils.privateKeyFromString(privateKeyString);

// generate signature
String signature = SnapAspiUtils.generateSignature(stringToSign, privateKey);
```

## TODO:
- Integrate as HttpClient interceptor
- Integrate as OKHttp interceptor
- Integrate as spring bean
