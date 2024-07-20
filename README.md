# ASPI SNAP Utilities

Utilty based on Standard Nasional API Pembayaran (Indonesia nationals payment standard API).
https://www.aspi-indonesia.or.id/standar-dan-layanan/standar-open-api-pembayaran-indonesia-snap/

## Features:
- Generate signature
  - Symmetric
  - TODO: Asymmetric
- Generate timestamp (for `X-TIMESTAMP` request header) based on current date time.
- Encode request body

## TODO:
- Integrate as HttpClient interceptor
- Integrate as OKHttp interceptor
- Integrate as spring bean
