# SDA Uppmax Integration

## Introduction

The SDA Uppmax Integration is a service used in the Sensitive Data Archive project. The goal of the project is to automate the submission of sensitive data through Bianca. Specifically, the service contains one endpoint used for
- Authenticating the user (initially uppmax) and allowing to perform further actions
- Creation of token and s3config file for a specified SDA user

## Endpoint Request

Currently one endpoint is available when running the service, described with curl:
```bash
curl --location --request POST '<base_url>:8080/token' \
--header 'Authorization: Basic <username>:<password>' \
--header 'Content-Type: text/plain' \
--data-raw '{
    "swamid": "<swamid>",
    "projectid": "<projectid>"
}'
```

The `token` endpoint requires basic auth and the allowed credentials can be defined in the configuration file `config.yaml`.

## Endpoint Response

The `token` endpoint returns the following structure, if the user is authorised to access the `<projectid>` requested:

```bash
{
    "swamid": "<swamid>",
    "projectid": "<projectid>",
    "request_time": "<request_time>",
    "expiration": "<expiration>",
    "s3config": "<base64_encoded_s3config>"
}
```
The `s3config` file is base64 encoded in the response described above.

## How to run
The app can be confiugured via ENVs or via a yaml file, an example config file is located in the root of this repo.
In order to run the service locally install [golang](https://go.dev/learn/), navigate to the root of the repository and run
```bash
go run .
```
The following configuration is required to run the service
| Variable     | Description  | Example |
| ------------ | :----------: | ------: |
| iss | JWT issuer | `https://login.test.ega.nbis.se` |
| pathToKey | Path to private key | `../my_key.pem` |
| uppmaxUsername | Username for token requester | `some_username` |
| uppmaxPassword | Password for token requester | `some_password` |
| s3url | The URL to the s3Inbox | `inbox.test.ega.nbis.se` |
| expirationDays | Token validity duration in days | 14 |