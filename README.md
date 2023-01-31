# SDA Uppmax Integration

## Introduction

The SDA Uppmax Integration is a service used in the Sensitive Data Archive project. The goal of the project is to automate the submission of sensitive data through Bianca. Specifically, the service contains one endpoint used for
- Authenticating the user (initially uppmax) and allowing to perform further actions
- Creation of token and s3config file for a specified SDA user

## Endpoint Request

Currently one endpoint is available when running the service, described with curl:
```bash
curl --location --request POST '<base_url>:8080/token' \
--header 'Authorization: Basic <basic_auth_from_creds>' \
--header 'Content-Type: text/plain' \
--data-raw '{
    "swamid": "<swamid>",
    "projectid": "<projectid>"
}'
```
where `<basic_auth_from_creds>` is the base64 encoded string `username:password`.

The `token` endpoint requires basic auth and the allowed credentials can be defined in the configuration file `config.yaml`.

ex.
```bash
$ curl --location --request POST 'localhost:8080/token' \
       --header "Authorization: Basic $(printf 'uppmax:uppmax' | base64)" \
       --header 'Content-Type: text/plain' \
       --data-raw '{"swamid": "test@sda.dev", "projectid": "sda001"}'
```
can be used in the docker compose development environment.

## Endpoint Response

The `token` endpoint returns the following structure, if the user is authorised to access the `<projectid>` requested:

```bash
{
    "swamid": "<swamid>",
    "projectid": "<projectid>",
    "request_time": "<request_time>",
    "expiration": "<expiration>",
    "s3config": "<base64_encoded_s3config>"
    "crypt4gh_key": "<base64_encoded_crypt4gh_pub_key>"
}
```
The `s3config` file is base64 encoded in the response described above.

## How to run
The app can be configured via ENVs or via a yaml file, an example config file is located in the root of this repo.
In order to run the service locally install [golang](https://go.dev/learn/), navigate to the root of the repository and run
```bash
go run .
```
The following configuration is required to run the service
| Variable     | Description  | Example |
| ------------ | :----------: | ------: |
| crypt4ghKey | Path to public key | `../sda_crypt4gh.pub` |
| expirationDays | Token validity duration in days | 14 |
| iss | JWT issuer | `https://issuer.example.com` |
| jwtKey | Path to private key | `../my_key.pub` |
| s3url | The URL to the s3Inbox | `s3.example.com` |
| uppmaxUsername | Username for token requester | `some_username` |
| uppmaxPassword | Password for token requester | `some_password` |

## How to deploy
To deploy the service without using vault (e.g. using minikube) in the `lega` namespace, build and push the image using
```sh
docker build -t harbor.nbis.se/uppmax/integration .
docker push harbor.nbis.se/uppmax/integration
```
Create a secret using
```sh
kubectl -n lega create secret generic <secret_name> --from-file=<key_path> --from-file=<public_key_path>
```
The names of the files should be added in the values files in `jwt.keyName` and `crypt4ghKey` respectively in the `values.yaml`. Populate the rest of the `values.yaml` file with the correct values and then install using the local copy of the helm charts with
```sh
helm install --namespace <namespace_name> uppmax charts/uppmax-integration
```
while to install using the published charts use
```sh
helm repo add uppmax https://nbisweden.github.io/sda-uppmax-integration/
helm repo update
helm install --namespace <namespace_name> uppmax charts/uppmax-integration
```
