# Authentication Architecture

## Code architecture

This code is written in using the sans-io pattern. which means that the code it self is not handling any IO, it is responsible for the business logic and the IO is handled by the caller.

## Hierarchy

1. Authentication to the Auki network
2. Authentication to the Discovery service
3. Authentication to a specific domain.

Each token in the hierarchy has a different purpose and scope and depends on the previous token.

## Authentication to the Auki network

First step to being able to communicate with the Auki network is to authenticate to the Auki network.
This can be done with different methods:

- Username and password
- AppKey and AppSecret
- Opaque token (enterprise specific)

This token is crucial for all other authentication steps.

## Authentication to the Discovery service

The Discovery service is a service that is used to discover nodes and domains in the Auki network.
It is used to find nodes that are online and to get the information about the nodes and domains.
The authentication to the Discovery service is done using the token issued by the Auki network.
The Discovery service will use the token to authenticate the request and will return a list of nodes and domains that are online.

## Authentication to a specific domain

The authentication to a specific domain is done using the token issued by the Auki network.
The domain is authenticated using the token and the domain name.
The domain name is used to identify the domain and the token is used to authenticate the request.
