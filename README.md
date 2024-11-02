# go-oidc4vc-demo

GO-OIDC4VC-DEMO is a demonstration project showcasing the integration of OpenID Connect (OIDC) with Verifiable Credentials (VCs) using Go. It provides a set of services that facilitate the issuance, verification, and management of digital identities and credentials.

## Starting the Services with Docker Compose

To quickly start all services for the GO-OIDC4VC-DEMO project using Docker Compose, follow these steps:

### Prerequisites

- Ensure that you have [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/) installed on your machine.

### Instructions

1. **Clone the Repository (if you haven't already):**

   ```bash
   git clone https://github.com/tumy-tech-labs/go-oidc4vc-demo
   cd go-oidc4vc-demo
   ```

### Start the services

```bash
docker-compose up -d --build
```