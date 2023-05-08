# sigstore-lab

This repo contains the helm chart and the instructions for building a secure supply chain lab built in [SigStore](https://www.sigstore.dev/) and [OpenUnison](https://openunison.github.io/).  The lab is a multi-tenant system that uses a GitHub repository to store all user projects and execute build scripts.  In order to build this lab you will need:

1. Kubernetes cluster
2. An NGINX Ingress controller with a `LoadBalancer` setup
3. An AWS Account (for storing images in ECR)
4. **Recommended** - TLS wildcard certificate
5. A GitHub Organziation to host participant repositories
6. The SigStore Policy Controller

# Amazon Web Services

In an AWS account, create a public Elastic Container Registry (ECR) for storing generated containers.

Next, [create an IAM identity provider for GitHub](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).

Next, create an IAM policy called `sigstorelab` with the the following JSON.   Make the following replacements:

| Item | Value |
| ---- | ----- |
| `ACCOUNT` | AWS Account number |
| `REGISTRY_NAME` | The name of your ECR registry |
| `GITHUB_ORG` | The name of your GitHub org |



```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr-public:DescribeImageTags",
                "ecr-public:DescribeImages",
                "ecr-public:PutRepositoryCatalogData",
                "ecr-public:UploadLayerPart",
                "ecr-public:DeleteRepositoryPolicy",
                "ecr-public:UntagResource",
                "ecr-public:CreateRepository",
                "ecr-public:DescribeRegistries",
                "ecr-public:GetRepositoryCatalogData",
                "ecr-public:BatchDeleteImage",
                "ecr-public:TagResource",
                "ecr-public:CompleteLayerUpload",
                "ecr-public:GetRepositoryPolicy",
                "ecr-public:DeleteRepository",
                "ecr-public:InitiateLayerUpload",
                "ecr-public:DescribeRepositories",
                "ecr-public:PutImage",
                "ecr-public:GetRegistryCatalogData",
                "ecr-public:ListTagsForResource",
                "ecr-public:PutRegistryCatalogData",
                "ecr-public:BatchCheckLayerAvailability",
                "ecr-public:InitiateLayerUpload"
            ],
            "Resource": "arn:aws:ecr-public::ACCOUNT:repository/REGISTRY_NAME",
            "Condition": {
                "StringLike": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:GITHUB_ORG/*-workshop-application:ref:refs/heads/main"
                }
            }
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "ecr-public:GetAuthorizationToken",
                "sts:GetServiceBearerToken"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:GITHUB_ORG/*-workshop-application:ref:refs/heads/main"
                }
            }
        }
    ]
}
```

Next, create a *Role* for the OIDC identity provider you previously created.  Attach the `sigstore` *Policy* to the *Role*.

# Scratchpad Container

You'll need to build the scratchpad container that is used by participants.  It's suggested to build and push to the AWS repo so you don't have issues with Dockerhub pull request limits.

```bash
cd scratchpad
docker buildx build --platform linux/amd64  --tag public.ecr.aws/REPO/scratchpad:signed --no-cache .
docker push public.ecr.aws/REPO/scratchpad:signed
COSIGN_EXPERIMENTAL=1 cosign sign public.ecr.aws/REPO/scratchpad:signed
```

# Pause Container

The lab's manifests use the pause container as a placeholder, but it's not signed by the Kubernetes project.  You'll need to pull it, push it into your AWS public ECR and sign it:

```bash
docker pull registry.k8s.io/pause
docker tag registry.k8s.io/pause public.ecr.aws/REPO/pause:signed
docker push public.ecr.aws/REPO/pause:signed
COSIGN_EXPERIMENTAL=1 cosign sign public.ecr.aws/REPO/pause:signed
```

# Kubernetes Cluster

First get your cluster up and running.  It's best to use a wild card certificate for your cluster.  Assuming you created the certicate as the `Secret` *wildcard-tls* in the *ingress-nginx* namespace, this will update your NGINX configuration to use it as the default certificate:

```
kubectl patch deployments.apps ingress-nginx-controller --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--default-ssl-certificate=ingress-nginx/wildcard-tls" }]' -n ingress-nginx
```

Create the namespace `openunison`:

```
kubectl create ns openunison
```

# SigStore Policy Controller

First, deploy the policy controller admission controller:

```
helm repo add sigstore https://sigstore.github.io/helm-charts
helm repo update
kubectl create namespace cosign-system
helm install policy-controller -n cosign-system sigstore/policy-controller --devel
```

Next, we'll create a simple policy that requires an image to be signed with the "keyless" authority for sigstore, create with the following:

```yaml
apiVersion: policy.sigstore.dev/v1alpha1
kind: ClusterImagePolicy
metadata:
  name: keyless
spec:
  images:
  - glob: "**"
  authorities:
  - name: keyless
    keyless:
      url: "https://fulcio.sigstore.dev"
```

# ArgoCD

ArgoCD is used to synchronize manifests from GitHub into participant's namespaces.  First, deploy ArgoCD.  

First, update these manifests for your host and deploy:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server-http-ingress
  namespace: argocd
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
spec:
  rules:
  - http:
      paths:
      - backend:
          service:
            name: argo-cd-argocd-server
            port: 
              name: http
        path: "/"
        pathType: Prefix
    host: argocd.civosigstore.tremolo.dev
  tls:
  - hosts:
    - argocd.civosigstore.tremolo.dev
    secretName: argocd-web-tls-none
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server-grpc-ingress
  namespace: argocd
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
spec:
  rules:
  - http:
      paths:
      - backend:
          service:
            name: argo-cd-argocd-server
            port: 
              name: https
        path: "/"
        pathType: Prefix
    host: grpc-argocd.civosigstore.tremolo.dev
  tls:
  - hosts:
    - grpc-argocd.civosigstore.tremolo.dev
    secretName: argocd-grpc-tls-none
```

Next, patch the ArgoCD deployment to work with the ingress controller:

```
kubectl patch deployments argocd-server -n argocd -p '{"spec":{"template":{"spec":{"containers":[{"name":"server","command":["argocd-server","--staticassets","/shared/app","--repo-server","argocd-repo-server:8081","--logformat","text","--loglevel","info","--redis","argocd-redis:6379","--insecure"]}]}}}}'
```

Finally, patch the ArgoCD configuration to allow the *admin* user to use an API key:

```
kubectl patch configmap argocd-cm -n argocd -p '{"data":{"accounts.admin":"apiKey, login"}}'
```

Once the pods are restarted, you should be able to login directly to ArgoCD.

Next, we need to create a token that will be used by OpenUnison to automate ArgoCD.  

First, login to the admin account from the cli:

```
argocd login grpc-argocd.civosigstore.tremolo.dev
```

Then generate a JWT for the admin account:

```
mkdir /tmp/argocd
argocd account generate-token > /tmp/argocd/ARGOCD_TOKEN
kubectl create secret generic argocd-token --from-file=/tmp/argocd -n openunison
rm -rf /tmp/argocd
```

Lastly, we need to configure ArgoCD for SSO with OpenUnison:

```
kubectl patch configmap argocd-cm -n argocd -p '{"data":{"url":"https://argocd.civosigstore.tremolo.dev","oidc.config":"name: OpenUnison\nissuer: https://ou.civosigstore.tremolo.dev/auth/idp/k8sIdp\nclientID: argocd\nrequestedScopes: [\"openid\",\"profile\",\"email\",\"groups\"]"}}'
kubectl patch configmap argocd-rbac-cm -p '{"data":{"policy.csv":"g, \"k8s-cluster-k8s-administrators-internal\", role:admin"}}' -n argocd
```

# OpenUnison

OpenUnison is the orchestration system between GitHub, Kubernetes, and ArgoCD.  It will provide secure access to the cluster via both the kubectl cli and the Kubernetes dashboard.  Before we can get started deploying OpenUnison, we need to configure GitHub to provide authentication and setup a Github application.  First, create a GitHub organization that will be used to store participents repositories.

OpenUnison, when used as an automation portal, needs an SMTP server to be able to send notifications.  If you don't have an SMTP server or don't want to configure one, you can use the [SMTP blackhole container](https://github.com/TremoloSecurity/smtp-blackhole). 

With SMTP configured, the next step is to setup your database.  This configuration assumes MariaDB but any of [OpenUnison's supported databases can be used](https://openunison.github.io/namespace_as_a_service/#databases).  If you don't have a database readily available, you can use this [example MariaDB](https://raw.githubusercontent.com/OpenUnison/kubeconeu/main/src/main/yaml/mariadb_k8s.yaml).  Create a database called `unison` with the appropriate credentials to access it.

Next, deploy the kubernetes dashboard:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
```

Once your organization is created, setup an [OAuth application](https://openunison.github.io/deployauth/#github) per the instructions on the OpenUnison documentation site.  For your **Authorization callback URL**, specifcy `https://ou.civosigstore.tremolo.dev/auth/github`, replacing `ou.civosigstore.tremolo.dev` with your own host name. Generate a new client secret and place it in a file you'll use to deploy OpenUnison.

Once your OAuth App is created, create a team in the organization called `lap-participants`.  This will be used to enable access to your organization.

Next, we'll need to create a [GitHub App](https://openunison.github.io/applications/github/#creating-a-github-provisioning-target) so OpenUnison can create resources in our organization.  Once you create the app, download the key into a directory and name the key `openunison.pem`.  Next, create a `Secret` from this file for OpenUnison:

```
kubectl create secret generic githubapp --from-file=/path/to/github-key/ -n openunison
```

We're now able to deploy OpenUnison.  Update the [openunison values file](yaml/openunison-values.yaml):

| Line | Change |
| ---- | ------ |
| 2 - 4 | Update the hosts for your domain |
| 70 | Get the client id from the OAuth application your created in GitHub |
| 71 | The name of your orgnaization followed by `/`.  For instance `CivoNavigateSigstore/` |
| 119 - 124 | Update for your database configuration.  See the [OpenUnison Namespace as a Service](https://openunison.github.io/namespace_as_a_service/#databases) docs for details. |
| 126 - 131 | Update for your SMTP settings if using an external SMTP service |
| 135 | The app id from the GitHub App created above |
| 136 | The name of the GitHub organization that participant repositories will be in |
| 138 | The DNS domain for your SigStore lab |
| 139 | The image URL of the scratchpad container that was created and signed above |
| 140 | The image URL of the pause container that was signed above |
| 142 | The AWS identity provider role created above to store the sigstore policy |
| 143 | The name of the repository that will store all images participant images as tags |
| 144 | A base64 encoded PNG file for the github orgnaization that is 210 pixels wide and 240 pixels high |

With the values file created, the next step is to deploy OpenUnison using the *ouctl* tool.  Include the the sigstore_lab chart included in this repository:

```bash
ouctl install-auth-portal --additional-helm-charts=sigstore-lab=/path/to/sigstore-lab/sigstore_lab -s /path/to/github -b /path/to/db -t /tmp/path/to/smtp ~/git/sigstore-lab/yaml/openunison-values.yaml
```

