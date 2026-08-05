# IKB42603 Cloud Computing Security Essentials
## Lab 0: Environment Setup Report

**Name:** Jim Moriarty

### Objective
To set up and configure the local environment required for the Cloud Computing Security Essentials labs, ensuring all necessary tools (Docker, AWS CLI, Kubernetes, and helper tools) are properly installed and ready for subsequent exercises.

### Learning Outcomes
- Successfully install and verify Docker for container management.
- Configure AWS CLI v2 to interact with local cloud emulators like LocalStack.
- Set up a local Kubernetes cluster using `kind` and `kubectl`.
- Install essential helper tools including OpenSSL and oathtool for security-related tasks.
- Gain hands-on experience in initializing and testing a simulated cloud and container orchestration environment.

### Environment
- **Operating System:** Linux
- **Tools:** Docker, AWS CLI v2, kind, kubectl, OpenSSL, oathtool, Trivy, LocalStack

### Step-by-Step Implementation

#### 1. Install Docker
Docker is required to run containers and the LocalStack cloud simulator.
- Installed Docker on the system.
- Verified the installation by checking the version and running the `hello-world` container.

#### 2. Install AWS CLI v2
AWS CLI v2 is used to send AWS commands to the LocalStack environment locally.
- Installed AWS CLI v2.
- Verified the installation by checking the version (`aws --version`).

#### 3. Install kind & kubectl
`kind` is used to run a local Kubernetes cluster inside Docker, and `kubectl` is the command-line tool to control the cluster.
- Installed `kind` and `kubectl`.
- Verified the installations by checking their respective versions (`kind --version` and `kubectl version --client`).

#### 4. Helper Tools (OpenSSL, oathtool, Trivy)
These helper tools are required for various lab tasks such as encryption, MFA/TOTP code generation, and vulnerability scanning.
- Installed and verified OpenSSL and oathtool. (Trivy is run via Docker).

#### 5. Start & Stop the Lab Environment
The lab environment consists of LocalStack and a local Kubernetes cluster.
- Started LocalStack on port 4566 and checked its health status.
- Created a Kubernetes cluster named `ccse` using `kind`.
- Verified the cluster was up using `kubectl cluster-info` and `kubectl get nodes`.

#### 6. One-Time AWS CLI Configuration
Set up dummy credentials for the AWS CLI so that it can interact with LocalStack without prompting for configuration.
- Configured dummy `aws_access_key_id` and `aws_secret_access_key`.
- Set the default region to `us-east-1`.
- Tested the connection to LocalStack using the `--endpoint-url` flag to get caller identity.

### Commands Used
- `docker --version`: Checks the installed Docker version.
- `docker run hello-world`: Verifies Docker can pull and run images.
- `aws --version`: Checks the installed AWS CLI version.
- `kind --version`: Verifies the installation of kind.
- `kubectl version --client`: Verifies the installation of kubectl.
- `kubectl cluster-info`: Displays information about the Kubernetes cluster.
- `kubectl get nodes`: Lists the nodes in the local Kubernetes cluster.
- `aws configure`: Prompts for AWS credentials configuration.
- `aws sts get-caller-identity --endpoint-url=http://localhost:4566`: Tests AWS CLI connectivity to LocalStack.

### Screenshots

**Step 1 - Docker Installation:**  
![Step 1 - Docker Installation](./1.png)

**Step 1.2 - Docker Verification:**  
![Step 1.2 - Docker Verification](./1.2.png)

**Step 2 - AWS CLI v2:**  
![Step 2 - AWS CLI v2](./2.png)

**Step 3 - kind & kubectl:**  
![Step 3 - kind & kubectl](./3.png)

**Step 4 - Helper Tools:**  
![Step 4 - Helper Tools](./4.png)

**Step 5 - Start Environment:**  
![Step 5 - Start Environment](./5.png)

**Step 6 - AWS CLI Configuration:**  
![Step 6 - AWS CLI Configuration](./6.png)

### Challenges Encountered
- Ensuring the LocalStack service is fully initialized before attempting to connect with AWS CLI.
- Verifying the correct Docker permissions to allow smooth execution of container workloads without requiring root privileges for every command.

### Lessons Learned
- Setting up a local environment like LocalStack and a local Kubernetes cluster provides an excellent, cost-free method for testing cloud and container deployments securely.
- Proper configuration of CLI tools using dummy credentials is a crucial step for working safely with emulators without risking real cloud resources.
- Validating the successful setup through verification commands avoids troubleshooting downstream lab steps.

### References
- [Docker Documentation](https://docs.docker.com/)
- [AWS CLI v2 Documentation](https://docs.aws.amazon.com/cli/)
- [LocalStack Documentation](https://docs.localstack.cloud/)
- [kind (Kubernetes in Docker) Documentation](https://kind.sigs.k8s.io/)
- [Kubectl Documentation](https://kubernetes.io/docs/reference/kubectl/)
