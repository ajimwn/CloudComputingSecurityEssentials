# IKB42603 Cloud Computing Security Essentials
## Lab 1: Account Security and IAM Report

**Name:** Jim Moriarty

### Objective
To understand and implement cloud account security, identity governance, and the principle of least privilege using LocalStack IAM and Kubernetes Role-Based Access Control (RBAC).

### Learning Outcomes
1. Stand up a local cloud lab using Docker and LocalStack (an AWS-compatible simulator).
2. Apply the principle of least privilege by replacing root usage with scoped IAM users, groups, and policies.
3. Create and test fine-grained permissions, distinguishing what an identity is *allowed* versus *denied* to do.
4. Implement and verify Role-Based Access Control (RBAC) in Kubernetes, the real enforcement engine.
5. Audit identities and reason about MFA, access keys, and credential hygiene.

### Environment
- **Operating System:** Linux
- **Tools:** Docker, AWS CLI v2, kind, kubectl, LocalStack

### Step-by-Step Implementation

#### Session A: Cloud Identity with LocalStack
1. **One-Time Environment Setup:** Verified Docker and started LocalStack in a container. Configured the AWS CLI with dummy credentials to point at the LocalStack endpoint (`http://localhost:4566`).
2. **Task 1: Map the Cloud Identity Landscape:** 
   Completed the mapping of core cloud identity components:
   | Concept | AWS Term | Purpose |
   | :--- | :--- | :--- |
   | All-powerful owner | Root user | The original identity that has complete, unrestricted access to all AWS services and resources in the account. Should only be used for initial setup and billing. |
   | Human/app identity | IAM User | An entity that represents a person or application that interacts with AWS. It has long-term credentials like passwords or access keys. |
   | Permission bundle | IAM Policy | A JSON document that explicitly defines what actions are allowed or denied on which resources. |
   | Collection of users | IAM Group | A collection of IAM users. Policies attached to the group are automatically applied to all its members, making management scalable. |
   | Temporary identity | IAM Role | An identity with specific permissions that can be assumed by users, applications, or services for a limited time (short-lived credentials). |

3. **Task 2: Create a Least-Privilege Admin:** Created an IAM group `Admins` and attached the `AdministratorAccess` policy to it. Created a dedicated admin user (`CloudAdmin`) and added them to the group to replace root usage.
4. **Task 3: Enforce Least Privilege with a Scoped Policy:** Created an `Analyst` user and attached a scoped, read-only policy (`AmazonS3ReadOnlyAccess`). 
   *Explanation of Blast-Radius Reduction:* If the Analyst account were stolen, the damage is strictly limited to reading S3 data. Because of least privilege, the attacker cannot delete data, spin up expensive instances, or change passwords. This drastically reduces the "blast radius" compared to a compromised admin account.
5. **Task 4: Credential Hygiene & Access Keys:** Created an access key for the Analyst user for programmatic access, listed the keys, and practiced credential hygiene by rotating (deactivating) the access key.

#### Session B: Enforced Access Control with Kubernetes RBAC
6. **Setup Local Kubernetes Cluster:** Used `kind` to create a throwaway Kubernetes cluster named `ccse-lab1` and verified its status.
7. **Task 5: Separate Environments with Namespaces:** Created two separate Kubernetes namespaces: `dev` and `prod`.
8. **Task 6: Define a Role and Bind It:** Created a service account `dev-user` in the `dev` namespace. Created a Role `pod-reader` granting only get/list/watch permissions for pods in `dev`, and bound it to `dev-user` using a RoleBinding.
9. **Task 7: Test That Access Control Works:** Used `kubectl auth can-i` to test permissions.
   - `kubectl auth can-i list pods -n dev --as=$SA` -> **YES** (reading pods in dev is allowed)
   - `kubectl auth can-i delete pods -n dev --as=$SA` -> **NO** (deleting pods is not granted)
   - `kubectl auth can-i list pods -n prod --as=$SA` -> **NO** (the role does not extend to prod)
   *Authentication vs Authorization:* The service account successfully passes **authentication** (Kubernetes knows who `dev-user` is). However, it is blocked by **authorization** when attempting to delete pods or access `prod`, because the RoleBinding does not explicitly grant those permissions.

10. **Verification Command:**
    Output for `kubectl get rolebinding dev-user-binding -n dev -o yaml` is recorded to prove the cluster RBAC is in place. *(Note: The output is included in Screenshot 5 below).*

### Commands Used
- `docker run -d --name localstack -p 4566:4566 localstack/localstack`: Starts LocalStack.
- `aws --endpoint-url=http://localhost:4566 sts get-caller-identity`: Checks operating identity.
- `aws ... iam create-group --group-name Admins`: Creates an IAM group.
- `aws ... iam attach-group-policy`: Attaches a policy to a group.
- `aws ... iam create-user`: Creates an IAM user.
- `aws ... iam add-user-to-group`: Adds an IAM user to a group.
- `aws ... iam list-attached-user-policies`: Lists policies attached to a user.
- `aws ... iam update-access-key --status Inactive`: Rotates/deactivates an access key.
- `kind create cluster --name ccse-lab1`: Creates a local Kubernetes cluster.
- `kubectl create namespace dev`: Creates a Kubernetes namespace.
- `kubectl create serviceaccount dev-user -n dev`: Creates a service account.
- `kubectl create role` & `kubectl create rolebinding`: Sets up RBAC roles and bindings.
- `kubectl auth can-i`: Tests permissions for a specific action.

### Questions
- **Q1. Why is attaching policies to groups better than attaching them directly to users?**  
  Attaching policies to groups is highly scalable, manageable, and auditable. When a user changes roles, you simply move them between groups, and their permissions update automatically, preventing permission drift.
- **Q2. What is the difference between an IAM User and an IAM Role?**  
  An **IAM User** is a permanent identity with long-term credentials (like a password or access keys) representing a specific person or app. An **IAM Role** is a temporary identity with short-lived credentials that can be assumed by users or services on-the-fly.
- **Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.**  
  Least privilege ensures an identity only has the bare minimum permissions needed. The Analyst was given only `AmazonS3ReadOnlyAccess`. If compromised, the attacker can only read S3 data. They cannot delete resources, run costly instances, or escalate privileges, meaning the "blast radius" (the extent of potential damage) is severely limited.
- **Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?**  
  A **Role** defines a set of permissions (e.g., getting/listing pods) within a specific namespace—it dictates *what* can be done. A **RoleBinding** binds that Role to a subject (like a user or service account)—it dictates *who* can do it.
- **Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?**  
  It failed because its Role and RoleBinding were explicitly scoped only to the `dev` namespace. It demonstrates the **Principle of Least Privilege** and environment segmentation, ensuring identities cannot cross boundaries into unauthorized environments.

### Screenshots

**Task 1 - get-caller-identity:**  
Output of `sts get-caller-identity` showing the operating identity.
![Task 1 - get-caller-identity](./1.png)

**Task 2 - get-group Admins:**  
Output of `get-group Admins` showing the CloudAdmin user as a member.
![Task 2 - get-group Admins](./2.png)

**Task 3 - list-attached-user-policies:**  
Output of `list-attached-user-policies` for the Analyst showing only the read-only policy.
![Task 3 - list-attached-user-policies](./3.png)

**Task 4 & 5 - Credential Hygiene and Namespaces:**  
Output demonstrating access keys rotation and Kubernetes namespace creation.
![Task 4 & 5](./4.png)

**Task 6 & 7 - Kubernetes RBAC Enforcement:**  
The three `kubectl auth can-i` results (YES / NO / NO) and RoleBinding verification.
![Task 7 - kubectl auth can-i](./5.png)

### Challenges Encountered
- Mapping LocalStack simulated endpoints properly so that AWS CLI connects locally instead of trying to reach the actual AWS cloud.
- Ensuring `kind` cluster context is correctly configured for `kubectl` so that RBAC commands target the local environment rather than a remote server.
- Verifying exact syntax for `kubectl auth can-i` when masquerading as a specific service account.

### Lessons Learned
- **Cloud Identity Concepts:** Gained hands-on experience distinguishing between Root users, IAM Users, Policies, Groups, and Roles.
- **Group vs User Policies:** Learned that attaching policies to groups allows for scalable and auditable access control compared to direct user attachments.
- **Least Privilege (Blast Radius Reduction):** Saw firsthand how explicitly granting an Analyst only read-only access prevents widespread damage if credentials are leaked.
- **Kubernetes RBAC (Role vs RoleBinding):** Understood how Roles define permissions while RoleBindings assign them, ensuring identities can only interact with authorized namespaces.
- **Environment Segmentation:** Demonstrated how least privilege actively prevents unauthorized cross-environment access (e.g., stopping a dev account from altering prod).

### References
- Course lectures — Week 1 (Fundamentals), Week 2 (Security Architecture), Week 5 (Access Control), Week 7 (Identity Management).
- [AWS CLI v2 Documentation](https://docs.aws.amazon.com/cli/)
- [LocalStack Documentation](https://docs.localstack.cloud/)
- [kind (Kubernetes in Docker) Documentation](https://kind.sigs.k8s.io/)
- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- CSA Security Guidance v5 — Domain on Identity & Access Management.
