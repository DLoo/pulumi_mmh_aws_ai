from typing import List, Optional, Dict, Any
import pulumi
from pulumi import Input, Output
import pulumi_aws as aws
# Removed pulumi_awsx as it's no longer needed for VPC creation
import pulumi_eks as eks
import pulumi_kubernetes as k8s
from pulumi_kubernetes.helm.v3 import Chart, ChartOpts, FetchOpts
import json


# --- Configuration ---
config = pulumi.Config()
project_name = config.require("project_name")
aws_region = aws.get_region().region
eks_cluster_name = config.get("eks_cluster_name") or f"{project_name}-cluster"

# --- [MODIFIED] Load Existing Network Configuration ---
# We now load the IDs of the existing resources instead of their CIDR blocks.
existing_vpc_id = config.require("existing_vpc_id")
existing_public_subnet_ids = config.require_object("existing_public_subnet_ids")
existing_private_subnet_ids = config.require_object("existing_private_subnet_ids")

# Load other configurations
eks_cluster_version = config.get("eks_cluster_version") or "1.31"
# eks_ebs_csi_driver_version = config.get("eks_ebs_csi_driver_version") or "v1.44.0-eksbuild.1"
# eks_efs_csi_driver_version = config.get("eks_efs_csi_driver_version") or "3.1.9"
# eks_cert_manager_version = config.get("eks_cert_manager_version") or "v1.18.0"
# eks_velero_version = config.get("eks_velero_version") or "10.0.4"
# eks_aws_load_balancer_controller_version = config.get("eks_aws_load_balancer_controller_version") or "1.13.2"
# eks_cluster_autoscaler_version = config.get("eks_cluster_autoscaler_version") or "9.46.6"
# eks_velero_aws_plugin_version = config.require("eks_velero_aws_plugin_version")
# route53_hosted_zone_id = config.require("route53_hosted_zone_id")
# velero_s3_bucket_name = config.require("velero_s3_bucket_name")

# eks_efs_protect = config.get_bool("eks_efs_protect", False)
# eks_velero_protect = config.get_bool("eks_velero_protect", True)
eks_cluster_protect = config.get_bool("eks_cluster_protect", False)

# Node configuration with defaults
node_config = {
    "instance_types": config.get_object("eks_node_instance_types") or ["t3.large"],
    "desired_count": config.get_int("eks_node_desired_count") or 2,
    "min_count": config.get_int("eks_node_min_count") or 2,
    "max_count": config.get_int("eks_node_max_count") or 5,
}

# --- Helper Functions (Unchanged) ---
def create_common_tags(name: str, additional_tags: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Create a consistent set of tags for resources."""
    tags = {
        "Name": f"{project_name}-{name}",
        "Project": project_name,
        "Environment": config.get("environment") or "development",
        "ManagedBy": "pulumi"
    }
    if additional_tags:
        tags.update(additional_tags)
    return tags

# --- [REMOVED] Networking Creation ---
# The logic for creating a VPC, subnets, and NAT Gateways has been removed.
# We will now look up the existing network resources.

# --- [NEW] Look up existing network resources ---
# Get the VPC object using its ID to access its properties, like the CIDR block.
vpc = aws.ec2.get_vpc(id=existing_vpc_id)

# The public and private subnet IDs are taken directly from the config.
# We can use them in other resources without further lookups.
public_subnet_ids = existing_public_subnet_ids
private_subnet_ids = existing_private_subnet_ids

# --- IAM Roles (Largely Unchanged) ---
# This logic remains the same as the roles are for the EKS service itself,
# not tied to the creation of the VPC.
eks_service_role = aws.iam.Role(f"{project_name}-eks-service-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }),
    tags=create_common_tags("eks-service-role"))

aws.iam.RolePolicyAttachment(f"{project_name}-eks-service-policy-attachment",
    role=eks_service_role.name, policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
aws.iam.RolePolicyAttachment(f"{project_name}-eks-vpc-resource-controller-attachment",
    role=eks_service_role.name, policy_arn="arn:aws:iam::aws:policy/AmazonEKSVPCResourceController")

eks_node_instance_role = aws.iam.Role(f"{project_name}-eks-node-role",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }),
    tags=create_common_tags("eks-node-role"))

# eks_node_instance_profile = aws.iam.InstanceProfile(f"{project_name}-eks-node-profile",
#     role=eks_node_instance_role.name,
#     tags=create_common_tags("eks-node-profile")
# )

managed_node_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
]
for i, policy_arn in enumerate(managed_node_policy_arns):
    aws.iam.RolePolicyAttachment(f"{project_name}-nodegroup-policy-attachment-{i}",
        role=eks_node_instance_role.name, policy_arn=policy_arn)


# --- WAF (Largely Unchanged) ---
# WAF configuration is independent of the VPC creation logic.
web_acl = aws.wafv2.WebAcl(f"{project_name}-web-acl",
    name=f"{project_name}-web-acl",
    scope="REGIONAL",
    default_action=aws.wafv2.WebAclDefaultActionArgs(allow={}),
    visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
        cloudwatch_metrics_enabled=True,
        metric_name=f"{project_name}-web-acl-metrics",
        sampled_requests_enabled=True,
    ),
    rules=[
        aws.wafv2.WebAclRuleArgs(
            name="Allow-LetsEncrypt-Challenge",
            priority=0,
            action=aws.wafv2.WebAclRuleActionArgs(allow={}),
            statement=aws.wafv2.WebAclRuleStatementArgs(
                byte_match_statement=aws.wafv2.WebAclRuleStatementByteMatchStatementArgs(
                    field_to_match=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchArgs(
                        uri_path=aws.wafv2.WebAclRuleStatementByteMatchStatementFieldToMatchUriPathArgs()
                    ),
                    search_string="/.well-known/acme-challenge/",
                    positional_constraint="STARTS_WITH",
                    text_transformations=[aws.wafv2.WebAclRuleStatementByteMatchStatementTextTransformationArgs(priority=0, type="NONE")]
                )
            ),
            visibility_config=aws.wafv2.WebAclVisibilityConfigArgs(
                cloudwatch_metrics_enabled=True, metric_name="allow-letsencrypt", sampled_requests_enabled=True
            ),
        ),
    ],
    tags=create_common_tags("waf-acl")
)

# --- EKS Cluster ---
# --- [MODIFIED] Use the looked-up and configured network IDs ---
primary_instance_type = node_config["instance_types"][0] if node_config["instance_types"] else "t3.large"

eks_cluster = eks.Cluster(f"{project_name}-eks",
    name=eks_cluster_name,
    service_role=eks_service_role,
    # instance_role=eks_node_instance_role,
    vpc_id=vpc.id,  # Use the ID from the looked-up VPC
    public_subnet_ids=public_subnet_ids,    # Use the list from config
    private_subnet_ids=private_subnet_ids,  # Use the list from config
    create_oidc_provider=True,
    version=eks_cluster_version,
    enabled_cluster_log_types=["api", "audit", "authenticator", "controllerManager", "scheduler"],
    tags=create_common_tags("eks"),
    # instance_roles=[eks_node_instance_role],
    # instance_profile_name=eks_node_instance_profile.name,
    node_group_options=eks.ClusterNodeGroupOptionsArgs(
        instance_type=primary_instance_type,
        desired_capacity=node_config["desired_count"],
        min_size=node_config["min_count"],
        max_size=node_config["max_count"],
        labels={"ondemand": "true"}
    ),
    opts=pulumi.ResourceOptions(
        protect=eks_cluster_protect,
        delete_before_replace=False
        # depends_on=[vpc]
    ))


kubeconfig = eks_cluster.kubeconfig
k8s_provider = k8s.Provider(f"{project_name}-k8s-provider", kubeconfig=kubeconfig)



# --- Outputs ---
pulumi.export("vpc_id", vpc.id)
pulumi.export("vpc_cidr_block", vpc.cidr_block)
pulumi.export("public_subnet_ids", public_subnet_ids)
pulumi.export("private_subnet_ids", private_subnet_ids)
pulumi.export("waf_acl_arn", web_acl.arn)
pulumi.export("eks_cluster_name", eks_cluster.eks_cluster.name)
pulumi.export("eks_cluster_endpoint", eks_cluster.eks_cluster.endpoint)
pulumi.export("kubeconfig", pulumi.Output.secret(kubeconfig))
