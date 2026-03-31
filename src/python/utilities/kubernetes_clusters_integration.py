import argparse
import kubernetes
import os
import shlex
import subprocess
import sys
from termcolor import colored as color

INTEGRATION_COMMANDS = [
    "helm repo add streamsec https://lightlytics.github.io/helm-charts",
    "helm repo update",
    "helm upgrade --install streamsec-agent --set streamsec.apiToken={TOKEN} --set streamsec.apiUrl={ENV} "
    "-n streamsec-agent --create-namespace streamsec/streamsec-agent"
]

# Add the project root directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..')))
try:
    from src.python.common.common import *
except ModuleNotFoundError:
    sys.path.append("../../..")
    from src.python.common.common import *


def main(environment, ll_username, ll_password, ll_f2a, ws_name, stage=None, account_id=None, region=None,
         enable_runtime_agent=False):
    # Setting the environment URL
    stream_url = f"{environment}.lightops.io" if stage else f"{environment}.streamsec.io"

    print(color("Checking if prerequisites are installed", "blue"))
    for req in ['helm', 'kubectl']:
        try:
            subprocess.check_output([req, 'version'])
        except Exception as e:
            log.debug(e)
            sys.exit(f"Missing {req} installation")
    print(color("Everything is good with the prerequisites", "green"))

    print(color("Adding the 'streamsec' repo to helm", "blue"))
    subprocess.check_output(INTEGRATION_COMMANDS[0].split(' '))
    print(color("Added 'streamsec' repo to helm successfully", "green"))

    print(color("Updating helm repo", "blue"))
    subprocess.check_output(INTEGRATION_COMMANDS[1].split(' '))
    print(color("helm repo updated successfully", "green"))

    print(color("Getting all K8s contexts", "blue"))
    k8s_all_contexts = kubernetes.config.list_kube_config_contexts()
    k8s_contexts = {c['context']['cluster'] for c in k8s_all_contexts[0]}
    k8s_active_context = k8s_all_contexts[1].get("context").get('cluster')
    print(color(f"Found {len(k8s_contexts)} contexts", "green"))

    print(color("Trying to login into Stream Security", "blue"))
    graph_client = get_graph_client(environment, ll_username, ll_password, ll_f2a, ws_name, stage)
    print(color("Logged in successfully!", "green"))

    print(color("Getting all EKS clusters ARNs", "blue"))
    eks_clusters = graph_client.get_resources_by_type(resource_type="eks")
    print(color(f"Found {len(eks_clusters)} clusters", "green"))

    if account_id or region:
        filtered = []
        for c in eks_clusters:
            arn_parts = c['id'].split(':')
            if len(arn_parts) < 5:
                print(color(f"Skipping cluster with unexpected ARN format: {c['id']}", "yellow"))
                continue
            cluster_region = arn_parts[3]
            cluster_account = arn_parts[4]
            if account_id and cluster_account != account_id:
                continue
            if region and cluster_region != region:
                continue
            filtered.append(c)
        print(color(f"Filtered to {len(filtered)} clusters (account_id={account_id}, region={region})", "blue"))
        if not filtered:
            sys.exit(color("No clusters matched the provided account_id/region filters. "
                           "Please verify your --account_id and --region values.", "red"))
        eks_clusters = filtered

    print(color("Getting all Kubernetes existing integrations", "blue"))
    eks_integrations_list = graph_client.get_kubernetes_integrations()
    eks_integrations = {i['eks_arn']: i for i in eks_integrations_list}
    print(color(f"Found {len(eks_integrations)} integrations", "green"))

    for cluster in eks_clusters:
        cluster_name = cluster['display_name'].split("/")[0]
        cluster_arn = cluster['id']
        if cluster_arn not in k8s_contexts:
            print(color(f"{cluster_name} | No context available for the cluster, skipping", "yellow"))
            continue
        print(color(f"{cluster_name} | Checking if cluster is already integrated", "blue"))
        relevant_integration = eks_integrations.get(cluster_arn)
        if relevant_integration:
            if relevant_integration['status'] == "READY":
                print(color(f"{cluster_name} | Cluster is already integrated!", "green"))
                continue
            elif relevant_integration['status'] == "UNINITIALIZED":
                print(color(f"{cluster_name} | Cluster is uninitialized, trying to reintegrate helm", "yellow"))
                if not integrate_helm(cluster, stream_url, relevant_integration['collection_token'], enable_runtime_agent):
                    print(color(f"{cluster_name} | Helm installation failed!", "red"))
                continue
            else:
                print(color(f"{cluster_name} | Cluster has wrong status ({relevant_integration['status']}) - "
                            f"please remove it manually and run the script again", "yellow"))
                continue
        else:
            print(color(f"{cluster_name} | Integration not found, creating it", "blue"))
            integration_metadata = graph_client.create_kubernetes_integration(cluster_arn, cluster_name)
            if not integration_metadata:
                print(color(f"{cluster_name} | Couldn't create the integration in Stream Security env - "
                            f"please contact support", "red"))
                continue
            print(color(f"{cluster_name} | Integration created successfully in Stream Security!", "green"))

            if not integrate_helm(cluster, stream_url, integration_metadata['collection_token'], enable_runtime_agent):
                print(color(f"{cluster_name} | Helm installation failed!", "red"))
            continue

    print(color("Reverting back to original context", "blue"))
    subprocess.check_output(["kubectl", "config", "use-context", k8s_active_context])
    print(color("Reverted successfully", "green"))

    print(color("Script finished", "green"))


def integrate_helm(cluster, stream_url, integration_token, enable_runtime_agent=False):
    cluster_name = cluster['display_name'].split("/")[0]
    print(color(f"{cluster_name} | Switching Kubernetes context", "blue"))
    switch_cmd_output = subprocess.check_output(["kubectl", "config", "use-context", cluster['id']])
    print(f"{cluster_name} | Switching Kubernetes context command result: {switch_cmd_output}")

    # Setting up helm installation command
    helm_cmd = INTEGRATION_COMMANDS[2].replace("{TOKEN}", integration_token).replace("{ENV}", stream_url)
    helm_cmd += f" --set streamsec.env.CLUSTER_ID={cluster['id']}"
    if enable_runtime_agent:
        helm_cmd += " --set streamsec.runtime_agent.enabled=true"
    print(color(f"{cluster_name} | Executing helm commands", "blue"))
    try:
        res = subprocess.check_output(shlex.split(helm_cmd))
        print(f"{cluster_name} | Installation command result: {res}")
    except Exception as e:
        print(color(f"{cluster_name} | Something went wrong when running 'helm' commands, error: {e}", "red"))
        return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='This script will integrate all EKS clusters in the Workspace with Stream Security.')
    parser.add_argument(
        "--environment_sub_domain", help="The Stream Security environment sub domain", required=True)
    parser.add_argument(
        "--environment_user_name", help="The Stream Security environment user name", required=True)
    parser.add_argument(
        "--environment_password", help="The Stream Security environment password", required=True)
    parser.add_argument(
        "--environment_f2a_token", help="F2A Token if set", default=None)
    parser.add_argument(
        "--ws_name", help="The WS from which to fetch information", default=None)
    parser.add_argument(
        "--stage", action="store_true")
    parser.add_argument(
        "--account_id", help="Filter clusters by AWS account ID", default=None)
    parser.add_argument(
        "--region", help="Filter clusters by AWS region", default=None)
    parser.add_argument(
        "--enable_runtime_agent", help="Enable the runtime agent (Tetragon-based)", action="store_true")
    args = parser.parse_args()
    main(args.environment_sub_domain, args.environment_user_name, args.environment_password, args.environment_f2a_token,
         args.ws_name, stage=args.stage, account_id=args.account_id, region=args.region,
         enable_runtime_agent=args.enable_runtime_agent)
