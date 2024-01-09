#!/bin/bash  

#
# Notes:
#
#										Installs TAP pre-reqs, namley:
#										-Cluster-Essentials
#                   -TAP-Cli-Compoents
#
# -02-Jan-2024:     TAP-1.7.1:
#                    Do not trust the pivnet file-id's.  These tend to be wrong.
# 									 Go out to: https://network.pivotal.io/products/tanzu-application-platform
#                    Pull up the cluster-essentials or tap-cli, then goto the download link,
#                    and copy it from there.  Same is true for the SHA.
#

# set -x

# ToDo:
# -Add kpack-cli download, install 0.12


theCloud=""
thePivNetToken=""

theTanzuRegistryHostName=""
theTanzuRepoName=""
theTanzuNetUserName=""
theTanzuNetPassWord=""

theTAPRegistryLoginServer=""
theTAPRegistryHostName=""
theTAPRegistryRepoName=""
theTAPRegistryUserName=""
theTAPRegistryPassWord=""

theDomainName=""
theGithubToken=""
theClusterName=""
theAzureSubscription=""
theAzureRegion=""
theResponse=""

theTAPVersion=""
theClusterEssentialsFileID=""
theClusterEssentialsInstallBundle=""

useForce=""
returnVal=0

function usage() {

  echo ""
  echo "Usage: $0 -Installs TAP-PreReqs to a target cloud." 
  echo ""
  echo ""
  echo "Options: "
  echo ""
  echo "   A number of parameters can be exported to evars to reduce cycle-time."
  echo "   These are prefaced with TS_ below."  
  echo ""
  echo "  *** Also MAKE SURE you are docker login'd to BOTH, BEFORE RUNNING: ***"
  echo "     -registry.tanzu.vmware.com"
  echo "     -your-target-registry"
  echo ""
  echo "  -F -UseForce Flag.  This will FORCEFULLY re-install ALL CLIs."  
	echo ""    
  echo ""  
  
  echo "TS_ Variables:"
	echo "     export TS_TARGET_CLOUD='AKS'"
	echo "     export TS_PIVNET_TOKEN='-the-token-'"
	echo ""	
	
	echo "     export TS_TANZU_REGISTRY_HOSTNAME='registry.tanzu.vmware.com'"
	echo "     export TS_TANZU_USERNAME='me@somewhere.com'"
	echo "     export TS_TANZU_PASSWORD='-the-password-'"	
	echo ""	
	
	echo "     export TS_TAP_REGISTRY_HOSTNAME='ericmtaptestdemoacr.azurecr.io/ericmtaptestdemoacr'"
	echo "     export TS_TAP_REGISTRY_REPO_NAME='ericm48'"	
	echo "     export TS_TAP_REGISTRY_USERNAME='me@somewhere.com'"
	echo "     export TS_TAP_REGISTRY_PASSWORD='-the-password-'"	
	echo ""
	
	echo "     export TS_DOMAIN_NAME='my-dns.net'"
	echo "     export TS_GITHUB_TOKEN='-the-token-'"
	echo "     export TS_CLUSTER_NAME='tap-cluster-171'"
	echo "     export TS_AZURE_SUBSCRIPTION='-the-token-'"
	echo "     export TS_AZURE_REGION='eastus'"
	echo "     export TS_TAP_VERSION='1.7.1'"	
	echo ""
	echo ""
	echo ""		
  
}

function load_params() {
  
  if [[ -z $TS_TARGET_CLOUD ]]; then
		echo " "		
		echo "Type: AKS for Azure, EKS for Amazon, GKE for Google"
		echo "If you choose EKS, Keep docker.io credentials handy..."
		read -p "Enter The Target Cloud: " theCloud  
	else
		theCloud="$TS_TARGET_CLOUD"
  fi

  if [[ -z $TS_PIVNET_TOKEN ]]; then
		read -p "Enter the Pivnet token: " thePivNetToken	
	else
		thePivNetToken="$TS_PIVNET_TOKEN"
  fi
  
  if [[ -z $TS_TANZU_REGISTRY_HOSTNAME ]]; then
		read -p "Enter the Tanzu Registry HostName: " theTanzuRegistryHostName
	else
		theTanzuRegistryHostName="$TS_TANZU_REGISTRY_HOSTNAME"
  fi

  if [[ -z $TS_TANZU_USERNAME ]]; then
		read -p "Enter the Tanzu network username: " theTanzuNetUserName
	else
		theTanzuNetUserName="$TS_TANZU_USERNAME"
  fi

  if [[ -z $TS_TANZU_PASSWORD ]]; then
		read -p "Enter the Tanzu network password: " theTanzuNetPassWord
	else
		theTanzuNetPassWord="$TS_TANZU_PASSWORD"
  fi

  if [[ -z $TS_DOMAIN_NAME ]]; then
		read -p "Enter the target domain-name for Learning Center: " theDomainName
	else
		theDomainName="$TS_DOMAIN_NAME"
  fi

  if [[ -z $TS_GITHUB_TOKEN ]]; then
		read -p "Enter the Github Token: " theGithubToken
	else
		theGithubToken="$TS_GITHUB_TOKEN"
  fi

  if [[ -z $TS_GITHUB_TOKEN ]]; then
		read -p "Enter the Target Cluster-Name: " theClusterName
	else
		theClusterName="$TS_CLUSTER_NAME"
  fi

  if [[ -z $TS_TAP_REGISTRY_LOGIN_SERVER ]]; then
		read -p "Enter the TAP Registry LoginServer: " theTAPRegistryLoginServer
	else
		theTAPRegistryLoginServer="$TS_TAP_REGISTRY_LOGIN_SERVER"
  fi  

  if [[ -z $TS_TAP_REGISTRY_HOSTNAME ]]; then
		read -p "Enter the TAP Registry HostName: " theTAPRegistryHostName
	else
		theTAPRegistryHostName="$TS_TAP_REGISTRY_HOSTNAME"
  fi

  if [[ -z $TS_TAP_REGISTRY_REPO_NAME ]]; then
		read -p "Enter the TAP Registry RepoName: " theTAPRegistryRepoName
	else
		theTAPRegistryRepoName="$TS_TAP_REGISTRY_REPO_NAME"
  fi

  if [[ -z $TS_TAP_REGISTRY_USERNAME ]]; then
		read -p "Enter the TAP Registry UserName: " theTAPRegistryUserName
	else
		theTAPRegistryUserName="$TS_TAP_REGISTRY_USERNAME"
  fi

  if [[ -z $TS_TAP_REGISTRY_PASSWORD ]]; then
		read -p "Enter the TAP Registry PassWord: " theTAPRegistryPassWord
	else
		theTAPRegistryPassWord="$TS_TAP_REGISTRY_PASSWORD"
  fi

  if [[ -z $TS_TAP_VERSION ]]; then
		read -p "Enter the TAP Version: " theTAPVersion
	else
		theTAPVersion="$TS_TAP_VERSION"
  fi

  if [[ -z $TS_CLUSTER_ESSENTIALS_FILEID ]]; then
		read -p "Enter the FILEID for the ClusterEssentials Version: " theClusterEssentialsFileID
	else
		theClusterEssentialsFileID="$TS_CLUSTER_ESSENTIALS_FILEID"
  fi

  if [[ -z $TS_CLUSTER_ESSENTIALS_INSTALL_BUNDLE ]]; then
		read -p "Enter the FILEID for the ClusterEssentials Version: " theClusterEssentialsInstallBundle
	else
		theClusterEssentialsInstallBundle="$TS_CLUSTER_ESSENTIALS_INSTALL_BUNDLE"
  fi

	
	# AKS Things:

	if [[  "$theCloud" == "AKS" ]]; then

	  if [[ -z $TS_AZURE_SUBSCRIPTION ]]; then
			read -p "Enter the Azure Subscription: " theAzureSubscription
		else
			theAzureSubscription="$TS_AZURE_SUBSCRIPTION"
	  fi
	
	  if [[ -z $TS_AZURE_REGION ]]; then
			read -p "Enter the Azure Region (eastus): " theAzureRegion
		else
			theAzureRegion="$TS_AZURE_REGION"
	  fi


	fi
  
}

function display_params() {
	echo ""
	echo ""
	echo "Parameters SET:"
	echo ""	
	echo "                   TargetCloud: $theCloud"
	echo "                   PivNetToken: $thePivNetToken"	
	echo "                   GithubToken: $theGithubToken"
	
	echo ""
	echo "      TanzuNetRegistryHostName: $theTanzuRegistryHostName"	
	echo "              TanzuNetUserName: $theTanzuNetUserName"	
	echo "              TanzuNetPassWord: ***"	# theTanzuNetPassWord

	echo ""	
	echo "       ClusterEssentialsFileID: $theClusterEssentialsFileID"
	echo "ClusterEssentialsInstallBundle: $theClusterEssentialsInstallBundle"
	
	echo ""
  echo "        TAPRegistryLoginServer: $theTAPRegistryLoginServer"
	echo "           TAPRegistryHostName: $theTAPRegistryHostName"	
	echo "           TAPRegistryRepoName: $theTAPRegistryRepoName"
	echo "           TAPRegistryUserName: $theTAPRegistryUserName"	
	echo "           TAPRegistryPassWord: ***"	# theTanzuNetPassWord
	echo "                    TAPVersion: $theTAPVersion"	

	echo ""
	echo "     DomainName: $theDomainName"
	echo "     ClusterName: $theClusterName"
	echo ""
	
	if [[  "$theCloud" == "AKS" ]]; then	
	
		echo "     AzureSubscription: $theAzureSubscription"	
		echo "     AzureRegion: $theAzureRegion"	
	
		echo ""
		echo ""
		
		echo "Be ready to enter a code for Azure Login!"

	fi

	echo ""
	echo ""	
  echo "  *** Also MAKE SURE you are docker login'd to BOTH, BEFORE RUNNING: ***"
  echo "     -registry.tanzu.vmware.com"
  echo "     -your-target-registry"
  echo ""
	
	echo ""
	echo ""
	
	read -p "Press ENTER to proceed or ctrl-c to end." theResponse

}
	
function install_aks()
{	
  
	az --version &> /dev/null

	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then
	  echo " "
		echo "Installing az-CLI..."
		curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
	fi

	echo "az-Cli Version: "
	az --version   		
	
	echo " "
	echo "Authenticate to AZ cli by following the screen Instructions below..."
	az login
	
	echo " "
	echo "Resource group created with name eric-tap-east-rg in region and the subscription mentioned above..."
	az group create --name eric-tap-east-rg --location $theAzureRegion --subscription $theAzureSubscription

	echo " "
	echo "Creating AKS cluster with 3 node and sku as Standard_B8ms..."
	az aks create --resource-group eric-tap-east-rg --name $theClusterName --subscription $theAzureSubscription --node-count 3 --enable-addons monitoring --generate-ssh-keys --node-vm-size Standard_B8ms -z 1 --enable-cluster-autoscaler --min-count 3 --max-count 3
	
	echo "AKS Cluster Created!"
	
	kubectl version &> /dev/null

	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then
	  echo " "
		echo "Install az aks kubectl......"
	
		sudo az aks install-cli
	fi
	
	echo "kubectl-CLI Version: "
	kubectl version	
	
	echo "Set the context..."
	az account set --subscription $theAzureSubscription
	az aks get-credentials --resource-group eric-tap-east-rg --name $theClusterName
	
	echo "Verify K8s Nodes..."
	kubectl get nodes

	echo " "
	echo "Create RG for Repo..."
	az group create --name eric-tap-workshop-imagerepo-rg --location $theAzureRegion

	echo "Create Container Registry..."

	az acr create --resource-group eric-tap-workshop-imagerepo-rg --name ericmtaptestdemoacr --sku Standard


	# 08-Jan-2024: Not sure if we wanna leave this in here..disabling 4 now..
	
#	echo "Fetching ACR Admin Credentials..."
#	az acr update -n ericmtaptestdemoacr --admin-enabled true
#	acrusername=$(az acr credential show --name ericmtaptestdemoacr --query "username" -o tsv)
#	acrloginserver=$(az acr show --name ericmtaptestdemoacr --query loginServer -o tsv)
#	acrpassword=$(az acr credential show --name ericmtaptestdemoacr --query passwords[0].value -o tsv)
#	if grep -q "/"  <<< "$acrpassword";
#	   then
#		    acrpassword1=$(az acr credential show --name ericmtaptestdemoacr --query passwords[1].value -o tsv)
#		    if grep -q "/"  <<< "$acrpassword1";
#		      then
#	 					 echo "Update the password manually in tap-values file(repopassword): password is $acrpassword1 "
#
#				else
#	   			acrpassword=$acrpassword1
#	      fi
#	else
#	  echo "PassWord Updated in tap values file"
#	fi
#	
#	echo " "	
#	echo "Preparing the tap-values file..."
#	sed -i -r "s/tanzunetusername/$tanzunetusername/g" "$HOME/tap-script/tap-values.yaml"
#	sed -i -r "s/tanzunetpassword/$tanzunetpassword/g" "$HOME/tap-script/tap-values.yaml"
#	sed -i -r "s/registryname/$acrloginserver/g" "$HOME/tap-script/tap-values.yaml"
#	sed -i -r "s/repousername/$acrusername/g" "$HOME/tap-script/tap-values.yaml"
#	sed -i -r "s/repopassword/$acrpassword/g" "$HOME/tap-script/tap-values.yaml"
#	sed -i -r "s/domainname/$domainname/g" "$HOME/tap-script/tap-values.yaml"
#	sed -i -r "s/githubtoken/$githubtoken/g" "$HOME/tap-script/tap-values.yaml"
#
	echo " "	
	echo "Creating namespace tap-install..."
	  
	kubectl create ns tap-install

}	 # End of install_aks


function install_aws()
{
	 read -p "Enter the region: " region
   read -p "Enter the dockerhub username: " dockerusername
   read -p "Enter the dockerhub password: " dockerpassword

   echo "#########################################"
	 echo "Installing AWS cli"
   echo "#########################################"
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   sudo apt install unzip
	 unzip awscliv2.zip
	 sudo ./aws/install
	 ./aws/install -i /usr/local/aws-cli -b /usr/local/bin

   echo "#########################################"
   echo "AWS CLI version"
   echo "#########################################"
	 aws --version

   echo "############################################################################"
   echo "############# Provide AWS access key and secrets  ##########################"
   echo "############################################################################"
   aws configure

   read -p "Enter AWS session token: " aws_token
   aws configure set aws_session_token $aws_token

   echo "############ Install Kubectl #######################"
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

   echo "############  Kubectl Version #######################"
   kubectl version

   echo "################## Creating IAM Roles for EKS Cluster and nodes ###################### "
cat <<EOF > cluster-role-trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

cat <<EOF > node-role-trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

	aws iam create-role --role-name tap-EKSClusterRole --assume-role-policy-document file://"cluster-role-trust-policy.json"
	aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy --role-name tap-EKSClusterRole
	aws iam create-role --role-name tap-EKSNodeRole --assume-role-policy-document file://"node-role-trust-policy.json"
	aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy --role-name tap-EKSNodeRole
	aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly --role-name tap-EKSNodeRole
	aws iam attach-role-policy --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy --role-name tap-EKSNodeRole

	echo "########################### Creating VPC Stacks through cloud formation ##############################"
	aws cloudformation create-stack --region $region --stack-name tap-demo-vpc-stack --template-url https://amazon-eks.s3.us-west-2.amazonaws.com/cloudformation/2020-10-29/amazon-eks-vpc-private-subnets.yaml
	echo "############## Waiting for VPC stack to get created ###################"
	echo "############## Paused for 5 mins ##########################"
	sleep 5m
	pubsubnet1=$(aws ec2 describe-subnets --filters Name=tag:Name,Values=tap-demo-vpc-stack-PublicSubnet01 --query Subnets[0].SubnetId --output text)
	pubsubnet2=$(aws ec2 describe-subnets --filters Name=tag:Name,Values=tap-demo-vpc-stack-PublicSubnet02 --query Subnets[0].SubnetId --output text)
	rolearn=$(aws iam get-role --role-name tap-EKSClusterRole --query Role.Arn --output text)
	sgid=$(aws ec2 describe-security-groups --filters Name=description,Values="Cluster communication with worker nodes" --query SecurityGroups[0].GroupId --output text)

	echo "########################## Creating EKS Cluster ########################################"
	ekscreatecluster=$(aws eks create-cluster --region $region --name tap-demo-ekscluster --kubernetes-version 1.21 --role-arn $rolearn --resources-vpc-config subnetIds=$pubsubnet1,$pubsubnet2,securityGroupIds=$sgid)

	echo "############## Waiting for EKS cluster to get created ###################"
	echo "############## Paused for 15 mins ###############################"
	sleep 15m
	aws eks update-kubeconfig --region $region --name tap-demo-ekscluster
	rolenodearn=$(aws iam get-role --role-name tap-EKSNodeRole --query Role.Arn --output text)

	echo "######################### Creating Node Group ###########################"
	aws eks create-nodegroup --cluster-name tap-demo-ekscluster --nodegroup-name tap-demo-eksclusterng --node-role $rolenodearn --instance-types t2.2xlarge --scaling-config minSize=1,maxSize=2,desiredSize=2 --disk-size 40  --subnets $pubsubnet1
	
	echo "############## Waiting for Node groups to get created ###################"
	echo "############### Paused for 10 mins ################################"
	sleep 10m
	
	echo "################ Prepare Tap values file ##################"
	aws ecr create-repository --repository-name tapdemoacr
	ecrusername=AWS
	ecrpassword=$(aws ecr get-login-password --region $region)
	ecrregistryid=$(aws ecr describe-repositories --repository-names tapdemoacr --query repositories[0].registryId --output text)
	ecrloginserver=$ecrregistryid.dkr.ecr.$region.amazonaws.com
	
cat <<EOF > tap-values.yaml
profile: full
ceip_policy_disclosed: true # Installation fails if this is set to 'false'
buildservice:
  kp_default_repository: "index.docker.io/$dockerusername/build-service" # Replace the project id with yours. In my case eknath-se is the project ID
  kp_default_repository_username: $dockerusername
  kp_default_repository_password: $dockerpassword
  tanzunet_username: "$tanzunetusername" # Provide the Tanzu network user name
  tanzunet_password: "$tanzunetpassword" # Provide the Tanzu network password
  descriptor_name: "tap-1.0.0-full"
  enable_automatic_dependency_updates: true
supply_chain: testing_scanning
ootb_supply_chain_testing_scanning:
  registry:
    server: "index.docker.io"
    repository: "$dockerusername" # Replace the project id with yours. In my case eknath-se is the project ID
  gitops:
    ssh_secret: ""
  cluster_builder: default
  service_account: default

learningcenter:
  ingressDomain: "$domainname" # Provide a Domain Name

metadata_store:
  app_service_type: LoadBalancer # (optional) Defaults to LoadBalancer. Change to NodePort for distributions that don't support LoadBalancer
grype:
  namespace: "tap-install" # (optional) Defaults to default namespace.
  targetImagePullSecret: "registry-credentials"
contour:
  envoy:
    service:
      type: LoadBalancer
tap_gui:
  service_type: LoadBalancer # NodePort for distributions that don't support LoadBalancer
  app_config:
    app:
      baseUrl: http://lbip:7000
    integrations:
      github: # Other integrations available see NOTE below
        - host: github.com
          token: $githubtoken  # Create a token in github
    catalog:
      locations:
        - type: url
          target: https://github.com/Eknathreddy09/tanzu-java-web-app/blob/main/catalog/catalog-info.yaml
    backend:
      baseUrl: http://lbip:7000
      cors:
        origin: http://lbip:7000
EOF
	echo "####################################################################"
	echo "########### Creating Secrets in tap-install namespace  #############"
	echo "####################################################################"
	
	kubectl create ns tap-install
	kubectl create secret docker-registry registry-credentials --docker-server=https://index.docker.io/v1/ --docker-username=$dockerusername --docker-password=$dockerpassword -n tap-install
	kubectl create secret docker-registry image-secret --docker-server=https://index.docker.io/v1/ --docker-username=$dockerusername --docker-password=$dockerpassword -n tap-install
	
	echo "######### Prepare the tap-values file ##########"
	sed -i -r "s/tanzunetusername/$tanzunetusername/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/tanzunetpassword/$tanzunetpassword/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/registryname/$ecrloginserver/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/repousername/$ecrusername/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/repopassword/$ecrpassword/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/domainname/$domainname/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/repousername/$dockerusername/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/repopassword/$dockerpassword/g" "$HOME/tap-script/tap-values.yaml"
	sed -i -r "s/githubtoken/$githubtoken/g" "$HOME/tap-script/tap-values.yaml"

} # End of install_aws

function install_gke()
{

   echo "#########################################"
   echo "#########################################"
	 echo "Installing GKE cli"
   echo "#########################################"
   echo "#########################################"
	 sudo apt-get install apt-transport-https ca-certificates gnupg -y
	 echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
	 curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
	 sudo apt-get update && sudo apt-get install google-cloud-sdk -y

   echo "#########################################"
	 echo "Authenticate to Gcloud by following the screen Instructions below"
   echo "#########################################"
   echo "#########################################"
	 gcloud init

   echo "#########################################"
   echo "gloud CLI version"
   echo "#########################################"
	 gcloud version
   echo "#########################################"
   echo "#########################################"
   echo "############ Installing Kubectl #######################"
   echo "#########################################"   

   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   echo "############  Kubectl Version #######################"
   kubectl version
   region=$(gcloud config get-value compute/region)

   echo "############################## Creating GKE Clusters ###############################"
   gcloud container clusters create --machine-type e2-standard-8 --num-nodes 1 --cluster-version latest --region=$region tap-demo-gkecluster

   echo "######################## Creating GCR Repo ##########################"
   gcloud iam service-accounts create tap-demo-gcrrepo --display-name="For TAP Images"
   projid=$(gcloud config get-value project)
   gcloud iam service-accounts keys create tap-demo-cred.json --iam-account=tap-demo-gcrrepo@$projid.iam.gserviceaccount.com
   gsutil ls
   gsutil iam ch serviceAccount:tap-demo-gcrrepo@$projid.iam.gserviceaccount.com:legacyBucketWriter gs://artifacts.$projid.appspot.com/
   kubectl create ns tap-install

   echo "######### Preparing the tap-values file ##########"
   projid=$(gcloud config get-value project)
   service_account_key="$(cat tap-demo-cred.json)"
   
cat <<EOF > tap-values.yaml
profile: full
ceip_policy_disclosed: true # Installation fails if this is set to 'false'
buildservice:
  kp_default_repository: "gcr.io/$projid/build-service" # Replace the project id with yours. In my case eknath-se is the project ID
  kp_default_repository_username: _json_key
  kp_default_repository_password: '$(echo $service_account_key)'
  tanzunet_username: "$tanzunetusername" # Provide the Tanzu network user name
  tanzunet_password: "$tanzunetpassword" # Provide the Tanzu network password
  descriptor_name: "tap-1.0.0-full"
  enable_automatic_dependency_updates: true
supply_chain: testing_scanning
ootb_supply_chain_testing_scanning:
  registry:
    server: "gcr.io"
    repository: "$projid/supply-chain" # Replace the project id with yours. In my case eknath-se is the project ID
  gitops:
    ssh_secret: ""
  cluster_builder: default
  service_account: default

learningcenter:
  ingressDomain: "$domainname" # Provide a Domain Name

metadata_store:
  app_service_type: LoadBalancer # (optional) Defaults to LoadBalancer. Change to NodePort for distributions that don't support LoadBalancer
grype:
  namespace: "tap-install" # (optional) Defaults to default namespace.
  targetImagePullSecret: "registry-credentials"
contour:
  envoy:
    service:
      type: LoadBalancer
tap_gui:
  service_type: LoadBalancer # NodePort for distributions that don't support LoadBalancer
  app_config:
    app:
      baseUrl: http://lbip:7000
    integrations:
      github: # Other integrations available see NOTE below
        - host: github.com
          token: $githubtoken  # Create a token in github
    catalog:
      locations:
        - type: url
          target: https://github.com/Eknathreddy09/tanzu-java-web-app/blob/main/catalog/catalog-info.yaml
    backend:
      baseUrl: http://lbip:7000
      cors:
        origin: http://lbip:7000
EOF

	echo "#####################################################################################################"
	echo "########### Creating Secrets in tap-install namespace  #############"
	kubectl create secret docker-registry registry-credentials --docker-server=gcr.io --docker-username=_json_key --docker-password="$(cat tap-demo-cred.json)" -n tap-install
	kubectl create secret docker-registry image-secret --docker-server=gcr.io --docker-username=_json_key --docker-password="$(cat tap-demo-cred.json)" -n tap-install
	
}	# End of install_gke


function install_tap_prereqs()
{

	pivnet --version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then

		echo " "	
		echo "Installing pivnet-CLI..."
		
		wget https://github.com/pivotal-cf/pivnet-cli/releases/download/v3.0.1/pivnet-linux-amd64-3.0.1
		chmod +x pivnet-linux-amd64-3.0.1
		sudo mv pivnet-linux-amd64-3.0.1 /usr/local/bin/pivnet

	fi
	
  echo "pivnet-CLI Version: "
	pivnet --version


	if [[ ! -f $HOME/tanzu-cluster-essentials/install.sh || "$useForce" == "T" ]]; then
	   
		echo "Downloading Tanzu Cluster Essentials CLI..."
		pivnet login --api-token=${thePivNetToken}	
		pivnet download-product-files --product-slug='tanzu-cluster-essentials' --release-version="$theTAPVersion" --product-file-id="$theClusterEssentialsFileID"
		
		rm -rfv $HOME/tanzu-cluster-essentials
		mkdir $HOME/tanzu-cluster-essentials
		
		tar -xvf tanzu-cluster-essentials-linux-amd64-"$theTAPVersion".tgz -C $HOME/tanzu-cluster-essentials
   
		#
		# Set these eVARS!! The cluster-essential's install.sh below, requires these 
		# INSTALL_ eVars be set!  Even tho we already downloaded it...doh!
		#

		# ToDo: Relo ClusterEssentials to my target registry..then run it.

	fi

	
	#export INSTALL_BUNDLE='registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:ca8584ff2ad4a4cf7a376b72e84fd9ad84ac6f38305767cdfb12309581b521f5'  #v1.7.1

  # HERE DUDE: Hackify what the ACR version of the INSTALL_BUNDLE evar would look like...

	export INSTALL_BUNDLE="$theClusterEssentialsInstallBundle"	
	export INSTALL_REGISTRY_HOSTNAME=${theTanzuRegistryHostName}
	export INSTALL_REGISTRY_USERNAME=${theTanzuNetUserName}
	export INSTALL_REGISTRY_PASSWORD=${theTanzuNetPassWord}
   
	cd $HOME/tanzu-cluster-essentials
	
	kubectl create ns kapp-controller
	
	#
	# More games with BAD install scripts..
	#

	echo " "	   
	echo "Attempting ClusterEssentials LOCAL Install.sh..."	
	
	yes | ./install.sh
	
	kapp --version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then
		
		echo " "		
		echo "Installing kapp-CLI..."
		sudo cp $HOME/tanzu-cluster-essentials/kapp /usr/local/bin/kapp
		sudo cp $HOME/tanzu-cluster-essentials/imgpkg /usr/local/bin/imgpkg

	fi
	
	echo "kapp-CLI Version: "
	kapp --version

	echo "imgpkg-CLI Version: "
	imgpkg --version
	
   
}	# End of install_tap_prereqs


function install_tanzu_cli_pkg()
{

	tanzu version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then

		echo " "
	  echo "Installing tanzu-CLI From Package-Mgr..."
	  
		sudo mkdir -p /etc/apt/keyrings/
		sudo apt-get update
		sudo apt-get install -y ca-certificates curl gpg
		
		curl -fsSL https://packages.vmware.com/tools/keys/VMWARE-PACKAGING-GPG-RSA-KEY.pub | sudo gpg --yes --dearmor -o /etc/apt/keyrings/tanzu-archive-keyring.gpg
		echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/tanzu-archive-keyring.gpg] https://storage.googleapis.com/tanzu-cli-os-packages/apt tanzu-cli-jessie main" | sudo tee /etc/apt/sources.list.d/tanzu.list
		
		sudo apt-get update
		sudo apt-get install -y tanzu-cli
			
		cp /usr/bin/tanzu /usr/local/bin/tanzu
		
	fi
	
	echo "tanzu-CLI Version:"
  tanzu version
	
}

function install_tanzu_pluginz()
{

	echo " "
  echo "Installing Tanzu-Plugins..."
  
  tanzu plugin group search --show-details
  tanzu plugin group search --name vmware-tanzu/default --show-details
  tanzu plugin install --group vmware-tap/default:v"$theTAPVersion"
  tanzu plugin group get vmware-tap/default:v"$theTAPVersion"
  
  echo "Tanzu-Plugins: "
  tanzu plugin list

}

function install_otherz()
{

	docker --version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then

		echo " "
		echo "Installing docker-CLI... "
		sudo apt-get update
		sudo apt-get install -y ca-certificates curl  gnupg  lsb-release
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
		
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
		sudo apt-get update
		sudo apt-get install -y docker-ce docker-ce-cli containerd.io -y
		sudo usermod -aG docker $USER
		
 	fi		
 	
	echo "docker-CLI version: "
	docker --version
		
	jq --version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then		
		
		echo "Installing jq-CLI..."
		sudo apt-get install -y jq
		
	fi
			
	echo "jq-CLI version: "			
	jq --version


	kp version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then		

		echo " "
		echo "Installing KPack kp-CLI v0.12.0..."
		
		wget "https://github.com/buildpacks-community/kpack-cli/releases/download/v0.12.0/kp-linux-amd64-0.12.0"
		cp -f ./kp-linux-amd64-0.12.0 /usr/local/bin/kp
		chmod +x /usr/local/bin/kp
		
	fi
	
	echo "kp-CLI Version:"
	kp version   

	sops --version &> /dev/null	
	returnVal=$?
	
	if [[ $returnVal -ne 0 || "$useForce" == "T" ]]; then		

		echo " "
		echo "Installing sops-CLI v3.7.3..."   
		curl -LO https://github.com/getsops/sops/releases/download/v3.7.3/sops-v3.7.3.linux.amd64
		mv sops-v3.7.3.linux.amd64 /usr/local/bin/sops
		chmod +x /usr/local/bin/sops		
	fi
	
	echo "sops-CLI Version: "
	sops --version
	
}

function create_tap_registry_secret()
{   

	echo "DELETING PREVIOUS TAP Registry Secret..."  
	  
	yes | tanzu secret registry delete tap-registry --namespace tap-install
	
	echo " "
	echo "Creating The TAP Registry Secret..."
	echo "   For Repo: $theTAPRegistryHostName"
	
	tanzu secret registry add tap-registry \
	  --username ${theTAPRegistryUserName} --password ${theTAPRegistryPassWord} \
		--server ${theTAPRegistryHostName} \
		--export-to-all-namespaces --yes --namespace tap-install

	echo "Current Tanzu Secrets: "	
	tanzu secret registry list -n tap-install
		
}

function setup_initial_secretz()
{
	
	echo " "
	echo "Creating Secrets in tap-install namespace..."

	echo "Creating Tanzu Secret: registry-credentials..."	
	tanzu secret registry delete registry-credentials --namespace tap-install
	tanzu secret registry add registry-credentials --server $theTAPRegistryLoginServer --username $theTAPRegistryUserName --password $theTAPRegistryPassWord --namespace tap-install
	
	#kubectl delete secret registry-credentials -n tap-install	
	#kubectl create secret docker-registry registry-credentials --docker-server=$theTAPRegistryLoginServer --docker-username=$theTAPRegistryUserName --docker-password=$theTAPRegistryPassWord -n tap-install
 	
	echo "Creating Tanzu Secret: image-secret..."	
	tanzu secret registry delete image-secret --namespace tap-install
 	tanzu secret registry add image-secret --server $theTAPRegistryLoginServer --username $theTAPRegistryUserName --password $theTAPRegistryPassWord --namespace tap-install
   
	#kubectl delete secret image-secret -n tap-install   
  #kubectl create secret docker-registry image-secret --docker-server=$theTAPRegistryLoginServer --docker-username=$theTAPRegistryUserName --docker-password=$theTAPRegistryPassWord -n tap-install

	if [[  "$theCloud" == "AKS" ]]; then

		echo "Creating Tanzu Secret: lsp-pull-credentials..."	
		tanzu secret registry delete lsp-pull-credentials --namespace tap-install
		tanzu secret registry add lsp-pull-credentials --server $theTAPRegistryLoginServer --username $theTAPRegistryUserName --password $theTAPRegistryPassWord --namespace tap-install --yes
			
		echo "Creating Tanzu Secret: lsp-push-credentials..."		
		tanzu secret registry delete lsp-push-credentials --namespace tap-install
		tanzu secret registry add lsp-push-credentials --server $theTAPRegistryLoginServer --username $theTAPRegistryUserName --password $theTAPRegistryPassWord --namespace tap-install --yes

  fi
  
}


function copy_tap_packages()
{

	# better be docker login'd into source registry! 
	# better be docker login'd into target registry!

	echo " "
  echo "***WARNING: You better be docker log'd into 2x !!!"  
	
  echo "Adding TAP Registry As TAP Repository..."  
	 
	tanzu package repository add tanzu-tap-repository \
	  --url ${theTAPRegistryHostName}/${theTAPRegistryRepoName}/tap-packages:${theTAPVersion} \
	  --namespace tap-install


	# TanzuRegistry -> TAPRegistry
  # Naming: 
  #	./tap/tap-1.5.4/tap-packages
  # ./tap/tap-1.5.4/tap-workloads

	echo "Copying TAP Packages From Tanzu Registry To TAP Registry..."  
	
  imgpkg copy --include-non-distributable-layers -b \
  	${theTanzuRegistryHostName}/tanzu-application-platform/tap-packages:${theTAPVersion} \
  	--to-repo ${theTAPRegistryHostName}/${theTAPRegistryRepoName}/tap-packages

	echo "Copying Cluster-Essentials-Bundle From Tanzu Registry To TAP Registry..."  
	
	imgpkg copy --include-non-distributable-layers -b \
	  registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:ca8584ff2ad4a4cf7a376b72e84fd9ad84ac6f38305767cdfb12309581b521f5 \
	  --to-repo ${theTAPRegistryHostName}/${theTAPRegistryRepoName}/cluster-essentials-bundle
	  
# HERE DUDE Add TS_ClusterEssentials evar handling..
	  

}



#
# Main
#

	if [  "$1" == "-F" ] || [ "$1" == "-f" ] 
		then
	    useForce="T"
	fi		

	if [  "$1" == "-H" ] || [ "$1" == "-h" ] || [ "$1" == "--H" ] || [ "$1" == "--h" ] || [ "$1" == "-help" ] || [ "$1" == "--help" ]
		then
			usage
			exit 10
	fi		

	currentDir=""
	currentDir=$("pwd")

	load_params
  display_params

	if [[ "$theCloud" == "AKS" ]]; then
		install_aks
	fi

	if [[ "$theCloud" == "AWS" ]]; then
		install_aws			
	fi
	
	if [[ "$theCloud" == "GKE" ]]; then
		install_gke			
	fi

	setup_initial_secretz

	install_otherz
		
	install_tap_prereqs
	
	install_tanzu_cli_pkg
	
	install_tanzu_pluginz
	
	create_tap_registry_secret	
	
	copy_tap_packages	
	
	cd $currentDir

