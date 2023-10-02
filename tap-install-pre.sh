#!/bin/bash  

#
# Notes:
#
#										Installs TAP pre-reqs, namley:
#										-Cluster-Essentials
#                   -TAP-Cli-Compoents
#
# -19-Sept-2023:     Do not trust the pivnet file-id's.  These tend to be wrong.
# 									 Go out to: https://network.pivotal.io/products/tanzu-application-platform
#                    Pull up the cluster-essentials or tap-cli, then goto the download link,
#                    and copy it from there.  Same is true for the SHA.
#

# set -x


theCloud=""
thePivNetToken=""

theTanzuRegistryHostName=""
theTanzuNetUserName=""
theTanzuNetPassWord=""

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

function usage() {

  echo ""
  echo "Usage: $0 -Installs TAP-PreReqs to a target cloud." 
  echo ""
  echo ""
  echo "Options: "
  echo ""
  echo "  -A number of parameters can be exported to evars to reduce cycle-time."
  echo "   These are prefaced with TS_ below."  
  echo ""
  echo "  Also MAKE SURE you are docker login'd to BOTH, BEFORE RUNNING:"
  echo "     -registry.tanzu.vmware.com"
  echo "     -your-target-registry"
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
	echo "     export TS_CLUSTER_NAME='tap-cluster-153'"
	echo "     export TS_AZURE_SUBSCRIPTION='-the-token-'"
	echo "     export TS_AZURE_REGION='eastus'"
	echo "     export TS_TAP_VERSION='1.5.4'"	
	echo ""
	echo ""
	echo ""		
  
}

function load_params() {
  
  if [[ -z $TS_TARGET_CLOUD ]]; then
		echo "######################## Type: AKS for Azure, EKS for Amazon, GKE for Google ########################"
		echo "############################ If you choose EKS, Keep docker.io credentials handy ######################"
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
	echo "     TargetCloud: $theCloud"
	echo "     PivNetToken: $thePivNetToken"	
	echo "     GithubToken: $theGithubToken"		
	echo ""

	echo "     TanzuNetRegistryHostName: $theTanzuRegistryHostName"	
	echo "             TanzuNetUserName: $theTanzuNetUserName"	
	echo "             TanzuNetPassWord: ***"	# theTanzuNetPassWord
	echo ""
	
	echo "     TAPRegistryHostName: $theTAPRegistryHostName"	
	echo "     TAPRegistryRepoName: $theTAPRegistryRepoName"
	echo "     TAPRegistryUserName: $theTAPRegistryUserName"	
	echo "     TAPRegistryPassWord: ***"	# theTanzuNetPassWord
	echo "              TAPVersion: $theTAPVersion"	
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
	
	read -p "Press ENTER to proceed or ctrl-c to end." theResponse

}
	
function install_aks()
{	
	 
	 echo "#################  Installing AZ cli #####################"
	 curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   echo "#########################################"
   echo "################ AZ CLI version #####################"
   az --version   

   echo "#####################################################################################################"
   echo "#############  Authenticate to AZ cli by following the screen Instructions below ####################"
   echo "#####################################################################################################"
	 az login
   
   echo "#########################################"
   echo "Resource group created with name eric-tap-east-rg in region and the subscription mentioned above"
   echo "#########################################"
	 az group create --name eric-tap-east-rg --location $theAzureRegion --subscription $theAzureSubscription

   echo "#########################################"
	 echo "Creating AKS cluster with 3 node and sku as Standard_B8ms"
   echo "#########################################"
   az aks create --resource-group eric-tap-east-rg --name $theClusterName --subscription $theAzureSubscription --node-count 3 --enable-addons monitoring --generate-ssh-keys --node-vm-size Standard_B8ms -z 1 --enable-cluster-autoscaler --min-count 3 --max-count 3

   echo "############### Created AKS Cluster ###############"
	 echo "############### Install kubectl ##############"
	 
	 sudo az aks install-cli
	 
	 echo "############### Set the context ###############"
	 az account set --subscription $theAzureSubscription
	 az aks get-credentials --resource-group eric-tap-east-rg --name $theClusterName
	 
	 echo "############## Verify the nodes #################"
   echo "#####################################################################################################"
	 kubectl get nodes
   
   echo "#####################################################################################################"
	 echo "###### Create RG for Repo  ######"
	 az group create --name eric-tap-workshop-imagerepo-rg --location $theAzureRegion
	 
	 echo "####### Create container registry  ############"
   echo "#####################################################################################################"
	 az acr create --resource-group eric-tap-workshop-imagerepo-rg --name ericmtaptestdemoacr --sku Standard
	 
	 echo "####### Fetching acr Admin credentials ##########"
	 az acr update -n ericmtaptestdemoacr --admin-enabled true
   acrusername=$(az acr credential show --name ericmtaptestdemoacr --query "username" -o tsv)
   acrloginserver=$(az acr show --name ericmtaptestdemoacr --query loginServer -o tsv)
   acrpassword=$(az acr credential show --name ericmtaptestdemoacr --query passwords[0].value -o tsv)
   if grep -q "/"  <<< "$acrpassword";
       then
			    acrpassword1=$(az acr credential show --name ericmtaptestdemoacr --query passwords[1].value -o tsv)
			    if grep -q "/"  <<< "$acrpassword1";
			      then
          	   echo "##########################################################################"
	   					 echo "Update the password manually in tap-values file(repopassword): password is $acrpassword1 "
            	 echo "###########################################################################"
    			else
		   			acrpassword=$acrpassword1
	        fi
   else
      echo "PassWord Updated in tap values file"
   fi
   
   echo "######### Preparing the tap-values file ##########"
   sed -i -r "s/tanzunetusername/$tanzunetusername/g" "$HOME/tap-script/tap-values.yaml"
   sed -i -r "s/tanzunetpassword/$tanzunetpassword/g" "$HOME/tap-script/tap-values.yaml"
   sed -i -r "s/registryname/$acrloginserver/g" "$HOME/tap-script/tap-values.yaml"
   sed -i -r "s/repousername/$acrusername/g" "$HOME/tap-script/tap-values.yaml"
   sed -i -r "s/repopassword/$acrpassword/g" "$HOME/tap-script/tap-values.yaml"
   sed -i -r "s/domainname/$domainname/g" "$HOME/tap-script/tap-values.yaml"
   sed -i -r "s/githubtoken/$githubtoken/g" "$HOME/tap-script/tap-values.yaml"

   echo "####################################################################"
   echo "########### Creating Secrets in tap-install namespace  #############"
   echo "####################################################################"
      
   kubectl create ns tap-install
   kubectl create secret docker-registry registry-credentials --docker-server=$acrloginserver --docker-username=$acrusername --docker-password=$acrpassword -n tap-install
   kubectl create secret docker-registry image-secret --docker-server=$acrloginserver --docker-username=$acrusername --docker-password=$acrpassword -n tap-install

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
	echo "############# Installing Pivnet CLI ###########"
	wget https://github.com/pivotal-cf/pivnet-cli/releases/download/v3.0.1/pivnet-linux-amd64-3.0.1
	chmod +x pivnet-linux-amd64-3.0.1
	sudo mv pivnet-linux-amd64-3.0.1 /usr/local/bin/pivnet
	   
	echo "########## Downloading Tanzu Cluster Essentials #############"
	pivnet login --api-token=${thePivNetToken}
	
	
	pivnet download-product-files --product-slug='tanzu-cluster-essentials' --release-version="$theTAPVersion" --product-file-id=1583335
	
	#pivnet download-product-files --product-slug='tanzu-cluster-essentials' --release-version=1.6.1 --product-file-id=1358494   
	#pivnet download-product-files --product-slug='tanzu-cluster-essentials' --release-version='1.5.3' --product-file-id='1553881'
	#pivnet download-product-files --product-slug='tanzu-cluster-essentials' --release-version='1.4.0' --product-file-id=1407185
	#pivnet download-product-files --product-slug='tanzu-cluster-essentials' --release-version='1.3.0' --product-file-id=1330470
	
	rm -rfv $HOME/tanzu-cluster-essentials
	mkdir $HOME/tanzu-cluster-essentials
	
	tar -xvf tanzu-cluster-essentials-linux-amd64-"$theTAPVersion".tgz -C $HOME/tanzu-cluster-essentials
	
	# tar -xvf tanzu-cluster-essentials-linux-amd64-1.5.3.tgz -C $HOME/tanzu-cluster-essentials
	# tar -xvf tanzu-cluster-essentials-linux-amd64-1.4.0.tgz -C $HOME/tanzu-cluster-essentials
	# tar -xvf tanzu-cluster-essentials-linux-amd64-1.3.0.tgz -C $HOME/tanzu-cluster-essentials 	      
	
	
	#export INSTALL_BUNDLE='registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:4b071c4ca187e727664012b4a197c22ebe3d3dd04938771330fa0db768c1e3a4' #v1.5.3
	#export INSTALL_BUNDLE=registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256-61dff81ced8a604c82e88f4fb78f4eacb1bc27492cf6a07183702137210d6d74     
	#export INSTALL_BUNDLE=registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:2354688e46d4bb4060f74fca069513c9b42ffa17a0a6d5b0dbb81ed52242ea44
	#export INSTALL_BUNDLE=registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:54bf611711923dccd7c7f10603c846782b90644d48f1cb570b43a082d18e23b9     
   
   
	#
	# Set these eVARS!! The cluster-essential's install.sh below, requires these 
	# INSTALL_ eVars be set!  Even tho we already downloaded it...doh!
	#
																																																		 
	export INSTALL_BUNDLE='registry.tanzu.vmware.com/tanzu-cluster-essentials/cluster-essentials-bundle@sha256:5ce0dcf500b1292abd621147ac0b17cef4503d827aa1c06dffc744891fc36077' #v1.5.4!
	export INSTALL_REGISTRY_HOSTNAME=${theTanzuRegistryHostName}
	export INSTALL_REGISTRY_USERNAME=${theTanzuNetUserName}
	export INSTALL_REGISTRY_PASSWORD=${theTanzuNetPassWord}
   
	echo "######## Installing Cluster-Essentials ###########"
	cd $HOME/tanzu-cluster-essentials
	
	#
	# More games with BAD install scripts..
	#
	printf 'yy' | ./install.sh
	
	echo "######## Installing Kapp ###########"
	sudo cp $HOME/tanzu-cluster-essentials/kapp /usr/local/bin/kapp
	sudo cp $HOME/tanzu-cluster-essentials/imgpkg /usr/local/bin/imgpkg
	echo "#################################"
	kapp version

   
}	# End of install_tap_prereqs


function install_tanzu_cli_pivnet()
{

   echo "######## Installing Tanzu-CLI From Pivnet ###########"

	 #pivnet download-product-files --product-slug='tanzu-application-platform' --release-version='1.5.3' --product-file-id='1478717'	 
	 #pivnet download-product-files --product-slug='tanzu-application-platform' --release-version='1.5.0' --product-file-id=1404618
	 #pivnet download-product-files --product-slug='tanzu-application-platform' --release-version='1.4.0' --product-file-id=1404618
   #pivnet download-product-files --product-slug='tanzu-application-platform' --release-version='1.3.0' --product-file-id=1310085
   
   rm -rfv $HOME/tanzu     
   mkdir $HOME/tanzu
   
   tar -xvf tanzu-framework-linux-amd64-v0.28.1.3.tar -C $HOME/tanzu
          
   #tar -xvf tanzu-framework-linux-amd64.tar -C $HOME/tanzu
	 #tar -xvf tanzu-framework-linux-amd64-v0.25.4.tar -C $HOME/tanzu

   export TANZU_CLI_NO_INIT=true
   
   cd $HOME/tanzu
	 sudo install cli/core/v0.28.1/tanzu-core-linux_amd64 /usr/local/bin/tanzu     
	 
	 #sudo install cli/core/v0.25.4/tanzu-core-linux_amd64 /usr/local/bin/tanzu	 		
	 #sudo install cli/core/v0.25.0/tanzu-core-linux_amd64 /usr/local/bin/tanzu
	 
   tanzu version
   
   tanzu plugin install --local cli all
   tanzu plugin list

}

function install_tanzu_cli_pkg()
{

  echo "######## Installing Tanzu-CLI From Package-Mgr ###########"
  
	sudo mkdir -p /etc/apt/keyrings/
	sudo apt-get update
	sudo apt-get install -y ca-certificates curl gpg
	
	curl -fsSL https://packages.vmware.com/tools/keys/VMWARE-PACKAGING-GPG-RSA-KEY.pub | sudo gpg --yes --dearmor -o /etc/apt/keyrings/tanzu-archive-keyring.gpg
	echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/tanzu-archive-keyring.gpg] https://storage.googleapis.com/tanzu-cli-os-packages/apt tanzu-cli-jessie main" | sudo tee /etc/apt/sources.list.d/tanzu.list
	sudo apt-get update
	sudo apt-get install -y tanzu-cli

	cp /usr/bin/tanzu /usr/local/bin/tanzu
  tanzu version
	
}

function install_tanzu_pluginz()
{

  echo "######## Installing Tanzu-Plugins ###########"
  
  tanzu plugin group search --show-details
  tanzu plugin group search --name vmware-tanzu/default --show-details
  tanzu plugin install --group vmware-tap/default:v"$theTAPVersion"
  tanzu plugin group get vmware-tap/default:v"$theTAPVersion"
  
  tanzu plugin list

}

function install_otherz()
{
   echo "######### Installing Docker ############"
   sudo apt-get update
   sudo apt-get install -y ca-certificates curl  gnupg  lsb-release
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
   
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   sudo apt-get update
   sudo apt-get install -y docker-ce docker-ce-cli containerd.io -y
   sudo usermod -aG docker $USER

   echo "####### Verify JQ Version  ###########"
   sudo apt-get install -y jq
   jq --version
}


function create_tap_registry_secret()
{   

	echo "######### DELETING PREVIOUS TAP Registry Secret ############"  
	  
	yes | tanzu secret registry delete tap-registry --namespace tap-install
	
	echo ""
	echo "######### Creating The TAP Registry Secret ############"
	echo " For Repo: $theTAPRegistryHostName"
	
	tanzu secret registry add tap-registry \
	  --username ${theTAPRegistryUserName} --password ${theTAPRegistryPassWord} \
		--server ${theTAPRegistryHostName} \
		--export-to-all-namespaces --yes --namespace tap-install
	
	tanzu secret registry list -n tap-install
		
}

function copy_tap_packages()
{

	# better be docker login'd into source registry
	# better be docker login'd into target registry

  echo "######### *** WARNING: You better be docker log'd into 2X !!! ############"  
	
  echo "######### Adding TAP Registry As TAP Repository ############"  
	 
	tanzu package repository add tanzu-tap-repository \
	  --url ${theTAPRegistryHostName}/${theTAPRegistryRepoName}/tap-packages:${theTAPVersion} \
	  --namespace tap-install

  echo "######### Copying TAP Packages To TAP Registry ############"  

  imgpkg copy --include-non-distributable-layers -b \
  	${theTanzuRegistryHostName}/tanzu-application-platform/tap-packages:${theTAPVersion} \
  	--to-repo ${theTanzuRegistryHostName}/${theTanzuRepoName}/tap-packages

}



#
# Main
#
	if [  "$1" == "-H" ] || [ "$1" == "-h" ] || [ "$1" == "--H" ] || [ "$1" == "--h" ] || [ "$1" == "-help" ] || [ "$1" == "--help" ]
		then
			usage
			exit 10
	fi		

	currentDir=""
	currentDir=$("pwd")

	load_params
  display_params


	create_tap_registry_secret	
	
	exit 23	

	if [[ "$theCloud" == "AKS" ]]; then
		install_aks
	fi

	if [[ "$theCloud" == "AWS" ]]; then
		install_aws			
	fi
	
	if [[ "$theCloud" == "GKE" ]]; then
		install_gke			
	fi
	
	install_tap_prereqs
	
	install_tanzu_cli_pkg
	
	install_tanzu_pluginz
	
	install_otherz  
	
	create_tap_registry_secret	
	
	cd $currentDir

