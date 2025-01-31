#!/bin/bash

# Tap install for version: 1.5.4

echo "############# Create Target Namespace ####################"
kubectl create namespace dev1

tanzu secret registry list -n tap-install


echo "############# DELETEING PREVIOUS Tanzu Application Platform package repository to the cluster ####################"
tanzu package repository delete tanzu-tap-repository -n tap-install --yes

echo "############# Adding Tanzu Application Platform package repository to the cluster ####################"
tanzu package repository add tanzu-tap-repository --url $TS_TAP_REGISTRY_HOSTNAME/$TS_TAP_REGISTRY_REPO_NAME/tap-packages --namespace tap-install

tanzu package repository get tanzu-tap-repository --namespace tap-install

echo "############# List the available packages ####################"
tanzu package available list --namespace tap-install

echo "############# Tanzu Application Platform Package Repository Status ####################"
tanzu package repository list -A

echo "############### TAP ${TAP_VERSION} Install   ##################"
tanzu package install tap -p tap.tanzu.vmware.com -v ${TAP_VERSION} --values-file ./tap-values-${TAP_VERSION}-acr.yaml -n tap-install

# HERE DUDE! for now...til I figure out the rest below...
exit 1010

tanzu package installed list -A

reconcilestat=$(tanzu package installed list -A -o json | jq ' .[] | select(.status == "Reconcile failed: Error (see .status.usefulErrorMessage for details)" or .status == "Reconciling")' | jq length | awk '{sum=sum+$0} END{print sum}')

if [ $reconcilestat > '0' ];
    then
	tanzu package installed list -A
	sleep 20m
	echo "################# Wait for 20 minutes #################"
	tanzu package installed list -A
	tanzu package installed get tap -n tap-install
	reconcilestat1=$(tanzu package installed list -A -o json | jq ' .[] | select(.status == "Reconcile failed: Error (see .status.usefulErrorMessage for details)" or .status == "Reconciling")' | jq length | awk '{sum=sum+$0} END{print sum}')
	if [ $reconcilestat1 > '0' ];
	   then
		echo "################### Something is wrong with package install, Check the package status manually ############################"
		echo "################### Exiting #########################"
		exit
	else
		tanzu package installed list -A
		echo "################### Please check if all the packages are succeeded ############################"
		tanzu package installed get tap -n tap-install
	fi
else
	ip=$(kubectl get svc -n tap-gui -o=jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}')
        sed -i -r "s/lbip/$ip/g" "$HOME/tap-script/tap-values.yaml"
        tanzu package installed update tap --package-name tap.tanzu.vmware.com --version ${TAP_VERSION} -n tap-install -f $HOME/tap-script/tap-values.yaml
fi

echo "############## Get the package install status #################"
tanzu package installed get tap -n tap-install
tanzu package installed list -A


echo "############# Updating tap-values file with LB ip ################"

ip=$(kubectl get svc -n tap-gui -o=jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}')
hostname=$(kubectl get svc -n tap-gui -o=jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}')

if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];
 then
   sed -i -r "s/lbip/$ip/g" "$HOME/tap-script/tap-values.yaml"
else
  sed -i -r "s/lbip/$hostname/g" "$HOME/tap-script/tap-values.yaml"
fi

tanzu package installed update tap --package-name tap.tanzu.vmware.com --version ${TAP_VERSION} -n tap-install -f $HOME/tap-script/tap-values.yaml
tanzu package installed list -A

echo "################ Cluster supply chain list #####################"
tanzu apps cluster-supply-chain list

echo "################ Developer namespace in tap-install #####################"

cat <<EOF > developer.yaml
---
apiVersion: v1
kind: Secret
metadata:
  name: tap-registry
  annotations:
    secretgen.carvel.dev/image-pull-secret: ""
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: e30K

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: default
secrets:
  - name: registry-credentials
imagePullSecrets:
  - name: registry-credentials
  - name: tap-registry

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: default
rules:
- apiGroups: [source.toolkit.fluxcd.io]
  resources: [gitrepositories]
  verbs: ['*']
- apiGroups: [source.apps.tanzu.vmware.com]
  resources: [imagerepositories]
  verbs: ['*']
- apiGroups: [carto.run]
  resources: [deliverables, runnables]
  verbs: ['*']
- apiGroups: [kpack.io]
  resources: [images]
  verbs: ['*']
- apiGroups: [conventions.apps.tanzu.vmware.com]
  resources: [podintents]
  verbs: ['*']
- apiGroups: [""]
  resources: ['configmaps']
  verbs: ['*']
- apiGroups: [""]
  resources: ['pods']
  verbs: ['list']
- apiGroups: [tekton.dev]
  resources: [taskruns, pipelineruns]
  verbs: ['*']
- apiGroups: [tekton.dev]
  resources: [pipelines]
  verbs: ['list']
- apiGroups: [kappctrl.k14s.io]
  resources: [apps]
  verbs: ['*']
- apiGroups: [serving.knative.dev]
  resources: ['services']
  verbs: ['*']
- apiGroups: [servicebinding.io]
  resources: ['servicebindings']
  verbs: ['*']
- apiGroups: [services.apps.tanzu.vmware.com]
  resources: ['resourceclaims']
  verbs: ['*']
- apiGroups: [scanning.apps.tanzu.vmware.com]
  resources: ['imagescans', 'sourcescans']
  verbs: ['*']

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: default
subjects:
  - kind: ServiceAccount
    name: default
---
apiVersion: scanning.apps.tanzu.vmware.com/v1beta1
kind: ScanPolicy
metadata:
  name: scan-policy
spec:
  regoFile: |
    package policies

    default isCompliant = false

    # Accepted Values: "Critical", "High", "Medium", "Low", "Negligible", "UnknownSeverity"
    violatingSeverities := ["Critical","High","UnknownSeverity"]
    ignoreCVEs := []

    contains(array, elem) = true {
      array[_] = elem
    } else = false { true }

    isSafe(match) {
      fails := contains(violatingSeverities, match.Ratings.Rating[_].Severity)
      not fails
    }

    isSafe(match) {
      ignore := contains(ignoreCVEs, match.Id)
      ignore
    }

    isCompliant = isSafe(input.currentVulnerability)

EOF
kubectl apply -f developer.yaml -n tap-install
kubectl apply -f tekton-pipeline.yaml -n tap-install
cat <<EOF > ootb-supply-chain-basic-values.yaml
grype:
  namespace: tap-install
  targetImagePullSecret: registry-credentials
EOF

echo "################### Installing Grype Scanner ##############################"
tanzu package install grype-scanner --package-name grype.scanning.apps.tanzu.vmware.com --version ${TAP_VERSION}  --namespace tap-install -f ootb-supply-chain-basic-values.yaml

echo "################### Creating workload ##############################"
#tanzu -n dev1 apps workload create tanzu-java-web-app-aks -f workload-tanzu-java-web-app-aks.yaml
#tanzu -n dev1 apps workload get tanzu-java-web-app-aks

tanzu -n default apps workload create tanzu-java-web-app-aks -f workload-tanzu-java-web-app-aks.yaml
tanzu -n default apps workload get tanzu-java-web-app-aks


echo "#######################################################################"
echo "################ Monitor the progress #################################"
echo "#######################################################################"
#tanzu -n dev1 apps workload tail tanzu-java-web-app-aks --since 10m --timestamp

tanzu -n default apps workload tail tanzu-java-web-app-aks --since 10m --timestamp
