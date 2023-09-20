#!/bin/bash

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
tanzu package installed update tap --package-name tap.tanzu.vmware.com --version 1.3.2 -n tap-install -f $HOME/tap-script/tap-values.yaml
tanzu package installed list -A

echo "################ Cluster supply chain list #####################"
tanzu apps cluster-supply-chain list

echo "################ Developer namespace in tap-install #####################"

cat <<EOF > developer.yaml
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
tanzu package install grype-scanner --package-name grype.scanning.apps.tanzu.vmware.com --version 1.3.2  --namespace tap-install -f ootb-supply-chain-basic-values.yaml
echo "################### Creating workload ##############################"
tanzu apps workload create tanzu-java-web-app  --git-repo https://github.com/Eknathreddy09/tanzu-java-web-app --git-branch main --type web --label apps.tanzu.vmware.com/has-tests=true --label app.kubernetes.io/part-of=tanzu-java-web-app  --type web -n tap-install --yes
tanzu apps workload get tanzu-java-web-app -n tap-install
echo "#######################################################################"
echo "################ Monitor the progress #################################"
echo "#######################################################################"
tanzu apps workload tail tanzu-java-web-app --since 10m --timestamp -n tap-install
