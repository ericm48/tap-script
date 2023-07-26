#!/bin/bash

read -p "Enter the Tanzu network username: " tanzunetusername
read -p "Enter the Tanzu network password: " tanzunetpassword
export INSTALL_REGISTRY_USERNAME=$tanzunetusername
export INSTALL_REGISTRY_PASSWORD=$tanzunetpassword
export INSTALL_REGISTRY_HOSTNAME=registry.tanzu.vmware.com

echo "################# Create namespace ###########################"
kubectl create ns tap-install

echo "################# Create secret tap-registry ##############################"
tanzu secret registry add tap-registry --username ${INSTALL_REGISTRY_USERNAME} --password ${INSTALL_REGISTRY_PASSWORD} --server ${INSTALL_REGISTRY_HOSTNAME} --export-to-all-namespaces --yes --namespace tap-install

echo "############# Adding Tanzu Application Platform package repository to the cluster ####################"
tanzu package repository add tanzu-tap-repository --url registry.tanzu.vmware.com/tanzu-application-platform/tap-packages:1.5.0 --namespace tap-install

#tanzu package repository add tanzu-tap-repository --url registry.tanzu.vmware.com/tanzu-application-platform/tap-packages:1.4.2 --namespace tap-install
#tanzu package repository add tanzu-tap-repository --url registry.tanzu.vmware.com/tanzu-application-platform/tap-packages:1.3.2 --namespace tap-install

tanzu package repository get tanzu-tap-repository --namespace tap-install
echo "############# List the available packages ####################"
tanzu package available list --namespace tap-install

echo "############### TAP 1.5.0 Install   ##################"
tanzu package install tap -p tap.tanzu.vmware.com -v 1.5.0 --values-file $HOME/tap-script/tap-values.yaml -n tap-install

#echo "############### TAP 1.4.2 Install   ##################"
#tanzu package install tap -p tap.tanzu.vmware.com -v 1.4.2 --values-file $HOME/tap-script/tap-values.yaml -n tap-install
#tanzu package install tap -p tap.tanzu.vmware.com -v 1.3.2 --values-file $HOME/tap-script/tap-values.yaml -n tap-install

tanzu package installed list -A
