# -*- coding:utf-8 -*-
__Author__ = '九辩<jiangyu.zjy@alibaba-inc.com>'
"""
   运行时依赖检查: 部署或异常恢复情况下保证顺序
"""
import os
import time
import random
import logging
import commands
import base64
import yaml
import traceback

from kubernetes import client, config
from kubernetes.client.rest import ApiException

caCrt="""{{ca.crt}}"""
token="""{{token}}"""
local_core_k8s_cfg_path = "/root/core_cfg"
config.load_incluster_config()
default_namespace = "default"

kubeConfig = """apiVersion: v1
kind: Config
users:
- name: env-controller
  user:
    token: %s
clusters:
- cluster:
    certificate-authority-data: %s
    server: https://kubernetes/
  name: self-hosted-cluster
contexts:
- context:
    cluster: self-hosted-cluster
    user: env-controller
  name: svcs-acct-context
current-context: svcs-acct-context
""" % (token, caCrt)

def writeKubeConfig():
    with open(local_core_k8s_cfg_path, 'w') as fp:
        fp.write(kubeConfig)

class Appinstance(object):

    def __init__(self):
        config.load_kube_config(config_file=local_core_k8s_cfg_path)
        self.Dependency = self.get_dependency()


    def get_dependency(self):
        dependencyConfigMapName = str(os.getenv("MyChart")) + ".dependency"
        #TODO use namespace var instead of "default"
        try:
            dependencyConfigMap = client.CoreV1Api().read_namespaced_config_map(dependencyConfigMapName, default_namespace)
            dependenciesStr = dependencyConfigMap.data['Dependency.yaml']
            if not dependenciesStr:
                return None
            return yaml.load(dependenciesStr).get("dependencies", [])
        except ApiException as e:
            traceback.print_exc()
            return None

    def is_deployment_ready(self, deployment):
        return deployment.status.available_replicas == deployment.status.replicas

    def is_statefulset_ready(self, statefulset):
        return statefulset.status.ready_replicas == statefulset.status.replicas

    def is_job_ready(self, job):
        return job.spec.completions == job.status.succeeded

    def check_one_appinstance_status(self, name, version):
        myChartLabel = "MyChart=%s-%s" % (name, version)
        appLabel = "app=%s" % name
        try:
            checked = False
            returnObj = client.ExtensionsV1beta1Api().list_namespaced_deployment(default_namespace, label_selector=appLabel)
            deployments = returnObj.items
            if len(deployments) != 0:
                checked = True
                for deployment in deployments:
                    if not self.is_deployment_ready(deployment):
                        return False
            returnObj = client.AppsV1beta1Api().list_namespaced_stateful_set(default_namespace, label_selector=appLabel)
            statefulsets = returnObj.items
            if len(statefulsets) != 0:
                checked = True
                for statefulset in statefulsets:
                    if not self.is_statefulset_ready(statefulset):
                        return False
                    else:
                        if name == 'vipserver':
                            time.sleep(150)
            returnObj = client.BatchV1Api().list_namespaced_job(default_namespace, label_selector=appLabel)
            jobs = returnObj.items
            if len(jobs) != 0:
                checked = True
                for job in jobs:
                    if not self.is_job_ready(job):
                        return False
            return checked
        except ApiException as e:
            traceback.print_exc()
        return False

    def check_dependencies_until_all_successed(self):
        if not self.Dependency:
            return True
        while True:
            RandomSleep()
            OK = True
            for instance in self.Dependency:
                instanceOK = True
                for i in range(10):
                    # check appinstance status
                    status = self.check_one_appinstance_status(instance.get("name"), instance.get("version"))
                    if status:
                        instanceOK = True
                        print "The status of Appinstance %s-%s is ready." % (instance.get("name"), instance.get("version"))
                        break
                    else:
                        logging.warning("The status of Appinstance %s-%s is NotReady." % (
                            instance.get("name"), instance.get("version")))
                        instanceOK = False
                        RandomSleep()
                if instanceOK:
                    continue
                else:
                    OK = False
                    break
            if OK:
                logging.info("All dependencies is checked ok.")
                return True

def RandomSleep():
    time.sleep(random.randint(5, 10))

if __name__ == '__main__':
    writeKubeConfig()
    app = Appinstance()
    app.check_dependencies_until_all_successed()