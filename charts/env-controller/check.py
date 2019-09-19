# -*- coding:utf-8 -*-
__Author__ = '昊赜<caihong.lch@alibaba-inc.com>'
"""
   运行时依赖检查: 部署或异常恢复情况下保证顺序
"""
import os
import time
import random
import logging
import commands
import base64

from kubernetes import client, config
from kubernetes.client.rest import ApiException

caCrt="""{{ca.crt}}"""
token="""{{token}}"""
core_k8s_cfg_name = "kube-external-config"
core_k8s_cfg_namespace = "kube-system"
local_core_k8s_cfg_path = "/root/core_cfg"
config.load_incluster_config()
api_instance = client.CoreV1Api()
appsv1beta1_instance = client.AppsV1beta1Api()

# Appinstance crd info
group = "apps.mwops.alibaba-inc.com"
version = "v1alpha1"
namespace = "ark-system"
plural = "appinstances"
mysqlha_type = "apps.mwops.alibaba-inc.com/v1alpha1.database.mysqlha"
xdb_type = "apps.mwops.alibaba-inc.com/v1alpha1.database.xdb"


class Appinstance(object):

    def __init__(self, name):
        self.AppinstanceName = name
        config.load_kube_config(config_file=local_core_k8s_cfg_path)
        self.Client = client.CustomObjectsApi()
        logging.info("My appinstance name:%s" % self.AppinstanceName)
        self.Appinstance = self.get_appinstance(self.AppinstanceName)
        if not self.Appinstance:
            logging.error("Exception when get custom_object of Appinstance %s" % name)
            exit(1)
        self.Dependency = self.Appinstance.get("spec", []).get("dependencies", [])
        self.Dependency = [d for d in self.Dependency if
                           d.get("instanceName") != "coredns-0"]
        logging.info("All dependencies: %s" % self.Dependency)

    def get_appinstance(self, name):
        try:
            appinsatnce = self.Client.get_namespaced_custom_object(group=group,
                                                                   version=version,
                                                                   namespace=namespace,
                                                                   plural=plural,
                                                                   name=name)
        except ApiException as e:
            logging.error("Exception when calling CustomObjectsApi->get_namespaced_custom_object %s: %s" % (name, e))
            return None
        return appinsatnce

    def update_appinstance(self):
        try:
            self.Appinstance = self.get_appinstance(self.AppinstanceName)
        except ApiException as e:
            logging.error("Exception when get custom_object of Appinstance %s" % self.AppinstanceName)
            exit(1)
        self.Dependency = [d for d in self.Dependency if
                           d.get("instanceName") != "coredns-0"]

    def check_one_appinstance_status(self, name):
        appinstance = self.get_appinstance(name)
        if not appinstance:
            return False, "Appinstance {} don't exist".format(name)

        if appinstance.get("status").get("Phase") == "Ready":
            return True, None
        else:
            Message = appinstance.get("status").get("Message")
            return False, Message

    def check_dependencies_until_all_successed(self):
        while True:
            RandomSleep()
            OK = True
            self.update_appinstance()
            while not CheckCoredns():
                RandomSleep()
                continue
            for instance in self.Dependency:
                instanceOK = True
                for i in range(10):
                    # check db
                    if instance.get("instanceName") == "mysqlha-0":
                        instanceOK = CheckMysqlha(self.Appinstance)
                        if instanceOK:
                            instanceOK = True
                            break
                        else:
                            instanceOK = False
                            RandomSleep()

                    # check appinstance status
                    status, message = self.check_one_appinstance_status(instance.get("instanceName"))
                    if status:
                        instanceOK = True
                        logging.info("The status of Appinstance %s is ready." % instance.get("instanceName"))
                        break
                    else:
                        logging.warning("The status of Appinstance %s is NotReady. Message: %s" % (
                            instance.get("instanceName"), message))
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


def initKubeoneCfg():
    body = client.CoreV1Api().read_namespaced_config_map(core_k8s_cfg_name, core_k8s_cfg_namespace)
    # print body
    if "core_cfg" in body.data:
        kubecfg = body.data["core_cfg"]
    f = open(local_core_k8s_cfg_path, 'w+')
    f.write(kubecfg)
    f.close()


def initLogging(logFilename):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s-%(levelname)s- %(message)s',
        datefmt='%y-%m-%d %H:%M',
        filename=logFilename,
        filemode='w');
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s-%(levelname)s: %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)


def GetInitInfo():
    env_dist = os.environ
    mychart = env_dist.get('MyChart')
    logging.info("Start checking the dependence for the release %s" % mychart)
    return mychart

#
# def CheckCoredns():
#     body = appsv1beta1_instance.read_namespaced_deployment("coredns", "kube-system")
#     for i in range(3):
#         if body.status.replicas == body.status.ready_replicas:
#             logging.info("The status of coredns is ready.")
#             return True
#         else:
#             logging.warning("The status of coredns is not ready.")
#             RandomSleep()
#             continue
#     return False

#
# def CheckMysqlha(appinstance):
#     resources = appinstance.get("spec").get("resources")
#     if not resources:
#         return True
#     for r in resources:
#         if r.get("type") == mysqlha_type:
#             mysql_host = "db.acs-system"
#             mysql_port = 3306
#             mysql_user = "root"
#             mysql_password = "aliyun_cos"
#             mysql_ping = commands.getstatusoutput(
#                 "mysqladmin -u" + mysql_user + " -p" + mysql_password + " -h" + mysql_host + " ping")
#             if mysql_ping[0] != 0:
#                 logging.info("db_host:%s  db_port:%s  db_user:%s" % (mysql_host, mysql_port, mysql_user))
#                 logging.warning("The status of database is not ready.")
#                 logging.error("mysqladmin ping error:%s" % mysql_ping[1])
#                 return False
#             else:
#                 logging.info("The status of database is ready.")
#         elif r.get("type") == xdb_type:
#             for wl in appinstance.get("spec").get("workloadSettings"):
#                 if wl.get("name") == "deployToNamespace":
#                     namespace = wl.get("name")
#             for p in r.get("parameterValues"):
#                 xdb_sectet_name = p.get("value")
#                 body = api_instance.read_namespaced_secret(xdb_sectet_name, namespace)
#                 db_host = base64.b64decode(body.data.get("db_host"))
#                 db_password = base64.b64decode(body.data.get("db_password"))
#                 db_port = base64.b64decode(body.data.get("db_port"))
#                 db_user = base64.b64decode(body.data.get("db_user"))
#                 checkdb = "mysqladmin -u{db_user} -P{db_port} -p{db_password} -h{db_host} ping".format(db_user=db_user,
#                                                                                                        db_port=db_port,
#                                                                                                        db_password=db_password,
#                                                                                                        db_host=db_host)
#                 mysql_ping = commands.getstatusoutput(checkdb)
#                 if mysql_ping[0] != 0:
#                     logging.info("db_host:%s  db_port:%s  db_user:%s" % (db_host, db_port, db_user))
#                     logging.error("mysqladmin ping error:%s" % mysql_ping[1])
#                     return False
#                 else:
#                     logging.info("xdb is ready. db_host:%s db_user:%s", db_host, db_user)
#     return True


def RandomSleep():
    time.sleep(random.randint(5, 10))


if __name__ == '__main__':
    initLogging('logger.log')
    logging.info("Check program is running ...")
    initKubeoneCfg()
    # my_appinstance_name = GetInitInfo()
    my_appinstance_name = '-'.join(GetInitInfo().split("-")[:-1])
    my_appinstance_name = '-'.join([my_appinstance_name, "0"])
    my_appinstance_name = my_appinstance_name.replace(".", "-")
    app = Appinstance(my_appinstance_name)
    app.check_dependencies_until_all_successed()