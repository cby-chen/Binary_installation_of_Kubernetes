# 手动部署：https://github.com/cby-chen/Kubernetes


**声明**，该脚本不及互联网上其他大佬的一件脚本，该脚本仅仅是突发奇想编写的，希望大佬不喜勿喷。

  

这个脚本执行环境比较苛刻，我写的这个脚本比较垃圾，还未能达到各种环境下都可以执行。  

  

当前脚本Kubernetes集群，以及lb负载均衡，需要在CentOS系统，执行脚本节点可以选择Ubuntu或者CentOS系统。  

  

当前脚本中引用的Kubernetes二进制包是v1.23.3 v1.23.4 v1.23.5 v1.23.6. v1.24.0 v1.24.1 v1.24.2


  

| 主机名称 | IP地址 | 说明 | 软件 |
| --- | --- | --- | --- |
| Master01 | 192.168.1.81 | master节点 | kube-apiserver、kube-controller-manager、kube-scheduler、etcd、kubelet、kube-proxy、nfs-client |
| Master02 | 192.168.1.82 | master节点 | kube-apiserver、kube-controller-manager、kube-scheduler、etcd、kubelet、kube-proxy、nfs-client |
| Master03 | 192.168.1.83 | master节点 | kube-apiserver、kube-controller-manager、kube-scheduler、etcd、kubelet、kube-proxy、nfs-client |
| Node01 | 192.168.1.84 | node节点 | kubelet、kube-proxy、nfs-client |
| Node02 | 192.168.1.85 | node节点 | kubelet、kube-proxy、nfs-client |
| Node03 | 192.168.1.86 | node节点 | kubelet、kube-proxy、nfs-client |
| Node04 | 192.168.1.87 | node节点 | kubelet、kube-proxy、nfs-client |
| Node05 | 192.168.1.88 | node节点 | kubelet、kube-proxy、nfs-client |
| Lb01 | 192.168.1.80 | node节点 | kubelet、kube-proxy、nfs-client |
| Lb02 | 192.168.1.90 | node节点 | kubelet、kube-proxy、nfs-client |
|  | 192.168.1.89 | vip |  |
| cby | 192.168.1.60 | 执行脚本节点 | bash |


作者：陈步云  
微信：15648907522

脚本项目地址：https://github.com/cby-chen/Binary_installation_of_Kubernetes

手动项目地址：https://github.com/cby-chen/Kubernetes

# 使用说明：
该脚本示例需要八台服务器，在八台服务器中有一台是用于执行该脚本的，  
另外有六台k8s服务器，其他俩台作为lb负载均衡服务器。  
将其中服务器配置好静态IP，修改如下变量中的IP即可。  
同时查看服务器中的网卡名，并将其修改。  
执行脚本可使用bash -x 即可显示执行中详细信息。  
该脚本已适配centos7和centos8。  
脚本中hosts有俩处，记得修改。  
在执行过程中，新开窗口输入   
tail -f *.txt   
可以查看到具体信息  


```
脚本中是需要在GitHub上下载软件包

手动提前下载好

wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/cby/Kubernetes.tar
wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/v1.23.4/kubernetes-v1.23.4.tar
wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/v1.23.5/kubernetes-v1.23.5.tar
wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/v1.23.6/kubernetes-v1.23.6.tar

wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/v1.24.0/kubernetes-v1.24.0.tar
wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/v1.24.1/kubernetes-v1.24.1.tar
wget  https://ghproxy.com/https://github.com/cby-chen/Kubernetes/releases/download/v1.24.2/kubernetes-v1.24.2.tar

下载脚本

备用1
wget https://raw.githubusercontent.com/cby-chen/Binary_installation_of_Kubernetes/main/Binary_installation_of_Kubernetes_v1.23.sh
wget https://raw.githubusercontent.com/cby-chen/Binary_installation_of_Kubernetes/main/Binary_installation_of_Kubernetes_v1.24.sh
备用2
wget "https://cdn.jsdelivr.net/gh/cby-chen/Binary_installation_of_Kubernetes@master/Binary_installation_of_Kubernetes_v1.23.sh"
wget "https://cdn.jsdelivr.net/gh/cby-chen/Binary_installation_of_Kubernetes@master/Binary_installation_of_Kubernetes_v1.24.sh"
备用3
wget https://www.oiox.cn/Binary_installation_of_Kubernetes_v1.23.sh
wget https://www.oiox.cn/Binary_installation_of_Kubernetes_v1.24.sh


修改参数

vim Binary_installation_of_Kubernetes.sh

如下：

#每个节点的IP，以及vip
export k8s_master01="192.168.1.61"
export k8s_master02="192.168.1.61"
export k8s_master03="192.168.1.63"
export k8s_node01="192.168.1.64"
export k8s_node02="192.168.1.65"
export k8s_node03="192.168.1.66"
export k8s_node04="192.168.1.67"
export k8s_node05="192.168.1.68"
export lb_01="192.168.1.57"
export lb_02="192.168.1.58"
export lb_vip="192.168.1.59"

#物理网络ip地址段，注意反斜杠转译
export ip_segment="192.168.1.0\/24"

#k8s自定义域名
export domain="x.oiox.cn"

#服务器网卡名
export eth="ens18"


修改hosts（有俩处）

cat > /etc/hosts <<EOF
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
$k8s_master01 k8s-master01
$k8s_master02 k8s-master02
$k8s_master03 k8s-master03
$k8s_node01 k8s-node01
$k8s_node02 k8s-node02
$k8s_node03 k8s-node03
$k8s_node04 k8s-node04
$k8s_node05 k8s-node05
$lb_01 lb01
$lb_02 lb02
$lb_vip lb-vip
EOF

执行脚本

bash -x Binary_installation_of_Kubernetes.sh


```
dashboard
```
查看端口号
kubectl get svc kubernetes-dashboard -n kubernetes-dashboard

查看token

1.23：
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep admin-user | awk '{print $1}')

1.24：
kubectl -n kubernetes-dashboard create token admin-user

```
# 更新

------
2022-03更新  
现已支持centos7 和centos8 自动适配  
同时支持自定义k8s node节点结构  
在变量中需要几台节点就写几台节点即可  
注意的是，新增节点，要在脚本中的hosts中也要修改  
不建议乱改。


------
2022-04更新  
优化执行结构 更新版本选择 适配多版本 修复BUG

------
2022-04-06更新  
修复 selinux 关闭异常

------


2022-04-21更新  
新增v1.23.6 并修复BUG

------

2022-04-25更新  
为了节省按安装，优化安装结构，并修复BUG

------

2022-7-14更新：  
修复升级内核问题  新增1.24版本

------

> **关于**
>
> https://www.oiox.cn/
>
> https://www.oiox.cn/index.php/start-page.html
>
> **CSDN、GitHub、知乎、开源中国、思否、掘金、简书、华为云、阿里云、腾讯云、哔哩哔哩、今日头条、新浪微博、个人博客**
>
> **全网可搜《小陈运维》**
>
> **文章主要发布于微信公众号**
