

---

## ELK-Stack-Project Start to End walkthrough

Introduction

 This repository was created to show the configuration of the cloud network built on the Azure platform, along with the implementation of the ELK Stack and testing. 
 
 The objective here is to briefly cover the following sections divided into three main areas:
 
Part 1 
- A visual of the network via a network diagram.
- A description of the deployment of the cloud infrastructure topology

Part 2
- Tables specifying access policies and network addresses.

Part 3
- Elastic Search, Logstash and Kibana (ELK) introduction and usage.
- A description of the investigation completed using Kibana dashboard.
 
The six files below have been applied and tested to generate an automated ELK Stack Deployment on Azure. A more detailed walkthrough is explained in the readme below.

  - [pentest.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/ansible_config.yml)
  - [install-elk.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/install-elk.yml)
  - [filebeat-config.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/filebeat-configuration.yml)
  - [filebeat-playbook.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/filebeat-playbook.yml)
  - [metricbeat-config.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/metricbeat-configuration.yml)
  - [metricbeat-playbook.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/metricbeat-playbook.yml)

---

### Part 1 - Description of the Azure Network Topology

The below network diagram is a visual representation of the cloud based infrastructure on the Azure platform.

<details>
<summary> <b> Click here to view Virtual Networks overview. </b> </summary>
	
---
	
> Cloud Diagram
	
![vNet Diagram](https://github.com/wazzy88/Wshaikh/blob/9cca12bcc4bc06cbdb19967edbd6798e748d6c93/Resources/10.04.2022_12.14.42_REC.png)
	
Virtual networks?
> Azure platform
- The Azure cloud platform is designed to help users build, run, and manage applications across multiple clouds with the tools and frameworks of your choice. Thus, for the purpose of this project the cloud infrastructure was build using this very tool.

![Azure](https://github.com/wazzy88/Wshaikh/blob/907361d132b94690a9b37f309548b1cb019df902/Azure%20Pictures/09.04.2022_11.47.37_REC.png)
	
> Resource Groups
- This cloud build starts with a resouce group. A resource group is a container that holds related resources for an Azure solution. The resource group can include all the resources for the solution, or only those resources that you want to manage as a group. You decide how you want to allocate resources to resource groups based on what makes the most sense for your organization. 
	
![Azure RG](https://github.com/wazzy88/Wshaikh/blob/7e6b235a4209f4a6d7105f815160104d80737ea6/Azure%20Pictures/09.04.2022_13.10.30_REC.png)
	
---
Virtual Computing?
	
> Network Security Groups
	
 - A traffic filter, by creating 'rules' for both inbound and outbound connections to the cloud. This vital tool was essential for being the gatekeeper of harmful and unwanted connections to my clouds specific virtual networks (Was_RG).
	
![NSG](https://github.com/wazzy88/Wshaikh/blob/bdd70501ec7755838a515674fe9056a039bc88f8/Azure%20Pictures/09.04.2022_13.20.49_REC.png)
	
> Virtual Machines
	
 - The brains of the operation -computers! My off-premises computers built on the cloud are vital to the network. They run the commands to make connections for pentesting and also to house containers.  
	
![Virtual Machines - VMs](https://github.com/wazzy88/Wshaikh/blob/019e7b6b84aa59e0f4f4563b976bcb6803307a56/Azure%20Pictures/09.04.2022_13.31.16_REC.png)
	
> Load Balancer

- The load balancer's main purpose is to distribute web traffic across multiple servers. In our network, the load balancer was installed in front of the VM to 
   
   - monitor and log the configuration and traffic of virtual networks, subnets, and NICs.
   - protect critical web applications
   - deny communications with known malicious IP addresses
   - record network packets
   - deploy network-based intrusion detection/intrusion prevention systems (IDS/IPS)
   - manage traffic to web applications
   - act as secondary to network security rules and firewall protection
   - protect Azure resources within virtual networks.
	
![Load Balancer](https://github.com/wazzy88/Wshaikh/blob/58070d88bab622e39b9a026b4d142d6b4fa7d56e/Azure%20Pictures/09.04.2022_14.12.28_REC.png)
	
---
Jumpbox Useage
	
> What is the advantage of a jumpbox or Jump server?
- A "bridge" that connects to the NSG and in-turn to the outside world (internet). It provides a controlled way to access the vNet  It helps to improve security also prevents all Azure VM’s to expose to the public.
	

![JBOX](https://github.com/wazzy88/Wshaikh/blob/bfbe6c4f9e38101e628ef7623d136035afb02de9/Azure%20Pictures/09.04.2022_13.55.02_REC.png)
	
> Containers (Docker)
- A Docker container image is a lightweight, standalone, executable package of software that includes everything needed to run an application: code, runtime, system tools, system libraries and settings.Container images become containers at runtime and in the case of Docker containers – images become containers when they run on Docker Engine (docker_2022). 
	
> Provisioners (Ansible)
- A lighter version of Virtual Machine! Smaller, lighter, however does not need to be a full virtual machine and still carries out the application that another other VM would do. 
	
![Ansible](https://github.com/wazzy88/Wshaikh/blob/c0ea68d181e128218da236c6591cd1d7ba1820b8/Azure%20Pictures/0_Sr1T30hc8WT269jV.jpg)
	
---	

> The configuration details of each machine may be found below.
 
| Name     | Function | IP Address | Operating System |
|----------|----------|------------|------------------|
| Jump-Box-Provisioner | Gateway  | 20.75.255.192 ; 10.1.0.4   | Linux            |
| Web-1(VM)       |webserver    | 10.1.0.5     | Linux            |
| Web-2(VM)        |webserver    | 10.1.0.6     | Linux            |
| ELKServer(VM)    |Kibana       | 20.117.89.2 ; 10.0.0.4     | Linux            |
| RedTeam-LB|Load Balancer| 20.216.21.150| DVWA            |
 
In addition to the above, Azure has provisioned a load balancer in front of all machines except for the jump box. The load balancer's targets are organized into availability sets as: Web-1 and Web-2
	
</details>

---

### Part 2 - Access Policies
 
The idea in our cloud was to bring a 'zero trust model'. Here access was given via NSG through rule setting on specific IP Addresses (listed below). This was companied with crypto keys - public key authentication to help ensure our network held a criteria for security.
 
Only the Jump Box machine can accept connections from the Internet. Access to this machine is only allowed from the following IP addresses:20.75.255.192. Machines within the network can only be accessed by SSH with crypto key to the Jump Box.
 
A summary of the access policies in place can be found in the table below.
 
| Name     | Publicly Accessible | Allowed IP Addresses |
|----------|---------------------|----------------------|
| Jump-Box-Provisioner | Yes                 | 20.75.255.192        |
| ELKServer      | Yes                  |  20.117.89.2:5601        |
| DVWA 1   | No                  |  10.1.0.1-254        |
| DVWA 2   | No                  |  10.1.0.1-254        |


 
---


### Part 3 - ELK Configuration/Filebeats/Metric Beats
 
Elasticsearch, Logstash, and Kibana = ELK, with the addition of Beats for this project.

The goal for the ELK stack is most commonly used for monitoring, troubleshooting and securing IT environments, in this case our cloud environment on Azure. Beats and Logstash take care of data collection and processing, Elasticsearch indexes and stores the data, and Kibana provides a user interface for querying the data and visualizing it (Logz.io_ 2022).

Ansible was used to automate the configuration of the ELK server. This was advantageous because Ansible can be used to easily configure new machines, update programs, and configurations on hundreds of servers at once, and the best part is that the process is the same for multiple machines. 

> What is the main advantage of automating configuration with Ansible?
- Ansible is focusing on bringing a server to a certain state of operation.

<details>
<summary> <b> Click here to view ELK Configuration. </b> </summary>

---
 
Quick overview:
 
- Deployed a new ELK VM on a new ELK virtual network.
- Created an Ansible play to install and configure an ELK instance.
- Restricted access to the new server.
- Viewed results on Kibana dashboard.

#### Created a new virtual network for the ELK stack (steps below). 
 
1. Created a new vNet located in the same resource group, in a different region, then the original due to subscription limitations.

![Create vNet](https://github.com/wazzy88/Wshaikh/blob/4fbdf092775329c4275442e97dd5f133cdd6dde6/Ansible%20-%20ELK/09.04.2022_17.26.02_REC.png)  

2. Created a Peer connection between our vNets. This will allow traffic to pass between our vNets and regions. This peer connection will make both a connection from our first vNet to our second vNet and a reverse connection from our second vNet back to our first vNet. This will allow traffic to pass in both directions.
 
![PeeringsELKtoRed](https://github.com/wazzy88/Wshaikh/blob/8bcae66d3207d0832ba8f0282aedcf856ad9547a/Ansible%20-%20ELK/09.04.2022_17.26.32_REC.png)

3. Create a new Ubuntu VM in our virtual network with the following configurations:

   - ```bash
        ssh azuresuser@<VMJBOX-provisioner>
     ``` 
   - ```bash
        sudo docker container list -a
     ``` 
   - ```bash
        sudo docker start strange_mclean && sudo docker attach strange_mclean
     ``` 
 
![connect_on_newVM](https://github.com/wazzy88/Wshaikh/blob/34365a69002f9bb30a8f8bcff97281a58ee1d7ca/Ansible%20-%20ELK/09.04.2022_17.35.42_REC.png)  
 
- Copy the SSH key from the Ansible container on our jump box:
   - RUN `cat id_rsa.pub` Configure a new VM using that SSH key.
 
#### Created an Ansible play to install and configure an ELK server.

In this step, we have to:
- Add our new VM to the Ansible hosts file.
- Create a new Ansible playbook to use for our new ELK virtual machine.
- From our Ansible container, add the new VM to Ansible's hosts file.
   - RUN etc/ansible/, then nano into our file. 

![hosts file editing](https://github.com/wazzy88/Wshaikh/blob/adb47c7a2eed04b4aa4eae5977a3b62d87e93703/Resources/Hostsfile.png)  

-  The YAML file, will now configure Elk VM with Docker. Setup below: 
 
 The playbook implements the following tasks:

```yaml
---
- name: Configure Elk VM with Docker
  hosts: elk
  remote_user: sysadmin
  become: true
  tasks:
```
 
After which, the ansible package manager module will install docker.io. Setup below:


```yaml
     # Use apt module
    - name: Install docker.io
      apt:
        update_cache: yes
        name: docker.io
        state: present
```

Following the installation of the docker.io, the ansible package manager will add 'pip3', a version of the 'pip installer' which is a standard package manager used to install and maintain packages for Python. Setup below:

```yaml
      # Use apt module
    - name: Install pip3
      apt:
        force_apt_get: yes
        name: python3-pip
        state: present
```

A verification is needed after docker is installed. Setup below:

```yaml
      # Use pip module
    - name: Install Docker python module
      pip:
        name: docker
        state: present
```

Here the ansible sysctl module configures the target virtual machine this our case is the the Elk server VM, to config more memory. An  increase to at least 262144.

```yaml
      # Use sysctl module
    - name: Use more memory
      sysctl:
        name: vm.max_map_count
        value: "262144"
        state: present
        reload: yes
```
```yaml
      # Use docker_container module
    - name: download and launch a docker elk container
      docker_container:
        name: elk
        image: sebp/elk:761
        state: started
        restart_policy: always
        published_ports:
          - 5601:5601
          - 9200:9200
          - 5044:5044
```

 The ansible systemd module is used to start docker on boot.

```yaml
      # Use systemd module
    - name: Enable service docker on boot
      systemd:
        name: docker
        enabled: yes
```
	
Now we can start launching and exposing the container by run

```bash
ansible-playbook install-elk.yml
```

#### Restricted access to the new server.
	
This step is to restrict access to the ELK VM using Azure's from the ELK Network security group. See below:

![Docker InboundSecRules output](https://github.com/wazzy88/Wshaikh/blob/bd271b48579cef9fe6cfeec8954a2803d53296be/Resources/ELK%20allow%20from%20IP.png)

Then try to access web browser to http://<your.ELK-VM.External.IP>:5601/app/kibana 
 
![Access_Kibana]()

</details>

---

### Target Machines & Beats
This ELK server is configured to monitor the following machines:

- Web-1 (DVWA 1) | 10.1.0.5
- Web-2 (DVWA 2) | 10.1.0.6

I have installed the following Beats on these machines:

- Filebeat
- Metricbeat

<details>
<summary> <b> Click here to view Target Machines & Beats. </b> </summary>

---

	
These Beats allow us to collect the following information from each machine, so what do they do?

- Filebeat: Filebeat detects changes to the filesystem. 
- After which we will create the Ansible playbook files for both of them.
	
![filebeat-config.yml](https://github.com/wazzy88/Wshaikh/blob/e99c19079bddf8fcf5a28df0963250bcbb1f8b35/Resources/filebeatandmetricbeatsyntax.png) 

Once we have this file on our Ansible container, edit it as specified:
- The username is elastic and the password is changeme.
- Scroll to line #1106 and replace the IP address with the IP address of our ELK machine.
output.elasticsearch:
hosts: ["10.1.0.4:9200"]
username: "elastic"
password: "changeme"
- Scroll to line #1806 and replace the IP address with the IP address of our ELK machine.
	setup.kibana:
host: "10.1.0.4:5601"
- Save both files filebeat-config.yml and metricbeat-config.yml into `/etc/ansible/files/`

![files_FMconfig]() 
 
 
Next, create a new playbook that installs Filebeat & Metricbeat, and then create a playbook file, `filebeat-playbook.yml` & `metricbeat-playbook.yml`

RUN `nano filebeat-playbook.yml` to enable the filebeat service on boot by Filebeat playbook template below:

```yaml
---
- name: Install and Launch Filebeat
  hosts: webservers
  become: yes
  tasks:
    # Use command module
  - name: Download filebeat .deb file
    command: curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.4.0-amd64.deb
    # Use command module
  - name: Install filebeat .deb
    command: dpkg -i filebeat-7.4.0-amd64.deb
    # Use copy module
  - name: Drop in filebeat.yml
    copy:
      src: /etc/ansible/roles/install-filebeat/files/filebeat-config.yml
      dest: /etc/filebeat/filebeat.yml
    # Use command module
  - name: Enable and Configure System Module
    command: filebeat modules enable system
    # Use command module
  - name: Setup filebeat
    command: filebeat setup
    # Use command module
  - name: Start filebeat service
    command: service filebeat start
    # Use systemd module
  - name: Enable service filebeat on boot
    systemd:
      name: filebeat
      enabled: yes

```

![Filebeat_playbook](https://github.com/wazzy88/Wshaikh/blob/bd271b48579cef9fe6cfeec8954a2803d53296be/Resources/Filebeat%20playbookyml.png) 
 
- RUN `ansible-playbook filebeat-playbook.yml`

![Filebeat_playbook_install](https://github.com/wazzy88/Wshaikh/blob/bd271b48579cef9fe6cfeec8954a2803d53296be/Resources/Installing%20filebeat.png)  

Verify that our playbook is completed by navigate back to the Filebeat installation page on the ELK server GUI
	
![Filebeat_playbook_verify1](https://github.com/wazzy88/Wshaikh/blob/bd271b48579cef9fe6cfeec8954a2803d53296be/Resources/Kibana.png)
		
	
`Metricbeat`: Metricbeat detects changes in system metrics, such as CPU usage and memory usage.

RUN `nano metricbeat-playbook.yml` to enable the metricbeat service on boot by Metricbeat playbook template below:

```yaml
---
- name: Install and Launch Metricbeat
  hosts: webservers
  become: true
  tasks:
    # Use command module
  - name: Download metricbeat
    command: curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-7.4.0-amd64.deb
    # Use command module
  - name: install metricbeat
    command: dpkg -i metricbeat-7.4.0-amd64.deb
    # Use copy module
  - name: drop in metricbeat config
    copy:
      src: /etc/ansible/roles/install-metricbeat/files/metricbeat-config.yml
      dest: /etc/metricbeat/metricbeat.yml
    # Use command module
  - name: enable and configure docker module for metric beat
    command: metricbeat modules enable docker
    # Use command module
  - name: setup metric beat
    command: metricbeat setup
    # Use command module
  - name: start metric beat
    command: service metricbeat start
    # Use systemd module
  - name: Enable service metricbeat on boot
    systemd:
      name: metricbeat
      enabled: yes
```

![Metricbeat_playbook](https://github.com/wazzy88/Wshaikh/blob/bd271b48579cef9fe6cfeec8954a2803d53296be/Resources/Metricbeat%20playbookyml.png)  
 
- RUN `ansible-playbook metricbeat-playbook.yml`

![Metricbeat_playbook_result](https://github.com/wazzy88/Wshaikh/blob/bd271b48579cef9fe6cfeec8954a2803d53296be/Resources/Installing%20metricbeat.png)  

Verify that this playbook is completed by navigate back to the Filebeat installation page on the ELK server GUI to ensure it is fully running. 
	
That concludes the overview for the setup of the ELK server from azure the cloud to a visual representation on the Kibana dashboard.
	
Thank you. 
 
</details>

---


### Citations and References:

#### General Resources:

- [`elk-docker` Container Documentation](https://elk-docker.readthedocs.io/)
- [Elastic.co: The Elastic Stack](https://www.elastic.co/elastic-stack)
- [Ansible Documentation](https://docs.ansible.com/ansible/latest/index.html)
- [`elk-docker` Image Documentation](https://elk-docker.readthedocs.io/#elasticsearch-logstash-kibana-elk-docker-image-documentation)
- [Virtual Memory Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/5.0/vm-max-map-count.html#vm-max-map-count)
- [Docker Commands Cheatsheet](https://phoenixnap.com/kb/list-of-docker-commands-cheat-sheet)

#### Azure Documentation:

- Azure's page on peer networks: [Network-Peering](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview)
- Peer networking in Azure How-To: [Global vNet Peering](https://azure.microsoft.com/en-ca/blog/global-vnet-peering-now-generally-available/)
- Microsoft Support: [How to open a support ticket](https://docs.microsoft.com/en-us/azure/azure-portal/supportability/how-to-create-azure-support-request)

---
