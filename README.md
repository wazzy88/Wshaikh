

---

## ELK-Stack-Project Start to End walkthrough

Introduction

 This repository was created to show the configuration of the cloud network built on the azure platform, along with the penetration testing of the cloud infrastructure.
 
 The objective here is to briefly cover the following in three main areas:
 
Part 1 
- A visual of the network via a network diagram.
- A description of the deployment of the cloud infrastucture toplogy

Part 2
- Tables specifying access policies and network addresses.

Part 3
- Elastic Search, Logstash and Kibana (ELK) introduction and usage.
- A description of the investigation completed using Kibana dashboard.
 
These files have been tested and used to generate an automated ELK Stack Deployment on Azure. They can be used to either recreate the entire deployment figured below. Otherwise, select portions of the YAML files may be used to install only certain pieces of it, for example, Filebeat and Metricbeat.

  - [pentest.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/ansible_config.yml)
  - [install-elk.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/install-elk.yml)
  - [filebeat-config.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/filebeat-configuration.yml)
  - [filebeat-playbook.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/filebeat-playbook.yml)
  - [metricbeat-config.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/metricbeat-configuration.yml)
  - [metricbeat-playbook.yml](https://github.com/wazzy88/Wshaikh/blob/a1bda298d92c82ecf7cc548282bc9bb43bc87656/Configuration%20Files/metricbeat-playbook.yml)

---

### Part 1 - Description of the Topology

The main purpose of this network is to expose a traffic to high level cloud infrastructre with monitoring measures and mitigation techniques.

<details>
<summary> <b> Click here to view Virtual Networks overview. </b> </summary>
	
---
	
> Cloud Diagram
	
![vNet Diagram]()
	
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
	
 - The brains of the operation -computers! My off-premesis computers built on the cloud are vital to the enrity of the network. They run the commands to make connections for pentesting and also to house containers.  
	
![Virtual Machines - VMs](https://github.com/wazzy88/Wshaikh/blob/019e7b6b84aa59e0f4f4563b976bcb6803307a56/Azure%20Pictures/09.04.2022_13.31.16_REC.png)
	
> Load Balancer

- The load balancer's main purpose is to distribute web traffic across multiple servers. In our network, the load balancer was installed in front of the VM to 
   - protect Azure resources within virtual networks.
   - monitor and log the configuration and traffic of virtual networks, subnets, and NICs.
   - protect critical web applications
   - deny communications with known malicious IP addresses
   - record network packets
   - deploy network-based intrusion detection/intrusion prevention systems (IDS/IPS)
   - manage traffic to web applications
   - minimize complexity and administrative overhead of network security rules
   - maintain standard security configurations for network devices
   - document traffic configuration rules
   - use automated tools to monitor network resource configurations and detect changes
	
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
 
The idea in our cloud was to bring a 'zero trust model'. Here access was given via NSG through rule setting on specific IP Adresses (listed below). This was companied with crypto keys - public key authentication to help ensure our network held a critiera for securirty.
 
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
 
![PeeringsELKtoRed]()
 
![PeeringsRedtoELK] () 

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
 
![connect_on_newVM]()  
 
- Copy the SSH key from the Ansible container on our jump box:
   - RUN `cat id_rsa.pub` Configure a new VM using that SSH key.
 
#### Created an Ansible play to install and configure an ELK instance.

In this step, we have to:
- Add our new VM to the Ansible hosts file.
- Create a new Ansible playbook to use for our new ELK virtual machine.
- From our Ansible container, add the new VM to Ansible's hosts file.
   - RUN `nano /etc/ansible/hosts` and put our IP with `ansible_python_interpreter=/usr/bin/python3`

![hosts file editing]()  

- In the below play, representing the header of the YAML file, I defined the title of my playbook based on the playbook's main goal by setting the keyword 'name:' to: "Configure Elk VM with Docker". Next, I defined the user account for the SSH connection, by setting the keyword 'remote_user:' to "sysadmin" then activated privilege escalation by setting the keyword 'become:' to "true". 
 
 The playbook implements the following tasks:

```yaml
---
- name: Configure Elk VM with Docker
  hosts: elk
  remote_user: sysadmin
  become: true
  tasks:
```
 
In this play, the ansible package manager module is tasked with installing docker.io. The keyword 'update_cache:' is set to "yes" to download package information from all configured sources and their dependencies prior to installing docker, it is necessary to successfully install docker in this case. Next the keyword 'state:' is set to "present" to verify that the package is installed.


```yaml
     # Use apt module
    - name: Install docker.io
      apt:
        update_cache: yes
        name: docker.io
        state: present
```

In this play, the ansible package manager module is tasked with installing  'pip3', a version of the 'pip installer' which is a standard package manager used to install and maintain packages for Python.
The keyword 'force_apt_get:' is set to "yes" to force usage of apt-get instead of aptitude. The keyword 'state:' is set to "present" to verify that the package is installed.

```yaml
      # Use apt module
    - name: Install pip3
      apt:
        force_apt_get: yes
        name: python3-pip
        state: present
```

In this play the pip installer is used to install docker and also verify afterwards that docker is installed ('state: present').

```yaml
      # Use pip module
    - name: Install Docker python module
      pip:
        name: docker
        state: present
```

In this play, the ansible sysctl module configures the target virtual machine (i.e., the Elk server VM) to use more memory. On newer version of Elasticsearch, the max virtual memory areas is likely to be too low by default (ie., 65530) and will result in the following error: "elasticsearch | max virtual memory areas vm.max_map_count [65530] likely too low, increase to at least [262144]", thus requiring the increase of vm.max_map_count to at least 262144 using the sysctl module (keyword 'value:' set to "262144"). The keyword 'state:' is set to "present" to verify that the change was applied. The sysctl command is used to modify Linux kernel variables at runtime, to apply the changes to the virtual memory variables, the new variables need to be reloaded so the keyword 'reload:' is set to "yes" (this is also necessary in case the VM has been restarted).

```yaml
      # Use sysctl module
    - name: Use more memory
      sysctl:
        name: vm.max_map_count
        value: "262144"
        state: present
        reload: yes
```

In this play, the ansible docker_container module is used to download and launch our Elk container. The container is pulled from the docker hub repository. The keyword 'image:' is set with the value "sebp/elk:761", "sebp" is the creator of the container (i.e., Sebastien Pujadas). "elk" is the container and "761" is the version of the container. The keyword 'state:' is set to "started" to start the container upon creation. The keyword 'restart_policy:' is set to "always" and will ensure that the container restarts if we restart our web vm. Without it, we will have to restart our container when we restart the machine.
The keyword 'published_ports:' is set with the 3 ports that are used by our Elastic stack configuration, i.e., "5601" is the port used by Kibana, "9200" is the port used by Elasticsearch for requests by default and "5400" is the default port Logstash listens on for incoming Beats connections (we will go over the Beats we installed in the following section "Target Machines & Beats").

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

In this play, the ansible systemd module is used to start docker on boot, setting the keyword 'enabled:' to "yes".

```yaml
      # Use systemd module
    - name: Enable service docker on boot
      systemd:
        name: docker
        enabled: yes
```
![Install_elk_yml]()

Now we can start launching and exposing the container by run

```bash
ansible-playbook install-elk.yml
```

The following screenshot displays the result of running `install-elk.yml`

![Docker ELKResult output]()

SSH to our container: ```ssh sysadmin@10.1.0.4``` and RUN ```sudo docker ps```

The following screenshot displays the result of running `docker ps` after successfully configuring the Elastic Stack instance.

![Docker InstallELK output]()

Logging into the Elk server and manually launch the ELK container with: 

```bash
sudo docker start elk
```
then ```curl http://localhost:5601/app/kibana``` does return HTML.

The following screenshot displays the result of running `curl` after start ELK container

![Docker curl output]()

#### Restricted access to the new server.
	
This step is to restrict access to the ELK VM using Azure's network security groups (NSGs). We need to add public IP address to a whitelist, just as we did when clearing access to jump box.

Go to Network Security Group to config our host IP to Kibana as follow

![Docker InboundSecRules output]()

Then try to access web browser to http://<your.ELK-VM.External.IP>:5601/app/kibana 
 
![Access_Kibana]()

</details>

---

### Target Machines & Beats
This ELK server is configured to monitor the following machines:

- Web-1 (DVWA 1) | 10.0.0.5
- Web-2 (DVWA 2) | 10.0.0.6

I have installed the following Beats on these machines:

- Filebeat
- Metricbeat

<details>
<summary> <b> Click here to view Target Machines & Beats. </b> </summary>

---

	
These Beats allow us to collect the following information from each machine:

`Filebeat`: Filebeat detects changes to the filesystem. I use it to collect system logs and more specifically, I use it to detect SSH login attempts and failed sudo escalations.

We will create a [filebeat-config.yml](https://github.com/Diablo5G/ELK-Stack-Project/blob/main/Ansible/filebeat-config.yml) and [metricbeat-config.yml](https://github.com/Diablo5G/ELK-Stack-Project/blob/main/Ansible/metricbeat-config.yml) configuration files, after which we will create the Ansible playbook files for both of them.

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

![Filebeat_playbook]() 
 
- RUN `ansible-playbook filebeat-playbook.yml`

![Filebeat_playbook_result]()  

Verify that our playbook is completed by navigate back to the Filebeat installation page on the ELK server GUI

![Filebeat_playbook_verify]()
	
![Filebeat_playbook_verify1]()
		
	
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

![Metricbeat_playbook]()  
 
- RUN `ansible-playbook metricbeat-playbook.yml`

![Metricbeat_playbook_result]()  

Verify that this playbook is completed by navigate back to the Filebeat installation page on the ELK server GUI

![Metricbeat_playbook_verify]()

 
</details>

---
 
### Using the Playbook

Next, I want to verify that `filebeat` and `metricbeat` are actually collecting the data they are supposed to and that my deployment is fully functioning.

To do so, I have implemented 3 tasks:

1. Generate a high amount of failed SSH login attempts and verify that Kibana is picking up this activity.
2. Generate a high amount of CPU usage on my web servers and verify that Kibana picks up this data.
3. Generate a high amount of web requests to my web servers and make sure that Kibana is picking them up.
	
<details>
<summary> <b> Click here to view Using the Playbook. </b> </summary>

---


#### Generating a high amount of failed SSH login attempts:

To generate these attempts I intentionally tried to connect to my Web-1 web server from the Jump Box instead of connecting from my Ansible container in order to generate failed attempts (the server can't verify my private key outside of the container). All ELK Stack scripts refer to [Elk_Stack_scripts.sh](https://github.com/Diablo5G/ELK-Stack-Project/blob/main/Linux/Elk_Stack_scripts.sh)

To do so I used the following short script to automate 1000 failed SSH login attempts: 


```bash
for i in {1..1000}; do ssh Web_1@10.0.0.5; done
```

![ssh failed attempts]()


Next We check Kibana to see if the failed attempts were logged:


![filebeat failed ssh attempts]()

I can see that all the failed attempts were detected and sent to Kibana.

- Now Let's breakdown the syntax of my previous short script:

   - `for` begins the `for` loop.

   - `i in` creates a variable named `i` that will hold each number `in` our list.

   - `{1..1000}` creates a list of 1000 numbers, each of which will be given to our `i` variable.

   - `;` separates the portions of our `for` loop when written on one line.

   - `do` indicates the action taken by each loop.

   - `ssh sysadmin@10.0.0.5` is the command run by `do`.

   - `;` separates the portions of our for loop when it's written on one line.

   - `done` closes the `for` loop.

- Now I can run the same short script command with a few modifications, to test that `filebeat` is logging all failed attempts on all web servers where `filebeat` was deployed.

I want to run a command that will attempt to SSH into multiple web servers at the same time and continue forever until I stop it:

```bash
while true; do for i in {5..6}; do ssh Web_1@10.0.0.$i; done
```

- Now let's breakdown the syntax of my previous short script:

   - `while` begins the `while` loop.

   - `true` will always be equal to `true` so this loop will never stop, unless we force quit it.

   - `;` separates the portions of our `while` loop when it's written on one line.

   - `do` indicates the action taken by each loop.

   - `i in` creates a variable named `i` that will hold each number in our list.

   - `{5..6}` creates a list of numbers (5 and 6), each of which will be given to our `i` variable.

   - `ssh sysadmin@10.0.0.$i` is the command run by `do`. It is passing in the `$i` variable so the `wget` command will be run on each server, i.e., 10.0.0.5, 10.0.0.6 (Web-1, Web-2).


Next, I want to confirm that `metricbeat` is functioning. To do so I will run a linux stress test.


#### Generating a high amount of CPU usage on my web servers (Web-1, Web-2) and confirming that Kibana is collecting the data.


1. From my Jump Box, I start my Ansible container with the following command:

```bash
sudo docker start goofy_wright && sudo docker attach goofy_wright
```

2. Then, SSH from my Ansible container to Web-1.

```bash
ssh sysadmin@10.0.0.5
```

3. Install the `stress` module with the following command:

```bash
sudo apt install stress
```

4. Run the service with the following command and let the stress test run for a few minutes:

```bash
sudo stress --cpu 1
```

   - _Note: The stress program will run until we quit with Ctrl+C._
	
Next, view the Metrics page for that VM in Kibana and comparing 2 of web servers to see the differences in CPU usage, confirmed that `metricbeat` is capturing the increase in CPU usage due to our stress command:

![cpu stress test results]()


Another view of the CPU usage metrics Kibana collected:

![cpu stress test results graph]()


#### Generate a high amount of web requests to both web servers and make sure that Kibana is picking them up.

This time we will generate a high amount of web requests directed to one of my web servers. To do so, I will use `wget` to launch a DoS attack.

1. Log into my Jump Box Provisioner
	
   - ```bash
        ssh sysadmin@<jump-box-provisioner>
     ``` 

2. We need to add a new firewall rule to allow my Jump Box (10.0.0.4) to connect to my web servers over HTTP on port 80. To do so, I add a new Inbound Security Rule to Red-Team Network Security Group:

![jump to http to webservers]()


3. Run the following command to download the file `index.html` from Web-1 VM:

   - ```bash
        wget 10.0.0.5
     ```

Output of the command:

![index html download]()


4. Confirm that the file has been downloaded with the `ls` command:


   - ```bash
        sysadmin@Jump-Box-Provisioner:~$ ls 
        index.html
     ```

5. Next, run the `wget` command in a loop to generate a very high number of web requests, I will use the `while` loop:

   - ```bash
        while true; do wget 10.0.0.5; done
     ```

The result is that the `Load`, `Memory Usage` and `Network Traffic` were hit as seen below:

![load increase DoS](https://github.com/Diablo5G/ELK-Stack-Project/blob/main/Resources/Images/load%20increase%20DoS.png)

After stopping the `wget` command, I can see that thousands of index.html files were created (as seen below).


![index html files]()


I can use the following command to clean that up:

```bash
rm *
```

Now if we use `ls` again, the directory is a lot cleaner:


![directory cleanup]()


I can also avoid the creation of the `index.html` file by adding the flag `-O` to my command so that I can specify a destination file where all the `index.html` files will be concatenated and written to.

Since I don't want to save the `index.html` files, I will not write them to any output file but instead send them directly to a directory that doesn't save anything, i.e., `/dev/null`. 

I use the following command to do that:


```bash
while true; do wget 10.0.0.5 -O /dev/null; done
```

Now, if I want to perform the `wget` DoS request on all my web servers, I can use the previous command I used to generate failed SSH login attempts on all my web servers, but this time I will tweak the command to send `wget` requests to all webservers:

```bash
while true; do for i in {5..6}; do wget -O /dev/null 10.0.0.$i; done
```

Note that we need to press CTRL + C to stop the `wget` requests since I am using the `while` loop.


My Elastic Stack server is now functioning and correctly monitoring my load-balanced exposed DVWA web application.

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
