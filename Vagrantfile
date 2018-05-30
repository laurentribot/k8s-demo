# -*- mode: ruby -*-
# vi: set ft=ruby :

servers = [
  { name: 'k8s-controller', autostart: true, ip: '192.168.56.11' },
  { name: 'k8s-worker-0', autostart: true, ip: '192.168.56.12' },
  { name: 'k8s-worker-1', autostart: true, ip: '192.168.56.13' },
  { name: 'k8s-demo', autostart: true, ip: '192.168.56.10' }
]

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/bionic64"
  config.ssh.username = 'vagrant'
  config.ssh.insert_key = true

  servers.each do |server|

    config.vm.define server[:name], autostart: server[:autostart] do |box|

      box.vm.hostname = "#{server[:name]}"
      box.vm.network "private_network", ip: "#{server[:ip]}", auto_config: false

      box.vm.synced_folder "../data", "/vagrant_data"
      box.vm.synced_folder "./ansible", "/ansible"

      box.vm.provision "file", source: "scripts/network/netplan-#{server[:name]}", destination: "/tmp/netplan"
      box.vm.provision "file", source: "scripts/network/hosts", destination: "/tmp/hosts"
      box.vm.provision "file", source: "scripts/network/sysctl.conf", destination: "/tmp/sysctl.conf"

      # Configuration de l'interface réseau private network
      box.vm.provision "shell", privileged: true, inline: "cat /tmp/netplan > /etc/netplan/50-cloud-init.yaml"

      # Ajout des VMs au fichier /etc/hosts
      box.vm.provision "shell", privileged: true, inline: "cat /tmp/hosts >> /etc/hosts"

      # Activation ssh par password
      box.vm.provision "shell", privileged: true, inline: "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config"
      box.vm.provision "shell", privileged: true, inline: "systemctl restart sshd.service"

      # Désactivation ipv6
      # box.vm.provision "shell", privileged: true, inline: "cat /tmp/sysctl.conf > /etc/sysctl.d/99-sysctl.conf && sysctl -p"
      box.vm.provision "shell", privileged: true, inline: "netplan apply"
      box.vm.provision "shell", privileged: true, inline: "sed 's/preserve_hostname: false/preserve_hostname: true/' -i /etc/cloud/cloud.cfg"

      # User ansible
      box.vm.provision "file", source: "scripts/users/create-users.sh", destination: "/tmp/create-users.sh"
      box.vm.provision "shell", privileged: true, inline: "bash /tmp/create-users.sh"

      # Config apt
      box.vm.provision "file", source: "scripts/apt/config-apt.sh", destination: "/tmp/config-apt.sh"
      box.vm.provision "shell", privileged: true, inline: "bash /tmp/config-apt.sh"

      box.vm.provision "shell", privileged: true, inline: "apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install python2.7 python-pip sshpass -q -y"

      if "#{server[:name]}" == 'k8s-demo'

        box.vm.provision "file", source: "scripts/pypi/install-pypi.sh", destination: "/tmp/install-pypi.sh"
        box.vm.provision "shell", privileged: true, inline: "bash /tmp/install-pypi.sh"

        box.vm.provision "shell", privileged: true, inline: "pip install --quiet ansible docker-compose"

        box.vm.provision "file", source: "scripts/users/inject-ansible-key.sh", destination: "/tmp/inject-ansible-key.sh"
        box.vm.provision "shell", privileged: false, inline: "bash /tmp/inject-ansible-key.sh"
        box.vm.provision "shell", privileged: true, inline: "bash /tmp/inject-ansible-key.sh"

        box.vm.provision "shell", privileged: false, inline: "cd /ansible; ansible-playbook -i hosts.yml enrolment.yml"
        box.vm.provision "shell", privileged: false, inline: "cd /ansible; ansible-playbook -i hosts.yml config-k8s.yml"

        box.vm.provision "shell", privileged: true, inline: "cd /ansible; ansible-playbook -i hosts.yml etcd.yml"
        box.vm.provision "shell", privileged: true, inline: "cd /ansible; ansible-playbook -i hosts.yml controller.yml"
        box.vm.provision "shell", privileged: true, inline: "cd /ansible; ansible-playbook -i hosts.yml worker.yml"
        box.vm.provision "shell", inline: "cd /ansible; ansible-playbook -i hosts.yml kubectl.yml"
        box.vm.provision "shell", inline: "cd /ansible; ansible-playbook -i hosts.yml docker-registry.yml"
        box.vm.provision "shell", inline: "cd /ansible; ansible-playbook -i hosts.yml dns.yml"
        box.vm.provision "shell", inline: "cd /ansible; ansible-playbook -i hosts.yml dashboard.yml"
      end

      if "#{server[:name]}".start_with?("k8s-worker")
        box.vm.provision "shell", privileged: true, inline: "swapoff -a"
        box.vm.provision "shell", privileged: true, inline: "sed 's%/swap.img%# /swap.img%' -i /etc/fstab"
      end

      box.vm.provider "virtualbox" do |vb|
        vb.memory = "2048"
        vb.cpus = "2"
        vb.name = "#{server[:name]}"
      end

    end

  end

end
