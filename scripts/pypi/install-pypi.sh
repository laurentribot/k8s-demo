apt-get install docker.io -y -q
docker load -i /vagrant_data/images/codekoala-pypi-latest.tar
mkdir -p /var/lib/pypi
cp /vagrant_data/python/* /var/lib/pypi
touch /var/lib/pypi/.htpasswd

docker run -t -i -d --restart always -h k8s-demo -v /var/lib/pypi:/srv/pypi:rw -p 9090:80 --name pypi codekoala/pypi
docker exec -t -i -d pypi pypi-server -U /srv/pypi

cat <<-EOF >/etc/pip.conf
[global]
index_url = http://192.168.56.10:9090
disable-pip-version-check = true
no-cache-dir = off
trusted-host =
  192.168.56.10
EOF