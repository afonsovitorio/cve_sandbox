sed 's/version: \(.*\)/version: '\''\1'\''/' /home/vagrant/docker-compose.yml > /home/vagrant/docker-compose_new.yml
mv /home/vagrant/docker-compose_new.yml /home/vagrant/docker-compose.yml
