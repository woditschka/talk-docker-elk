#!/bin/sh

#--------------------------------------------------------------------------------------
# install nginx and forward /ops to kibana

apt-get -y install nginx

cat >/etc/nginx/sites-available/default <<'EOL'
server {
  listen 80 default_server;
  listen [::]:80 default_server ipv6only=on;

  root /usr/share/nginx/html;
  index index.html index.htm;

  server_name docker-elk;

  location / {
    try_files $uri $uri/ =404;
  }

  location ~* /ops/.* {
    rewrite ^/ops/(.*) /$1 break;
    
    proxy_pass http://127.0.0.1:5601;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  }
}
EOL

service nginx restart

#--------------------------------------------------------------------------------------
# https://www.elastic.co/guide/en/logstash/current/input-plugins.html
# https://www.elastic.co/guide/en/logstash/current/output-plugins.html
#
#--------------------------------------------------------------------------------------
# https://registry.hub.docker.com/
#
# https://registry.hub.docker.com/u/library/logstash/
# https://registry.hub.docker.com/u/library/elasticsearch/
# https://registry.hub.docker.com/u/library/kibana/

#--------------------------------------------------------------------------------------
# create structure on host
mkdir -p /var/docker/elasticsearch
mkdir -p /var/docker/logstash
chmod -R uga+rwX /var/docker


#--------------------------------------------------------------------------------------
# create logstash config
cat >/var/docker/logstash/syslog.conf <<'EOL'
input {
  tcp {
    port => 25826
    type => syslog
  }
  udp {
    port => 25826
    type => syslog
  }
}
 
filter {

 if [type] == "syslog" {
    grok {
      match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
    }
  }
  if "docker/" in [program] {
    mutate {
      add_field => {
        "container_id" => "%{program}"
      }
    }
    mutate {
      gsub => [
        "container_id", "docker/", ""
      ]
    }
    mutate {
      update => [
        "program", "docker"
      ]
    }
  }
}
 
output {
  stdout {
    codec => rubydebug
  }
  elasticsearch {
    host => db
  }
}
EOL

#--------------------------------------------------------------------------------------
# install ELK stack
docker run -d --restart=always -v /var/docker/elasticsearch:/usr/share/elasticsearch/data --name elasticsearch elasticsearch:1.7.3

docker run -d --restart=always --link elasticsearch -p 5601:5601 --name kibana kibana:4.1.2

docker run -d --restart=always --link elasticsearch:db -v /var/docker/logstash:/conf -p 25826:25826 --name logstash logstash:1.5.4-1 logstash -f /conf/syslog.conf

#--------------------------------------------------------------------------------------
# create rsyslog config

sudo cat >/etc/rsyslog.d/10-logstash.conf <<'EOL'
*.* @@127.0.0.1:25826
EOL

#--------------------------------------------------------------------------------------
# restart rsyslog

service rsyslog restart
