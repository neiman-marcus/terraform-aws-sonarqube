#!/bin/bash

function enable_debug  {
# download cloudwatch agent
curl -o https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
# install cloudwatch agent
rpm -U ./amazon-cloudwatch-agent.rpm
# create the cloudwatch agent configuration file
if [[ ! -d /etc/awslogs/state ]]; then
    mkdir -p /etc/awslogs/state
fi
if [[ -f /etc/awslogs/awslogs.conf ]]; then
    mv /etc/awslogs/awslogs.conf /etc/awslogs/awslogs.conf.orig
fi
cat <<'EOF' > /etc/awslogs/awslogs.conf
[general]
state_file = /etc/awslogs/state/agent-state
logging_config_file = /etc/awslogs/awslogs.conf
use_gzip_http_content_encoding = true

[/var/logs/messages]
file = /var/log/messages
log_group_name = sonarqube-ecs-logs
log_stream_name = {instance_id}/var/log/messages
datetime_format = %b %d %H:%M:%S
time_zone = UTC

[${logDir}/sonar.log]
file = ${logDir}/sonar.log
log_group_name = sonarqube-ecs-logs
log_stream_name = {instance_id}/${logDir}/sonar.log
datetime_format = %b %d %H:%M:%S
time_zone = UTC

[${logDir}/web.log]
file = ${logDir}/web.log
log_group_name = sonarqube-ecs-logs
log_stream_name = {instance_id}/${logDir}/web.log
datetime_format = %b %d %H:%M:%S
time_zone = UTC

[${logDir}/ce.log]
file = ${logDir}/ce.log
log_group_name = sonarqube-ecs-logs
log_stream_name = {instance_id}/${logDir}/ce.log
datetime_format = %b %d %H:%M:%S
time_zone = UTC

[${logDir}/es.log]
file = ${logDir}/es.log
log_group_name = sonarqube-ecs-logs
log_stream_name = {instance_id}/${logDir}/es.log
datetime_format = %b %d %H:%M:%S
time_zone = UTC
EOF
# start cloudwatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/etc/awslogs/awslogs.conf -s
}

# this will be used to create the sonarqube logs directory and files
mkdir -p ${logDir}
chmod 0755 ${logDir}
touch ${logDir}/sonar.log
chmod 0666 ${logDir}/sonar.log
touch ${logDir}/web.log
chmod 0666 ${logDir}/web.log
touch ${logDir}/ce.log
chmod 0666 ${logDir}/ce.log
touch ${logDir}/es.log
chmod 0666 ${logDir}/es.log

# turn this on if you want a peek into what the container and the ec2 instance are doing
enable_debug

# this part binds the ec2 instance to the cluster
cat <<'EOF' >> /etc/ecs/ecs.config
ECS_CLUSTER=${clusterName}
# only turn this on if you have opted in see url for details...
# https://aws.amazon.com/blogs/compute/migrating-your-amazon-ecs-deployment-to-the-new-arn-and-resource-id-format-2/
#ECS_CONTAINER_INSTANCE_PROPAGATE_TAGS_FROM=ec2_instance
EOF

# sonarqube/elasticsearch values - this is why we cannot go with fargate
sysctl -w vm.max_map_count=262144
sysctl -w fs.file-max=65536

# change the default values for docker so elasticsearch will come up
cat <<'EOF' > /etc/sysconfig/docker
# The max number of open files for the daemon itself, and all
# running containers.  The default value of 1048576 mirrors the value
# used by the systemd service unit.
DAEMON_MAXFILES=1048576

# Additional startup options for the Docker daemon, for example:
# OPTIONS="--ip-forward=true --iptables=true"
# By default we limit the number of open files per container
# The docker service on Amazon instances limits the number of open files to 4096 by default
OPTIONS="--default-ulimit nofile=1024:65535"

# How many seconds the sysvinit script waits for the pidfile to appear
# when starting the daemon.
DAEMON_PIDFILE_TIMEOUT=10
EOF

# updates
yum update -y
yum update -y ecs-init

# make sure ssm agent is installed
cd /tmp
yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm

# make the changes you just made take effect
which systemctl;rc=$?
if [ $rc -eq 0 ]; then
   systemctl restart docker
   systemctl restart amazon-ssm-agent
else
   service docker restart
   service amazon-ssm-agent restart
fi
