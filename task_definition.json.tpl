[
    {
        "ulimit": [
            {
                "softLimit": 65535,
                "hardLimit": 65535,
                "name": "nofile"
            },
            {
                "softLimit": 4096,
                "hardLimit": 4096,
                "name": "nproc"
            }
        ],
        "dnsSearchDomains": null,
        "logConfiguration": {
            "logDriver": "awslogs",
            "secretOptions": null,
            "options": {
                "awslogs-create-group": "true",
                "awslogs-group": "sonarqube-ecs-logs",
                "awslogs-region": "${awsRegion}",
                "awslogs-stream-prefix": "${clusterName}"
            }
        },
        "portMappings": [
            {
                "hostPort": 9000,
                "protocol": "tcp",
                "containerPort": 9000
            },
            {
                "hostPort": 9092,
                "protocol": "tcp",
                "containerPort": 9092
            }
        ],
        "command": null,
        "linuxParameters": null,
        "cpu": 1024,
        "environment": [
            {
                "name": "SONARQUBE_JDBC_URL",
                "value": "jdbc:postgresql://${dbEndpoint}/${dbName}"
            },
            {
                "name": "SONARQUBE_JDBC_USERNAME",
                "value": "${dbUser}"
            }
        ],
        "resourceRequirements": null,
        "ulimits": null,
        "dnsServers": null,
        "mountPoints": [
            {
                "containerPath": "/opt/sonarqube/logs",
                "sourceVolume": "sonarqube_logs"
            }
        ],
        "workingDirectory": "/opt/sonarqube",
        "secrets": [
            {
                "valueFrom": "${dbPassword}",
                "name": "SONARQUBE_JDBC_PASSWORD"
            }
        ],
        "dockerSecurityOptions": null,
        "memory": 3072,
        "memoryReservation": null,
        "volumesFrom": [],
        "stopTimeout": 300,
        "image": "${awsAccount}.dkr.ecr.${awsRegion}.amazonaws.com/sonarqube:latest",
        "image": "${containerImage}",
        "startTimeout": 300,
        "firelensConfiguration": null,
        "dependsOn": null,
        "disableNetworking": null,
        "interactive": null,
        "healthCheck": {
            "retries": 10,
            "command": [
                "/bin/true"
            ],
            "timeout": 5,
            "interval": 60,
            "startPeriod": 300
        },
        "essential": true,
        "links": null,
        "hostname": null,
        "extraHosts": null,
        "pseudoTerminal": null,
        "user": "sonarqube",
        "readonlyRootFilesystem": null,
        "dockerLabels": {
            "Owner": "${appOwner}",
            "Application": "${appName}"
        },
        "systemControls": null,
        "privileged": null,
        "taskRoleArn": "${taskRoleArn}",
        "name": "${clusterName}"
    }
]
