#!/bin/bash

# Name of the conda environment to find
if [ ! "$(docker ps -aqf "name=openstack-rabbitmq" 2>/dev/null)" ]; then
    echo "Container exists"
else
    echo "Hello"
fi
