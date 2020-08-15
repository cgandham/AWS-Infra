#!/bin/bash
echo "username=admin" >> /etc/environment
echo "password=very_strong_password" >> /etc/environment
echo "s3bucketname=webapp.chandana.gandham5" >> /etc/environment
echo "rdsinstance=${rds_endpoint}" >> /etc/environment
echo "ACCESS_KEY=${ACCESS_KEY}" >> /etc/environment
echo "SECRET_KEY=${SECRET_KEY}" >> /etc/environment
echo "codedeploy_bucketname=codedeploy.chandanawebapp.me2" >> /etc/environment
