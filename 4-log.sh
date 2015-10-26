#!/bin/sh

#--------------------------------------------------------------------------------------
# log directtly to syslog
logger -s -p 1 "This is fake error..."
logger -s -p 1 "This is another fake error..."
logger -s -p 1 "This is one more fake error..."


#--------------------------------------------------------------------------------------
# log docker to syslog
docker run --log-driver syslog ubuntu echo "Test"