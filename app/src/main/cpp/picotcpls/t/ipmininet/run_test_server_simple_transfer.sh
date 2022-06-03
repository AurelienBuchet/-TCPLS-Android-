truncate -s 60M test_multipath.data
FAILOVER=$1
if [ $FAILOVER -eq 1 ]
then
  ./../../cli -t -f -T simple_transfer -i test_multipath.data -k ../assets/server.key -c ../assets/server.crt -Z fc00:0:5::2 192.168.5.2 4443
else
  ./../../cli -t -T simple_transfer -i test_multipath.data -k ../assets/server.key -c ../assets/server.crt -Z fc00:0:5::2 192.168.5.2 4443
fi

