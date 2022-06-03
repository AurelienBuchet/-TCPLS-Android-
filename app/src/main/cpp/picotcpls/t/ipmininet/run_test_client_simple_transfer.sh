FAILOVER=$1
if [ $FAILOVER -eq 1 ]
then
  ./../../cli -t  -T simple_transfer -f -P fc00:0:5::2 192.168.5.2 4443
else
  ./../../cli -t  -T simple_transfer -P fc00:0:5::2 192.168.5.2 4443
fi

