echo "WARNING quictracker currently is not supported as it does not implement the final version of rfc9000"
exit 1
docker run --rm --network="host" -v $(pwd):/usr/opt/project mpiraux/quictracker /test_suite -scenario padding -hosts /usr/opt/project/hosts.txt
