#/bin/sh -x
#expected to be in Nice
echo "Environment cleaning"
modprobe pim
rm dpu_app_device.tar
rm temp_sample
echo "Waiting for encrypted applications ..."
until [ -f ./dpu_app_device.tar ]
do
    sleep 1
done
tar -xf dpu_app_device.tar
echo "Encrypted application received, run it"
./host_app_device
until [ -f ./temp_sample ]
do
    sleep 1
done
echo "Sending encrypted sensor data to the server"
#cp temp_sample ../server
#share to Rennes IP address
scp -P 1535 temp_sample root@2.10.21.94:/home/root/tandem_demo/server/