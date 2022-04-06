#/bin/sh -x
#expected to be run in UPMEM FPGA, IP is Orange IP address
IP=2.10.21.94
PORT=1535
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
#share to Orange IP address
scp -P $PORT temp_sample root@$IP:/home/root/tandem_demo/server/