#/bin/sh -x
#expected to be run in Orange FPGA, IP is UPMEM IP address
IP=77.197.106.105
PORT=1535
echo "Environment cleaning"
modprobe pim
rm OK
rm temp_sample
echo "Launching server application"
./host_app_server &
until [ -f ./OK ]
do
    sleep 5
done
echo "Sending encrypted application to the device"
#cp dpu_app_device.tar ../device
#share to UPMEM FPGA
scp -P $PORT dpu_app_device.tar root@$IP:/home/root/tandem_demo/device/