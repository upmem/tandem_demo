#/bin/sh -x
#expected to be in Rennes
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
#share to Nice IP address
scp -P 1535 dpu_app_device.tar root@77.197.106.105:/home/root/tandem_demo/device/