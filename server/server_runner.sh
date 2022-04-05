#/bin/sh -x
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
cp dpu_app_device.tar ../device
