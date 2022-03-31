#/bin/sh
echo "Environment cleaning"
modprobe pim
rm OK
echo "launching server application"
./host_app_server &
until [ -f ./OK ]
do
    sleep 5
done
echo "send encrypted application to device device"
cp dpu_app_device.tar ../device
