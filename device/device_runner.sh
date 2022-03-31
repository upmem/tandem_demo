#/bin/sh
echo "Environment cleaning"
modprobe pim
rm dpu_app_device.tar
echo "Waiting for encrypted applications ..."
until [ -f ./dpu_app_device.tar ]
do
    sleep 5
done
tar -xvf dpu_app_device.tar
echo "Encrypted application received, run it"
./host_app_device