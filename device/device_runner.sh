#/bin/sh
echo "Environment cleaning"
modprobe pim
rm dpu_app_device.tar
rm temp_sample
echo "Waiting for encrypted applications ..."
until [ -f ./dpu_app_device.tar ]
do
    sleep 1
done
tar -xvf dpu_app_device.tar
echo "Encrypted application received, run it"
./host_app_device
until [ -f ./temp_sample ]
do
    sleep 1
done
cp temp_sample ../server
