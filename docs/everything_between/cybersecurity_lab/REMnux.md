# REMnux - REMnux
## Create Virtual Machine
After downloading the VMHD for REMnux (available [here](https://docs.remnux.org/install-distro/get-virtual-appliance)):  

* Open the virtual machine in VMware Workstation Pro (File > Open)  
* (optional) Rename the virtual machine as required  
* Allocate 4 CPUs  
* Increase RAM to 8GB  
* Add a second network adapter connected to the custom VMnet network  

## Install Additional Tools
* Power on the virtual machine
* Change the timezone (if required)  
* Change the keyboard layout (if required)  
* Update (`sudo apt update && sudo apt full-upgrade -y`)  
* (optional but highly recommended) Shut down and take snapshot of fresh OS installation  
* Install additional applications:  
```
python3 -m pip install --user capa floss lief
pip install capa
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
sudo insmod lime-`uname -r`.ko "path=/tmp/mem.lime format=lime"
sha256sum /tmp/mem.lime > /tmp/mem.lime.sha256
```
* Shutdown and disable NAT adapter  
* Snapshot!