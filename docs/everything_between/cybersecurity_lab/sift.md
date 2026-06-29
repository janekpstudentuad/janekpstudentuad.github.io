# SIFT Workstation - SIFT
## Create Virtual Machine
After downloading the VMHD for SIFT Workstation (available [here](https://www.sans.org/tools/sift-workstation). You will need a SANS account but the download is free):  

* Open the virtual machine in VMware Workstation Pro (File > Open)  
* (optional) Rename the virtual machine as required  
* Snapshot!
## Install Volatility
* Power on the virtual machine and update (`sudo apt update && sudo apt full-upgrade -y`)  
* Volatility installation:  
```
sudo apt install -y python3-pip libfuzzy-dev libdistorm3-dev yara
python3 -m pip install --upgrade pip
python3 -m pip install volatility3
echo 'export PATH=$PATH:/home/sansforensics/.local/bin' >> ~/.bashrc
source ~/.bashrc
```
* Snapshot!