## Pi-develop

How to develop raspberry pi 4b.

- First of all, you need to go [<u>website</u>](https://www.raspberrypi.com/software/) to download **Raspberry Pi Imager**.

- After that, put your micro disk to your computer to download operating system (here I chose Raspberry Pi OS(other), **Raspberry Pi OS Lite(64-bit)**). If you want to use VNC viewer, a tool for remote connection to Raspberry Pi, you need to download **Raspberry Pi OS full**.

- Remember to open SSH item, so that you can use VNC viewer or terminal to connect Raspberry Pi.

- When the OS is wrote into the micro disk, you need to make two files to ensure that the Raspberry Pi can successfully connect to the mobile phone hotspot. The first file you need to create is ```ssh```, an empty file.

```
cd /Volum/bootfs
touch ssh
```

- And then, you need to create ```wpa_supplicant.conf```,

```
sudo vim wpa_supplicant.conf

# and insert the following information

country=CN
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
network={
  ssid="Fanhang"
  psk="12345678"
  priority=1
}
```

- Now, you can insert micro disk into Raspberry Pi and open Raspberry Pi.

- I use personal hotpot to connect Raspberry Pi, so that I use Network Analyzer, a tool that can be used to view the IP addresses of connection hotspots, to find Raspberry Pi's IP.

- Finally, use terminal to connect Raspberry without Desktop.
```
ssh pi@172.20.10.7
```
