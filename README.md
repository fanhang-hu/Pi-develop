## Pi-develop

How to develop Raspberry Pi 4B.

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

This method always fail, therefore, I use network cables, connect one end to the Raspberry Pi and the other end to the computer to carry out network sharing.

Don't forget to open i2c connect,
```
sudo raspi-config
sudo reboot
```

After connect the Raspberry Pi, we need to configure some necessary environments.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install auditd -y
python3 -m venv exp-attack
source exp-attack/bin/activate
sudo apt install build-essential -y
gcc --version
source exp-attack/bin/activate
sudo apt update
sudo apt install i2c-tools python3-smbus -y
sudo i2cdetect -y 1
pip3 install adafruit-circuitpython-vl53l1x
sudo apt install python3-rpi.gpio
ln -s /usr/lib/python3/dist-packages/RPi /home/pi/exp-attack/lib/python3.13/site-packages/
python3 -c "import RPi.GPIO; print('OK')"
```

Now, we can test our code.


## test-v1-replay_zero
```bash
./scripts/run_rpi_experiment.sh --mode baseline --duration-sec 30
./scripts/run_rpi_experiment.sh --mode bias --duration-sec 30
./scripts/run_rpi_experiment.sh --mode delay --duration-sec 30
./scripts/run_rpi_experiment.sh --mode replay --duration-sec 40
./scripts/run_rpi_experiment.sh --mode replay_zero --duration-sec 40
./scripts/run_rpi_experiment.sh --mode replay_zero --duration-sec 40 --replay-force-start-sec 10 --replay-force-end-sec 20 --replay-force-value 0.0
```

## test-v2
```bash
./scripts/run_rpi_experiment.sh --mode bias --duration-sec 30 \
  --bias-force-start-sec 10 \
  --bias-force-end-sec 20 \
  --attack-interval-ms 1 \
  --attack-burst-writes 10 \
  --attack-burst-gap-ms 0
```
