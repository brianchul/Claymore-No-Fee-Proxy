# flakjacket ETH
## fork from JuicyPasta with some improvement

Removes Claymore's 1-2% mining fee using Stratum Proxy. Tested on Ubuntu 16.04 and Windows 10 with Claymore 9.7 ETH.\
Since Claymore no longer maintain but it still works on PhoenixMiner.\
Works with PhoenixMiner_5.2e, may work with future versions.\
Available to listen to multiple ports.

## How it works?
This proxy is placed between Claymore and Internet in order to catch mining fee packet and substituting the devfee address with your wallet address. The redirection are done on the fly and do not require stoping or relaunching the mining software.

## Limitation
This proxy will not intercept SSL connection, SSL MITM may or may not update in future version.\
PhoenixMiner will set fallback to unencrypted connection if SSL connection is not reachable, so it works in the present.
## Setup

### Python
~~Python 2.7 is required~~
Supports to Python 3\
python package - termcolor
### PIP
`pip install termcolor`

### Create a fake Wan Network
Since Claymore may detect localhost IP (see FAQ), create a fake Wan as localhost is needed.\
PhoenixMiner does not detect at this point but may in the future.\
Follow this [guide for Windows](https://github.com/JuicyPasta/Claymore-No-Fee-Proxy/wiki/Creating-a-fake-WAN-network-(Win))

~~NB: DNS redirection is not mandatory anymore (except for ETH-fork mining).~~

## Redirect mining pool DNS
Redirect mining pool IP to the IP set above.\
The Hosts file may contain all mining pools used by PhoenixMiner, you can add it to your Windows Hosts file or your own dns server if you have one.

You need to check if your preferred mining pool is in this list, if so you need to avoid redirect since it may causing loop.\
PhoenixMiner won't use the same pool and port in epools or in command line options.

## Get Mining pool IP (optional)
Useful if you want to capture all fee pools.\
Get mining pool's IP using ping command e.g. :`ping ethermine.org`
## RUN

Run the proxy daemon first and pay attention to change the pool you use, you must specify here your real pool (some example in start-proxy.bat):
```
./stratum_proxy.py --local-host FAKE_wan_IP --local-port 8008 --remote-host MINING_POOL_URL_OR_IP --remote-port MINING_POOL_PORT --wallet-address WALLET
```

Help :
```
usage: stratum_proxy.py [-h] [-o REMOTE_HOST] [-p REMOTE_PORT] [-O LOCAL_HOST]
                        [-P LOCAL_PORT] -w WALLET_ADDRESS

optional arguments:
  -h, --help            show this help message and exit
  -o REMOTE_HOST, --remote-host REMOTE_HOST
                        Hostname of Stratum mining pool
  -p REMOTE_PORT, --remote-port REMOTE_PORT
                        Port of Stratum mining pool
  -O LOCAL_HOST, --local-host LOCAL_HOST
                        On which network interface listen for stratum miners.
                        Use "localhost" for listening on internal IP only.
  -P LOCAL_PORT, --local-port LOCAL_PORT
                        Port on which port listen for stratum miners.
                        You can use comma to set multiple port to listen to
                        E.g. 3333,4444,5555
  -w WALLET_ADDRESS, --wallet-address WALLET_ADDRESS
                        Wallet address, may include rig name with "." or "/"
                        separator
```

Run the mining software with the fake WAN IP
```
./ethdcrminer64 -epool 194.12.12.2:8008 ....
```

## Known issues
- Mining ETH-Fork coins is not fully supported.
- Proxy is only compatible with ESM mode 0 & 1

## Features
- Redirecting DevFee to your wallet
- Detecting network outage
- Minimal footprint
- Detecting worker name separator
- Custom worker name
- Available to listen to multiple ports.
## FAQ

### What if i use other pool?
Claymore try to mine the fee on the same pool as you. So you have to change the pool server above by yours in the proxy arg.

### Is it lightweight?
We try to reduce the footprint to the maximum, the stratum proxy daemon take up to 130MB RAM and few CPU resources. The power consumption is trivial.

### How can i be 100% sure this is not a scam ?
This is an open source project, so you can read the source code and check it. BTW, don't hesitate to create pull requests if you see something broken.

### Should i run the proxy on every mining station?
Yes, we recommand to install the proxy on every mining station. If you have a farm consider having a couple of dedicated computer (with good CPU and network).

### Is it compatible with every currency?
This proxy was designed to be used with Claymore ETH version. If you are planning to mine ETH-like, you have to specify `-allcoins 1` in claymore and replace the host file with the right pool. [Windows guide here](https://github.com/JuicyPasta/Claymore-No-Fee-Proxy/wiki/Redirecting-all-domains-(Win)) [Linux guide here](https://github.com/JuicyPasta/Claymore-No-Fee-Proxy/wiki/Redirecting-all-domains-(Linux))
Since Claymore 9.6 you are able to mine ETC more easily, use `-allcoins etc` arg in claymore (So you can skip the redirections guide above).
DNS redirection is only needed when Claymore can't mine on the same pool as you.
Zcash version in the futur?  

### Is it compatible with dual mode mining?
Yes, the claymore software take the fee from ETH mining only.

### How to change the worker name ?
Spot and edit `worker_name` variable. By default the worker name is _rekt_. The worker name is disabled for unknown pool.

### How can I check if it works?
Read the window output (1 devfee per hour). You can also check your pool stats, but some pool ignore small mining time if it did not find a share. But it mines for you !

### Claymore warns me something about local proxy...
Claymore check the pool's IP to avoid local proxies, if you have the warning make sure you followed this guide: [Fake WAN For Windows](https://github.com/JuicyPasta/Claymore-No-Fee-Proxy/wiki/Creating-a-fake-WAN-network-(Win))

### I detect a strange behaviour or reduced hashrate with untested claymore version
If you see something wrong with a new Claymore version, maybe the cheat has been detected and Claymore tries to punish us.
If it's the case, tell us in the issue section with clues.

## Contact & Issues
You can chat us on [Gitter](https://gitter.im/claymore-no-fee-proxy/Lobby)
If you met an issue you can also post in the issue section.

## Credit & Donations
Offer us a beer (or something healthier)
The easiest way to make a donation is redirecting the devfee to our wallet for a few time. :-) Or you can still send a simple donation.
- [JuicyPasta](https://github.com/JuicyPasta) - 0xfeE03fB214Dc0EeDc925687D3DC9cdaa1260e7EF
- Drdada - 0xB7716d5A768Bc0d5bc5c216cF2d85023a697D04D (ethermine)

