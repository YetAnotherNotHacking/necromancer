# Necromancer
A utility capable of syncing live minecraft servers in near real time to avoid losing data

## Design
The program is designed as follows:

There is a central command server or authority, this is whatever server that it actively running the network and has the most up to date version of the world. They are rutienely scanning their files and tracking updates with an api for other servers to be able to fetch the hashes and sizes of all their files, check differences and download them. Scans will run every  minute, less if the scan process can be completed rapidly. The more frequent this scans, the less time will be lost from a server outage. It is planned that this will automatically spin up to the server that is currently running/is failed over to so that the other nodes can maintain their world version, though I don't know how I will implement this.

The client will also check their files every time the authority posts and update, they will compare the differences and put all of the local files with a different hash on a queue to be downloaded from the authority so that they can be updated to maintain their syncronization with the current host.

## Setup
**Authority:**
1. Download the latest version of the authority:
```
wget https://github.com/YetAnotherNotHacking/necromancer/releases/download/v0.2.2beta/storagemanager
```
2. Copy it to your system binary location
```
sudo cp storagemanager /usr/bin/
```
3. Set up the configs for your system, follow the prompts. (cd to your server dir before this)
```
storagemanager init
```
4. Add users. You should follow the prompts it asks.
```
storagemanager useredit
```
5. Run the authority, remember it has to populate its databases with your servers file status so be ready to wait a bit for that, in your server dir:
```
nohup storagemanager run &
```
**Client:**
1. Download the latest edition of the client
```
wget https://github.com/YetAnotherNotHacking/necromancer/releases/download/v0.2.2beta/client
```
2. Copy the client your system's binary locatoin
```
cp client /usr/bin
```
3. Make the dir that the files are going to be cloned into
```
mkdir path/to/save/to
```
4. Once that is made, run the following command to set the config and follow its prompts:
```
client init
```
5. Login with your credentials to the server once you configure the other elements with the following command:
```
client login
```
6. Once that is done, run the client
```
client run
```

## Support
Please make an issue in the GitHub for any problems you encounter! We are looking to make this program as helpful as possible for as many people as possible. Feature requests are absolutely welcome!