# Necromancer
A minecraft regional redundant availability tool to prevent servers from dying due to losing a host.

## Design
The program is designed as follows:

There is a central command server or authority, this is whatever server that it actively running the network and has the most up to date version of the world. They are rutienely scanning their files and tracking updates with an api for other servers to be able to fetch the hashes and sizes of all their files, check differences and download them. Scans will run every 10 minutes, less if the scan process can be completed rapidly. The more frequent this scans, the less time will be lost from a server outage. It is planned that this will automatically spin up to the server that is currently running/is failed over to so that the other nodes can maintain their world version, though I don't know how I will implement this.

The client will also check their files every time the authority posts and update, they will compare the differences and put all of the local files with a different hash on a queue to be downloaded from the authority so that they can be updated to maintain their syncronization with the current host.

## Installation:
This is designed for Linux hosts, you are able to download the Linux binary from the releases page of the GitHub.

## Setup
**Authority**
1. Download the binary for your operating system
2. Copy it to /usr/bin or add it to your path on other operating systems (optional)
3. ./storagemanager init or storagemanager init if you added to path
4. Follow the prompts from the init system to generate a config
5. Once config is generated, run storagemanager run to run the system with your defined configs.