# Running Packet Filters with Netfilter nftables

## Run packet filters using `nftables`:
- run `sudo apt install nft`.
- `nft-scripts/ipv6_drop.sh` is a script that uses `nft` to create a packet filter and use `wget` to test an IPv6 address for an apache web server.
- ensure these config options are set
```
CONFIG_NETFILTER=y
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_NETDEV=y
```

## QEMU 
- One way to test the packet filter in emulation is to setup an apache web server on the host and then make a request from QEMU to web server via an IPv6 address.
- Add this option to a QEMU command to setup IPv6 support
- `-netdev user,id=net0,ipv6=on,ipv6-net=fdf2:5e8e:743d::0/43`
- QEMU will assign the base IPv6 prefix plus 2 for use in contacting the host. So in this case use `fdf2:5e8e:743d::2` from QEMU to contact host.
