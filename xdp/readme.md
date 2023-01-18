# 1 lpm program
## 1.1 load
```
root@ax:~/test# ./lpm_loader -S --filename lpm_prog.o --progsec xdp_lpm -d ens192 -F -l 1.1.1.1,2.3.4.0/24 -q -D
ips: [1.1.1.1,2.3.4.0/24]
ip/mask: 1.1.1.1/32
key: 1.1.1.1, value: 1.1.1.1
ip/mask: 2.3.4.0/24
key: 2.3.4.0, value: 2.3.4.0
```
## 1.2 read
```
root@ax:~/test# ./lpm_reader

Reading data from BPF map
 - BPF map (bpf_map_type:11) id: 710, name: ip_lpm_map, key_size: 28, value_size: 4, max_entries: 1024
1_1.1.1.1/32: 1.1.1.1
1_2.3.4.0/24: 2.3.4.0
```
