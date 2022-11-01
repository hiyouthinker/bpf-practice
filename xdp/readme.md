# 1 xdp_lpm
## 1.1 load
```
root@ax:~/test# ./xdp_loader -S --filename xdp_prog_kern.o --progsec xdp_lpm -d ens192 -F -l 1.1.1.1,2.3.4.0/24 -q -D
The fd of session_nat_table_inner0 in session_nat_table_outer is 3
The fd of session_nat_table_inner1 in session_nat_table_outer is 5
The fd of session_nat_table_inner2 in session_nat_table_outer is 6
The fd of session_nat_table_inner3 in session_nat_table_outer is 7
The fd of session_nat_table_inner4 in session_nat_table_outer is 8
The fd of session_nat_table_inner5 in session_nat_table_outer is 9
The fd of session_nat_table_inner6 in session_nat_table_outer is 10
The fd of session_nat_table_inner7 in session_nat_table_outer is 11
ips: [1.1.1.1,2.3.4.0/24]
ip/mask: 1.1.1.1/32
key: 1.1.1.1, value: 1.1.1.1
ip/mask: 2.3.4.0/24
key: 2.3.4.0, value: 2.3.4.0
```
## 1.2 read
```
root@ax:~/test# ./xdp_reader

Reading data from BPF map
 - BPF map (bpf_map_type:11) id: 630, name: ip_lpm_map, key_size: 28, value_size: 4, max_entries: 1024
1.1.1.1/32: 1.1.1.1
2.3.4.0/24: 2.3.4.0
^C
```
