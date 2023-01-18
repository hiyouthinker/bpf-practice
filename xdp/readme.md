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
# 2 forward program
## 2.1 load
```
young@xxx:~/bpf-practice/xdp$ sudo ./control/forward_loader -S --filename ebpf/forward_prog.o --progsec xdp_icmp_echo -d lo -F -q -D
......
The fd of session_nat_table_inner0 in session_nat_table_outer is 3
The fd of session_nat_table_inner1 in session_nat_table_outer is 4
The fd of session_nat_table_inner2 in session_nat_table_outer is 5
The fd of session_nat_table_inner3 in session_nat_table_outer is 6
young@xxx:~/bpf-practice/xdp$ sudo ./control/forward_loader -S --filename ebpf/forward_prog.o --progsec xdp_ip_forward -d lo -F -q -D
......
The fd of session_nat_table_inner0 in session_nat_table_outer is 3
The fd of session_nat_table_inner1 in session_nat_table_outer is 4
The fd of session_nat_table_inner2 in session_nat_table_outer is 5
The fd of session_nat_table_inner3 in session_nat_table_outer is 6
young@xxx:~/bpf-practice/xdp$ sudo ./control/forward_loader -S --filename ebpf/forward_prog.o --progsec xdp_udp_fullnat_forward -d lo -F -q -D
......
The fd of session_nat_table_inner0 in session_nat_table_outer is 3
The fd of session_nat_table_inner1 in session_nat_table_outer is 4
The fd of session_nat_table_inner2 in session_nat_table_outer is 5
The fd of session_nat_table_inner3 in session_nat_table_outer is 6
```
## 2.2 read
```
young@xxx:~/bpf-practice/xdp$ sudo ./control/forward_reader -d lo -q
=============================================================================== 000
All pkts                                                     7 pkts         462 bytes
TCPv4                                                        7 pkts         462 bytes
-----------------------------------------
Without Tag                                                  7 pkts         462 bytes
-----------------------------------------
CPU00: PASS                                                         1
CPU01: PASS                                                         4
CPU02: PASS                                                         2
-----------------------------------------
^C
```
