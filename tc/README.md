# 1 add qdisc/filter
```
tc qdisc add dev eth1 clsact
tc filter add dev eth1 ingress bpf da obj tc_prog_kern.o sec tc
```
# 2 show qdisc/filter
```
tc qdisc show dev eth1
tc filter show dev eth1 ingress
```
# 3 del qdisc/filter
```
tc filter del dev eth1 ingress
tc qdisc del dev eth1 clsact
```
