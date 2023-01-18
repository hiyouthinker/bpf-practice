# 1 load & read
```shell
# load program & read statistics
young@xxx:~/bpf-practice/sk_filter$ sudo ./sk_filter_user -p 8080 -r 5
......
Prepare to bind to 0.0.0.0:8080
reuse / bind / listen / attach_ebpf success!
success: 0/0, failure: 0
success: 0/0, failure: 0
success: 0/0, failure: 0
success: 0/1, failure: 0
success: 0/2, failure: 0
success: 0/3, failure: 0
success: 1/3, failure: 0
success: 1/4, failure: 0
success: 2/4, failure: 0
success: 3/4, failure: 0
success: 4/4, failure: 0
```
# 2 test
```
young@xxx:~$ nc 127.0.0.1 8080 -zvw 3
Connection to 127.0.0.1 8080 port [tcp/http-alt] succeeded!
root@xxx:~$ nc 127.0.0.1 8080 -zvw 3
Connection to 127.0.0.1 8080 port [tcp/http-alt] succeeded!
......
```
