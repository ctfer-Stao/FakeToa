bpftool prog load bpf_toa.bpf.o /sys/fs/bpf/set_toa_tcp_bs
sleep 3
prog_id=$(bpftool prog show | grep set_toa_tcp_bs | cut -d':' -f1)
bpftool cgroup attach /sys/fs/cgroup/ sock_ops id $prog_id