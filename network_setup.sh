#!/bin/bash
ip netns add ns1
ip netns add ns2
ip link add veth1 type veth peer name veth2
ip l set veth1 netns ns1
ip l set veth2 netns ns2
ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec ns2 ip addr add 10.0.0.2/24 dev veth2
ip netns exec ns1 ip link set veth1 up
ip netns exec ns2 ip link set veth2 up
ip netns exec ns1 ping 10.0.0.2  # Ping from ns1 to ns2 to verify correct setup
