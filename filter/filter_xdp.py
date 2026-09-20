#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
from bcc import BPF
from bcc import lib
import sys
import time
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from datetime import datetime

curdir = os.path.dirname(__file__)
def usage():
    print("Usage: {0} <ifdev> <flag>".format(sys.argv[0]))
    exit(1)

bpf_text = """
#include <uapi/linux/bpf.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#define DEBUG_BUILD
#define NUM_FEATURES 12
#define FIXED_POINT_DIGITS 16
#define FXP_VALUE FIXED_POINT_DIGITS

struct pkt_key_t {
  u32 protocol;
  u32 saddr;
  u32 daddr;
  u32 sport;
  u32 dport;
};

struct welford_stat_t {
  u64 sum;
  u64 m2;
};

struct pkt_leaf_t {
  u32 num_packets;
  u64 last_packet_timestamp;
  u32 sport;
  u32 dport;
  struct welford_stat_t stats[3];
};

enum flow_feature_idx {
  FEAT_TOT_LEN   = 0,
  FEAT_INTERVAL  = 1,
  FEAT_DIRECTION = 2,
  NUM_FLOW_FEATS = 3
};

#define IDX_RAW_OFFSET   3
#define IDX_MEAN_OFFSET  6
#define IDX_SQCV_OFFSET  9

static __always_inline int64_t fxp_mul(int64_t a, int64_t b) {
  if ((a > -(1LL << 30)) && (a < (1LL << 30)) &&
      (b > -(1LL << 30)) && (b < (1LL << 30))) {
    return (a * b) >> FXP_VALUE;
  }
  return (a >> (FXP_VALUE / 2)) * (b >> (FXP_VALUE / 2));
}

static __always_inline int64_t fxp_div_sqcv(uint64_t variance, uint64_t mean_sq) {
  if (mean_sq == 0) return 0;
  if (variance < (1ULL << 46)) {
    return (int64_t)((variance << FXP_VALUE) / mean_sq);
  }
  uint64_t denom = mean_sq >> FXP_VALUE;
  return (denom > 0) ? (int64_t)(variance / denom) : 0;
}

static __always_inline void update_welford_feature(struct welford_stat_t *stat,
                                                   uint64_t num_packets,
                                                   int64_t new_val,
                                                   int64_t *out_mean,
                                                   int64_t *out_sqcv) {
  uint64_t n_prev = num_packets - 1;
  int64_t old_mean = (int64_t)(stat->sum / n_prev);

  stat->sum += (uint64_t)new_val;
  int64_t new_mean = (int64_t)(stat->sum / num_packets);
  *out_mean = new_mean;

  int64_t delta1 = new_val - old_mean;
  int64_t delta2 = new_val - new_mean;
  int64_t term = fxp_mul(delta1, delta2);
  if (term > 0) {
    stat->m2 += (uint64_t)term;
  }

  if (new_mean > 0) {
    uint64_t variance = stat->m2 / n_prev;
    uint64_t mean_sq = (uint64_t)fxp_mul(new_mean, new_mean);
    *out_sqcv = fxp_div_sqcv(variance, mean_sq);
  } else {
    *out_sqcv = 0;
  }
}

BPF_TABLE("lru_hash", struct pkt_key_t, struct pkt_leaf_t, sessions, 1024);
BPF_HASH(dropcnt, int, u32);
BPF_HASH(pkt_len, int64_t, int64_t);

int xdp_drop_packet(struct xdp_md *ctx) {
  int64_t ts = bpf_ktime_get_ns();
  void* data_end = (void*)(long)ctx->data_end;
  void* data = (void*)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  struct iphdr *iph;
  struct tcphdr *th;
  struct udphdr *uh;
  struct pkt_key_t pkt_key = {};


  pkt_key.protocol = 0;
  pkt_key.saddr = 0;
  pkt_key.daddr = 0;
  pkt_key.sport = 0;
  pkt_key.dport = 0;

  ethernet: {
    if (data + nh_off > data_end) {
      return XDP_DROP;
    }
    switch(eth->h_proto) {
      case htons(ETH_P_IP): goto ip;
      default: goto EOP;
    }
  }
  ip: {
    iph = data + nh_off;
    if ((void*)&iph[1] > data_end) {
      return XDP_DROP;
    }
    pkt_key.saddr    = iph->saddr;
    pkt_key.daddr    = iph->daddr;
    pkt_key.protocol = iph->protocol;

    switch(iph->protocol) {
      case IPPROTO_TCP: goto tcp;
      case IPPROTO_UDP: goto udp;
      default: goto EOP;
    }
  }
  tcp: {
    th = (struct tcphdr *)(iph + 1);
    if ((void*)(th + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(th->source);
    pkt_key.dport = ntohs(th->dest);
    goto drop;
  }
  udp: {
    uh = (struct udphdr *)(iph + 1);
    if ((void*)(uh + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);
    goto drop;
  }
  drop: {
    struct pkt_leaf_t *pkt_leaf = sessions.lookup(&pkt_key);
    if (!pkt_leaf) {
      struct pkt_leaf_t zero = {};
      zero.sport = pkt_key.sport;
      zero.dport = pkt_key.dport;
      zero.num_packets = 0;
      zero.last_packet_timestamp = ts;
      sessions.update(&pkt_key, &zero);
      pkt_leaf = sessions.lookup(&pkt_key);
    }
    if (pkt_leaf != NULL) {
      int64_t feat[NUM_FEATURES] = {0};
      pkt_leaf->num_packets += 1;
      feat[0] = pkt_leaf->sport;
      feat[1] = pkt_leaf->dport;
      feat[2] = iph->protocol;
      feat[3] = ntohs(iph->tot_len);
      feat[4] = 0;
      if (pkt_leaf->last_packet_timestamp > 0) {
        feat[4] = ts - pkt_leaf->last_packet_timestamp;
      }
      pkt_leaf->last_packet_timestamp = ts;
      feat[5] = (pkt_key.sport == feat[0]);

      feat[0] <<= FXP_VALUE;
      feat[1] <<= FXP_VALUE;
      feat[2] <<= FXP_VALUE;
      feat[3] <<= FXP_VALUE;
      feat[4] <<= FXP_VALUE;
      feat[5] <<= FXP_VALUE;

      if (pkt_leaf->num_packets > 1) {
        #pragma unroll
        for (int i = 0; i < NUM_FLOW_FEATS; i++) {
          update_welford_feature(&pkt_leaf->stats[i],
                                 pkt_leaf->num_packets,
                                 feat[IDX_RAW_OFFSET + i],
                                 &feat[IDX_MEAN_OFFSET + i],
                                 &feat[IDX_SQCV_OFFSET + i]);
        }
      } else {
        #pragma unroll
        for (int i = 0; i < NUM_FLOW_FEATS; i++) {
          pkt_leaf->stats[i].sum = (uint64_t)feat[IDX_RAW_OFFSET + i];
          pkt_leaf->stats[i].m2 = 0;
          feat[IDX_MEAN_OFFSET + i] = feat[IDX_RAW_OFFSET + i];
          feat[IDX_SQCV_OFFSET + i] = 0;
        }
      }

      sessions.update(&pkt_key, pkt_leaf);
      int _zero = 0;
      u32 val = 0, *vp;
      vp = dropcnt.lookup_or_init(&_zero, &val);
      *vp += 1;
      return XDP_PASS;
    }
  }
  EOP: {
    return XDP_PASS;
  }
  return XDP_PASS;
}

"""

def map_bpf_table(hashmap, values):
    MAP_SIZE = len(values)
    assert len(hashmap.items()) == MAP_SIZE
    keys = (hashmap.Key * MAP_SIZE)()
    new_values = (hashmap.Leaf * MAP_SIZE)()

    for i in range(MAP_SIZE):
        keys[i] = ct.c_int(i)
        new_values[i] = ct.c_longlong(values[i])
    hashmap.items_update_batch(keys, new_values)

if __name__ == '__main__':

    if len(sys.argv) < 2 or len(sys.argv) > 4:
        usage()
    device = sys.argv[1]
    resdir = "."
    flags = 0
    offload_device = None
    ret = []

    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= BPF.XDP_FLAGS_SKB_MODE
    if "-D" in sys.argv:
        # XDP_FLAGS_DRV_MODE
        flags |= BPF.XDP_FLAGS_DRV_MODE
    if "-H" in sys.argv:
        # XDP_FLAGS_HW_MODE
        offload_device = device
        flags |= BPF.XDP_FLAGS_HW_MODE

    # If logdir is provided
    if len(sys.argv) >= 3 and not sys.argv[2].startswith("-"):
        resdir = sys.argv[2]
    elif len(sys.argv) == 4 and not sys.argv[3].startswith("-"):
        resdir = sys.argv[3]

    b = BPF(text=bpf_text, cflags=["-w", "-Wno-microsoft-anon-tag", "-fms-extensions"])
    # b = BPF(text=bpf_text, device=offload_device)
    # for i in range(0, lib.bpf_num_functions(b.module)):
    #     func_name = lib.bpf_function_name(b.module, i)
    #     print(func_name, lib.bpf_function_size(b.module, func_name))

    try:
        fn = b.load_func("xdp_drop_packet", BPF.XDP)
        b.attach_xdp(device, fn=fn, flags=flags)
        # fn = b.load_func("forward_packet", BPF.XDP)
        # b.attach_xdp(device2, fn=fn, flags=flags)

        dropcnt = b.get_table("dropcnt")

        prev = 0
        interval = 100
        start = datetime.now()
        print("[CLASSIFIER_READY]", flush=True)
        while True:
            try:
                dropcnt.clear()
                start1 = datetime.now()
                time.sleep(1)
                end = datetime.now()
                for k, v in dropcnt.items():
                    rate = int(v.value / (end - start1).total_seconds())
                    print(f"{end} {rate}", flush=True)
                    ret.append(rate)
                duration = (end - start).total_seconds()
                if duration > interval:
                    break
            except KeyboardInterrupt:
                break
    finally:
        try:
            os.makedirs(resdir, exist_ok=True)
            filename = f"{resdir}/rxpps.log"
            with open(filename, 'w') as f:
                for d in ret:
                    f.write(f"{d}\n")
        except Exception as e:
            print(f"Error writing {resdir}/rxpps.log: {e}", file=sys.stderr)
        try:
            b.remove_xdp(device, flags)
        except Exception as e:
            print(f"Error removing XDP: {e}", file=sys.stderr)
        # b.remove_xdp('router-veth2', flags)

