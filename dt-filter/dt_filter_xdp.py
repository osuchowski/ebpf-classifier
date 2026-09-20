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
import json
import numpy as np
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
#define TREE_LEAF -1
#define TREE_UNDEFINED -2
#define MAX_TREE_DEPTH DT_MAX_TREE_DEPTH
#define FIXED_POINT_DIGITS 16
#define FXP_VALUE FIXED_POINT_DIGITS
#define NUM_FEATURES 12

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
#ifdef DEBUG_BUILD
BPF_HASH(tmp,  struct ethhdr, int);
BPF_HASH(tmp2, struct ethhdr, bool);
BPF_HASH(tmp3, struct ethhdr, int64_t);
#endif
BPF_HASH(dropcnt, int, u32);
BPF_ARRAY(childrenLeft, s64, DT_CHILDREN_LEFT_SIZE);
BPF_ARRAY(childrenRight, s64, DT_CHILDREN_RIGHT_SIZE);
BPF_ARRAY(feature, s64, DT_FEATURE_SIZE);
BPF_ARRAY(threshold, s64, DT_THRESHOLD_SIZE);
BPF_ARRAY(value, s64, DT_VALUE_SIZE);

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    u32 check = (__force u32)iph->check;

    check += (__force u32)htons(0x0100);
    iph->check = (__force __sum16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

int dt_xdp_drop_packet(struct xdp_md *ctx) {
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
    if ((void*)&iph[1] > data_end)
      return XDP_DROP;
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
    goto dt;
  }
  udp: {
    uh = (struct udphdr *)(iph + 1);
    if ((void*)(uh + 1) > data_end) {
      return XDP_DROP;
    }
    pkt_key.sport = ntohs(uh->source);
    pkt_key.dport = ntohs(uh->dest);
    goto dt;
  }
  dt: {
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

      int i = 0;
      int current_node = 0;

      for (i = 0; i < MAX_TREE_DEPTH; i++) {
        int64_t* current_left_child  = childrenLeft.lookup(&current_node);
        int64_t* current_right_child = childrenRight.lookup(&current_node);
        int64_t* current_feature     = feature.lookup(&current_node);
        int64_t* current_threshold   = threshold.lookup(&current_node);
        if (current_left_child == NULL || current_right_child == NULL || current_feature == NULL || current_threshold == NULL || *current_left_child == TREE_LEAF || *current_feature == TREE_UNDEFINED) {
          break;
        } else {
          if (*current_feature >= 0 && *current_feature < NUM_FEATURES ) {
            int64_t current_feature_value = feat[*current_feature];
            if (current_feature_value <= *current_threshold) {
              current_node = (int) *current_left_child;
            } else {
              current_node = (int) *current_right_child;
            }
          }
        }
      }
      int64_t* current_value = value.lookup(&current_node);
      if (current_value) {
        if (*current_value == 0 || *current_value == 1) {
          bool is_anomaly = (bool)(*current_value);
          #ifdef DEBUG_BUILD
          tmp.update(eth, &current_node);
          tmp2.update(eth, &is_anomaly);
          tmp3.update(eth, current_value);
          #endif
          int _zero = 0;
          u32 val = 0, *vp;
          vp = dropcnt.lookup_or_init(&_zero, &val);
          *vp += 1;
          if (is_anomaly) {
            #ifdef DEBUG_BUILD
            return XDP_PASS;
            #else
            return XDP_DROP;
            #endif
          }
          return XDP_PASS;
        }
      }
    }
  }
  forward : {
    struct bpf_fib_lookup fib_params = {};
    if (iph->ttl <= 1) {
        return XDP_PASS;
    }
    __builtin_memset(&fib_params, 0, sizeof(fib_params));
    if (eth->h_proto == htons(ETH_P_IP)) {
        if ((void*)&iph[1] > data_end) {
            return XDP_DROP;
        }
        fib_params.family = AF_INET;
        fib_params.tos = iph->tos;
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src = iph->saddr;
        fib_params.ipv4_dst = iph->daddr;
        fib_params.ifindex = ctx->ingress_ifindex;
    } else {
        return XDP_PASS;
    }
    long rc;
    int _zero = 0;
    u32 val = 0, *vp;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
    // feats2.update(eth, &rc);
    switch(rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        ip_decrease_ttl(iph);
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        return bpf_redirect(fib_params.ifindex, 0);
    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED:
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
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

    prefix_path = f"{curdir}/runs"
    with open(f'{prefix_path}/childrenLeft', 'r') as f:
        children_left = np.array(json.load(f))
    with open(f'{prefix_path}/childrenRight', 'r') as f:
        children_right = np.array(json.load(f))
    with open(f'{prefix_path}/threshold', 'r') as f:
        threshold = np.array(json.load(f))
    with open(f'{prefix_path}/feature', 'r') as f:
        feature = np.array(json.load(f))
    with open(f'{prefix_path}/value', 'r') as f:
        value = np.array(json.load(f))

    bpf_text = bpf_text.replace('DT_CHILDREN_LEFT_SIZE', f"{len(children_left)}")
    bpf_text = bpf_text.replace('DT_CHILDREN_RIGHT_SIZE', f"{len(children_right)}")
    bpf_text = bpf_text.replace('DT_FEATURE_SIZE', f"{len(feature)}")
    bpf_text = bpf_text.replace('DT_VALUE_SIZE', f"{len(value)}")
    bpf_text = bpf_text.replace('DT_THRESHOLD_SIZE', f"{len(threshold)}")
    bpf_text = bpf_text.replace('DT_MAX_TREE_DEPTH', f"20")

    b = BPF(text=bpf_text, cflags=["-w", "-Wno-microsoft-anon-tag", "-fms-extensions"])
    ret = []
    # for i in range(0, lib.bpf_num_functions(b.module)):
    #     func_name = lib.bpf_function_name(b.module, i)
    #     print(func_name, lib.bpf_function_size(b.module, func_name))

    try:
        b.attach_xdp(device, fn = b.load_func("dt_xdp_drop_packet", BPF.XDP), flags=flags)

        dropcnt  = b.get_table("dropcnt")
        # feats = b.get_table("feats")

        map_children_right = b.get_table("childrenRight")
        map_children_left  = b.get_table("childrenLeft")
        map_value          = b.get_table("value")
        map_threshold      = b.get_table("threshold")
        map_feature        = b.get_table("feature")

        map_bpf_table(map_children_right, children_right)
        map_bpf_table(map_children_left, children_left)
        map_bpf_table(map_value, value)
        map_bpf_table(map_threshold, threshold)
        map_bpf_table(map_feature, feature)
        # for k, v in map_value.items():
        #     print(k.value, v.value)

        prev = 0
        interval = 110
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

