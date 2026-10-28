#include "capture.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.h"

#define ETH_HDR_LEN 14
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88a8
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct {
    int fd;
    uint8_t *ring;
    size_t ring_size;
    unsigned int frame_count;
    int frame_size;
    int block_size;
    int num_blocks;
} ring_handle;

struct capturer {
    pthread_mutex_t mu;
    ring_handle ring;
    char iface[64];
    bool promisc;
    int protocol_mode; /* 0=udp 1=tcp 2=all */
    int snaplen;
    detector *det;
    pcdn_prefix *nets;
    size_t nnets;
    atomic_bool stop;
};

static int proto_mode(const char *p)
{
    if (strcmp(p, "tcp") == 0)
        return 1;
    if (strcmp(p, "all") == 0)
        return 2;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 经典 BPF 过滤器                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    struct sock_filter ins[128];
    int n;
    int labels[64];
    struct {
        int idx;
        int label;
    } jumps[64];
    int njumps;
    bool failed;
} bpf_builder;

static void bpf_emit(bpf_builder *b, uint16_t code, uint32_t k, uint8_t jt, uint8_t jf)
{
    if (b->n >= (int)ARRAY_LEN(b->ins)) {
        b->failed = true;
        return;
    }
    b->ins[b->n].code = code;
    b->ins[b->n].jt = jt;
    b->ins[b->n].jf = jf;
    b->ins[b->n].k = k;
    b->n++;
}

static void bpf_mark(bpf_builder *b, int label)
{
    if (label >= 0 && label < (int)ARRAY_LEN(b->labels))
        b->labels[label] = b->n;
}

static void bpf_jeq(bpf_builder *b, uint32_t val, int label)
{
    if (label < 0 || label >= (int)ARRAY_LEN(b->labels)) {
        b->failed = true;
        return;
    }
    if (b->njumps >= (int)ARRAY_LEN(b->jumps)) {
        /* 跳转表满：不能静默丢弃，否则会生成语义错误的过滤器 */
        b->failed = true;
        return;
    }
    b->jumps[b->njumps].idx = b->n;
    b->jumps[b->njumps].label = label;
    b->njumps++;
    bpf_emit(b, BPF_JMP | BPF_JEQ | BPF_K, val, 0, 0);
}

#define BPF_LD_H_ABS (BPF_LD | BPF_H | BPF_ABS)
#define BPF_LD_B_ABS (BPF_LD | BPF_B | BPF_ABS)
#define BPF_RET_K (BPF_RET | BPF_K)

static bool bpf_resolve(bpf_builder *b)
{
    for (int i = 0; i < b->njumps; i++) {
        int idx = b->jumps[i].idx;
        int label = b->jumps[i].label;
        if (label < 0 || label >= (int)ARRAY_LEN(b->labels)) {
            b->failed = true;
            return false;
        }
        int target = b->labels[label];
        int skip = target - (idx + 1);
        if (skip < 0 || skip > 255) {
            b->failed = true;
            return false;
        }
        b->ins[idx].jt = (uint8_t)skip;
    }
    return true;
}

static int ipv4_accept_protos(int mode, uint32_t *out)
{
    if (mode == 1) {
        out[0] = PROTO_TCP;
        return 1;
    }
    if (mode == 2) {
        out[0] = PROTO_TCP;
        out[1] = PROTO_UDP;
        return 2;
    }
    out[0] = PROTO_UDP;
    return 1;
}

static int ipv6_accept_next(int mode, uint32_t *out)
{
    int n = 0;
    out[n++] = 0;
    out[n++] = 43;
    out[n++] = 44;
    out[n++] = 51;
    out[n++] = 60;
    out[n++] = 135;
    if (mode == 1) {
        out[n++] = PROTO_TCP;
    } else if (mode == 2) {
        out[n++] = PROTO_TCP;
        out[n++] = PROTO_UDP;
    } else {
        out[n++] = PROTO_UDP;
    }
    return n;
}

static bool build_capture_bpf(int mode, int snaplen, struct sock_filter *out, int *nout,
                              char *err, size_t errlen)
{
    if (snaplen <= 0) {
        set_err(err, errlen, "snaplen 必须大于 0（当前 %d）", snaplen);
        return false;
    }
    bpf_builder b;
    memset(&b, 0, sizeof(b));
    enum { ACCEPT = 40 };
    uint32_t accept = (uint32_t)snaplen;

    for (int i = 0; i < 3; i++) {
        int depth = i;
        bpf_mark(&b, depth);
        bpf_emit(&b, BPF_LD_H_ABS, (uint32_t)(12 + 4 * i), 0, 0);
        if (i < 2) {
            bpf_jeq(&b, ETHERTYPE_VLAN, i + 1);
            bpf_jeq(&b, ETHERTYPE_QINQ, i + 1);
        } else {
            bpf_jeq(&b, ETHERTYPE_VLAN, ACCEPT);
            bpf_jeq(&b, ETHERTYPE_QINQ, ACCEPT);
        }
        bpf_jeq(&b, ETHERTYPE_IPV4, 10 + i);
        bpf_jeq(&b, ETHERTYPE_IPV6, 20 + i);
        bpf_emit(&b, BPF_RET_K, 0, 0, 0);
    }

    for (int i = 0; i < 3; i++) {
        int l3 = 14 + 4 * i;
        bpf_mark(&b, 10 + i);
        bpf_emit(&b, BPF_LD_H_ABS, (uint32_t)(l3 + 6), 0, 0);
        bpf_emit(&b, BPF_ALU | BPF_AND | BPF_K, 0x1fff, 0, 0);
        bpf_jeq(&b, 0, 30 + i);
        bpf_emit(&b, BPF_RET_K, 0, 0, 0);
        bpf_mark(&b, 30 + i);
        bpf_emit(&b, BPF_LD_B_ABS, (uint32_t)(l3 + 9), 0, 0);
        uint32_t protos[4];
        int np = ipv4_accept_protos(mode, protos);
        for (int k = 0; k < np; k++)
            bpf_jeq(&b, protos[k], ACCEPT);
        bpf_emit(&b, BPF_RET_K, 0, 0, 0);

        bpf_mark(&b, 20 + i);
        bpf_emit(&b, BPF_LD_B_ABS, (uint32_t)(l3 + 6), 0, 0);
        uint32_t nh[16];
        int nn = ipv6_accept_next(mode, nh);
        for (int k = 0; k < nn; k++)
            bpf_jeq(&b, nh[k], ACCEPT);
        bpf_emit(&b, BPF_RET_K, 0, 0, 0);
    }

    bpf_mark(&b, ACCEPT);
    bpf_emit(&b, BPF_RET_K, accept, 0, 0);
    if (b.failed || !bpf_resolve(&b)) {
        set_err(err, errlen, "BPF 过滤器构建失败");
        return false;
    }
    memcpy(out, b.ins, (size_t)b.n * sizeof(struct sock_filter));
    *nout = b.n;
    return true;
}

static int attach_bpf(int fd, int mode, int snaplen, char *err, size_t errlen)
{
    struct sock_filter ins[128];
    int n = 0;
    if (!build_capture_bpf(mode, snaplen, ins, &n, err, errlen))
        return -1;
    struct sock_fprog prog = {.len = (unsigned short)n, .filter = ins};
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) != 0) {
        set_err(err, errlen, "设置内核 BPF 过滤器失败：%s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 网卡 / 环形缓冲                                                     */
/* ------------------------------------------------------------------ */

static void load_local_nets(capturer *c)
{
    free(c->nets);
    c->nets = NULL;
    c->nnets = 0;
    struct ifaddrs *ifas = NULL;
    if (getifaddrs(&ifas) != 0)
        return;
    for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_netmask)
            continue;
        if (strcmp(ifa->ifa_name, c->iface) != 0)
            continue;
        pcdn_prefix pfx;
        memset(&pfx, 0, sizeof(pfx));
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
            memcpy(pfx.base.b, &sin->sin_addr, 4);
            pfx.base.v6 = 0;
            pfx.base.valid = true;
            uint32_t m = ntohl(mask->sin_addr.s_addr);
            int bits = 0;
            while (bits < 32 && (m & (1u << (31 - bits))))
                bits++;
            pfx.bits = (uint8_t)bits;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            struct sockaddr_in6 *mask6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
            memcpy(pfx.base.b, &sin6->sin6_addr, 16);
            pfx.base.v6 = 1;
            pfx.base.valid = true;
            int bits = 0;
            for (int i = 0; i < 16; i++) {
                uint8_t m = mask6->sin6_addr.s6_addr[i];
                for (int k = 7; k >= 0; k--) {
                    if (m & (1u << k))
                        bits++;
                    else
                        goto done6;
                }
            }
        done6:
            pfx.bits = (uint8_t)bits;
        } else {
            continue;
        }
        c->nets = xrealloc(c->nets, (c->nnets + 1) * sizeof(pcdn_prefix));
        c->nets[c->nnets++] = pfx;
    }
    freeifaddrs(ifas);
}

static int set_promisc(int fd, const char *iface, bool enable)
{
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = (int)if_nametoindex(iface);
    mr.mr_type = PACKET_MR_PROMISC;
    if (mr.mr_ifindex == 0)
        return -1;
    return setsockopt(fd, SOL_PACKET, enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP, &mr,
                      sizeof(mr));
}

static bool ring_open(const char *iface, bool promisc, int frame_size, int block_size,
                      int num_blocks, ring_handle *out, char *err, size_t errlen)
{
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        set_err(err, errlen, "网卡不存在或无法获取索引：%s", iface);
        return false;
    }
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        set_err(err, errlen, "打开 AF_PACKET socket 失败：%s", strerror(errno));
        return false;
    }
    int version = TPACKET_V2;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) != 0) {
        set_err(err, errlen, "设置 PACKET_VERSION 失败：%s", strerror(errno));
        close(fd);
        return false;
    }

    int frames_per_block = block_size / frame_size;
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = (unsigned int)block_size;
    req.tp_block_nr = (unsigned int)num_blocks;
    req.tp_frame_size = (unsigned int)frame_size;
    req.tp_frame_nr = (unsigned int)(frames_per_block * num_blocks);
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) != 0) {
        set_err(err, errlen, "设置 PACKET_RX_RING 失败（frame=%d block=%d blocks=%d）：%s",
                frame_size, block_size, num_blocks, strerror(errno));
        close(fd);
        return false;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        set_err(err, errlen, "绑定网卡 %s 失败：%s", iface, strerror(errno));
        close(fd);
        return false;
    }

    size_t ring_size = (size_t)block_size * (size_t)num_blocks;
    void *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        set_err(err, errlen, "mmap 抓包环形缓冲失败：%s", strerror(errno));
        close(fd);
        return false;
    }
    if (promisc)
        (void)set_promisc(fd, iface, true);

    out->fd = fd;
    out->ring = ring;
    out->ring_size = ring_size;
    out->frame_count = req.tp_frame_nr;
    out->frame_size = frame_size;
    out->block_size = block_size;
    out->num_blocks = num_blocks;
    return true;
}

static void ring_close(ring_handle *r)
{
    if (r->ring && r->ring != MAP_FAILED)
        munmap(r->ring, r->ring_size);
    if (r->fd >= 0)
        close(r->fd);
    memset(r, 0, sizeof(*r));
    r->fd = -1;
}

/* ------------------------------------------------------------------ */
/* 报文解析                                                            */
/* ------------------------------------------------------------------ */

static bool ipv6_transport_offset(const uint8_t *data, size_t len, size_t off, uint8_t *proto,
                                  size_t *l4off)
{
    if (len < off + 40)
        return false;
    uint8_t next = data[off + 6];
    size_t p = off + 40;
    for (int i = 0; i < 8; i++) {
        switch (next) {
        case 0:
        case 43:
        case 60:
        case 135: {
            if (len < p + 2)
                return false;
            size_t hlen = ((size_t)data[p + 1] + 1) * 8;
            if (hlen < 8 || len < p + hlen)
                return false;
            next = data[p];
            p += hlen;
            break;
        }
        case 44: {
            if (len < p + 8)
                return false;
            uint16_t frag = (uint16_t)((data[p + 2] << 8) | data[p + 3]);
            if (frag & 0xfff8)
                return false;
            next = data[p];
            p += 8;
            break;
        }
        case 51: {
            if (len < p + 2)
                return false;
            size_t hlen = ((size_t)data[p + 1] + 2) * 4;
            if (len < p + hlen)
                return false;
            next = data[p];
            p += hlen;
            break;
        }
        default:
            *proto = next;
            *l4off = p;
            return true;
        }
    }
    return false;
}

static bool is_local_to(const pcdn_ip *ip, const pcdn_prefix *nets, size_t nnets)
{
    if (!ip->valid)
        return false;
    if (ip_is_loopback(ip) || ip_is_linklocal(ip))
        return true;
    if (nnets == 0)
        return !ip_is_public(ip);
    for (size_t i = 0; i < nnets; i++) {
        if (prefix_contains(&nets[i], ip))
            return true;
    }
    return false;
}

static void handle_frame(capturer *c, const uint8_t *data, size_t caplen, int wirelen,
                         int64_t ts_ns)
{
    if (caplen < ETH_HDR_LEN)
        return;
    size_t off = ETH_HDR_LEN;
    uint16_t eth_type = (uint16_t)((data[12] << 8) | data[13]);
    int guard = 0;
    while ((eth_type == ETHERTYPE_VLAN || eth_type == ETHERTYPE_QINQ) && guard++ < 8) {
        if (caplen < off + 4)
            return;
        eth_type = (uint16_t)((data[off + 2] << 8) | data[off + 3]);
        off += 4;
    }

    pcdn_ip src, dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    uint8_t proto = 0;
    size_t l4off = 0;
    bool v6 = false;

    if (eth_type == ETHERTYPE_IPV4) {
        if (caplen < off + 20)
            return;
        size_t ihl = (size_t)(data[off] & 0x0f) * 4;
        if (ihl < 20 || caplen < off + ihl)
            return;
        uint16_t frag = (uint16_t)((data[off + 6] << 8) | data[off + 7]);
        if (frag & 0x1fff)
            return;
        proto = data[off + 9];
        memcpy(src.b, data + off + 12, 4);
        memcpy(dst.b, data + off + 16, 4);
        src.v6 = dst.v6 = 0;
        src.valid = dst.valid = true;
        l4off = off + ihl;
    } else if (eth_type == ETHERTYPE_IPV6) {
        if (caplen < off + 40)
            return;
        v6 = true;
        memcpy(src.b, data + off + 8, 16);
        memcpy(dst.b, data + off + 24, 16);
        src.v6 = dst.v6 = 1;
        src.valid = dst.valid = true;
        if (!ipv6_transport_offset(data, caplen, off, &proto, &l4off))
            return;
    } else {
        return;
    }

    if (caplen < l4off + 4)
        return;
    /* IPv6 扩展头在 BPF 里一律放行，解析出真正的上层协议后需再次确认它与
     * 抓包协议一致，否则 protocol = "udp"/"tcp" 时会把另一种协议也计入统计。 */
    if ((c->protocol_mode == 1 && proto != PROTO_TCP) ||
        (c->protocol_mode == 0 && proto != PROTO_UDP))
        return;
    uint16_t src_port = (uint16_t)((data[l4off] << 8) | data[l4off + 1]);
    uint16_t dst_port = (uint16_t)((data[l4off + 2] << 8) | data[l4off + 3]);
    if (proto != PROTO_TCP && proto != PROTO_UDP)
        return;
    if (ip_equal(&src, &dst))
        return;

    bool src_local = is_local_to(&src, c->nets, c->nnets);
    bool dst_local = is_local_to(&dst, c->nets, c->nnets);

    observation o;
    memset(&o, 0, sizeof(o));
    bool up;
    if (src_local && !dst_local) {
        up = true;
        memcpy(o.mac.b, data + 6, 6);
        o.ip = src;
        o.local_port = src_port;
        o.remote_ip = dst;
    } else if (dst_local && !src_local) {
        up = false;
        memcpy(o.mac.b, data, 6);
        o.ip = dst;
        o.local_port = dst_port;
        o.remote_ip = src;
    } else {
        return;
    }
    if (!ip_is_public(&o.remote_ip))
        return;
    o.up = up;
    o.v6 = v6;
    o.proto = proto;
    o.length = wirelen;
    o.ts_ns = ts_ns;
    detector_observe(c->det, &o);
}

/* ------------------------------------------------------------------ */
/* 对外接口                                                            */
/* ------------------------------------------------------------------ */

capturer *capturer_create(const char *iface, bool promisc, const config_t *cfg, detector *det,
                          char *err, size_t errlen)
{
    capturer *c = xcalloc(1, sizeof(*c));
    pthread_mutex_init(&c->mu, NULL);
    atomic_init(&c->stop, false);
    snprintf(c->iface, sizeof(c->iface), "%s", iface);
    c->promisc = promisc;
    c->protocol_mode = proto_mode(config_capture_proto(cfg));
    c->snaplen = config_snaplen_value(cfg);
    c->det = det;
    c->ring.fd = -1;

    int frame, block, blocks;
    config_ring_params(cfg, &frame, &block, &blocks);
    if (!ring_open(iface, promisc, frame, block, blocks, &c->ring, err, errlen)) {
        pthread_mutex_destroy(&c->mu);
        free(c);
        return NULL;
    }
    if (attach_bpf(c->ring.fd, c->protocol_mode, c->snaplen, err, errlen) != 0) {
        ring_close(&c->ring);
        pthread_mutex_destroy(&c->mu);
        free(c);
        return NULL;
    }
    load_local_nets(c);
    return c;
}

void capturer_destroy(capturer *c)
{
    if (!c)
        return;
    capturer_stop(c);
    ring_close(&c->ring);
    free(c->nets);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

void capturer_stop(capturer *c)
{
    if (c)
        atomic_store(&c->stop, true);
}

int capturer_run(capturer *c, char *err, size_t errlen)
{
    (void)err;
    (void)errlen;
    unsigned int frame_idx = 0;
    int err_count = 0;
    while (!atomic_load(&c->stop)) {
        pthread_mutex_lock(&c->mu);
        if (atomic_load(&c->stop)) {
            pthread_mutex_unlock(&c->mu);
            break;
        }
        struct pollfd pfd = {.fd = c->ring.fd, .events = POLLIN};
        int pr = poll(&pfd, 1, 1000);
        if (pr < 0) {
            pthread_mutex_unlock(&c->mu);
            if (errno == EINTR)
                continue;
            err_count++;
            if (err_count > 1000)
                return -1;
            struct timespec req = {0, 5000000};
            nanosleep(&req, NULL);
            continue;
        }
        if (pr == 0) {
            pthread_mutex_unlock(&c->mu);
            continue;
        }
        bool handled = false;
        if (frame_idx >= c->ring.frame_count)
            frame_idx = 0;
        for (unsigned int guard = 0; guard < c->ring.frame_count; guard++) {
            uint8_t *base = c->ring.ring + (size_t)frame_idx * (size_t)c->ring.frame_size;
            struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)base;
            if (!(hdr->tp_status & TP_STATUS_USER))
                break;
            int wirelen = (int)hdr->tp_len;
            size_t frame_size = (size_t)c->ring.frame_size;
            size_t mac_off = hdr->tp_mac;
            /* 先校验 tp_mac 落在本帧内，再据此裁剪长度：越界的偏移不能用来构造指针 */
            if (mac_off > frame_size) {
                __sync_synchronize();
                hdr->tp_status = TP_STATUS_KERNEL;
                frame_idx = (frame_idx + 1) % c->ring.frame_count;
                continue;
            }
            size_t caplen = hdr->tp_snaplen;
            size_t frame_avail = frame_size - mac_off;
            if (caplen > frame_avail)
                caplen = frame_avail;
            int64_t ts_ns = (int64_t)hdr->tp_sec * 1000000000LL + hdr->tp_nsec;
            handle_frame(c, base + mac_off, caplen, wirelen, ts_ns);
            __sync_synchronize();
            hdr->tp_status = TP_STATUS_KERNEL;
            frame_idx = (frame_idx + 1) % c->ring.frame_count;
            handled = true;
        }
        (void)handled;
        pthread_mutex_unlock(&c->mu);
    }
    return 0;
}

int capturer_reconfigure(capturer *c, const config_t *cfg, bool promisc, char *err,
                         size_t errlen)
{
    char e[512];
    int frame, block, blocks;
    config_ring_params(cfg, &frame, &block, &blocks);
    int mode = proto_mode(config_capture_proto(cfg));
    int snaplen = config_snaplen_value(cfg);

    pthread_mutex_lock(&c->mu);
    bool same = strcmp(cfg->capture.iface, c->iface) == 0 && frame == c->ring.frame_size &&
                block == c->ring.block_size && blocks == c->ring.num_blocks;
    if (same) {
        if (mode != c->protocol_mode || snaplen != c->snaplen) {
            if (attach_bpf(c->ring.fd, mode, snaplen, err, errlen) != 0) {
                char tmp[600];
                snprintf(tmp, sizeof(tmp), "重设内核 BPF 过滤器失败：%s", err);
                set_err(err, errlen, "%s", tmp);
                pthread_mutex_unlock(&c->mu);
                return -1;
            }
        }
        if (promisc != c->promisc) {
            if (set_promisc(c->ring.fd, c->iface, promisc) != 0) {
                set_err(err, errlen, "设置混杂模式失败：%s", strerror(errno));
                pthread_mutex_unlock(&c->mu);
                return -1;
            }
        }
        c->protocol_mode = mode;
        c->snaplen = snaplen;
        c->promisc = promisc;
        pthread_mutex_unlock(&c->mu);
        return 0;
    }

    ring_handle nr;
    if (!ring_open(cfg->capture.iface, promisc, frame, block, blocks, &nr, e, sizeof(e))) {
        set_err(err, errlen, "重开抓包 socket 失败（网卡 %s）：%s", cfg->capture.iface, e);
        pthread_mutex_unlock(&c->mu);
        return -1;
    }
    if (attach_bpf(nr.fd, mode, snaplen, e, sizeof(e)) != 0) {
        ring_close(&nr);
        set_err(err, errlen, "重开抓包 socket 失败（网卡 %s）：%s", cfg->capture.iface, e);
        pthread_mutex_unlock(&c->mu);
        return -1;
    }
    ring_close(&c->ring);
    c->ring = nr;
    snprintf(c->iface, sizeof(c->iface), "%s", cfg->capture.iface);
    c->promisc = promisc;
    c->protocol_mode = mode;
    c->snaplen = snaplen;
    load_local_nets(c);
    pthread_mutex_unlock(&c->mu);
    return 0;
}
