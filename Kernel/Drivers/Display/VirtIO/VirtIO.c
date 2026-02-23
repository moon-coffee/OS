#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "../../../Serial.h"
#include "../../../IO/IO_Main.h"
#include "../../../Memory/Memory_Main.h"
#include "../../../Memory/Other_Utils.h"
#include "../../../Paging/Paging_Main.h"
#ifdef IMPLUS_DRIVER_MODULE
#include "../../DriverBinary.h"
#else
#include "../../DriverSelect.h"
#endif
#include "../../PCI/PCI_Main.h"

#define VIRTIO_VENDOR_ID 0x1AF4
#define VIRTIO_GPU_DEVICE_ID 0x1050
#define VIRTIO_GPU_DEVICE_NAME "VirtIO GPU"

#define PCI_CAP_ID_VENDOR 0x09

#define VIRTIO_PCI_CAP_COMMON_CFG 1
#define VIRTIO_PCI_CAP_NOTIFY_CFG 2
#define VIRTIO_PCI_CAP_DEVICE_CFG 4

#define VIRTIO_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_STATUS_DRIVER      0x02
#define VIRTIO_STATUS_DRIVER_OK   0x04
#define VIRTIO_STATUS_FEATURES_OK 0x08
#define VIRTIO_STATUS_FAILED      0x80

#define VIRTIO_F_VERSION_1 (1u << 0)

#define VIRTQ_DESC_F_NEXT  1
#define VIRTQ_DESC_F_WRITE 2

#define VIRTIO_GPU_CMD_GET_DISPLAY_INFO       0x0100
#define VIRTIO_GPU_CMD_RESOURCE_CREATE_2D     0x0101
#define VIRTIO_GPU_CMD_SET_SCANOUT            0x0103
#define VIRTIO_GPU_CMD_RESOURCE_FLUSH         0x0104
#define VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D    0x0105
#define VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING 0x0106

#define VIRTIO_GPU_RESP_OK_NODATA       0x1100
#define VIRTIO_GPU_RESP_OK_DISPLAY_INFO 0x1101

#define VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM 1

#define GPU_RESOURCE_ID 1
#define GPU_SCANOUT_ID  0

#define VIRTIO_MMIO_TIMEOUT 10000000u

#ifdef IMPLUS_DRIVER_MODULE
static const driver_kernel_api_t *g_driver_api = NULL;

static void *driver_module_memset(void *dst, int value, size_t n) {
    uint8_t *p = (uint8_t *)dst;
    for (size_t i = 0; i < n; ++i) {
        p[i] = (uint8_t)value;
    }
    return dst;
}

static int driver_module_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}

#define serial_write_string g_driver_api->serial_write_string
#define serial_write_uint32 g_driver_api->serial_write_uint32
#define kmalloc g_driver_api->kmalloc
#define kfree g_driver_api->kfree
#define pci_read_config g_driver_api->pci_read_config
#define pci_write_config g_driver_api->pci_write_config
#define map_mmio_virt g_driver_api->map_mmio_virt
#define memset driver_module_memset
#define strcmp driver_module_strcmp
#endif

typedef struct {
    uint8_t bus;
    uint8_t device;
    uint8_t func;
    uint64_t bar_addr[6];
    uint8_t bar_is_mem[6];
    uint32_t irq;
} virtio_gpu_pci_t;

typedef struct __attribute__((packed)) {
    uint8_t cap_vndr;
    uint8_t cap_next;
    uint8_t cap_len;
    uint8_t cfg_type;
    uint8_t bar;
    uint8_t id;
    uint8_t padding[2];
    uint32_t offset;
    uint32_t length;
} virtio_pci_cap_t;

typedef struct {
    volatile uint8_t *common_cfg;
    volatile uint8_t *notify_base;
    volatile uint8_t *device_cfg;
    uint32_t notify_off_multiplier;
} virtio_pci_transport_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} virtq_desc_t;

typedef struct __attribute__((packed)) {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} virtq_avail_t;

typedef struct __attribute__((packed)) {
    uint32_t id;
    uint32_t len;
} virtq_used_elem_t;

typedef struct __attribute__((packed)) {
    uint16_t flags;
    uint16_t idx;
    virtq_used_elem_t ring[];
} virtq_used_t;

typedef struct {
    uint16_t queue_index;
    uint16_t queue_size;
    volatile virtq_desc_t *desc;
    volatile virtq_avail_t *avail;
    volatile virtq_used_t *used;
    uint16_t avail_idx;
    uint16_t used_idx_seen;
    volatile uint16_t *notify_addr;
} virtqueue_t;

typedef struct __attribute__((packed)) {
    uint32_t type;
    uint32_t flags;
    uint64_t fence_id;
    uint32_t ctx_id;
    uint32_t padding;
} virtio_gpu_ctrl_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} virtio_gpu_rect_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t format;
    uint32_t width;
    uint32_t height;
} virtio_gpu_resource_create_2d_t;

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t length;
    uint32_t padding;
} virtio_gpu_mem_entry_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    uint32_t resource_id;
    uint32_t nr_entries;
    virtio_gpu_mem_entry_t entry;
} virtio_gpu_resource_attach_backing_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t rect;
    uint32_t scanout_id;
    uint32_t resource_id;
} virtio_gpu_set_scanout_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t rect;
    uint64_t offset;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_transfer_to_host_2d_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_rect_t rect;
    uint32_t resource_id;
    uint32_t padding;
} virtio_gpu_resource_flush_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
} virtio_gpu_resp_nodata_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_rect_t r;
    uint32_t enabled;
    uint32_t flags;
} virtio_gpu_display_one_t;

typedef struct __attribute__((packed)) {
    virtio_gpu_ctrl_hdr_t hdr;
    virtio_gpu_display_one_t pmodes[16];
} virtio_gpu_resp_display_info_t;

static int g_gpu_ready = 0;
static uint32_t g_gpu_width = 0;
static uint32_t g_gpu_height = 0;
static uint32_t *g_gpu_fb = NULL;
static virtqueue_t g_gpu_controlq;

static inline uint32_t align_up_u32(uint32_t value, uint32_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

static inline void memory_barrier(void) {
    __asm__ volatile ("" ::: "memory");
}

static uint8_t pci_cfg_read8(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    uint32_t v = pci_read_config(bus, device, func, (uint8_t)(offset & 0xFC));
    return (uint8_t)((v >> ((offset & 0x3u) * 8u)) & 0xFFu);
}

static uint16_t pci_cfg_read16(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    uint32_t v = pci_read_config(bus, device, func, (uint8_t)(offset & 0xFC));
    return (uint16_t)((v >> ((offset & 0x2u) * 8u)) & 0xFFFFu);
}

static uint32_t pci_cfg_read32(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset) {
    return pci_read_config(bus, device, func, (uint8_t)(offset & 0xFC));
}

static void pci_cfg_write16(uint8_t bus, uint8_t device, uint8_t func, uint8_t offset, uint16_t value) {
    uint8_t aligned = (uint8_t)(offset & 0xFC);
    uint32_t old = pci_read_config(bus, device, func, aligned);
    uint32_t shift = (uint32_t)((offset & 0x2u) * 8u);
    uint32_t mask = 0xFFFFu << shift;
    uint32_t merged = (old & ~mask) | ((uint32_t)value << shift);
    pci_write_config(bus, device, func, aligned, merged);
}

static void pci_read_bar_addrs(uint8_t bus, uint8_t device, uint8_t func, uint64_t out_bar[6], uint8_t out_is_mem[6]) {
    uint8_t i = 0;
    while (i < 6) {
        uint32_t bar = pci_cfg_read32(bus, device, func, (uint8_t)(0x10 + i * 4));
        out_bar[i] = 0;
        out_is_mem[i] = 0;

        if (bar == 0 || bar == 0xFFFFFFFFu) {
            i++;
            continue;
        }

        if (bar & 0x1u) {
            i++;
            continue;
        }

        out_is_mem[i] = 1;
        if (((bar >> 1) & 0x3u) == 0x2u && i < 5) {
            uint32_t bar_hi = pci_cfg_read32(bus, device, func, (uint8_t)(0x10 + (i + 1) * 4));
            out_bar[i] = (((uint64_t)bar_hi) << 32) | (uint64_t)(bar & ~0xFu);
            i += 2;
            continue;
        }

        out_bar[i] = (uint64_t)(bar & ~0xFu);
        i++;
    }
}

static const char *pci_device_name(uint16_t vendor_id, uint16_t device_id) {
    if (vendor_id == VIRTIO_VENDOR_ID && device_id == VIRTIO_GPU_DEVICE_ID) {
        return VIRTIO_GPU_DEVICE_NAME;
    }
    return NULL;
}

static int find_virtio_gpu(virtio_gpu_pci_t *gpu) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t func = 0; func < 8; func++) {
                uint32_t vd = pci_read_config((uint8_t)bus, device, func, 0x00);
                uint16_t vendor_id = (uint16_t)(vd & 0xFFFFu);
                uint16_t device_id = (uint16_t)((vd >> 16) & 0xFFFFu);

                if (vendor_id == 0xFFFFu) {
                    if (func == 0) {
                        break;
                    }
                    continue;
                }

                const char *device_name = pci_device_name(vendor_id, device_id);
                if (device_name != NULL && strcmp(device_name, VIRTIO_GPU_DEVICE_NAME) == 0) {
                    gpu->bus = (uint8_t)bus;
                    gpu->device = device;
                    gpu->func = func;
                    gpu->irq = pci_cfg_read8((uint8_t)bus, device, func, 0x3C);
                    pci_read_bar_addrs((uint8_t)bus, device, func, gpu->bar_addr, gpu->bar_is_mem);
                    return 1;
                }

                if (func == 0) {
                    uint32_t header_type = pci_read_config((uint8_t)bus, device, func, 0x0C);
                    if (((header_type >> 16) & 0x80u) == 0) {
                        break;
                    }
                }
            }
        }
    }
    return 0;
}

static int virtio_pci_find_caps(const virtio_gpu_pci_t *gpu, virtio_pci_transport_t *t) {
    t->common_cfg = NULL;
    t->notify_base = NULL;
    t->device_cfg = NULL;
    t->notify_off_multiplier = 0;

    uint16_t status = pci_cfg_read16(gpu->bus, gpu->device, gpu->func, 0x06);
    if ((status & (1u << 4)) == 0) {
        return 0;
    }

    uint8_t cap = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, 0x34);
    uint32_t guard = 0;

    while (cap != 0 && cap >= 0x40 && guard++ < 64) {
        uint8_t cap_id = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, cap);
        uint8_t cap_next = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 1));

        if (cap_id == PCI_CAP_ID_VENDOR) {
            virtio_pci_cap_t vcap;
            vcap.cap_vndr = cap_id;
            vcap.cap_next = cap_next;
            vcap.cap_len = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 2));
            vcap.cfg_type = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 3));
            vcap.bar = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 4));
            vcap.id = pci_cfg_read8(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 5));
            vcap.offset = pci_cfg_read32(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 8));
            vcap.length = pci_cfg_read32(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 12));

            if (vcap.bar < 6 && gpu->bar_is_mem[vcap.bar] && gpu->bar_addr[vcap.bar] != 0) {
                uint64_t phys = gpu->bar_addr[vcap.bar] + (uint64_t)vcap.offset;
                volatile uint8_t *base = (volatile uint8_t *)map_mmio_virt(phys);
                if (!base) {
                    return 0;
                }

                if (vcap.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG) {
                    t->common_cfg = base;
                } else if (vcap.cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG) {
                    t->notify_base = base;
                    t->notify_off_multiplier = pci_cfg_read32(gpu->bus, gpu->device, gpu->func, (uint8_t)(cap + 16));
                } else if (vcap.cfg_type == VIRTIO_PCI_CAP_DEVICE_CFG) {
                    t->device_cfg = base;
                }
            }
        }

        cap = cap_next;
    }

    return (t->common_cfg != NULL && t->notify_base != NULL) ? 1 : 0;
}

static inline uint8_t common_read8(volatile uint8_t *common, uint32_t off) {
    return *(volatile uint8_t *)(common + off);
}

static inline uint16_t common_read16(volatile uint8_t *common, uint32_t off) {
    return *(volatile uint16_t *)(common + off);
}

static inline uint32_t common_read32(volatile uint8_t *common, uint32_t off) {
    return *(volatile uint32_t *)(common + off);
}

static inline void common_write8(volatile uint8_t *common, uint32_t off, uint8_t v) {
    *(volatile uint8_t *)(common + off) = v;
}

static inline void common_write16(volatile uint8_t *common, uint32_t off, uint16_t v) {
    *(volatile uint16_t *)(common + off) = v;
}

static inline void common_write32(volatile uint8_t *common, uint32_t off, uint32_t v) {
    *(volatile uint32_t *)(common + off) = v;
}

static inline void common_write64(volatile uint8_t *common, uint32_t off, uint64_t v) {
    *(volatile uint64_t *)(common + off) = v;
}

static int virtio_pci_device_init(const virtio_gpu_pci_t *gpu, virtio_pci_transport_t *t) {
    uint16_t cmd = pci_cfg_read16(gpu->bus, gpu->device, gpu->func, 0x04);
    cmd |= (1u << 1);
    cmd |= (1u << 2);
    pci_cfg_write16(gpu->bus, gpu->device, gpu->func, 0x04, cmd);

    common_write8(t->common_cfg, 20, 0);
    common_write8(t->common_cfg, 20, VIRTIO_STATUS_ACKNOWLEDGE);
    common_write8(t->common_cfg, 20, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

    common_write32(t->common_cfg, 0, 0);
    (void)common_read32(t->common_cfg, 4);
    common_write32(t->common_cfg, 0, 1);
    (void)common_read32(t->common_cfg, 4);

    common_write32(t->common_cfg, 8, 0);
    common_write32(t->common_cfg, 12, 0);
    common_write32(t->common_cfg, 8, 1);
    common_write32(t->common_cfg, 12, VIRTIO_F_VERSION_1);

    uint8_t status = (uint8_t)(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
    common_write8(t->common_cfg, 20, status);
    status = common_read8(t->common_cfg, 20);
    if ((status & VIRTIO_STATUS_FEATURES_OK) == 0) {
        common_write8(t->common_cfg, 20, status | VIRTIO_STATUS_FAILED);
        return 0;
    }

    return 1;
}

static void *alloc_aligned(uint32_t size, uint32_t align) {
    uintptr_t raw = (uintptr_t)kmalloc(size + align - 1u);
    if (!raw) {
        return NULL;
    }
    uintptr_t aligned = (raw + (align - 1u)) & ~(uintptr_t)(align - 1u);
    return (void *)aligned;
}

static int virtqueue_init_ctrl(virtio_pci_transport_t *t, virtqueue_t *vq, uint16_t queue_index) {
    common_write16(t->common_cfg, 22, queue_index);
    uint16_t qsize = common_read16(t->common_cfg, 24);
    if (qsize < 2) {
        return 0;
    }

    uint32_t desc_bytes = (uint32_t)qsize * (uint32_t)sizeof(virtq_desc_t);
    uint32_t avail_bytes = 6u + (uint32_t)qsize * 2u;
    uint32_t used_off = align_up_u32(desc_bytes + avail_bytes, 4u);
    uint32_t used_bytes = 6u + (uint32_t)qsize * 8u;
    uint32_t total = used_off + used_bytes;

    uint8_t *ring = (uint8_t *)alloc_aligned(total, 4096u);
    if (!ring) {
        return 0;
    }
    memset(ring, 0, total);

    vq->queue_index = queue_index;
    vq->queue_size = qsize;
    vq->desc = (volatile virtq_desc_t *)ring;
    vq->avail = (volatile virtq_avail_t *)(ring + desc_bytes);
    vq->used = (volatile virtq_used_t *)(ring + used_off);
    vq->avail_idx = 0;
    vq->used_idx_seen = 0;

    common_write16(t->common_cfg, 26, 0xFFFFu);
    common_write64(t->common_cfg, 32, (uint64_t)(uintptr_t)vq->desc);
    common_write64(t->common_cfg, 40, (uint64_t)(uintptr_t)vq->avail);
    common_write64(t->common_cfg, 48, (uint64_t)(uintptr_t)vq->used);
    common_write16(t->common_cfg, 28, 1);

    uint16_t notify_off = common_read16(t->common_cfg, 30);
    vq->notify_addr = (volatile uint16_t *)(t->notify_base + ((uint32_t)notify_off * t->notify_off_multiplier));

    common_write16(t->common_cfg, 22, queue_index);
    if (common_read16(t->common_cfg, 28) == 0) {
        return 0;
    }

    return 1;
}

static int virtqueue_submit_sync(virtqueue_t *vq, void *cmd, uint32_t cmd_len, void *resp, uint32_t resp_len) {
    if (vq->queue_size < 2) {
        return 0;
    }

    vq->desc[0].addr = (uint64_t)(uintptr_t)cmd;
    vq->desc[0].len = cmd_len;
    vq->desc[0].flags = VIRTQ_DESC_F_NEXT;
    vq->desc[0].next = 1;

    vq->desc[1].addr = (uint64_t)(uintptr_t)resp;
    vq->desc[1].len = resp_len;
    vq->desc[1].flags = VIRTQ_DESC_F_WRITE;
    vq->desc[1].next = 0;

    vq->avail->ring[vq->avail_idx % vq->queue_size] = 0;
    memory_barrier();
    vq->avail_idx++;
    vq->avail->idx = vq->avail_idx;
    memory_barrier();

    *vq->notify_addr = vq->queue_index;

    uint32_t timeout = VIRTIO_MMIO_TIMEOUT;
    while ((uint16_t)(vq->used->idx - vq->used_idx_seen) == 0) {
        if (--timeout == 0) {
            return 0;
        }
    }

    vq->used_idx_seen = vq->used->idx;
    return 1;
}

static int gpu_cmd_get_display_info(virtqueue_t *vq, uint32_t *width, uint32_t *height) {
    virtio_gpu_ctrl_hdr_t cmd;
    virtio_gpu_resp_display_info_t resp;

    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));
    cmd.type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;

    if (!virtqueue_submit_sync(vq, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
        return 0;
    }
    if (resp.hdr.type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) {
        return 0;
    }
    if (resp.pmodes[0].r.width == 0 || resp.pmodes[0].r.height == 0) {
        return 0;
    }

    *width = resp.pmodes[0].r.width;
    *height = resp.pmodes[0].r.height;
    return 1;
}

static int gpu_cmd_resource_create_2d(virtqueue_t *vq, uint32_t width, uint32_t height) {
    virtio_gpu_resource_create_2d_t cmd;
    virtio_gpu_resp_nodata_t resp;

    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));
    cmd.hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    cmd.resource_id = GPU_RESOURCE_ID;
    cmd.format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
    cmd.width = width;
    cmd.height = height;

    if (!virtqueue_submit_sync(vq, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
        return 0;
    }
    return resp.hdr.type == VIRTIO_GPU_RESP_OK_NODATA;
}

static int gpu_cmd_resource_attach_backing(virtqueue_t *vq, void *fb, uint32_t bytes) {
    virtio_gpu_resource_attach_backing_t cmd;
    virtio_gpu_resp_nodata_t resp;

    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));
    cmd.hdr.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
    cmd.resource_id = GPU_RESOURCE_ID;
    cmd.nr_entries = 1;
    cmd.entry.addr = (uint64_t)(uintptr_t)fb;
    cmd.entry.length = bytes;

    if (!virtqueue_submit_sync(vq, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
        return 0;
    }
    return resp.hdr.type == VIRTIO_GPU_RESP_OK_NODATA;
}

static int gpu_cmd_set_scanout(virtqueue_t *vq, uint32_t width, uint32_t height) {
    virtio_gpu_set_scanout_t cmd;
    virtio_gpu_resp_nodata_t resp;

    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));
    cmd.hdr.type = VIRTIO_GPU_CMD_SET_SCANOUT;
    cmd.rect.x = 0;
    cmd.rect.y = 0;
    cmd.rect.width = width;
    cmd.rect.height = height;
    cmd.scanout_id = GPU_SCANOUT_ID;
    cmd.resource_id = GPU_RESOURCE_ID;

    if (!virtqueue_submit_sync(vq, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
        return 0;
    }
    return resp.hdr.type == VIRTIO_GPU_RESP_OK_NODATA;
}

static int gpu_cmd_transfer_to_host_2d(virtqueue_t *vq, uint32_t width, uint32_t height) {
    virtio_gpu_transfer_to_host_2d_t cmd;
    virtio_gpu_resp_nodata_t resp;

    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));
    cmd.hdr.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    cmd.rect.x = 0;
    cmd.rect.y = 0;
    cmd.rect.width = width;
    cmd.rect.height = height;
    cmd.offset = 0;
    cmd.resource_id = GPU_RESOURCE_ID;

    if (!virtqueue_submit_sync(vq, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
        return 0;
    }
    return resp.hdr.type == VIRTIO_GPU_RESP_OK_NODATA;
}

static int gpu_cmd_resource_flush(virtqueue_t *vq, uint32_t width, uint32_t height) {
    virtio_gpu_resource_flush_t cmd;
    virtio_gpu_resp_nodata_t resp;

    memset(&cmd, 0, sizeof(cmd));
    memset(&resp, 0, sizeof(resp));
    cmd.hdr.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    cmd.rect.x = 0;
    cmd.rect.y = 0;
    cmd.rect.width = width;
    cmd.rect.height = height;
    cmd.resource_id = GPU_RESOURCE_ID;

    if (!virtqueue_submit_sync(vq, &cmd, sizeof(cmd), &resp, sizeof(resp))) {
        return 0;
    }
    return resp.hdr.type == VIRTIO_GPU_RESP_OK_NODATA;
}

bool virtio_gpu_init(void) {
    virtio_gpu_pci_t gpu;
    virtio_pci_transport_t t;
    virtqueue_t controlq;

    g_gpu_ready = 0;
    g_gpu_width = 0;
    g_gpu_height = 0;
    g_gpu_fb = NULL;

    if (!find_virtio_gpu(&gpu)) {
        serial_write_string("[OS] [VIRTIO] PCI device \"VirtIO GPU\" not found\n");
        return false;
    }

    serial_write_string("[OS] [VIRTIO] GPU found (IRQ ");
    serial_write_uint32(gpu.irq);
    serial_write_string(")\n");

    if (!virtio_pci_find_caps(&gpu, &t)) {
        serial_write_string("[OS] [VIRTIO] Required PCI capabilities are missing\n");
        return false;
    }

    if (!virtio_pci_device_init(&gpu, &t)) {
        serial_write_string("[OS] [VIRTIO] Device init failed\n");
        return false;
    }

    if (!virtqueue_init_ctrl(&t, &controlq, 0)) {
        serial_write_string("[OS] [VIRTIO] Control queue init failed\n");
        return false;
    }

    uint8_t status = common_read8(t.common_cfg, 20);
    common_write8(t.common_cfg, 20, (uint8_t)(status | VIRTIO_STATUS_DRIVER_OK));

    uint32_t width = 1024;
    uint32_t height = 768;
    (void)gpu_cmd_get_display_info(&controlq, &width, &height);

    uint64_t pixel_count = (uint64_t)width * (uint64_t)height;
    if (pixel_count == 0 || pixel_count > (64ull * 1024ull * 1024ull)) {
        serial_write_string("[OS] [VIRTIO] Invalid display size\n");
        return false;
    }

    uint32_t fb_bytes = (uint32_t)(pixel_count * 4u);
    uint32_t *fb = (uint32_t *)kmalloc(fb_bytes);
    if (!fb) {
        serial_write_string("[OS] [VIRTIO] Framebuffer allocation failed\n");
        return false;
    }

    memset(fb, 0, fb_bytes);

    if (!gpu_cmd_resource_create_2d(&controlq, width, height)) {
        serial_write_string("[OS] [VIRTIO] RESOURCE_CREATE_2D failed\n");
        kfree(fb);
        return false;
    }
    if (!gpu_cmd_resource_attach_backing(&controlq, fb, fb_bytes)) {
        serial_write_string("[OS] [VIRTIO] ATTACH_BACKING failed\n");
        kfree(fb);
        return false;
    }
    if (!gpu_cmd_set_scanout(&controlq, width, height)) {
        serial_write_string("[OS] [VIRTIO] SET_SCANOUT failed\n");
        kfree(fb);
        return false;
    }
    serial_write_string("[OS] [VIRTIO] Init complete\n");
    g_gpu_controlq = controlq;
    g_gpu_width = width;
    g_gpu_height = height;
    g_gpu_fb = fb;
    g_gpu_ready = 1;
    return true;
}

bool virtio_gpu_is_ready(void) {
    return g_gpu_ready != 0;
}

uint32_t virtio_gpu_width(void) {
    return g_gpu_width;
}

uint32_t virtio_gpu_height(void) {
    return g_gpu_height;
}

void virtio_gpu_draw_pixel(uint32_t x, uint32_t y, uint32_t color) {
    if (!g_gpu_ready || !g_gpu_fb || x >= g_gpu_width || y >= g_gpu_height) {
        return;
    }
    g_gpu_fb[(uint64_t)y * g_gpu_width + x] = color;
}

void virtio_gpu_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    if (!g_gpu_ready || !g_gpu_fb || w == 0 || h == 0) {
        return;
    }
    if (x >= g_gpu_width || y >= g_gpu_height) {
        return;
    }
    uint32_t x_end = x + w;
    uint32_t y_end = y + h;
    if (x_end > g_gpu_width || x_end < x) {
        x_end = g_gpu_width;
    }
    if (y_end > g_gpu_height || y_end < y) {
        y_end = g_gpu_height;
    }

    for (uint32_t py = y; py < y_end; ++py) {
        uint64_t row = (uint64_t)py * g_gpu_width;
        for (uint32_t px = x; px < x_end; ++px) {
            g_gpu_fb[row + px] = color;
        }
    }
}

void virtio_gpu_present(void) {
    if (!g_gpu_ready) {
        return;
    }
    if (!gpu_cmd_transfer_to_host_2d(&g_gpu_controlq, g_gpu_width, g_gpu_height)) {
        return;
    }
    (void)gpu_cmd_resource_flush(&g_gpu_controlq, g_gpu_width, g_gpu_height);
}

static bool virtio_gpu_probe(void) {
    virtio_gpu_pci_t gpu;
    return find_virtio_gpu(&gpu) != 0;
}

static const display_driver_t g_virtio_display_driver = {
    .name = VIRTIO_GPU_DEVICE_NAME,
    .probe = virtio_gpu_probe,
    .init = virtio_gpu_init,
    .is_ready = virtio_gpu_is_ready,
    .width = virtio_gpu_width,
    .height = virtio_gpu_height,
    .draw_pixel = virtio_gpu_draw_pixel,
    .fill_rect = virtio_gpu_fill_rect,
    .present = virtio_gpu_present,
};

#ifdef IMPLUS_DRIVER_MODULE
#undef serial_write_string
#undef serial_write_uint32
#undef kmalloc
#undef kfree
#undef pci_read_config
#undef pci_write_config
#undef map_mmio_virt
#undef memset
#undef strcmp

const display_driver_t *driver_module_init(const driver_kernel_api_t *api) {
    if (!api || !api->serial_write_string || !api->serial_write_uint32 ||
        !api->kmalloc || !api->kfree || !api->pci_read_config ||
        !api->pci_write_config || !api->map_mmio_virt) {
        return NULL;
    }

    g_driver_api = api;
    return &g_virtio_display_driver;
}
#else
void virtio_gpu_register_driver(void) {
    (void)driver_select_register_display_driver(&g_virtio_display_driver);
}
#endif
