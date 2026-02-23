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

#define INTEL_VENDOR_ID 0x8086
#define INTEL_UHD_DEVICE_NAME "Intel UHD Graphics Gen9"

static const uint16_t gen9_device_ids[] = {
    0x1916, 0x191B, 0x1912, 0x191E, 0x1926, 0x1927,
    0x5916, 0x5912, 0x591B, 0x591E, 0x5926, 0x5927,
    0x3E90, 0x3E92, 0x3E91, 0x3E96, 0x3E9B, 0x3EA5,
    0x87CA, 0x87C0,
    0x9B21, 0x9BA5, 0x9BA8, 0x9BAA, 0x9BAC,
    0x9BC5, 0x9BC8,
    0x3E90, 0x3E93, 0x3E99, 0x3E9C, 0x3EA0, 0x3EA9,
    0x5912, 0x5916, 0x5917, 0x591A, 0x591C, 0x591D,
    0x5A84, 0x5A85,
    0x9B41, 0x9BCA, 0x9BCB, 0x9BCC,
    0
};

#define PIPE_A_CONF        0x70008
#define PIPE_A_SRC         0x6001C
#define PLANE_CTL_1A       0x70180
#define PLANE_STRIDE_1A    0x70188
#define PLANE_SIZE_1A      0x70190
#define PLANE_SURF_1A      0x7019C

#define PIPE_B_CONF        0x71008
#define PIPE_B_SRC         0x6101C
#define PLANE_CTL_1B       0x71180
#define PLANE_STRIDE_1B    0x71188
#define PLANE_SIZE_1B      0x71190
#define PLANE_SURF_1B      0x7119C

#define PIPE_C_CONF        0x72008
#define PIPE_C_SRC         0x6201C

#define PLANE_CTL_ENABLE   0x80000000u
#define PIPE_ENABLE        0x80000000u
#define PLANE_CTL_FORMAT_MASK 0x0F000000u
#define PLANE_CTL_FORMAT_XRGB8888 0x04000000u

#ifdef IMPLUS_DRIVER_MODULE
static const driver_kernel_api_t *g_driver_api = NULL;

#define serial_write_string g_driver_api->serial_write_string
#define serial_write_uint32 g_driver_api->serial_write_uint32
#define serial_write_uint64 g_driver_api->serial_write_uint64
#define pci_read_config g_driver_api->pci_read_config
#define pci_write_config g_driver_api->pci_write_config
#define map_mmio_virt g_driver_api->map_mmio_virt
#endif

typedef struct {
    uint8_t bus;
    uint8_t device;
    uint8_t func;
    uint16_t device_id;
    uint64_t mmio_base;
    uint64_t aperture_base;
    uint32_t aperture_size;
    uint32_t irq;
} intel_gpu_pci_t;

static int g_gpu_ready = 0;
static uint32_t g_gpu_width = 0;
static uint32_t g_gpu_height = 0;
static uint32_t *g_gpu_fb = NULL;
static volatile uint8_t *g_mmio = NULL;
static uint32_t g_stride = 0;
static uint32_t g_fb_offset = 0;

static inline uint32_t mmio_read32(uint32_t offset) {
    if (!g_mmio) return 0;
    volatile uint32_t *ptr = (volatile uint32_t *)(g_mmio + offset);
    uint32_t val = *ptr;
    __asm__ volatile ("" ::: "memory");
    return val;
}

static inline void mmio_write32(uint32_t offset, uint32_t value) {
    if (!g_mmio) return;
    __asm__ volatile ("" ::: "memory");
    volatile uint32_t *ptr = (volatile uint32_t *)(g_mmio + offset);
    *ptr = value;
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

static bool is_gen9_device(uint16_t device_id) {
    for (int i = 0; gen9_device_ids[i] != 0; i++) {
        if (gen9_device_ids[i] == device_id) {
            return true;
        }
    }
    return false;
}

static int find_intel_uhd(intel_gpu_pci_t *gpu) {
    for (uint16_t bus = 0; bus < 256; bus++) {
        for (uint8_t device = 0; device < 32; device++) {
            for (uint8_t func = 0; func < 8; func++) {
                uint32_t vd = pci_read_config((uint8_t)bus, device, func, 0x00);
                uint16_t vendor_id = (uint16_t)(vd & 0xFFFFu);
                uint16_t device_id = (uint16_t)((vd >> 16) & 0xFFFFu);

                if (vendor_id == 0xFFFFu) {
                    if (func == 0) break;
                    continue;
                }

                if (vendor_id == INTEL_VENDOR_ID && is_gen9_device(device_id)) {
                    gpu->bus = (uint8_t)bus;
                    gpu->device = device;
                    gpu->func = func;
                    gpu->device_id = device_id;
                    gpu->irq = pci_cfg_read8((uint8_t)bus, device, func, 0x3C);

                    uint32_t bar0 = pci_cfg_read32((uint8_t)bus, device, func, 0x10);
                    uint32_t bar0_hi = pci_cfg_read32((uint8_t)bus, device, func, 0x14);
                    gpu->mmio_base = (((uint64_t)bar0_hi) << 32) | (uint64_t)(bar0 & ~0xFu);

                    uint32_t bar2 = pci_cfg_read32((uint8_t)bus, device, func, 0x18);
                    uint32_t bar2_hi = pci_cfg_read32((uint8_t)bus, device, func, 0x1C);
                    gpu->aperture_base = (((uint64_t)bar2_hi) << 32) | (uint64_t)(bar2 & ~0xFu);

                    pci_write_config((uint8_t)bus, device, func, 0x18, 0xFFFFFFFF);
                    pci_write_config((uint8_t)bus, device, func, 0x1C, 0xFFFFFFFF);
                    uint32_t size_mask = pci_cfg_read32((uint8_t)bus, device, func, 0x18);
                    pci_write_config((uint8_t)bus, device, func, 0x18, bar2);
                    pci_write_config((uint8_t)bus, device, func, 0x1C, bar2_hi);
                    
                    if (size_mask != 0 && size_mask != 0xFFFFFFFF) {
                        gpu->aperture_size = (~(size_mask & ~0xFu)) + 1;
                    } else {
                        gpu->aperture_size = 256 * 1024 * 1024;
                    }

                    return 1;
                }

                if (func == 0) {
                    uint32_t header_type = pci_read_config((uint8_t)bus, device, func, 0x0C);
                    if (((header_type >> 16) & 0x80u) == 0) break;
                }
            }
        }
    }
    return 0;
}

static bool read_pipe_config(uint32_t pipe_conf_reg, uint32_t pipe_src_reg,
                              uint32_t plane_ctl_reg, uint32_t stride_reg,
                              uint32_t size_reg, uint32_t surf_reg,
                              uint32_t *width, uint32_t *height,
                              uint32_t *stride, uint32_t *fb_offset) {
    (void)pipe_src_reg;

    uint32_t pipe_conf = mmio_read32(pipe_conf_reg);
    serial_write_string("[OS] [INTEL] PIPE_CONF=0x");
    serial_write_uint32(pipe_conf);
    serial_write_string("\n");
    
    if ((pipe_conf & PIPE_ENABLE) == 0) {
        serial_write_string("[OS] [INTEL] Pipe disabled\n");
        return false;
    }

    uint32_t plane_ctl = mmio_read32(plane_ctl_reg);
    serial_write_string("[OS] [INTEL] PLANE_CTL=0x");
    serial_write_uint32(plane_ctl);
    serial_write_string("\n");
    
    if ((plane_ctl & PLANE_CTL_ENABLE) == 0) {
        serial_write_string("[OS] [INTEL] Plane disabled\n");
        return false;
    }

    uint32_t format = plane_ctl & PLANE_CTL_FORMAT_MASK;
    if (format != PLANE_CTL_FORMAT_XRGB8888) {
        serial_write_string("[OS] [INTEL] Unsupported format=0x");
        serial_write_uint32(format);
        serial_write_string("\n");
    }

    uint32_t plane_size = mmio_read32(size_reg);
    *height = ((plane_size >> 16) & 0x1FFFu) + 1;
    *width = (plane_size & 0x1FFFu) + 1;

    uint32_t stride_val = mmio_read32(stride_reg);
    *stride = (stride_val & 0x3FFu) * 64;

    if (*stride == 0 || *stride < (*width * 4)) {
        serial_write_string("[OS] [INTEL] Invalid stride, recalculating\n");
        *stride = ((*width * 4) + 63) & ~63u;
    }

    uint32_t surf = mmio_read32(surf_reg);
    *fb_offset = surf & ~0xFFFu;

    serial_write_string("[OS] [INTEL] Resolution: ");
    serial_write_uint32(*width);
    serial_write_string("x");
    serial_write_uint32(*height);
    serial_write_string("\n");
    serial_write_string("[OS] [INTEL] Stride: ");
    serial_write_uint32(*stride);
    serial_write_string(" bytes\n");
    serial_write_string("[OS] [INTEL] FB Offset: 0x");
    serial_write_uint32(*fb_offset);
    serial_write_string("\n");

    return true;
}

bool intel_uhd_init(void) {
    intel_gpu_pci_t gpu;

    g_gpu_ready = 0;
    g_gpu_width = 0;
    g_gpu_height = 0;
    g_gpu_fb = NULL;
    g_mmio = NULL;
    g_stride = 0;
    g_fb_offset = 0;

    if (!find_intel_uhd(&gpu)) {
        serial_write_string("[OS] [INTEL] Intel UHD Graphics Gen9 not found\n");
        return false;
    }

    serial_write_string("[OS] [INTEL] Intel GPU found\n");
    serial_write_string("[OS] [INTEL] Device ID: 0x");
    serial_write_uint32(gpu.device_id);
    serial_write_string("\n");
    serial_write_string("[OS] [INTEL] IRQ: ");
    serial_write_uint32(gpu.irq);
    serial_write_string("\n");

    uint16_t cmd = pci_cfg_read16(gpu.bus, gpu.device, gpu.func, 0x04);
    cmd |= (1u << 0) | (1u << 1) | (1u << 2);
    pci_cfg_write16(gpu.bus, gpu.device, gpu.func, 0x04, cmd);

    serial_write_string("[OS] [INTEL] MMIO: 0x");
    serial_write_uint64(gpu.mmio_base);
    serial_write_string("\n");

    if (gpu.mmio_base == 0 || gpu.mmio_base == 0xFFFFFFFFFFFFFFFFull) {
        serial_write_string("[OS] [INTEL] Invalid MMIO base\n");
        return false;
    }

    g_mmio = (volatile uint8_t *)map_mmio_virt(gpu.mmio_base);
    if (!g_mmio) {
        serial_write_string("[OS] [INTEL] Failed to map MMIO\n");
        return false;
    }

    for (volatile int i = 0; i < 1000; i++);

    bool pipe_found = false;

    serial_write_string("[OS] [INTEL] Checking Pipe A...\n");
    if (read_pipe_config(PIPE_A_CONF, PIPE_A_SRC, PLANE_CTL_1A,
                         PLANE_STRIDE_1A, PLANE_SIZE_1A, PLANE_SURF_1A,
                         &g_gpu_width, &g_gpu_height, &g_stride, &g_fb_offset)) {
        pipe_found = true;
    }

    if (!pipe_found) {
        serial_write_string("[OS] [INTEL] Checking Pipe B...\n");
        if (read_pipe_config(PIPE_B_CONF, PIPE_B_SRC, PLANE_CTL_1B,
                             PLANE_STRIDE_1B, PLANE_SIZE_1B, PLANE_SURF_1B,
                             &g_gpu_width, &g_gpu_height, &g_stride, &g_fb_offset)) {
            pipe_found = true;
        }
    }

    if (!pipe_found) {
        serial_write_string("[OS] [INTEL] No active pipe found, using defaults\n");
        g_gpu_width = 1024;
        g_gpu_height = 768;
        g_stride = g_gpu_width * 4;
        g_fb_offset = 0;
    }

    if (g_gpu_width == 0 || g_gpu_height == 0 || g_gpu_width > 8192 || g_gpu_height > 8192) {
        serial_write_string("[OS] [INTEL] Invalid resolution\n");
        return false;
    }

    if (g_stride < g_gpu_width * 4) {
        serial_write_string("[OS] [INTEL] Stride too small\n");
        return false;
    }

    serial_write_string("[OS] [INTEL] Aperture: 0x");
    serial_write_uint64(gpu.aperture_base);
    serial_write_string("\n");
    serial_write_string("[OS] [INTEL] Aperture Size: ");
    serial_write_uint32(gpu.aperture_size >> 20);
    serial_write_string(" MB\n");

    if (gpu.aperture_base == 0 || gpu.aperture_base == 0xFFFFFFFFFFFFFFFFull) {
        serial_write_string("[OS] [INTEL] Invalid aperture base\n");
        return false;
    }

    uint64_t fb_size = (uint64_t)g_gpu_height * (uint64_t)g_stride;
    if (fb_size == 0) {
        serial_write_string("[OS] [INTEL] Invalid framebuffer size\n");
        return false;
    }

    if (g_fb_offset >= gpu.aperture_size || g_fb_offset + fb_size > gpu.aperture_size) {
        serial_write_string("[OS] [INTEL] Framebuffer out of aperture range\n");
        g_fb_offset = 0;
        if (fb_size > gpu.aperture_size) {
            serial_write_string("[OS] [INTEL] Framebuffer too large\n");
            return false;
        }
    }

    uint64_t fb_phys = gpu.aperture_base + g_fb_offset;
    serial_write_string("[OS] [INTEL] FB Physical: 0x");
    serial_write_uint64(fb_phys);
    serial_write_string("\n");

    g_gpu_fb = (uint32_t *)map_mmio_virt(fb_phys);
    if (!g_gpu_fb) {
        serial_write_string("[OS] [INTEL] Failed to map framebuffer\n");
        return false;
    }

    for (uint32_t i = 0; i < 100; i++) {
        g_gpu_fb[i] = 0xFF0000FF;
    }
    __asm__ volatile ("mfence" ::: "memory");

    serial_write_string("[OS] [INTEL] Init complete: ");
    serial_write_uint32(g_gpu_width);
    serial_write_string("x");
    serial_write_uint32(g_gpu_height);
    serial_write_string("\n");

    g_gpu_ready = 1;
    return true;
}

bool intel_uhd_is_ready(void) {
    return g_gpu_ready != 0;
}

uint32_t intel_uhd_width(void) {
    return g_gpu_width;
}

uint32_t intel_uhd_height(void) {
    return g_gpu_height;
}

void intel_uhd_draw_pixel(uint32_t x, uint32_t y, uint32_t color) {
    if (!g_gpu_ready || !g_gpu_fb || x >= g_gpu_width || y >= g_gpu_height) {
        return;
    }

    uint32_t stride_pixels = g_stride / 4;
    uint64_t offset = (uint64_t)y * (uint64_t)stride_pixels + (uint64_t)x;
    g_gpu_fb[offset] = color;
}

void intel_uhd_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
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

    uint32_t stride_pixels = g_stride / 4;
    
    for (uint32_t py = y; py < y_end; ++py) {
        uint64_t row = (uint64_t)py * (uint64_t)stride_pixels;
        for (uint32_t px = x; px < x_end; ++px) {
            g_gpu_fb[row + px] = color;
        }
    }
}

void intel_uhd_present(void) {
    if (!g_gpu_ready) {
        return;
    }
    __asm__ volatile ("mfence" ::: "memory");
}

static bool intel_uhd_probe(void) {
    intel_gpu_pci_t gpu;
    return find_intel_uhd(&gpu) != 0;
}

static const display_driver_t g_intel_display_driver = {
    .name = INTEL_UHD_DEVICE_NAME,
    .probe = intel_uhd_probe,
    .init = intel_uhd_init,
    .is_ready = intel_uhd_is_ready,
    .width = intel_uhd_width,
    .height = intel_uhd_height,
    .draw_pixel = intel_uhd_draw_pixel,
    .fill_rect = intel_uhd_fill_rect,
    .present = intel_uhd_present,
};

#ifdef IMPLUS_DRIVER_MODULE
#undef serial_write_string
#undef serial_write_uint32
#undef serial_write_uint64
#undef pci_read_config
#undef pci_write_config
#undef map_mmio_virt

const display_driver_t *driver_module_init(const driver_kernel_api_t *api) {
    if (!api || !api->serial_write_string || !api->serial_write_uint32 ||
        !api->serial_write_uint64 || !api->pci_read_config ||
        !api->pci_write_config || !api->map_mmio_virt) {
        return NULL;
    }

    g_driver_api = api;
    return &g_intel_display_driver;
}
#else
void intel_uhd_register_driver(void) {
    (void)driver_select_register_display_driver(&g_intel_display_driver);
}
#endif
