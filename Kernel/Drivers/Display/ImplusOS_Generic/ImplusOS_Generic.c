#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "../../../Serial.h"
#include "../../../IO/IO_Main.h"
#include "../../../Memory/Memory_Main.h"
#ifndef IMPLUS_DRIVER_MODULE
#include "../../../Paging/Paging_Main.h"
#endif

#ifdef IMPLUS_DRIVER_MODULE
#include "../../DriverBinary.h"
#else
#include "../../DriverSelect.h"
#endif

#define GENERIC_FB_DEVICE_NAME "Generic Framebuffer"
#define GENERIC_FB_BYTES_PER_PIXEL 4U
#define GENERIC_FB_MAP_GRANULE (2ULL * 1024ULL * 1024ULL)
#define GENERIC_FB_MAX_MAPPINGS 64U

#ifdef IMPLUS_DRIVER_MODULE
static const driver_kernel_api_t *g_driver_api = NULL;

#define serial_write_string g_driver_api->serial_write_string
#define serial_write_uint32 g_driver_api->serial_write_uint32
#define kmalloc g_driver_api->kmalloc
#define kfree g_driver_api->kfree
#define map_mmio_virt g_driver_api->map_mmio_virt
#endif

typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t pixels_per_scan_line;
    uint64_t size_bytes;
    uint64_t map_offset_bytes;
    uint32_t mapped_chunks;
    uint8_t *mapped_bases[GENERIC_FB_MAX_MAPPINGS];
} framebuffer_t;

static framebuffer_t g_fb;
static int g_ready = 0;

static bool map_framebuffer_chunks(uint64_t phys_addr, uint64_t size_bytes) {
    if (size_bytes == 0) {
        return false;
    }

    uint64_t base_phys = phys_addr & ~(GENERIC_FB_MAP_GRANULE - 1ULL);
    uint64_t base_offset = phys_addr - base_phys;
    uint64_t total_span = base_offset + size_bytes;
    uint64_t chunks_u64 =
        (total_span + GENERIC_FB_MAP_GRANULE - 1ULL) / GENERIC_FB_MAP_GRANULE;

    if (chunks_u64 == 0 || chunks_u64 > GENERIC_FB_MAX_MAPPINGS) {
        serial_write_string("[FB] Framebuffer mapping size unsupported\n");
        return false;
    }

    for (uint32_t i = 0; i < GENERIC_FB_MAX_MAPPINGS; ++i) {
        g_fb.mapped_bases[i] = NULL;
    }

    for (uint32_t i = 0; i < (uint32_t)chunks_u64; ++i) {
        uint64_t chunk_phys = base_phys + ((uint64_t)i * GENERIC_FB_MAP_GRANULE);
        void *chunk_virt = map_mmio_virt(chunk_phys);
        if (chunk_virt == NULL) {
            serial_write_string("[FB] Failed to map framebuffer chunk\n");
            return false;
        }
        g_fb.mapped_bases[i] = (uint8_t *)chunk_virt;
    }

    g_fb.map_offset_bytes = base_offset;
    g_fb.mapped_chunks = (uint32_t)chunks_u64;
    return true;
}

static inline volatile uint32_t *resolve_pixel_ptr(uint64_t pixel_index) {
    uint64_t byte_offset =
        g_fb.map_offset_bytes + (pixel_index * (uint64_t)GENERIC_FB_BYTES_PER_PIXEL);
    uint64_t chunk_index = byte_offset / GENERIC_FB_MAP_GRANULE;
    if (chunk_index >= g_fb.mapped_chunks) {
        return NULL;
    }

    uint64_t chunk_offset = byte_offset % GENERIC_FB_MAP_GRANULE;
    return (volatile uint32_t *)(void *)(g_fb.mapped_bases[chunk_index] + chunk_offset);
}

bool generic_fb_set(const display_boot_framebuffer_t *framebuffer) {
    g_ready = 0;
    g_fb.mapped_chunks = 0;

    if (!framebuffer || !framebuffer->addr ||
        framebuffer->width == 0 || framebuffer->height == 0 ||
        framebuffer->pixels_per_scan_line < framebuffer->width) {
        return false;
    }

    uint32_t bytes_per_pixel = framebuffer->bytes_per_pixel;
    if (bytes_per_pixel == 0) {
        bytes_per_pixel = GENERIC_FB_BYTES_PER_PIXEL;
    }
    if (bytes_per_pixel != GENERIC_FB_BYTES_PER_PIXEL) {
        return false;
    }

    uint64_t required_bytes =
        (uint64_t)framebuffer->pixels_per_scan_line *
        (uint64_t)framebuffer->height *
        (uint64_t)bytes_per_pixel;
    if (framebuffer->size_bytes != 0 &&
        required_bytes > framebuffer->size_bytes) {
        return false;
    }

    if ((((uint64_t)(uintptr_t)framebuffer->addr) &
         (GENERIC_FB_BYTES_PER_PIXEL - 1ULL)) != 0ULL) {
        return false;
    }

    if (!map_framebuffer_chunks((uint64_t)(uintptr_t)framebuffer->addr, required_bytes)) {
        return false;
    }

    g_fb.width = framebuffer->width;
    g_fb.height = framebuffer->height;
    g_fb.pixels_per_scan_line = framebuffer->pixels_per_scan_line;
    g_fb.size_bytes = required_bytes;
    g_ready = 1;

    serial_write_string("[FB] Generic framebuffer initialized\n");
    return true;
}

static bool fb_probe(void) {
    return g_ready != 0;
}

static bool fb_init(void) {
    return g_ready != 0;
}

static bool fb_is_ready(void) {
    return g_ready != 0;
}

static uint32_t fb_width(void) {
    return g_fb.width;
}

static uint32_t fb_height(void) {
    return g_fb.height;
}

static void fb_draw_pixel(uint32_t x, uint32_t y, uint32_t color) {
    if (!g_ready) return;
    if (x >= g_fb.width || y >= g_fb.height) return;

    uint64_t pixel_index = (uint64_t)y * g_fb.pixels_per_scan_line + x;
    volatile uint32_t *dst = resolve_pixel_ptr(pixel_index);
    if (dst == NULL) {
        return;
    }
    *dst = color;
}

static void fb_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color) {
    if (!g_ready || w == 0 || h == 0) return;
    if (x >= g_fb.width || y >= g_fb.height) return;

    uint32_t x_end = x + w;
    uint32_t y_end = y + h;

    if (x_end > g_fb.width || x_end < x) x_end = g_fb.width;
    if (y_end > g_fb.height || y_end < y) y_end = g_fb.height;

    for (uint32_t py = y; py < y_end; py++) {
        uint64_t row_start = (uint64_t)py * g_fb.pixels_per_scan_line + x;
        uint32_t remaining = x_end - x;

        while (remaining > 0) {
            uint64_t byte_offset =
                g_fb.map_offset_bytes +
                (row_start * (uint64_t)GENERIC_FB_BYTES_PER_PIXEL);
            uint64_t chunk_index = byte_offset / GENERIC_FB_MAP_GRANULE;
            if (chunk_index >= g_fb.mapped_chunks) {
                return;
            }

            uint64_t chunk_offset = byte_offset % GENERIC_FB_MAP_GRANULE;
            uint64_t chunk_bytes_left = GENERIC_FB_MAP_GRANULE - chunk_offset;
            uint32_t chunk_pixels_left = (uint32_t)(chunk_bytes_left / GENERIC_FB_BYTES_PER_PIXEL);
            uint32_t run_pixels =
                (remaining < chunk_pixels_left) ? remaining : chunk_pixels_left;

            volatile uint32_t *dst =
                (volatile uint32_t *)(void *)(g_fb.mapped_bases[chunk_index] + chunk_offset);
            for (uint32_t i = 0; i < run_pixels; ++i) {
                dst[i] = color;
            }

            row_start += run_pixels;
            remaining -= run_pixels;
        }
    }
}

static void fb_present(void) {
}

static const display_driver_t g_generic_fb_driver = {
    .name = GENERIC_FB_DEVICE_NAME,
    .probe = fb_probe,
    .init = fb_init,
    .is_ready = fb_is_ready,
    .width = fb_width,
    .height = fb_height,
    .draw_pixel = fb_draw_pixel,
    .fill_rect = fb_fill_rect,
    .present = fb_present,
    .set_framebuffer = generic_fb_set,
};

#ifdef IMPLUS_DRIVER_MODULE

#undef serial_write_string
#undef serial_write_uint32
#undef kmalloc
#undef kfree
#undef map_mmio_virt

const display_driver_t *driver_module_init(const driver_kernel_api_t *api) {
    if (!api || !api->serial_write_string || !api->kmalloc ||
        !api->map_mmio_virt) {
        return NULL;
    }

    g_driver_api = api;
    return &g_generic_fb_driver;
}

#else

void generic_fb_register_driver(void) {
    (void)driver_select_register_display_driver(&g_generic_fb_driver);
}

#endif
