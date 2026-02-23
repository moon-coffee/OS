#include "WindowManager.h"

#include "../Drivers/Display/Display_Main.h"
#include "../Memory/Memory_Main.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define WM_MAX_WINDOWS 16

#define WM_BORDER 2u
#define WM_TITLEBAR_HEIGHT 20u

#define WM_SHADOW_OFFSET 2u
#define WM_SHADOW_SOFT_SIZE 2u
#define WM_SHADOW_HARD_SIZE 2u

#define WM_DESKTOP_TOP_COLOR        0xFF0F1621u
#define WM_DESKTOP_BOTTOM_COLOR     0xFF1B2940u
#define WM_FRAME_OUTER_COLOR        0xFF1C232Eu
#define WM_FRAME_INNER_COLOR        0xFF313C4Eu
#define WM_TITLEBAR_ACTIVE_TOP      0xFF6AADFFu
#define WM_TITLEBAR_ACTIVE_BOTTOM   0xFF376FDFu
#define WM_TITLEBAR_INACTIVE_TOP    0xFF5E6675u
#define WM_TITLEBAR_INACTIVE_BOTTOM 0xFF434A58u
#define WM_TITLEBAR_HILITE_COLOR    0xFFB9D6FFu
#define WM_SEPARATOR_ACTIVE_COLOR   0xFF1E3F88u
#define WM_SEPARATOR_INACTIVE_COLOR 0xFF2D3442u
#define WM_SHADOW_SOFT_COLOR        0xFF121821u
#define WM_SHADOW_HARD_COLOR        0xFF090D13u
#define WM_BUTTON_MIN_COLOR         0xFF5FCF8Fu
#define WM_BUTTON_MAX_COLOR         0xFFE6BA56u
#define WM_BUTTON_CLOSE_COLOR       0xFFE2646Cu
#define WM_BUTTON_BORDER_COLOR      0xFF1D2430u
#define WM_BUTTON_HILITE_COLOR      0xFFFFFFFFu
#define WM_DEFAULT_CLIENT_BG        0xFF0F131Au

typedef struct {
    uint8_t used;
    int32_t owner_pid;
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
    uint32_t z_order;
    uint8_t dirty;
    uint32_t *pixels;
} wm_window_t;

static wm_window_t g_windows[WM_MAX_WINDOWS];
static uint32_t g_next_z_order = 1;
static uint8_t g_initialized = 0;

static int32_t wm_find_window_index_by_pid(int32_t pid)
{
    if (pid < 0) {
        return -1;
    }

    for (int32_t i = 0; i < WM_MAX_WINDOWS; ++i) {
        if (g_windows[i].used && g_windows[i].owner_pid == pid) {
            return i;
        }
    }

    return -1;
}

static int32_t wm_find_free_slot(void)
{
    for (int32_t i = 0; i < WM_MAX_WINDOWS; ++i) {
        if (!g_windows[i].used) {
            return i;
        }
    }

    return -1;
}

static uint32_t wm_max_client_width(uint32_t screen_width)
{
    if (screen_width <= (WM_BORDER * 2u)) {
        return 0;
    }

    return screen_width - (WM_BORDER * 2u);
}

static uint32_t wm_max_client_height(uint32_t screen_height)
{
    if (screen_height <= (WM_TITLEBAR_HEIGHT + WM_BORDER)) {
        return 0;
    }

    return screen_height - (WM_TITLEBAR_HEIGHT + WM_BORDER);
}

static uint32_t wm_take_next_z_order(void)
{
    if (g_next_z_order == 0) {
        g_next_z_order = 1;
        for (int32_t i = 0; i < WM_MAX_WINDOWS; ++i) {
            if (g_windows[i].used) {
                g_windows[i].z_order = g_next_z_order++;
            }
        }
    }

    return g_next_z_order++;
}

static uint8_t wm_lerp_channel(uint8_t from, uint8_t to, uint32_t pos, uint32_t span)
{
    if (span == 0) {
        return from;
    }

    int32_t delta = (int32_t)to - (int32_t)from;
    int32_t value = (int32_t)from + (int32_t)((delta * (int32_t)pos) / (int32_t)span);
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return (uint8_t)value;
}

static uint32_t wm_lerp_color(uint32_t from, uint32_t to, uint32_t pos, uint32_t span)
{
    uint8_t a = wm_lerp_channel((uint8_t)((from >> 24) & 0xFFu),
                                (uint8_t)((to >> 24) & 0xFFu),
                                pos,
                                span);
    uint8_t r = wm_lerp_channel((uint8_t)((from >> 16) & 0xFFu),
                                (uint8_t)((to >> 16) & 0xFFu),
                                pos,
                                span);
    uint8_t g = wm_lerp_channel((uint8_t)((from >> 8) & 0xFFu),
                                (uint8_t)((to >> 8) & 0xFFu),
                                pos,
                                span);
    uint8_t b = wm_lerp_channel((uint8_t)(from & 0xFFu), (uint8_t)(to & 0xFFu), pos, span);

    return ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static void wm_draw_clipped_rect(int32_t x,
                                 int32_t y,
                                 uint32_t w,
                                 uint32_t h,
                                 uint32_t color,
                                 uint32_t screen_w,
                                 uint32_t screen_h)
{
    if (w == 0 || h == 0 || screen_w == 0 || screen_h == 0) {
        return;
    }

    int32_t x0 = x;
    int32_t y0 = y;
    int32_t x1 = x + (int32_t)w;
    int32_t y1 = y + (int32_t)h;

    if (x0 < 0) {
        x0 = 0;
    }
    if (y0 < 0) {
        y0 = 0;
    }
    if (x1 > (int32_t)screen_w) {
        x1 = (int32_t)screen_w;
    }
    if (y1 > (int32_t)screen_h) {
        y1 = (int32_t)screen_h;
    }

    if (x0 >= x1 || y0 >= y1) {
        return;
    }

    display_fill_rect((uint32_t)x0,
                      (uint32_t)y0,
                      (uint32_t)(x1 - x0),
                      (uint32_t)(y1 - y0),
                      color);
}

static void wm_draw_vertical_gradient_rect(int32_t x,
                                           int32_t y,
                                           uint32_t w,
                                           uint32_t h,
                                           uint32_t top_color,
                                           uint32_t bottom_color,
                                           uint32_t screen_w,
                                           uint32_t screen_h)
{
    if (w == 0 || h == 0 || screen_w == 0 || screen_h == 0) {
        return;
    }

    int32_t x0 = x;
    int32_t y0 = y;
    int32_t x1 = x + (int32_t)w;
    int32_t y1 = y + (int32_t)h;

    if (x0 < 0) {
        x0 = 0;
    }
    if (y0 < 0) {
        y0 = 0;
    }
    if (x1 > (int32_t)screen_w) {
        x1 = (int32_t)screen_w;
    }
    if (y1 > (int32_t)screen_h) {
        y1 = (int32_t)screen_h;
    }

    if (x0 >= x1 || y0 >= y1) {
        return;
    }

    uint32_t span = (h > 1u) ? (h - 1u) : 1u;
    for (int32_t sy = y0; sy < y1; ++sy) {
        uint32_t pos = (uint32_t)(sy - y);
        if (pos >= h) {
            pos = h - 1u;
        }

        uint32_t row_color = wm_lerp_color(top_color, bottom_color, pos, span);
        display_fill_rect((uint32_t)x0, (uint32_t)sy, (uint32_t)(x1 - x0), 1u, row_color);
    }
}

static void wm_draw_window_shadow(const wm_window_t *window, uint32_t screen_w, uint32_t screen_h)
{
    if (!window || !window->used) {
        return;
    }

    int32_t frame_x = (int32_t)window->x;
    int32_t frame_y = (int32_t)window->y;
    uint32_t outer_w = window->width + (WM_BORDER * 2u);
    uint32_t outer_h = window->height + WM_TITLEBAR_HEIGHT + WM_BORDER;

    wm_draw_clipped_rect(frame_x + (int32_t)outer_w,
                         frame_y + (int32_t)WM_SHADOW_OFFSET,
                         WM_SHADOW_SOFT_SIZE,
                         outer_h,
                         WM_SHADOW_SOFT_COLOR,
                         screen_w,
                         screen_h);
    wm_draw_clipped_rect(frame_x + (int32_t)WM_SHADOW_OFFSET,
                         frame_y + (int32_t)outer_h,
                         outer_w + WM_SHADOW_SOFT_SIZE,
                         WM_SHADOW_SOFT_SIZE,
                         WM_SHADOW_SOFT_COLOR,
                         screen_w,
                         screen_h);

    wm_draw_clipped_rect(frame_x + (int32_t)outer_w + (int32_t)WM_SHADOW_SOFT_SIZE,
                         frame_y + (int32_t)WM_SHADOW_OFFSET + (int32_t)WM_SHADOW_SOFT_SIZE,
                         WM_SHADOW_HARD_SIZE,
                         outer_h,
                         WM_SHADOW_HARD_COLOR,
                         screen_w,
                         screen_h);
    wm_draw_clipped_rect(frame_x + (int32_t)WM_SHADOW_OFFSET + (int32_t)WM_SHADOW_SOFT_SIZE,
                         frame_y + (int32_t)outer_h + (int32_t)WM_SHADOW_SOFT_SIZE,
                         outer_w + WM_SHADOW_HARD_SIZE,
                         WM_SHADOW_HARD_SIZE,
                         WM_SHADOW_HARD_COLOR,
                         screen_w,
                         screen_h);
}

static void wm_draw_window_buttons(int32_t title_x,
                                   int32_t title_y,
                                   uint32_t title_w,
                                   uint32_t title_h,
                                   uint32_t screen_w,
                                   uint32_t screen_h)
{
    const uint32_t button_size = 6u;
    const uint32_t button_gap = 3u;
    const uint32_t right_padding = 6u;
    const uint32_t total_width = (button_size * 3u) + (button_gap * 2u);

    if (title_w <= (right_padding * 2u) + total_width || title_h < button_size) {
        return;
    }

    int32_t button_y = title_y + (int32_t)((title_h - button_size) / 2u);
    int32_t min_x = title_x + (int32_t)title_w - (int32_t)right_padding - (int32_t)total_width;
    int32_t max_x = min_x + (int32_t)button_size + (int32_t)button_gap;
    int32_t close_x = max_x + (int32_t)button_size + (int32_t)button_gap;

    wm_draw_clipped_rect(min_x - 1, button_y - 1, button_size + 2u, button_size + 2u, WM_BUTTON_BORDER_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(max_x - 1, button_y - 1, button_size + 2u, button_size + 2u, WM_BUTTON_BORDER_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(close_x - 1, button_y - 1, button_size + 2u, button_size + 2u, WM_BUTTON_BORDER_COLOR, screen_w, screen_h);

    wm_draw_clipped_rect(min_x, button_y, button_size, button_size, WM_BUTTON_MIN_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(max_x, button_y, button_size, button_size, WM_BUTTON_MAX_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(close_x, button_y, button_size, button_size, WM_BUTTON_CLOSE_COLOR, screen_w, screen_h);

    wm_draw_clipped_rect(min_x, button_y, button_size, 1u, WM_BUTTON_HILITE_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(max_x, button_y, button_size, 1u, WM_BUTTON_HILITE_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(close_x, button_y, button_size, 1u, WM_BUTTON_HILITE_COLOR, screen_w, screen_h);
}

static void wm_compose_window(const wm_window_t *window, uint32_t screen_w, uint32_t screen_h, bool is_active)
{
    if (!window || !window->used || !window->pixels) {
        return;
    }

    int32_t frame_x = (int32_t)window->x;
    int32_t frame_y = (int32_t)window->y;
    uint32_t outer_w = window->width + (WM_BORDER * 2u);
    uint32_t outer_h = window->height + WM_TITLEBAR_HEIGHT + WM_BORDER;

    wm_draw_window_shadow(window, screen_w, screen_h);

    wm_draw_clipped_rect(frame_x, frame_y, outer_w, outer_h, WM_FRAME_OUTER_COLOR, screen_w, screen_h);

    if (outer_w > 2u && outer_h > 2u) {
        wm_draw_clipped_rect(frame_x + 1,
                             frame_y + 1,
                             outer_w - 2u,
                             outer_h - 2u,
                             WM_FRAME_INNER_COLOR,
                             screen_w,
                             screen_h);
    }

    int32_t title_x = frame_x + (int32_t)WM_BORDER;
    int32_t title_y = frame_y + (int32_t)WM_BORDER;
    uint32_t title_w = window->width;
    uint32_t title_h = WM_TITLEBAR_HEIGHT - WM_BORDER;

    uint32_t title_top_color = is_active ? WM_TITLEBAR_ACTIVE_TOP : WM_TITLEBAR_INACTIVE_TOP;
    uint32_t title_bottom_color = is_active ? WM_TITLEBAR_ACTIVE_BOTTOM : WM_TITLEBAR_INACTIVE_BOTTOM;

    wm_draw_vertical_gradient_rect(title_x,
                                   title_y,
                                   title_w,
                                   title_h,
                                   title_top_color,
                                   title_bottom_color,
                                   screen_w,
                                   screen_h);
    wm_draw_clipped_rect(title_x, title_y, title_w, 1u, WM_TITLEBAR_HILITE_COLOR, screen_w, screen_h);
    wm_draw_clipped_rect(title_x,
                         title_y + (int32_t)title_h - 1,
                         title_w,
                         1u,
                         is_active ? WM_SEPARATOR_ACTIVE_COLOR : WM_SEPARATOR_INACTIVE_COLOR,
                         screen_w,
                         screen_h);

    wm_draw_window_buttons(title_x, title_y, title_w, title_h, screen_w, screen_h);

    int32_t client_x = frame_x + (int32_t)WM_BORDER;
    int32_t client_y = frame_y + (int32_t)WM_TITLEBAR_HEIGHT;

    for (uint32_t py = 0; py < window->height; ++py) {
        int32_t sy = client_y + (int32_t)py;
        if (sy < 0 || sy >= (int32_t)screen_h) {
            continue;
        }

        uint64_t row = (uint64_t)py * (uint64_t)window->width;
        for (uint32_t px = 0; px < window->width; ++px) {
            int32_t sx = client_x + (int32_t)px;
            if (sx < 0 || sx >= (int32_t)screen_w) {
                continue;
            }

            display_draw_pixel((uint32_t)sx, (uint32_t)sy, window->pixels[row + px]);
        }
    }
}

static void wm_compose_desktop(void)
{
    if (!g_initialized || !display_is_ready()) {
        return;
    }

    uint32_t screen_w = display_width();
    uint32_t screen_h = display_height();
    if (screen_w == 0 || screen_h == 0) {
        return;
    }

    wm_draw_vertical_gradient_rect(0,
                                   0,
                                   screen_w,
                                   screen_h,
                                   WM_DESKTOP_TOP_COLOR,
                                   WM_DESKTOP_BOTTOM_COLOR,
                                   screen_w,
                                   screen_h);

    int32_t order[WM_MAX_WINDOWS];
    uint32_t count = 0;

    for (int32_t i = 0; i < WM_MAX_WINDOWS; ++i) {
        if (g_windows[i].used) {
            order[count++] = i;
        }
    }

    for (uint32_t i = 0; i < count; ++i) {
        uint32_t min_idx = i;
        for (uint32_t j = i + 1; j < count; ++j) {
            if (g_windows[order[j]].z_order < g_windows[order[min_idx]].z_order) {
                min_idx = j;
            }
        }

        if (min_idx != i) {
            int32_t tmp = order[i];
            order[i] = order[min_idx];
            order[min_idx] = tmp;
        }
    }

    for (uint32_t i = 0; i < count; ++i) {
        wm_compose_window(&g_windows[order[i]], screen_w, screen_h, i == (count - 1u));
    }

    display_present();

    for (int32_t i = 0; i < WM_MAX_WINDOWS; ++i) {
        if (g_windows[i].used) {
            g_windows[i].dirty = 0;
        }
    }
}

static void wm_fill_pixels(wm_window_t *window, uint32_t color)
{
    if (!window || !window->pixels || window->width == 0 || window->height == 0) {
        return;
    }

    uint64_t pixel_count = (uint64_t)window->width * (uint64_t)window->height;
    for (uint64_t i = 0; i < pixel_count; ++i) {
        window->pixels[i] = color;
    }
}

static void wm_set_window_position(wm_window_t *window, uint32_t slot, uint32_t screen_w, uint32_t screen_h)
{
    if (!window) {
        return;
    }

    uint32_t outer_w = window->width + (WM_BORDER * 2u);
    uint32_t outer_h = window->height + WM_TITLEBAR_HEIGHT + WM_BORDER;

    uint32_t max_x = (screen_w > outer_w) ? (screen_w - outer_w) : 0;
    uint32_t max_y = (screen_h > outer_h) ? (screen_h - outer_h) : 0;

    uint32_t step_x = 24u;
    uint32_t step_y = 20u;

    window->x = (max_x == 0) ? 0 : ((slot * step_x) % (max_x + 1u));
    window->y = (max_y == 0) ? 0 : ((slot * step_y) % (max_y + 1u));
}

static wm_window_t *wm_ensure_window_for_process(int32_t pid)
{
    int32_t idx = wm_find_window_index_by_pid(pid);
    if (idx >= 0) {
        return &g_windows[idx];
    }

    uint32_t screen_w = display_width();
    uint32_t screen_h = display_height();
    uint32_t default_w = wm_max_client_width(screen_w);
    uint32_t default_h = wm_max_client_height(screen_h);

    if (default_w == 0 || default_h == 0) {
        return NULL;
    }

    if (window_manager_create_window_for_process(pid, default_w, default_h) < 0) {
        return NULL;
    }

    idx = wm_find_window_index_by_pid(pid);
    if (idx < 0) {
        return NULL;
    }

    return &g_windows[idx];
}

void window_manager_init(void)
{
    memset(g_windows, 0, sizeof(g_windows));
    g_next_z_order = 1;
    g_initialized = 1;
    wm_compose_desktop();
}

int32_t window_manager_create_window_for_process(int32_t pid, uint32_t width, uint32_t height)
{
    if (!g_initialized || !display_is_ready() || pid < 0) {
        return -1;
    }

    uint32_t screen_w = display_width();
    uint32_t screen_h = display_height();
    if (screen_w == 0 || screen_h == 0) {
        return -1;
    }

    uint32_t max_w = wm_max_client_width(screen_w);
    uint32_t max_h = wm_max_client_height(screen_h);
    if (max_w == 0 || max_h == 0) {
        return -1;
    }

    if (width == 0 || height == 0) {
        return -1;
    }

    if (width > max_w) {
        width = max_w;
    }
    if (height > max_h) {
        height = max_h;
    }

    uint64_t pixel_count = (uint64_t)width * (uint64_t)height;
    if (pixel_count == 0 || pixel_count > (UINT32_MAX / sizeof(uint32_t))) {
        return -1;
    }

    uint32_t alloc_size = (uint32_t)(pixel_count * sizeof(uint32_t));

    int32_t idx = wm_find_window_index_by_pid(pid);
    if (idx < 0) {
        idx = wm_find_free_slot();
        if (idx < 0) {
            return -1;
        }
    }

    wm_window_t *window = &g_windows[idx];
    uint8_t was_used = window->used;

    uint32_t *new_pixels = window->pixels;
    if (!window->pixels || window->width != width || window->height != height) {
        new_pixels = (uint32_t *)kmalloc(alloc_size);
        if (!new_pixels) {
            return -1;
        }
    }

    if (new_pixels != window->pixels) {
        if (window->pixels) {
            kfree(window->pixels);
        }
        window->pixels = new_pixels;
    }

    window->used = 1;
    window->owner_pid = pid;
    window->width = width;
    window->height = height;
    window->dirty = 1;
    window->z_order = wm_take_next_z_order();

    if (!was_used) {
        wm_set_window_position(window, (uint32_t)idx, screen_w, screen_h);
    }

    wm_fill_pixels(window, WM_DEFAULT_CLIENT_BG);
    wm_compose_desktop();

    return idx;
}

void window_manager_destroy_window_for_process(int32_t pid)
{
    if (!g_initialized || pid < 0) {
        return;
    }

    int32_t idx = wm_find_window_index_by_pid(pid);
    if (idx < 0) {
        return;
    }

    wm_window_t *window = &g_windows[idx];
    if (window->pixels) {
        kfree(window->pixels);
    }

    memset(window, 0, sizeof(*window));
    wm_compose_desktop();
}

int32_t window_manager_draw_pixel_for_process(int32_t pid, uint32_t x, uint32_t y, uint32_t color)
{
    wm_window_t *window = wm_ensure_window_for_process(pid);
    if (!window || !window->pixels) {
        return -1;
    }

    if (x >= window->width || y >= window->height) {
        return -1;
    }

    window->pixels[(uint64_t)y * (uint64_t)window->width + (uint64_t)x] = color;
    window->dirty = 1;
    return 0;
}

int32_t window_manager_fill_rect_for_process(int32_t pid,
                                             uint32_t x,
                                             uint32_t y,
                                             uint32_t w,
                                             uint32_t h,
                                             uint32_t color)
{
    wm_window_t *window = wm_ensure_window_for_process(pid);
    if (!window || !window->pixels) {
        return -1;
    }

    if (w == 0 || h == 0) {
        return 0;
    }

    if (x >= window->width || y >= window->height) {
        return -1;
    }

    uint64_t x_end64 = (uint64_t)x + (uint64_t)w;
    uint64_t y_end64 = (uint64_t)y + (uint64_t)h;
    uint32_t x_end = (x_end64 > window->width) ? window->width : (uint32_t)x_end64;
    uint32_t y_end = (y_end64 > window->height) ? window->height : (uint32_t)y_end64;

    if (x_end <= x || y_end <= y) {
        return 0;
    }

    for (uint32_t py = y; py < y_end; ++py) {
        uint64_t row = (uint64_t)py * (uint64_t)window->width;
        for (uint32_t px = x; px < x_end; ++px) {
            window->pixels[row + px] = color;
        }
    }

    window->dirty = 1;
    return 0;
}

int32_t window_manager_present_for_process(int32_t pid)
{
    wm_window_t *window = wm_ensure_window_for_process(pid);
    if (!window || !window->pixels) {
        return -1;
    }

    window->z_order = wm_take_next_z_order();
    window->dirty = 1;
    wm_compose_desktop();
    return 0;
}
