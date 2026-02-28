#include <stdint.h>
#include <string.h>
#include "../PNG_Decoder/PNG_Decoder.h"
#include "../../Syscalls.h"

extern void* kmalloc(uint32_t size);
extern void kfree(void* ptr);

#define APP_FILE_READ_CHUNK       4096U
#define APP_FILE_INITIAL_CAPACITY 4096U
#define APP_SCREEN_WIDTH          640U
#define APP_SCREEN_HEIGHT         480U

static uint8_t *grow_file_buffer(const uint8_t *current,
                                 uint32_t used_size,
                                 uint32_t new_capacity)
{
    uint8_t *next = (uint8_t *)kmalloc(new_capacity);
    if (next == NULL) {
        return NULL;
    }

    if (current != NULL && used_size > 0U) {
        memcpy(next, current, used_size);
    }

    if (current != NULL) {
        kfree((void *)current);
    }
    return next;
}

uint8_t* load_file(const char* filename, uint32_t* out_size)
{
    if (filename == NULL || out_size == NULL) {
        return NULL;
    }

    int32_t fd = file_open(filename, 0);
    if (fd < 0) {
        serial_write_string("[APP] Failed to open file: ");
        serial_write_string(filename);
        serial_write_string("\n");
        return NULL;
    }

    uint8_t *buffer = NULL;
    uint32_t capacity = 0;
    uint32_t total_size = 0;
    uint8_t chunk[APP_FILE_READ_CHUNK];

    while (1) {
        int32_t read_size = (int32_t)file_read(fd, chunk, APP_FILE_READ_CHUNK);
        if (read_size < 0) {
            serial_write_string("[APP] File read failed\n");
            if (buffer != NULL) {
                kfree(buffer);
            }
            file_close(fd);
            return NULL;
        }
        if (read_size == 0) {
            break;
        }

        uint32_t read_u32 = (uint32_t)read_size;
        uint32_t needed = total_size + read_u32;
        if (needed < total_size) {
            serial_write_string("[APP] File too large\n");
            if (buffer != NULL) {
                kfree(buffer);
            }
            file_close(fd);
            return NULL;
        }

        if (needed > capacity) {
            uint32_t next_capacity = (capacity == 0U) ? APP_FILE_INITIAL_CAPACITY : capacity;
            while (next_capacity < needed) {
                uint32_t doubled = next_capacity * 2U;
                if (doubled <= next_capacity) {
                    next_capacity = needed;
                    break;
                }
                next_capacity = doubled;
            }

            uint8_t *next_buffer = grow_file_buffer(buffer, total_size, next_capacity);
            if (next_buffer == NULL) {
                serial_write_string("[APP] Memory allocation failed\n");
                if (buffer != NULL) {
                    kfree(buffer);
                }
                file_close(fd);
                return NULL;
            }
            buffer = next_buffer;
            capacity = next_capacity;
        }

        memcpy(buffer + total_size, chunk, read_u32);
        total_size += read_u32;
    }

    file_close(fd);
    *out_size = total_size;
    return buffer;
}

void draw_png_image(uint32_t* image_data, uint32_t width, uint32_t height,
                    uint32_t offset_x, uint32_t offset_y)
{
    if (!image_data) {
        return;
    }

    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < width; x++) {
            uint32_t pixel = image_data[y * width + x];

            uint32_t fb_x = offset_x + x;
            uint32_t fb_y = offset_y + y;
            
            if (fb_x >= APP_SCREEN_WIDTH || fb_y >= APP_SCREEN_HEIGHT) {
                continue;
            }

            draw_fill_rect(fb_x, fb_y, 1, 1, pixel);
        }
    }
}

static void log_png_decode_failure(const char *context)
{
    PNGDecodeStatus status = png_decoder_last_status();
    serial_write_string("[APP] PNG decode failed");
    if (context != NULL) {
        serial_write_string(" (");
        serial_write_string(context);
        serial_write_string(")");
    }
    serial_write_string(": code=");
    serial_write_uint32((uint32_t)status);
    serial_write_string(" message=");
    serial_write_string(png_decode_status_string(status));
    serial_write_string("\n");
}

void _start(void)
{
    serial_write_string("[U][APP] standalone process started\n");
    if (wm_create_window(450, 250) < 0) {
        serial_write_string("[U] Failed to create window\n");
    }

    int32_t cursor_x = 12;
    int32_t cursor_y = 12;
    uint8_t mouse_buttons = 0;

    draw_fill_rect(0, 0, APP_SCREEN_WIDTH, APP_SCREEN_HEIGHT, 0xFFFFFFFFu);

    uint32_t file_size = 0;
    uint8_t* png_file_data = load_file("Userland/image.png", &file_size);
    
    uint32_t image_width = 0, image_height = 0;
    uint32_t* decoded_image = NULL;

    if (png_file_data) {
        serial_write_string("[APP] PNG file loaded, size: ");
        serial_write_uint32(file_size);
        serial_write_string("\n");

        decoded_image = png_decode_buffer(png_file_data, file_size,
                                         &image_width, &image_height);

        if (decoded_image) {
            serial_write_string("[APP] PNG decoded successfully\n");
            serial_write_string("[APP] Image width: ");
            serial_write_uint32(image_width);
            serial_write_string("\n");
            serial_write_string("[APP] Image height: ");
            serial_write_uint32(image_height);
            serial_write_string("\n");
        } else {
            log_png_decode_failure("Userland/image.png");
        }

        kfree(png_file_data);
    } else {
        serial_write_string("[APP] Failed to load PNG file\n");
    }

    if (decoded_image) {
        draw_png_image(decoded_image, image_width,
        image_height, 50, 50);
    }

    while (1) {
        input_mouse_event_t mouse_event = {0};
        while (input_read_mouse(&mouse_event) > 0) {
            cursor_x = (int32_t)mouse_event.x;
            cursor_y = (int32_t)mouse_event.y;
            mouse_buttons = mouse_event.buttons;
        }

        input_keyboard_event_t key_event = {0};
        while (input_read_keyboard(&key_event) > 0) {
            if (key_event.pressed) {
                if (key_event.ascii == 'r' || key_event.ascii == 'R') {
                    cursor_x = 12;
                    cursor_y = 12;
                    draw_fill_rect(0, 0, APP_SCREEN_WIDTH, APP_SCREEN_HEIGHT, 0xFFFFFFFFu);
                } else if (key_event.ascii == 'q' || key_event.ascii == 'Q') {
                    if (decoded_image) {
                        kfree(decoded_image);
                    }
                    return;
                }
            }
        }

        draw_fill_rect((uint32_t)cursor_x,
                       (uint32_t)cursor_y,
                       8,
                       8,
                       (mouse_buttons & 0x1u) ? 0xFFFF4040u : 0xFF2060FFu);

        draw_present();
        process_yield();
    }

}
