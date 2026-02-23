#include <stdint.h>
#include <string.h>
#include "../PNG_Decoder/PNG_Decoder.h"
#include "../../Syscalls.h"

extern void* kmalloc(uint32_t size);
extern void kfree(void* ptr);

uint8_t* load_file(const char* filename, uint32_t* out_size)
{
    int32_t fd = file_open(filename, 0);
    if (fd < 0) {
        serial_write_string("[APP] Failed to open file: ");
        serial_write_string(filename);
        serial_write_string("\n");
        return NULL;
    }

    int32_t file_size = file_seek(fd, 0, 2);
    if (file_size < 0) {
        file_close(fd);
        return NULL;
    }

    file_seek(fd, 0, 0);

    uint8_t* buffer = kmalloc((uint32_t)file_size);
    if (!buffer) {
        serial_write_string("[APP] Memory allocation failed\n");
        file_close(fd);
        return NULL;
    }

    int32_t read_size = file_read(fd, buffer, (uint32_t)file_size);
    file_close(fd);

    if (read_size != file_size) {
        serial_write_string("[APP] File read failed\n");
        kfree(buffer);
        return NULL;
    }

    *out_size = (uint32_t)file_size;
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
            
            if (fb_x >= 640 || fb_y >= 480) {
                continue;
            }

            draw_fill_rect(fb_x, fb_y, 1, 1, pixel);
        }
    }
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

    draw_fill_rect(0, 0, 640, 480, 0xFFFFFFFFu);

    uint32_t file_size = 0;
    uint8_t* png_file_data = load_file("LOGO.PNG", &file_size);
    
    uint32_t image_width = 0, image_height = 0;
    uint32_t* decoded_image = NULL;

    if (png_file_data) {
        serial_write_string("[APP] PNG file loaded, size: ");
        serial_write_string("\n");

        decoded_image = png_decode_buffer(png_file_data, file_size,
                                         &image_width, &image_height);

        if (decoded_image) {
            serial_write_string("[APP] PNG decoded successfully: ");
            serial_write_string("\n");
            serial_write_string("[APP] Image size: ");
            serial_write_string("\n");
        } else {
            serial_write_string("[APP] PNG decode failed: ");
            serial_write_string(png_decoder_last_status_string());
            serial_write_string("\n");
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
                    draw_fill_rect(0, 0, 640, 480, 0xFFFFFFFFu);
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