#ifndef PS2_INPUT_H
#define PS2_INPUT_H

#include <stdint.h>

#define PS2_KBD_MOD_SHIFT (1u << 0)
#define PS2_KBD_MOD_CTRL  (1u << 1)
#define PS2_KBD_MOD_ALT   (1u << 2)
#define PS2_KBD_MOD_CAPS  (1u << 3)

typedef struct __attribute__((packed)) {
    uint16_t keycode;
    uint8_t pressed;
    uint8_t ascii;
    uint8_t modifiers;
    uint8_t reserved[3];
} ps2_keyboard_event_t;

typedef struct __attribute__((packed)) {
    uint16_t x;
    uint16_t y;
    uint8_t buttons;
    int8_t wheel;
    uint8_t reserved[2];
} ps2_mouse_event_t;

typedef struct {
    void (*init)(void);
    void (*poll)(void);
    int32_t (*read_keyboard)(ps2_keyboard_event_t *out_event);
    int32_t (*read_mouse)(ps2_mouse_event_t *out_event);
} ps2_input_driver_t;

void ps2_input_init(void);
void ps2_input_poll(void);
int32_t ps2_input_read_keyboard(ps2_keyboard_event_t *out_event);
int32_t ps2_input_read_mouse(ps2_mouse_event_t *out_event);

#endif
