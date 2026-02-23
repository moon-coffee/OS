#include "PS2_Input.h"

#include "../../IO/IO_Main.h"
#include "../../Serial.h"
#ifdef IMPLUS_DRIVER_MODULE
#include "../DriverBinary.h"
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef IMPLUS_DRIVER_MODULE
static const driver_kernel_api_t *g_driver_api = NULL;

#define inb g_driver_api->inb
#define outb g_driver_api->outb
#define serial_write_string g_driver_api->serial_write_string
#endif

#define PS2_DATA_PORT    0x60
#define PS2_STATUS_PORT  0x64
#define PS2_COMMAND_PORT 0x64

#define PS2_STATUS_OUTPUT_FULL 0x01
#define PS2_STATUS_INPUT_FULL  0x02
#define PS2_STATUS_AUX_DATA    0x20

#define PS2_CMD_READ_CONFIG   0x20
#define PS2_CMD_WRITE_CONFIG  0x60
#define PS2_CMD_DISABLE_PORT1 0xAD
#define PS2_CMD_ENABLE_PORT1  0xAE
#define PS2_CMD_DISABLE_PORT2 0xA7
#define PS2_CMD_ENABLE_PORT2  0xA8
#define PS2_CMD_TEST_PORT1    0xAB
#define PS2_CMD_TEST_PORT2    0xA9
#define PS2_CMD_SELF_TEST     0xAA
#define PS2_CMD_WRITE_MOUSE   0xD4

#define PS2_CONFIG_IRQ_PORT1   0x01
#define PS2_CONFIG_IRQ_PORT2   0x02
#define PS2_CONFIG_TRANSLATION 0x40

#define PS2_KBD_CMD_ENABLE_SCANNING   0xF4
#define PS2_MOUSE_CMD_SET_DEFAULTS    0xF6
#define PS2_MOUSE_CMD_ENABLE_REPORTING 0xF4

#define PS2_ACK       0xFA
#define PS2_RESEND    0xFE
#define PS2_TEST_OK   0x00
#define PS2_SELF_OK   0x55

#define PS2_COMMAND_TIMEOUT 100000u
#define PS2_MAX_POLL_READS  64u
#define PS2_QUEUE_SIZE      128u
#define PS2_SEND_RETRIES    3u
#define PS2_MOUSE_X_MAX     639
#define PS2_MOUSE_Y_MAX     479
#define PS2_MOUSE_DEFAULT_X 12
#define PS2_MOUSE_DEFAULT_Y 12

static uint8_t g_input_initialized = 0;
static uint8_t g_mouse_available = 0;

static uint8_t g_keyboard_e0_pending = 0;
static uint8_t g_keyboard_modifiers = 0;
static uint8_t g_mouse_packet[3];
static uint8_t g_mouse_packet_index = 0;
static uint8_t g_last_mouse_buttons = 0;
static uint16_t g_mouse_x = PS2_MOUSE_DEFAULT_X;
static uint16_t g_mouse_y = PS2_MOUSE_DEFAULT_Y;

static ps2_keyboard_event_t g_keyboard_queue[PS2_QUEUE_SIZE];
static uint32_t g_keyboard_head = 0;
static uint32_t g_keyboard_tail = 0;
static uint32_t g_keyboard_count = 0;

static ps2_mouse_event_t g_mouse_queue[PS2_QUEUE_SIZE];
static uint32_t g_mouse_head = 0;
static uint32_t g_mouse_tail = 0;
static uint32_t g_mouse_count = 0;

static int controller_wait_input_clear(uint32_t spins)
{
    while (spins > 0u) {
        if ((inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_FULL) == 0u) {
            return 0;
        }
        --spins;
    }
    return -1;
}

static int controller_wait_output_full(uint32_t spins)
{
    while (spins > 0u) {
        if ((inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) != 0u) {
            return 0;
        }
        --spins;
    }
    return -1;
}

static int controller_write_command(uint8_t command)
{
    if (controller_wait_input_clear(PS2_COMMAND_TIMEOUT) < 0) {
        return -1;
    }
    outb(PS2_COMMAND_PORT, command);
    return 0;
}

static int controller_write_data(uint8_t data)
{
    if (controller_wait_input_clear(PS2_COMMAND_TIMEOUT) < 0) {
        return -1;
    }
    outb(PS2_DATA_PORT, data);
    return 0;
}

static int controller_read_data(uint8_t *value_out)
{
    if (value_out == NULL) {
        return -1;
    }
    if (controller_wait_output_full(PS2_COMMAND_TIMEOUT) < 0) {
        return -1;
    }
    *value_out = inb(PS2_DATA_PORT);
    return 0;
}

static void controller_flush_output(void)
{
    for (uint32_t i = 0; i < PS2_MAX_POLL_READS; ++i) {
        if ((inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) == 0u) {
            break;
        }
        (void)inb(PS2_DATA_PORT);
    }
}

static int controller_read_config(uint8_t *config_out)
{
    if (controller_write_command(PS2_CMD_READ_CONFIG) < 0) {
        return -1;
    }
    return controller_read_data(config_out);
}

static int controller_write_config(uint8_t config)
{
    if (controller_write_command(PS2_CMD_WRITE_CONFIG) < 0) {
        return -1;
    }
    return controller_write_data(config);
}

static int controller_test_port(uint8_t test_command)
{
    uint8_t status = 0;
    if (controller_write_command(test_command) < 0) {
        return -1;
    }
    if (controller_read_data(&status) < 0) {
        return -1;
    }
    return (status == PS2_TEST_OK) ? 0 : -1;
}

static int device_wait_ack(void)
{
    for (uint32_t spin = 0; spin < PS2_COMMAND_TIMEOUT; ++spin) {
        if ((inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) == 0u) {
            continue;
        }
        uint8_t value = inb(PS2_DATA_PORT);
        if (value == PS2_ACK) {
            return 0;
        }
        if (value == PS2_RESEND) {
            return 1;
        }
    }
    return -1;
}

static int send_keyboard_command(uint8_t command)
{
    for (uint32_t retry = 0; retry < PS2_SEND_RETRIES; ++retry) {
        if (controller_write_data(command) < 0) {
            return -1;
        }
        int ack = device_wait_ack();
        if (ack == 0) {
            return 0;
        }
        if (ack < 0) {
            return -1;
        }
    }
    return -1;
}

static int send_mouse_command(uint8_t command)
{
    for (uint32_t retry = 0; retry < PS2_SEND_RETRIES; ++retry) {
        if (controller_write_command(PS2_CMD_WRITE_MOUSE) < 0) {
            return -1;
        }
        if (controller_write_data(command) < 0) {
            return -1;
        }
        int ack = device_wait_ack();
        if (ack == 0) {
            return 0;
        }
        if (ack < 0) {
            return -1;
        }
    }
    return -1;
}

static void keyboard_queue_push(const ps2_keyboard_event_t *event)
{
    if (event == NULL || g_keyboard_count >= PS2_QUEUE_SIZE) {
        return;
    }
    g_keyboard_queue[g_keyboard_head] = *event;
    g_keyboard_head = (g_keyboard_head + 1u) % PS2_QUEUE_SIZE;
    ++g_keyboard_count;
}

static int keyboard_queue_pop(ps2_keyboard_event_t *event_out)
{
    if (event_out == NULL || g_keyboard_count == 0u) {
        return 0;
    }
    *event_out = g_keyboard_queue[g_keyboard_tail];
    g_keyboard_tail = (g_keyboard_tail + 1u) % PS2_QUEUE_SIZE;
    --g_keyboard_count;
    return 1;
}

static void mouse_queue_push(const ps2_mouse_event_t *event)
{
    if (event == NULL || g_mouse_count >= PS2_QUEUE_SIZE) {
        return;
    }
    g_mouse_queue[g_mouse_head] = *event;
    g_mouse_head = (g_mouse_head + 1u) % PS2_QUEUE_SIZE;
    ++g_mouse_count;
}

static int mouse_queue_pop(ps2_mouse_event_t *event_out)
{
    if (event_out == NULL || g_mouse_count == 0u) {
        return 0;
    }
    *event_out = g_mouse_queue[g_mouse_tail];
    g_mouse_tail = (g_mouse_tail + 1u) % PS2_QUEUE_SIZE;
    --g_mouse_count;
    return 1;
}

static uint16_t clamp_u16_i32(int32_t value, uint16_t max_value)
{
    if (value < 0) {
        return 0;
    }
    if (value > (int32_t)max_value) {
        return max_value;
    }
    return (uint16_t)value;
}

static char keyboard_scancode_to_ascii(uint16_t keycode, uint8_t modifiers)
{
    if ((keycode & 0xFF00u) != 0u) {
        return 0;
    }

    uint8_t scancode = (uint8_t)keycode;
    int shift = (modifiers & PS2_KBD_MOD_SHIFT) != 0u;
    int caps = (modifiers & PS2_KBD_MOD_CAPS) != 0u;
    int alpha_upper = shift ^ caps;

    switch (scancode) {
    case 0x1E: return alpha_upper ? 'A' : 'a';
    case 0x30: return alpha_upper ? 'B' : 'b';
    case 0x2E: return alpha_upper ? 'C' : 'c';
    case 0x20: return alpha_upper ? 'D' : 'd';
    case 0x12: return alpha_upper ? 'E' : 'e';
    case 0x21: return alpha_upper ? 'F' : 'f';
    case 0x22: return alpha_upper ? 'G' : 'g';
    case 0x23: return alpha_upper ? 'H' : 'h';
    case 0x17: return alpha_upper ? 'I' : 'i';
    case 0x24: return alpha_upper ? 'J' : 'j';
    case 0x25: return alpha_upper ? 'K' : 'k';
    case 0x26: return alpha_upper ? 'L' : 'l';
    case 0x32: return alpha_upper ? 'M' : 'm';
    case 0x31: return alpha_upper ? 'N' : 'n';
    case 0x18: return alpha_upper ? 'O' : 'o';
    case 0x19: return alpha_upper ? 'P' : 'p';
    case 0x10: return alpha_upper ? 'Q' : 'q';
    case 0x13: return alpha_upper ? 'R' : 'r';
    case 0x1F: return alpha_upper ? 'S' : 's';
    case 0x14: return alpha_upper ? 'T' : 't';
    case 0x16: return alpha_upper ? 'U' : 'u';
    case 0x2F: return alpha_upper ? 'V' : 'v';
    case 0x11: return alpha_upper ? 'W' : 'w';
    case 0x2D: return alpha_upper ? 'X' : 'x';
    case 0x15: return alpha_upper ? 'Y' : 'y';
    case 0x2C: return alpha_upper ? 'Z' : 'z';
    case 0x39: return ' ';
    case 0x1C: return '\n';
    case 0x0E: return '\b';
    case 0x0F: return '\t';
    default:
        break;
    }

    if (!shift) {
        switch (scancode) {
        case 0x02: return '1';
        case 0x03: return '2';
        case 0x04: return '3';
        case 0x05: return '4';
        case 0x06: return '5';
        case 0x07: return '6';
        case 0x08: return '7';
        case 0x09: return '8';
        case 0x0A: return '9';
        case 0x0B: return '0';
        case 0x0C: return '-';
        case 0x0D: return '=';
        case 0x1A: return '[';
        case 0x1B: return ']';
        case 0x27: return ';';
        case 0x28: return '\'';
        case 0x29: return '`';
        case 0x2B: return '\\';
        case 0x33: return ',';
        case 0x34: return '.';
        case 0x35: return '/';
        default:
            return 0;
        }
    }

    switch (scancode) {
    case 0x02: return '!';
    case 0x03: return '@';
    case 0x04: return '#';
    case 0x05: return '$';
    case 0x06: return '%';
    case 0x07: return '^';
    case 0x08: return '&';
    case 0x09: return '*';
    case 0x0A: return '(';
    case 0x0B: return ')';
    case 0x0C: return '_';
    case 0x0D: return '+';
    case 0x1A: return '{';
    case 0x1B: return '}';
    case 0x27: return ':';
    case 0x28: return '"';
    case 0x29: return '~';
    case 0x2B: return '|';
    case 0x33: return '<';
    case 0x34: return '>';
    case 0x35: return '?';
    default:
        return 0;
    }
}

static void keyboard_update_modifiers(uint16_t keycode, int pressed)
{
    uint8_t code = (uint8_t)(keycode & 0x00FFu);
    switch (code) {
    case 0x2A:
    case 0x36:
        if (pressed) {
            g_keyboard_modifiers |= PS2_KBD_MOD_SHIFT;
        } else {
            g_keyboard_modifiers &= (uint8_t)~PS2_KBD_MOD_SHIFT;
        }
        break;
    case 0x1D:
        if (pressed) {
            g_keyboard_modifiers |= PS2_KBD_MOD_CTRL;
        } else {
            g_keyboard_modifiers &= (uint8_t)~PS2_KBD_MOD_CTRL;
        }
        break;
    case 0x38:
        if (pressed) {
            g_keyboard_modifiers |= PS2_KBD_MOD_ALT;
        } else {
            g_keyboard_modifiers &= (uint8_t)~PS2_KBD_MOD_ALT;
        }
        break;
    case 0x3A:
        if (pressed) {
            g_keyboard_modifiers ^= PS2_KBD_MOD_CAPS;
        }
        break;
    default:
        break;
    }
}

static void handle_keyboard_byte(uint8_t value)
{
    if (value == PS2_ACK || value == PS2_RESEND) {
        return;
    }
    if (value == 0xE0u) {
        g_keyboard_e0_pending = 1;
        return;
    }
    if (value == 0xE1u) {
        g_keyboard_e0_pending = 0;
        return;
    }

    int pressed = ((value & 0x80u) == 0u) ? 1 : 0;
    uint16_t keycode = (uint16_t)(value & 0x7Fu);
    if (g_keyboard_e0_pending) {
        keycode |= 0xE000u;
        g_keyboard_e0_pending = 0;
    }

    keyboard_update_modifiers(keycode, pressed);

    ps2_keyboard_event_t event = {0};
    event.keycode = keycode;
    event.pressed = (uint8_t)(pressed ? 1 : 0);
    event.modifiers = g_keyboard_modifiers;
    event.ascii = pressed ? (uint8_t)keyboard_scancode_to_ascii(keycode, g_keyboard_modifiers) : 0u;
    keyboard_queue_push(&event);
}

static void handle_mouse_byte(uint8_t value)
{
    if (value == PS2_ACK || value == PS2_RESEND) {
        return;
    }

    if (g_mouse_packet_index == 0u && (value & 0x08u) == 0u) {
        return;
    }

    g_mouse_packet[g_mouse_packet_index++] = value;
    if (g_mouse_packet_index < 3u) {
        return;
    }

    g_mouse_packet_index = 0;

    uint8_t b0 = g_mouse_packet[0];
    uint8_t b1 = g_mouse_packet[1];
    uint8_t b2 = g_mouse_packet[2];

    if ((b0 & 0xC0u) != 0u) {
        return;
    }

    int16_t dx = (int16_t)(int8_t)b1;
    int16_t dy = (int16_t)(int8_t)b2;
    uint8_t buttons = (uint8_t)(b0 & 0x07u);

    uint16_t next_x = clamp_u16_i32((int32_t)g_mouse_x + (int32_t)dx, PS2_MOUSE_X_MAX);
    uint16_t next_y = clamp_u16_i32((int32_t)g_mouse_y - (int32_t)dy, PS2_MOUSE_Y_MAX);

    if (next_x == g_mouse_x && next_y == g_mouse_y && buttons == g_last_mouse_buttons) {
        return;
    }

    g_mouse_x = next_x;
    g_mouse_y = next_y;

    ps2_mouse_event_t event = {0};
    event.x = g_mouse_x;
    event.y = g_mouse_y;
    event.buttons = buttons;
    event.wheel = 0;
    mouse_queue_push(&event);
    g_last_mouse_buttons = buttons;
}

void ps2_input_init(void)
{
    uint8_t config = 0;
    int port1_ok = 0;
    int port2_ok = 0;

    g_input_initialized = 0;
    g_mouse_available = 0;
    g_keyboard_e0_pending = 0;
    g_keyboard_modifiers = 0;
    g_mouse_packet_index = 0;
    g_last_mouse_buttons = 0;
    g_mouse_x = PS2_MOUSE_DEFAULT_X;
    g_mouse_y = PS2_MOUSE_DEFAULT_Y;
    g_keyboard_head = g_keyboard_tail = g_keyboard_count = 0;
    g_mouse_head = g_mouse_tail = g_mouse_count = 0;

    (void)controller_write_command(PS2_CMD_DISABLE_PORT1);
    (void)controller_write_command(PS2_CMD_DISABLE_PORT2);
    controller_flush_output();

    if (controller_read_config(&config) < 0) {
        serial_write_string("[OS] [PS2] Failed to read controller config\n");
        return;
    }

    config &= (uint8_t)~(PS2_CONFIG_IRQ_PORT1 | PS2_CONFIG_IRQ_PORT2);
    config |= PS2_CONFIG_TRANSLATION;
    if (controller_write_config(config) < 0) {
        serial_write_string("[OS] [PS2] Failed to write controller config\n");
        return;
    }

    if (controller_write_command(PS2_CMD_SELF_TEST) == 0) {
        uint8_t self_test = 0;
        if (controller_read_data(&self_test) == 0 && self_test != PS2_SELF_OK) {
            serial_write_string("[OS] [PS2] Controller self-test failed\n");
        }
    }

    port1_ok = (controller_test_port(PS2_CMD_TEST_PORT1) == 0) ? 1 : 0;
    port2_ok = (controller_test_port(PS2_CMD_TEST_PORT2) == 0) ? 1 : 0;

    if (port1_ok) {
        (void)controller_write_command(PS2_CMD_ENABLE_PORT1);
    }
    if (port2_ok) {
        (void)controller_write_command(PS2_CMD_ENABLE_PORT2);
        g_mouse_available = 1;
    }

    if (port1_ok && send_keyboard_command(PS2_KBD_CMD_ENABLE_SCANNING) < 0) {
        serial_write_string("[OS] [PS2] Keyboard enable failed\n");
    }

    if (g_mouse_available) {
        if (send_mouse_command(PS2_MOUSE_CMD_SET_DEFAULTS) < 0 ||
            send_mouse_command(PS2_MOUSE_CMD_ENABLE_REPORTING) < 0) {
            serial_write_string("[OS] [PS2] Mouse enable failed\n");
            g_mouse_available = 0;
        }
    }

    controller_flush_output();

    if (!port1_ok && !g_mouse_available) {
        serial_write_string("[OS] [PS2] No PS/2 keyboard/mouse detected\n");
        return;
    }

    g_input_initialized = 1;
    serial_write_string("[OS] [PS2] Input ready (poll mode)\n");
}

void ps2_input_poll(void)
{
    if (!g_input_initialized) {
        return;
    }

    while (inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL) {
        uint8_t status = inb(PS2_STATUS_PORT);
        uint8_t value = inb(PS2_DATA_PORT);

        if (value == PS2_ACK || value == PS2_RESEND) {
            g_mouse_packet_index = 0;
            continue;
        }

        if (status & PS2_STATUS_AUX_DATA) {
            if (!g_mouse_available) {
                continue;
            }

            if ((value & 0x08u) == 0u) {
                g_mouse_packet_index = 0;
                continue;
            }

            g_mouse_packet[g_mouse_packet_index++] = value;

            if (g_mouse_packet_index < 3u) {
                continue;
            }

            g_mouse_packet_index = 0;

            uint8_t b0 = g_mouse_packet[0];
            uint8_t b1 = g_mouse_packet[1];
            uint8_t b2 = g_mouse_packet[2];

            if ((b0 & 0xC0u) != 0u) {
                continue;
            }

            int16_t dx = (int16_t)(int8_t)b1;
            int16_t dy = (int16_t)(int8_t)b2;
            uint8_t buttons = (uint8_t)(b0 & 0x07u);

            uint16_t next_x = clamp_u16_i32((int32_t)g_mouse_x + (int32_t)dx, PS2_MOUSE_X_MAX);
            uint16_t next_y = clamp_u16_i32((int32_t)g_mouse_y - (int32_t)dy, PS2_MOUSE_Y_MAX);

            if (next_x == g_mouse_x && next_y == g_mouse_y && buttons == g_last_mouse_buttons) {
                continue;
            }

            g_mouse_x = next_x;
            g_mouse_y = next_y;

            ps2_mouse_event_t event = {0};
            event.x = g_mouse_x;
            event.y = g_mouse_y;
            event.buttons = buttons;
            event.wheel = 0;

            if (g_mouse_count >= PS2_QUEUE_SIZE) {
                g_mouse_tail = (g_mouse_tail + 1u) % PS2_QUEUE_SIZE;
                --g_mouse_count;
            }

            g_mouse_queue[g_mouse_head] = event;
            g_mouse_head = (g_mouse_head + 1u) % PS2_QUEUE_SIZE;
            ++g_mouse_count;

            g_last_mouse_buttons = buttons;
        } else {
            if (value == 0xE0u) {
                g_keyboard_e0_pending = 1;
                continue;
            }

            if (value == 0xE1u) {
                g_keyboard_e0_pending = 0;
                continue;
            }

            int pressed = ((value & 0x80u) == 0u) ? 1 : 0;
            uint16_t keycode = (uint16_t)(value & 0x7Fu);

            if (g_keyboard_e0_pending) {
                keycode |= 0xE000u;
                g_keyboard_e0_pending = 0;
            }

            keyboard_update_modifiers(keycode, pressed);

            ps2_keyboard_event_t event = {0};
            event.keycode = keycode;
            event.pressed = (uint8_t)(pressed ? 1 : 0);
            event.modifiers = g_keyboard_modifiers;
            event.ascii = pressed ? (uint8_t)keyboard_scancode_to_ascii(keycode, g_keyboard_modifiers) : 0u;

            if (g_keyboard_count >= PS2_QUEUE_SIZE) {
                g_keyboard_tail = (g_keyboard_tail + 1u) % PS2_QUEUE_SIZE;
                --g_keyboard_count;
            }

            g_keyboard_queue[g_keyboard_head] = event;
            g_keyboard_head = (g_keyboard_head + 1u) % PS2_QUEUE_SIZE;
            ++g_keyboard_count;
        }
    }
}

int32_t ps2_input_read_keyboard(ps2_keyboard_event_t *out_event)
{
    if (out_event == NULL) {
        return -1;
    }
    ps2_input_poll();
    return keyboard_queue_pop(out_event);
}

int32_t ps2_input_read_mouse(ps2_mouse_event_t *out_event)
{
    if (out_event == NULL) {
        return -1;
    }
    if (!g_mouse_available) {
        return 0;
    }
    ps2_input_poll();
    return mouse_queue_pop(out_event);
}

#ifdef IMPLUS_DRIVER_MODULE
static const ps2_input_driver_t g_ps2_input_driver = {
    .init = ps2_input_init,
    .poll = ps2_input_poll,
    .read_keyboard = ps2_input_read_keyboard,
    .read_mouse = ps2_input_read_mouse,
};

#undef inb
#undef outb
#undef serial_write_string

const ps2_input_driver_t *driver_module_init(const driver_kernel_api_t *api)
{
    if (api == NULL ||
        api->inb == NULL ||
        api->outb == NULL ||
        api->serial_write_string == NULL) {
        return NULL;
    }

    g_driver_api = api;
    return &g_ps2_input_driver;
}
#endif
