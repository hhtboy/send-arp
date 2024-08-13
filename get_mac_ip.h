#pragma once

#include <stddef.h>

void get_mac_address(const char *interface, char *mac_str, size_t buf_size);

void get_ip_address(const char *interface, char *ip_str, size_t buf_size);

