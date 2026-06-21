#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "ghost_event.h"

bool pipeline_forwarder_init(const char *host,
                             uint16_t port);

bool pipeline_send_batch(const ghost_event_t *events,
                         uint32_t count);

void pipeline_forwarder_shutdown(void);
