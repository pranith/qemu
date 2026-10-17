/*
 * QEMU Plugin API - linux-user-mode only implementations
 *
 * Common user-mode only APIs are in plugins/api-user. These helpers
 * are only specific to linux-user.
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019-2025, Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "loader.h"
#include "common-user/plugin-api.c.inc"

bool qemu_plugin_get_exec_context(struct qemu_plugin_exec_context *context,
                                  size_t size)
{
    CPUState *cpu = current_cpu ? current_cpu : thread_cpu;
    TaskState *task;

    if (!context || size < sizeof(*context) || !cpu) {
        return false;
    }

    memset(context, 0, sizeof(*context));
    context->vcpu_index = cpu->cpu_index;
    context->pid = getpid();
    task = get_task_state(cpu);
    context->tid = task && task->ts_tid ? task->ts_tid : syscall(SYS_gettid);
    context->valid_fields = QEMU_PLUGIN_CONTEXT_VCPU |
                            QEMU_PLUGIN_CONTEXT_PID |
                            QEMU_PLUGIN_CONTEXT_TID;
    return true;
}
