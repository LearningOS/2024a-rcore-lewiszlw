//! Process management syscalls
use core::mem;

use alloc::vec::Vec;

use crate::{
    config::{MAX_SYSCALL_NUM, PAGE_SIZE_BITS},
    mm::{translated_byte_buffer, MapPermission, VirtAddr},
    task::{
        change_program_brk, current_task_first_scheduled_time, current_task_syscall_times,
        current_user_token, exit_current_and_run_next, mmap_current_program,
        munmap_current_program, suspend_current_and_run_next, TaskStatus,
    },
    timer::{get_time_ms, get_time_us},
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");

    let time_val_len = mem::size_of::<TimeVal>();

    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };

    let data = unsafe {
        core::slice::from_raw_parts(&time_val as *const TimeVal as *const u8, time_val_len)
    };

    let mut buffers = translated_byte_buffer(current_user_token(), ts as *const u8, time_val_len);

    copy_data_to_buffers(data, &mut buffers);
    0
}

fn copy_data_to_buffers(data: &[u8], buffers: &mut Vec<&mut [u8]>) {
    let mut start = 0;
    let end = data.len();

    for buffer in buffers.iter_mut() {
        let min_end = core::cmp::min(buffer.len(), end - start);
        buffer.copy_from_slice(&data[start..min_end]);
        start = min_end;
        if start == end {
            break;
        }
    }
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(ti: *mut TaskInfo) -> isize {
    // trace!("kernel: sys_task_info NOT IMPLEMENTED YET!");

    let syscall_times = current_task_syscall_times();

    let first_scheduled_at = current_task_first_scheduled_time();
    let now = get_time_ms();

    let task_info = TaskInfo {
        status: TaskStatus::Running,
        syscall_times,
        time: now - first_scheduled_at,
    };

    let task_info_len = mem::size_of::<TaskInfo>();
    let data = unsafe {
        core::slice::from_raw_parts(&task_info as *const TaskInfo as *const u8, task_info_len)
    };

    let mut buffers = translated_byte_buffer(current_user_token(), ti as *const u8, task_info_len);

    copy_data_to_buffers(data, &mut buffers);

    0
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    // trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    if start << (64 - PAGE_SIZE_BITS) != 0 {
        return -1;
    }
    if port & !0x7 != 0 {
        return -1;
    }
    if port & 0x7 == 0 {
        return -1;
    }

    if len == 0 {
        return 0;
    }

    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);

    let mut permission = MapPermission::U;

    if port & 0x1 == 1 {
        permission |= MapPermission::R;
    }
    if port & 0x2 == 2 {
        permission |= MapPermission::W;
    }
    if port & 0x4 == 4 {
        permission |= MapPermission::X;
    }

    if let Err(_) = mmap_current_program(start_va, end_va, permission) {
        return -1;
    }

    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    // trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");

    if start << (64 - PAGE_SIZE_BITS) != 0 {
        return -1;
    }

    if len == 0 {
        return 0;
    }

    let start_va = VirtAddr::from(start);
    let end_va = VirtAddr::from(start + len);

    if let Err(_) = munmap_current_program(start_va, end_va) {
        return -1;
    }

    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
