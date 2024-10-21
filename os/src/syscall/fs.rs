//! File and filesystem-related syscalls
use core::mem;

use crate::fs::{linkat_file, open_file, unlinkat_file, OSInode, OpenFlags, Stat, StatMode};
use crate::mm::{translated_byte_buffer, translated_str, UserBuffer};
use crate::syscall::copy_data_to_buffers;
use crate::task::{current_task, current_user_token};

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_write", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_read", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        trace!("kernel: sys_read .. file.read");
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    trace!("kernel:pid[{}] sys_open", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    trace!("kernel:pid[{}] sys_close", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    0
}

/// YOUR JOB: Implement fstat.
pub fn sys_fstat(fd: usize, st: *mut Stat) -> isize {
    trace!(
        "kernel:pid[{}] sys_fstat NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let stat_len = mem::size_of::<Stat>();
    let mut buffers = translated_byte_buffer(current_user_token(), st as *const u8, stat_len);

    let task = current_task().unwrap();
    let task_inner = task.inner_exclusive_access();
    if let Some(file) = &task_inner.fd_table[fd] {
        if let Some(os_inode) = file.as_any().downcast_ref::<OSInode>() {
            let os_inode_inner = os_inode.inner_exclusive_access();
            let innode_id = os_inode_inner.inode.id;
            os_inode_inner.inode.read_disk_inode(|disk_inode| {
                let stat = Stat {
                    dev: 0,
                    ino: innode_id as u64,
                    mode: if disk_inode.is_dir() {
                        StatMode::DIR
                    } else {
                        StatMode::FILE
                    },
                    nlink: disk_inode.nlink,
                    pad: [0; 7],
                };
                let data = unsafe {
                    core::slice::from_raw_parts(&stat as *const Stat as *const u8, stat_len)
                };
                copy_data_to_buffers(data, &mut buffers);
            });
            0
        } else {
            -1
        }
    } else {
        -1
    }
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(old_name: *const u8, new_name: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_linkat NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let token = current_user_token();
    let old_name = translated_str(token, old_name);
    let new_name = translated_str(token, new_name);
    if old_name == new_name {
        return -1;
    }
    linkat_file(&old_name, &new_name);
    0
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(name: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_unlinkat NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    let token = current_user_token();
    let name = translated_str(token, name);
    match unlinkat_file(&name) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}
