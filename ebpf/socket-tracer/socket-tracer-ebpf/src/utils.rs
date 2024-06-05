use aya_ebpf::{
    cty::{c_long, c_void},
    helpers::{bpf_get_current_task, bpf_probe_read_kernel, gen::bpf_probe_read},
};

use crate::vmlinux::task_struct;

const NSEC_PER_SEC: u64 = 1_000_000_000;
const USER_HZ: u64 = 100;

#[inline]
pub unsafe fn bpf_probe_read_buf_with_size(
    src: *const u8,
    dst: &mut [u8],
    size: usize,
) -> Result<(), c_long> {
    let read_size = core::cmp::min(size, dst.len());
    let ret = bpf_probe_read(
        dst.as_mut_ptr() as *mut c_void,
        read_size as u32,
        src as *const c_void,
    );
    if ret == 0 {
        Ok(())
    } else {
        Err(ret)
    }
}

#[inline]
fn pl_nsec_to_clock_t(x: u64) -> u64 {
    x / (NSEC_PER_SEC / USER_HZ)
}

// TODO: there is a bug in this function, bpf verification fails
#[inline]
pub(crate) fn get_tgid_start_time() -> Result<u64, i32> {
    let task: *const task_struct = unsafe { bpf_get_current_task() as *const task_struct };
    if task.is_null() {
        return Err(1);
    }

    let group_leader: *const task_struct = unsafe {
        bpf_probe_read_kernel(&(*task).group_leader as *const _ as *const u64).map_err(|_| 1)?
            as *const task_struct
    };

    let start_boottime = unsafe {
        bpf_probe_read_kernel(&(*group_leader).start_boottime as *const u64).map_err(|_| 1)?
    };

    Ok(pl_nsec_to_clock_t(start_boottime))
}
