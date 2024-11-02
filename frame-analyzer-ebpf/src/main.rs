/*
 * Copyright (c) 2024 shadow3aaa@gitbub.com
 *
 * This file is part of frame-analyzer-ebpf.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::gen::bpf_ktime_get_ns,
    macros::{map, uprobe},
    maps::PerfEventArray,
    programs::ProbeContext,
};

use frame_analyzer_ebpf_common::FrameSignal;

#[map]
static PERF_EVENTS: PerfEventArray = PerfEventArray::new();

#[uprobe]
pub fn frame_analyzer_ebpf(ctx: ProbeContext) -> u32 {
    match try_frame_analyzer_ebpf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_frame_analyzer_ebpf(ctx: ProbeContext) -> Result<u32, u32> {
    let ktime_ns = unsafe { bpf_ktime_get_ns() };
    let frame_signal = FrameSignal::new(ktime_ns, ctx.arg::<usize>(0).unwrap());

    PERF_EVENTS.output(ctx, &frame_signal, 0)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
