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
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use frame_analyzer_ebpf_common::FrameSignal;
use crate::uprobe::UprobeHandler;

pub struct AnalyzeTarget {
    pub uprobe: UprobeHandler,
    buffers: HashMap<usize, (u64, VecDeque<Duration>)>,
}

impl AnalyzeTarget {
    pub fn new(uprobe: UprobeHandler) -> Self {
        Self {
            uprobe,
            buffers: HashMap::new(),
        }
    }

    pub fn update(&mut self) -> Option<Duration> {
        let perf_events = self.uprobe.perf_events().unwrap();
        for event in perf_events {
            let frame_signal = unsafe { trans(&event) };
            if let Some((timestamp, buffer)) = self.buffers.get_mut(&frame_signal.buffer) {
                let frametime = frame_signal.ktime_ns.saturating_sub(*timestamp);
                *timestamp = frame_signal.ktime_ns;

                if buffer.len() >= 144 {
                    buffer.pop_back();
                }

                buffer.push_front(Duration::from_nanos(frametime));
            } else {
                self.buffers
                    .insert(frame_signal.buffer, (frame_signal.ktime_ns, VecDeque::with_capacity(144)));
            }

            let max_len = self
                .buffers
                .values()
                .map(|(_, buffer)| buffer.len())
                .max()
                .unwrap_or_default();
            if self.buffers.get(&frame_signal.buffer)
                == self
                    .buffers
                    .values()
                    .filter(|(_, buffer)| buffer.len() == max_len)
                    .min_by_key(|(_, buffer)| buffer.iter().copied().sum::<Duration>())
            {
                return self.buffers.get(&frame_signal.buffer)?.1.front().copied();
            }
        }
        None
    }
}

const unsafe fn trans(buf: &[u8]) -> FrameSignal {
    std::ptr::read_unaligned(buf.as_ptr().cast::<FrameSignal>())
}
