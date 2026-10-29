from amaranth import *
from amaranth.lib.wiring import Component, In, Out, connect, flipped
from amaranth.hdl import Fragment
from amaranth.lib.data import StructLayout, ArrayLayout
from amaranth.lib.fifo import SyncFIFOBuffered

from transactron import *
from transactron.utils import logging, mod_incr
from transactron.utils.amaranth_ext.elaboratables import MultiPriorityEncoder

from logging import ERROR

from collections.abc import Callable

from .json_structs import LogRecordInfo, HwLoggerSpec, LogInfo, DataFormatInfo, LogChunkInfo


class LiteTransLogCapturer(Component):
    log_reset: Value
    log_lock: Value
    log_locked: Signal
    log_ready: Signal
    log_count: Signal
    log_head_offset: Signal
    log_global_overflow: Signal
    log_local_overflow: Signal
    log_mem_addr: Value
    log_mem_data: Signal

    def __init__(self,
                 elaboratable: Component,
                 log_filter: Callable[[logging.LogRecordInfo], bool] | None = None,
                 depth=1024,
                 max_event_id_width=16,
                 timestamp_width=16,
                 max_event_data_width=96,
                 superscalarity=2,
                 additional_latency=2,
                 local_fifo_depth=8,
                 ):
        self._elaboratable = elaboratable
        self._depth = depth
        self._superscalarity = superscalarity

        self._timestamp_width = timestamp_width
        self._max_event_id_width = max_event_id_width
        self._max_event_data_width = max_event_data_width
        self._local_fifo_depth = local_fifo_depth

        self._log_filter = log_filter if log_filter is not None else (lambda record: True)

        self._additional_latency = additional_latency

        # format timestamp [timestamp_width], source_id [max_event_data_width], data [max_event_data_width]
        self._event_width = timestamp_width + max_event_id_width + max_event_data_width
        self._event_info = []

        super().__init__({
            "dev": Out(elaboratable.signature),
            "log_reset": In(1),
            "log_lock": In(1),
            "log_locked": Out(1),
            "log_ready": Out(1),
            "log_count": Out(range(depth + 1)),
            "log_head_offset": Out(range(depth)),
            "log_global_overflow": Out(1),
            "log_local_overflow": Out(1),
            "log_mem_addr": In(range(depth)),
            "log_mem_data": Out(self._event_width * superscalarity),
        })

    def elaborate(self, platform):
        m = Module()

        m.submodules._elaboratable = _elaboratable = Fragment.get(self._elaboratable, platform)
        connect(m, flipped(self.dev), self._elaboratable)  # type: ignore

        records = [rec for rec in logging.get_log_records(0) if self._log_filter(rec)]
        records.sort(key=lambda r: r.level, reverse=True)  # sort by level, highest first
        assert len(records) <= 2**self._timestamp_width - 1, "Too many log records for timestamp width"

        max_data_width = max((sum(len(f) for f in src.fields) for src in records), default=0)
        assert max_data_width <= self._max_event_data_width, "Event data width exceeds max_event_data_width"

        layout = StructLayout({
            "timestamp": self._timestamp_width,
            "source_id": self._max_event_id_width,
            "data": max_data_width,
        })

        with m.If(self.log_lock):
            m.d.sync += self.log_locked.eq(1)

        timestamp = Signal(self._timestamp_width)
        with m.If(~self.log_locked):
            m.d.sync += timestamp.eq(timestamp + 1)

        record_streams = []

        for i, source in enumerate(records):
            self._event_info.append(LogInfo(
                id=i,
                info=LogRecordInfo(
                    logger_name=source.logger_name,
                    level=source.level,
                    format_spec=[
                        LogChunkInfo(
                            is_fmt=lci.is_fmt,
                            fmt_or_str=lci.fmt_or_str,
                        ) for lci in source.format_spec
                    ],
                    location=source.location,
                ),
                dataspec=[
                    DataFormatInfo(signed=f.shape().signed, width=len(f))
                    for f in source.fields
                ]
            ))

            trigger = source.trigger
            field_cat = Cat(source.fields)

            for _ in range(self._additional_latency):
                ts = Signal.like(trigger)
                ds = Signal.like(field_cat)
                m.d.sync += ts.eq(trigger)
                m.d.sync += ds.eq(field_cat)
                trigger = ts
                field_cat = ds


            local_layout = StructLayout({
                "timestamp": self._timestamp_width,
                "data": field_cat.shape(),
            })
            local_fifo = SyncFIFOBuffered(width=local_layout.size, depth=self._local_fifo_depth)
            m.submodules += local_fifo

            m.d.comb += local_fifo.w_data.eq(Cat(timestamp, field_cat))
            with m.If(trigger & ~self.log_locked):
                m.d.comb += local_fifo.w_en.eq(1)
                with m.If(~local_fifo.w_rdy):
                    m.d.sync += self.log_local_overflow.eq(1)

                if source.level >= ERROR:
                    with m.If(trigger):
                        m.d.sync += self.log_locked.eq(1)

            record_streams.append(local_fifo.r_stream)

        # choose superscalarity number of ready streams to consume from
        m.submodules.pencoder = pencoder = MultiPriorityEncoder(len(record_streams), self._superscalarity)
        m.d.comb += pencoder.input.eq(Cat(stream.valid for stream in record_streams))

        chosen_mask = Signal(len(record_streams))
        for i in range(len(record_streams)):
            for j in range(self._superscalarity):
                with m.If(pencoder.valids[j] & (pencoder.outputs[j] == i)):
                    m.d.comb += chosen_mask[i].eq(1)

            m.d.comb += record_streams[i].ready.eq(chosen_mask[i])

        chosen_outputs = Signal.like(pencoder.outputs)
        chosen_valids = Signal.like(pencoder.valids)
        stream_data = Array(Signal(layout) for _ in record_streams)
        m.d.sync += chosen_outputs.eq(pencoder.outputs)
        m.d.sync += chosen_valids.eq(pencoder.valids)

        for i, stream in enumerate(record_streams):
            ts = stream.payload[:self._timestamp_width]
            data = stream.payload[self._timestamp_width:]
            m.d.sync += stream_data[i].timestamp.eq(ts)
            m.d.sync += stream_data[i].source_id.eq(i)
            m.d.sync += stream_data[i].data.eq(data)

        # compress the chosen outputs into a (superscalarity * event_width) wide signal
        compressed_data = Signal(ArrayLayout(self._event_width, self._superscalarity))
        compressed_valids = Signal(self._superscalarity)
        m.d.sync += compressed_valids.eq(chosen_valids)

        for j in range(self._superscalarity):
            m.d.sync += compressed_data[j].eq(-1)  # sets the event id to max value -> invalid
            with m.If(chosen_valids[j]):
                m.d.sync += compressed_data[j].eq(stream_data[chosen_outputs[j]])

        # write the compressed packet to the memory if there are no events left
        m.submodules.mem = mem = Memory(
            width=self._event_width * self._superscalarity,
            depth=self._depth,
        )
        wr_port = mem.write_port()
        m.d.comb += wr_port.addr.eq(mod_incr(self.log_head_offset, self._depth))
        m.d.comb += wr_port.data.eq(compressed_data)

        with m.If(compressed_valids.any()):
            with m.If(self.log_count == self._depth):
                m.d.sync += self.log_global_overflow.eq(1)
            with m.Else():
                m.d.sync += self.log_count.eq(self.log_count + 1)

            m.d.comb += wr_port.en.eq(1)
            m.d.sync += self.log_head_offset.eq(wr_port.addr)

        rd_port = mem.read_port()
        m.d.comb += rd_port.addr.eq(self.log_mem_addr)
        m.d.comb += self.log_mem_data.eq(rd_port.data)

        with m.If(self.log_reset):
            m.d.sync += [
                timestamp.eq(0),
                self.log_locked.eq(0),
                self.log_local_overflow.eq(0),
                self.log_global_overflow.eq(0),
                self.log_count.eq(0),
                self.log_head_offset.eq(0),
            ]

        return m

    def get_log_info(self) -> HwLoggerSpec:
        return HwLoggerSpec(
            timestamp_width=self._timestamp_width,
            max_event_id_width=self._max_event_id_width,
            max_event_data_width=self._max_event_data_width,
            superscalarity=self._superscalarity,
            depth=self._depth,
            log_infos=self._event_info,
        )
