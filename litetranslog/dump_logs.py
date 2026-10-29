import argparse
import logging
from litex import RemoteClient
from .json_spec import HwLoggerSpec




class HwLoggerDumpTool:
    def __init__(self, client: RemoteClient, spec: HwLoggerSpec):
        self.client = client
        self.spec = spec

    def dump_raw_memory(self):
        log_count = self.client.regs.log_count.read()
        head_offset = self.client.regs.log_head_offset.read()

        mem_data_list = []
        for addr in range(self.spec.depth):
            self.client.regs.log_mem_addr.write(addr)
            val = self.client.regs.log_mem_data.read()
            mem_data_list.append(val)

        return log_count, head_offset, mem_data_list

    def parse_events(self):
        log_count, head_offset, memory = self.dump_raw_memory()

        if log_count == 0:
            print("Log buffer is empty.")
            return

        start_addr = (head_offset - log_count + 1) % self.spec.depth
        raw_events = []
        event_width = self.spec.timestamp_width + self.spec.max_event_id_width + self.spec.max_event_data_width
        sup = self.spec.superscalarity

        for i in range(log_count):
            addr = (start_addr + i) % self.spec.depth
            packed_val = memory[addr]

            for j in range(sup):
                shift = j * event_width
                slot_val = (packed_val >> shift) & ((1 << event_width) - 1)

                timestamp = slot_val & ((1 << self.spec.timestamp_width) - 1)
                source_id = (slot_val >> self.spec.timestamp_width) & ((1 << self.spec.max_event_id_width) - 1)
                data = slot_val >> (self.spec.timestamp_width + self.spec.max_event_id_width)

                max_source_id = (1 << self.spec.max_event_id_width) - 1
                if source_id == max_source_id:
                    continue

                raw_events.append({
                    "timestamp": timestamp,
                    "source_id": source_id,
                    "data": data,
                })

        # Restore chronological order by sorting strictly by timestamp
        raw_events.sort(key=lambda ev: ev["timestamp"])

        print(f"\n--- Retrieved {len(raw_events)} Log Events ---")
        for ev in raw_events:
            src_id = ev["source_id"]
            timestamp = ev["timestamp"]
            data = ev["data"]

            log_info = next((info for info in self.spec.log_infos if info.id == src_id), None)
            if log_info:
                args = []
                current_shift = 0
                for ds in log_info.dataspec:
                    mask = (1 << ds.width) - 1
                    val = (data >> current_shift) & mask
                    if ds.signed:
                        if val & (1 << (ds.width - 1)):
                            val -= (1 << ds.width)
                    args.append(val)
                    current_shift += ds.width

                formatted_msg = log_info.info.format(*args)
                level = logging.getLevelName(log_info.info.level)
                name = log_info.info.logger_name
                src_loc = log_info.info.location
                print(f"[{timestamp:06d}] {level}\t[{name}]\t[{src_loc}]\t{formatted_msg}")
            else:
                print(f"[{timestamp:06d}] [Unknown Source ID {src_id}] raw_data=0x{data:x}")


def main():
    parser = argparse.ArgumentParser(description="LiteX Transactron Hardware Log Dump Tool")
    parser.add_argument("--spec", required=True, help="Path to the HwLoggerSpec JSON file")
    parser.add_argument("--ip", default="192.168.1.50", help="Target IP address for RemoteClient (default: 192.168.1.50)")
    parser.add_argument("--port", type=int, default=1234, help="Target port for RemoteClient (default: 1234)")

    args = parser.parse_args()

    try:
        spec = HwLoggerSpec.decode(args.spec)
    except Exception as e:
        raise RuntimeError(f"Failed to load spec file '{args.spec}'") from e

    print(f"Connecting to target at {args.ip}:{args.port}...")
    client = RemoteClient(args.ip, args.port)
    client.open()

    try:
        dump_tool = HwLoggerDumpTool(client, spec)
        dump_tool.parse_events()
    finally:
        client.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()
