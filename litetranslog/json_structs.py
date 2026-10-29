from dataclasses import dataclass
from dataclasses_json import dataclass_json


type LogLevel = int


@dataclass_json
@dataclass
class LogChunkInfo:
    is_fmt: bool
    """True if this chunk is a format specifier, False if it is a raw string."""

    fmt_or_str: str
    """The format specifier or the raw string."""


@dataclass_json
@dataclass
class LogRecordInfo:
    """
    Simulator-backend-agnostic information about a log record that can
    be serialized and used outside the Amaranth context.
    """

    logger_name: str
    """Name of the logger which produced the record."""

    level: LogLevel
    """The severity level of the log."""

    format_spec: list[LogChunkInfo]
    """List of chunks that make up the formatted message."""

    location: SrcLoc
    """Source location of the log."""

    def format(self, *args: int) -> str:
        """Format the log message with a set of concrete arguments."""

        chunks = []
        fields_iter = iter(args)
        for chunk in self.format_spec:
            if chunk.is_fmt:
                val = next(fields_iter)

                if chunk.fmt_or_str.endswith("s"):
                    msg = bytearray()
                    while val:
                        byte = val & 0xFF
                        val >>= 8
                        if byte:
                            msg.append(byte)

                    fmt_val = msg.decode()
                    fmt = chunk.fmt_or_str[:-1]
                else:
                    fmt_val = val
                    fmt = chunk.fmt_or_str

                chunks.append(format(fmt_val, fmt))
            else:
                chunks.append(chunk.fmt_or_str)

        return "".join(chunks)


@dataclass_json
@dataclass
class DataFormatInfo:
    signed: bool
    width: int


@dataclass_json
@dataclass
class LogInfo:
    id: int
    info: LogRecordInfo
    dataspec: list[DataFormatInfo]


@dataclass_json
@dataclass
class HwLoggerSpec:
    timestamp_width: int
    max_event_id_width: int
    max_event_data_width: int
    superscalarity: int
    depth: int
    log_infos: list[LogInfo]

    def encode(self, file_name: str):
        """
        Encodes the hwlogger information as JSON and saves it to a file.
        """
        with open(file_name, "w") as fp:
            fp.write(self.to_json())  # type: ignore

    @staticmethod
    def decode(file_name: str) -> "GenerationInfo":
        """
        Loads the hwlogger information from a JSON file.
        """
        with open(file_name) as fp:
            return HwLoggerSpec.from_json(fp.read())  # type: ignore
