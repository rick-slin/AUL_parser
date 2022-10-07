from aul_parser import data_format
from aul_parser import errors


class BootRecord(object):
  """Boot record from a timesync file.

  Attributes:
    boot_identifier (guid): boot uuid that links timestamp together.
    timebase_numerator (int): timebase numerator.
    timebase_denominator (int): timebase denominator.
    timestamp (int): int64 number.
    time_zone_offset (int): number of minutes from UTC.
    daylight_saving_flag (int): 1 when daylight savings is in effect.
    sync_records (list): list of SyncRecord objects.
  """

  def __init__(self):
    """Initializes a Boot Record."""
    self.boot_identifier = None
    self.timebase_numerator = None
    self.timebase_denominator = None
    self.timestamp = None
    self.time_zone_offset = None
    self.daylight_saving_flag = None
    self.sync_records = []

  def find_sync_record(self, target_kernel_time):
    """ Returns the SyncRecord with the higher kernel_time that is below the
    provided value.

    Arguments:
      target_kernel_time (int): int64 value.

    Returns:
      closest_record: a SyncRecord object.

    Raises:
      ValueError: if there are no BootRecords.

    """
    if not self.sync_records:
      raise ValueError(
        f'No SyncRecords under this BootRecord: {self.boot_identifier}')

    closest_record = self.sync_records[-1]
    for index, record in enumerate(self.sync_records):
      # Find the record with the highest kernel_time that is below the target
      if record.kernel_time > target_kernel_time:
        closest_record = self.sync_records[index - 1]
        break

    return closest_record


class SyncRecord(object):
  """Sync record from a timesync file.

  Attributes:
    kernel_time: int64 number.
    timestamp (int): int64 number.
    time_zone_offset (int): number of minutes from UTC.
    daylight_saving_flag (int): 1 when daylight savings is in effect.
  """

  def __init__(self):
    """Initializes a Sync Record."""
    self.kernel_time = None
    self.timestamp = None
    self.time_zone_offset = None
    self.daylight_saving_flag = None


class TimeSyncCatalogue(object):
  """A catalogue of Timesync records.

    Attributes:
      boot_records (dict): a dictionary of BootRecords with their
      boot_identifier as the key.
  """

  def __init__(self):
    """Initializes a TimeSyncCatalogueObject"""
    self.boot_records = None

  def _find_sync_record(self, uuid, tracepoint_continuous_time):
    """ Among the SyncRecords that belong to the BootRecord with the provided
    boot uuid, the function returns the one    with the higher kernel_time that is below the
    provided value.

    Attributes:
        uuid (UUID): uuid that identifies the proper BootRecord.
        tracepoint_continuous_time (int): int64 value.

    Returns:
      closest_record: a SyncRecord object.

    Raises:
      ValueError: if no BootRecord can be found.
    """
    boot_record = self.boot_records.get(uuid)
    if not boot_record:
      raise ValueError(f'No BootRecord for {uuid}')

    closest_sync_record = boot_record.find_sync_record(
      tracepoint_continuous_time)

    return closest_sync_record

  def calculate_timestamp(
      self, tracepoint, firehose_base_continuous_time, parent_chunk_header):
    """"""
    tracepoint_continuous_time = firehose_base_continuous_time + (
        tracepoint.continuous_relative |
        tracepoint.continuous_relative_upper << 32)

    sync_record = self._find_sync_record(
      parent_chunk_header.boot_identifier, tracepoint_continuous_time)

    boot_record = self.boot_records[parent_chunk_header.boot_identifier]

    tracepoint_deviation = tracepoint_continuous_time * (
        parent_chunk_header.timebase_numerator /
        parent_chunk_header.timebase_denominator)

    sync_record_deviation = sync_record.kernel_time * (
        boot_record.timebase_numerator / boot_record.timebase_denominator)

    timestamp = (
        sync_record.timestamp + tracepoint_deviation - sync_record_deviation)

    return int(timestamp)


class TimesyncFile(data_format.BinaryDataFile):
  """Timesync file."""

  _FABRIC = data_format.BinaryDataFile.ReadDefinitionFile(
      'unified_logging.yaml')

  _DEBUG_INFO_BOOT_RECORD = [
      ('signature', 'Signature', '_FormatStreamAsSignature'),
      ('unknown', 'Unknown', '_FormatIntegerAsHexadecimal'),
      ('boot_identifier', 'Boot identifier', '_FormatUUIDAsString'),
      ('timebase_numerator', 'Timebase numerator',
       '_FormatIntegerAsHexadecimal'),
      ('timebase_denominator', 'Timebase denominator',
       '_FormatIntegerAsHexadecimal'),
      ('timestamp', 'Timestamp', '_FormatIntegerAsDecimal'),
      ('time_zone_offset', 'Timezone offset', '_FormatIntegerAsDecimal'),
      ('daylight_saving_flag', 'Daylight saving flag',
       '_FormatIntegerAsDecimal')]

  _DEBUG_INFO_SYNC_RECORD = [
      ('signature', 'Signature', '_FormatStreamAsSignature'),
      ('unknown', 'Unknown', '_FormatIntegerAsHexadecimal'),
      ('kernel_time', 'Kernel Time', '_FormatIntegerAsDecimal'),
      ('timestamp', 'Timestamp', '_FormatIntegerAsDecimal'),
      ('time_zone_offset', 'Timezone offset', '_FormatIntegerAsDecimal'),
      ('daylight_saving_flag', 'Daylight saving flag',
       '_FormatIntegerAsDecimal')]

  def __init__(self, debug=False, output_writer=None):
    """Initializes a timesync file.

    Args:
      debug (Optional[bool]): True if debug information should be written.
      output_writer (Optional[OutputWriter]): output writer.
    """
    super(TimesyncFile, self).__init__(
        debug=debug, output_writer=output_writer)

  def _ReadRecord(self, file_object, file_offset):
    """Reads a boot or sync record.

    Args:
      file_object (file): file-like object.
      file_offset (int): offset of the start of the record relative to the start
          of the file.

    Returns:
      record: record object
      int: offset of the end of the record relative to the start of the file.

    Raises:
      ParseError: if the file cannot be read.
    """
    signature_bytes = self._ReadData(file_object, file_offset, 4, 'signature')
    signature = int.from_bytes(signature_bytes, 'big')

    # Boot record
    if signature == 0xb0bb3000:
      data_type_map = self._GetDataTypeMap('timesync_boot_record')
      record_type = 'boot record'
      record_debug_info = self._DEBUG_INFO_BOOT_RECORD

    # Sync record
    elif signature == 0x54732000:
      data_type_map = self._GetDataTypeMap('timesync_sync_record')
      record_type = 'sync record'
      record_debug_info = self._DEBUG_INFO_BOOT_RECORD

    else:
      raise errors.ParseError(
          'Unsupported signature: {0:x}.'.format(signature))

    record, record_size = self._ReadStructureFromFileObject(
        file_object, file_offset, data_type_map, record_type)

    if self._debug:
      self._DebugPrintStructureObject(record, record_debug_info)

    file_offset += record_size

    return record, file_offset

  def ReadFileObject(self, file_object):
    """Reads a timesync file-like object.

    Args:
      file_object (file): file-like object.

    Raises:
      ParseError: if the file cannot be read.
    """
    file_offset = 0

    timesync_dict = {}

    last_boot_uuid = None
    while file_offset < self._file_size:
      record, file_offset = self._ReadRecord(file_object, file_offset)

      # There is always a Boot Record at the start
      if record.signature == b'\xb0\xbb':
        boot_record = BootRecord()

        boot_record.boot_identifier = record.boot_identifier
        boot_record.timebase_numerator = record.timebase_numerator
        boot_record.timebase_denominator = record.timebase_denominator
        boot_record.timestamp = record.timestamp
        boot_record.time_zone_offset = record.time_zone_offset
        boot_record.daylight_saving_flag = record.daylight_saving_flag

        timesync_dict[boot_record.boot_identifier] = boot_record
        last_boot_uuid = boot_record.boot_identifier

      # Each Sync Record falls under the last Boot Record encountered
      elif record.signature == b'\x54\x73\x20\x00':
          sync_record = SyncRecord()

          sync_record.kernel_time = record.kernel_time
          sync_record.timestamp = record.timestamp
          sync_record.time_zone_offset = record.time_zone_offset
          sync_record.daylight_saving_flag = record.daylight_saving_flag

          timesync_dict[last_boot_uuid].sync_records.append(sync_record)

    return timesync_dict
