import struct
import os
import binascii

# Data structures
class ELFFileHeader:
    def __init__(self, data):
        unpacked = struct.unpack('<QQQQIHHHI74sII', data)
        self.signature = unpacked[0]
        self.first_chunk_number = unpacked[1]
        self.last_chunk_number = unpacked[2]
        self.next_record_identifier = unpacked[3]
        self.header_size = unpacked[4]
        self.minor_version = unpacked[5]
        self.major_version = unpacked[6]
        self.chunk_data_offset = unpacked[7]
        self.number_of_chunks = unpacked[8]
        self.unknown = unpacked[9]
        self.file_flags = unpacked[10]
        self.checksum = unpacked[11]

    def to_bytes(self):
        return struct.pack('<QQQQIHHHI74sII', self.signature, self.first_chunk_number, self.last_chunk_number,
                           self.next_record_identifier, self.header_size, self.minor_version, self.major_version,
                           self.chunk_data_offset, self.number_of_chunks, self.unknown, self.file_flags, self.checksum)

class ChunkHeader:
    def __init__(self, data):
        unpacked = struct.unpack('<QQQQQIIII64sII', data)
        self.signature = unpacked[0]
        self.first_event_record_number = unpacked[1]
        self.last_event_record_number = unpacked[2]
        self.first_event_record_identifier = unpacked[3]
        self.last_event_record_identifier = unpacked[4]
        self.header_size = unpacked[5]
        self.last_event_record_data_offset = unpacked[6]
        self.free_space_offset = unpacked[7]
        self.event_records_checksum = unpacked[8]
        self.unknown1 = unpacked[9]
        self.unknown2 = unpacked[10]
        self.checksum = unpacked[11]

    def to_bytes(self):
        # Pack fields back into binary data
        return struct.pack('<QQQQQIIII64sII', self.signature, self.first_event_record_number,
                           self.last_event_record_number, self.first_event_record_identifier,
                           self.last_event_record_identifier, self.header_size, self.last_event_record_data_offset,
                           self.free_space_offset, self.event_records_checksum, self.unknown1, self.unknown2,
                           self.checksum)

class EventRecord:
    def __init__(self, data):
        unpacked = struct.unpack('<IIQQ', data)
        self.signature = unpacked[0]
        self.size = unpacked[1]
        self.event_record_identifier = unpacked[2]
        self.written_date_and_time = unpacked[3]

    def encode_hidden_message(self, message):
        message_len = len(message)
        max_bytes = 4  # 4 bytes for size field

        if message_len > max_bytes:
            raise ValueError("Message is too long to encode.")

        self.size = 0
        for i, char in enumerate(message):
            self.size |= (ord(char) << (i * 8))

    def to_bytes(self):
        # Pack fields back into binary data
        return struct.pack('<IIQQ', self.signature, self.size, self.event_record_identifier, self.written_date_and_time)

def calculate_crc32(data):
    # Compute the CRC32 checksum and format it as an 8-character hexadecimal string
    return binascii.crc32(data) & 0xFFFFFFFF

def process_event_log(file_path):
    with open(file_path, "rb") as f:
        file_buffer = bytearray(f.read())

    with open("SAMPLEEXE.exe", "rb") as g:
        exe_buffer = bytearray(g.read())

    # Counts index position of exe
    exe_counter = 0

    chunk_buffer = bytearray(b"")
    chunk_counter = 0
    record_counter = 0
    last_offset_counter = 0
    total_records_counter = 0
    total_records_counter_2 = 0

    previous_len = 0
    chunk_list = []
    len_req = os.path.getsize("SAMPLEEXE.exe")

    file_header = ELFFileHeader(file_buffer[:struct.calcsize('<QQQQIHHHI74sII')])

    total_chunks = file_header.last_chunk_number - file_header.first_chunk_number + 1
    each_chunk_req = (len_req // total_chunks) + 1

    if not file_buffer[:8].startswith(b"ElfFile"):
        raise ValueError("File does not have expected signature.")

    # Iterating through each chunk in original evtx
    for chunk_offset in range(file_header.first_chunk_number, file_header.last_chunk_number + 1):
        chunk_start = 0x1000 + (chunk_offset << 16)
        if chunk_start + struct.calcsize('<QQQQQQIII64sII') > len(file_buffer):
            break

        chunk_header = ChunkHeader(file_buffer[chunk_start:chunk_start + struct.calcsize('<QQQQQIIII64sII')])
        full_chunk_header = file_buffer[chunk_start:chunk_start + 512]

        if chunk_header.last_event_record_identifier != 0xFFFFFFFFFFFFFFFF:
            record_start = chunk_start + struct.calcsize('<QQQQQIIII64sII') + 0x180
            num_record = chunk_header.last_event_record_number - chunk_header.first_event_record_number + 1
            record_current = record_start

            # Iterating through each record in original evtx
            for each_record in range(num_record):
                record_current_end = record_current + struct.calcsize('<IIQQ')
                event_record = EventRecord(file_buffer[record_current:record_current_end])
                modified_event_data = file_buffer[record_current:record_current + event_record.size]

                chunk_buffer_temp = chunk_buffer + modified_event_data

                # If exe has not been fully added across the chunks
                if chunk_counter <= total_chunks:
                    if len(chunk_buffer_temp) >= (65536 - 512) - each_chunk_req:
                        chunk_list.append([chunk_counter, record_counter, len(chunk_buffer), previous_len,full_chunk_header, chunk_buffer])
                        total_records_counter_2 += record_counter
                        chunk_buffer = bytearray(b"")
                        record_counter = 0
                        chunk_counter += 1
                        # print(total_records_counter, total_records_counter_2, record_counter)

                # If exe has been fully added, no further space required
                else:
                    if len(chunk_buffer_temp) >= (65536 - 512):
                        chunk_list.append([chunk_counter, record_counter, len(chunk_buffer), previous_len,full_chunk_header,chunk_buffer])
                        chunk_buffer = bytearray(b"")
                        total_records_counter_2 += record_counter
                        record_counter = 0
                        chunk_counter += 1
                        # print(total_records_counter, total_records_counter_2, record_counter)

                # Final chunk
                if chunk_offset == file_header.last_chunk_number and (each_record + 1) == num_record:
                    chunk_list.append([chunk_counter, record_counter, len(chunk_buffer), previous_len, full_chunk_header,chunk_buffer])
                    chunk_buffer = bytearray(b"")
                    total_records_counter_2 += record_counter
                    print("PASS")
                    # print(total_records_counter, total_records_counter_2, record_counter)

                chunk_buffer += modified_event_data

                record_current += event_record.size
                record_counter += 1
                total_records_counter += 1

                last_offset_counter += len(chunk_buffer)
                previous_len = len(modified_event_data)
        break
    ## Final chunk to be added as well
    # chunk_list.append([chunk_counter, record_counter, len(chunk_buffer), previous_len,full_chunk_header,chunk_buffer])
    print(len(chunk_list))

    with open("newEVTX3.evtx", "wb") as evtx_output:
        # *** MANUAL OVERRIDE VALUES (For testing)
        # Values by default accounts for final chunk

        # Creating file header
        file_header.first_chunk_number = 0
        file_header.last_chunk_number = chunk_counter - 1 #*** -1 to remove consideration of final chunk
        file_header.number_of_chunks = chunk_counter + 1 - 1 #*** -1 to remove consideration of final chunk
        file_header.next_record_identifier = total_records_counter + 1 - record_counter #*** - record_counter to remove counts from final chunk
        file_header.checksum = calculate_crc32(file_header.to_bytes()[:120])
        new_header = file_header.to_bytes() + file_buffer[128:4096]

        evtx_output.write(new_header)
        record_counter = 1

        # Creating each chunk
        for i in chunk_list:
            # chunk_list contains a list of i, each containing the following list:
            #   Index 0: chunk_counter,
            #   Index 1: record_counter,
            #   Index 2: len(chunk_buffer),
            #   Index 3: previous_len,
            #   Index 4: full_chunk_header,
            #   Index 5: chunk_buffer

            # Creating chunk header
            chunk_head = ChunkHeader(i[-2][:128])
            chunk_head.first_event_record_number = record_counter
            chunk_head.last_event_record_number = record_counter + i[1] - 1
            chunk_head.first_event_record_identifier = record_counter
            chunk_head.last_event_record_identifier = record_counter + i[1] - 1
            chunk_head.last_event_record_data_offset = 512 + i[2] - i[3]
            record_counter += i[1]

            chunk_head.free_space_offset = 512 + i[2]
            chunk_head.event_records_checksum = calculate_crc32(i[-1])
            chunk_head.checksum = calculate_crc32(chunk_head.to_bytes()[:120] + i[-2][128:])
            chunk_head_final = chunk_head.to_bytes() + i[-2][128:]

            # Appending exe to empty chunk space
            chunk_whole = chunk_head_final + i[-1]
            hidden_index_end = 65536 - len(chunk_whole)
            hidden_data = exe_buffer[exe_counter:exe_counter + hidden_index_end]
            exe_counter = hidden_index_end
            chunk_whole += hidden_data
            evtx_output.write(chunk_whole)

if __name__ == "__main__":
    process_event_log("sec.evtx")
